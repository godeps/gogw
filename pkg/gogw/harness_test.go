package gogw_test

// harness_test.go builds the acceptance environment in-process: a mock control
// plane behind a switchable relay, one application per instance, one TLS front
// server per instance and one gateway per instance.
//
// The bootstrap order a release must follow is not arbitrary and every helper
// below respects it: the bundle is published, each instance is told to Prepare
// it, the prepared evidence is reported back, and only then is membership for
// that exact bundle hash published. Membership published before the evidence
// exists is rejected by design, so a test that skips a step would be testing a
// rollout that cannot happen.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/saker-ai/grayling/pkg/agent"
	"github.com/saker-ai/grayling/pkg/bucketing"
	"github.com/saker-ai/grayling/pkg/model"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/runtime"
	"github.com/traefik/traefik/v3/pkg/gogw"
	"github.com/traefik/traefik/v3/pkg/gogw/mock"
	"github.com/traefik/traefik/v3/pkg/server/service"
)

const (
	// awaitTimeout bounds every convergence wait. It is generous on purpose: a
	// slow machine must not turn a passing implementation into a flake.
	awaitTimeout = 20 * time.Second

	// awaitTick is the polling cadence of a convergence wait.
	awaitTick = 10 * time.Millisecond
)

// authority is the test certificate authority. Every leaf it issues carries a
// loopback address and the instance name, which is what the peer transport pins
// by digest and by server name.
type authority struct {
	cert   *x509.Certificate
	key    ed25519.PrivateKey
	path   string
	pool   *x509.CertPool
	serial atomic.Int64
}

// material is one issued key pair and its serving copy on disk. certFile and
// keyFile are stable per instance so a rotation can overwrite them in place and
// exercise the certificate watcher.
type material struct {
	pair     tls.Certificate
	key      ed25519.PrivateKey
	certFile string
	keyFile  string
	digest   string
}

func newAuthority(t *testing.T) *authority {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gogw-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &authority{cert: cert, key: key, path: path, pool: pool}
}

// issue writes a fresh leaf pair into dir as cert.pem and key.pem.
func (a *authority) issue(t *testing.T, name, dir string) material {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(a.serial.Add(1)),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    a.cert.NotBefore,
		NotAfter:     a.cert.NotAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, pub, a.key)
	require.NoError(t, err)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	digest := sha256.Sum256(der)
	return material{pair: pair, key: key, certFile: certFile, keyFile: keyFile, digest: hex.EncodeToString(digest[:])}
}

// switchboard is a raw TCP relay in front of the mock control plane. Cutting it
// black-holes the control plane and restoring it brings the same address back,
// which is the only way to exercise a reconnect against an unchanged
// configuration and to prove that a gateway started without a reachable control
// plane stays isolated.
type switchboard struct {
	listener net.Listener
	target   string
	open     atomic.Bool

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func newSwitchboard(t *testing.T, target string) *switchboard {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	relay := &switchboard{listener: listener, target: target, conns: map[net.Conn]struct{}{}}
	relay.open.Store(true)
	go relay.serve()
	t.Cleanup(relay.close)
	return relay
}

func (b *switchboard) addr() string { return b.listener.Addr().String() }

// origin is both the WSS connect origin and the resource download origin: the
// relay is byte transparent, so the mock's TLS endpoint is reachable through it.
func (b *switchboard) origin() string { return "https://" + b.addr() }

func (b *switchboard) serve() {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			return
		}
		if !b.open.Load() {
			_ = conn.Close()
			continue
		}
		go b.relay(conn)
	}
}

func (b *switchboard) relay(conn net.Conn) {
	upstream, err := net.DialTimeout("tcp", b.target, 2*time.Second)
	if err != nil {
		_ = conn.Close()
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = conn.Close()
		_ = upstream.Close()
		return
	}
	b.conns[conn] = struct{}{}
	b.conns[upstream] = struct{}{}
	b.mu.Unlock()
	go func() {
		_, _ = io.Copy(upstream, conn)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	b.mu.Lock()
	delete(b.conns, conn)
	delete(b.conns, upstream)
	b.mu.Unlock()
}

// cut refuses new connections and drops the live ones.
func (b *switchboard) cut() {
	b.open.Store(false)
	b.mu.Lock()
	defer b.mu.Unlock()
	for conn := range b.conns {
		_ = conn.Close()
	}
}

func (b *switchboard) restore() { b.open.Store(true) }

func (b *switchboard) close() {
	b.cut()
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	_ = b.listener.Close()
}

// instance is one co-deployed gateway under test: the application it fronts, the
// TLS terminator Traefik serves, and the gateway itself.
type instance struct {
	build   string
	name    string
	boot    string
	app     *httptest.Server
	server  *httptest.Server
	handler *atomic.Pointer[http.Handler]
	cfg     gogw.Config
	gateway *gogw.Gateway
	dir     string
	current material
	// previous is the key pair a rotation replaced, kept so a test can present
	// the retired certificate and the retired signing key.
	previous material
	cancel   context.CancelFunc
	done     chan struct{}
}

// start runs the gateway. It is called again by a restart test, which is what
// makes a restart observable from the outside.
func (in *instance) start(parent context.Context, t *testing.T) {
	t.Helper()
	require.Nil(t, in.cancel, "instance already running")
	ctx, cancel := context.WithCancel(parent)
	in.cancel, in.done = cancel, make(chan struct{})
	go func() {
		defer close(in.done)
		in.gateway.Run(ctx)
	}()
}

func (in *instance) stop(t *testing.T) {
	t.Helper()
	if in.cancel == nil {
		return
	}
	in.cancel()
	select {
	case <-in.done:
	case <-time.After(10 * time.Second):
		t.Error("gateway did not stop")
	}
	in.cancel, in.done = nil, nil
}

// rotate issues a new pair for the instance and replaces the serving files in
// place, which is what the certificate watcher observes.
func (in *instance) rotate(t *testing.T, ca *authority) {
	t.Helper()
	in.previous = in.current
	in.current = ca.issue(t, in.name, in.dir)
}

// activated is one published release and the membership revision that delivered
// it, kept so a test can republish membership for the same bundle hash.
type activated struct {
	release  mock.Release
	bundle   mock.Resource
	hash     string
	revision uint64
}

type cluster struct {
	ca      *authority
	scope   agent.Scope
	secret  []byte
	issuer  string
	control *mock.Server
	// signing is the control plane's release signing key, kept so a test can sign
	// one publication itself.
	signing ed25519.PrivateKey
	server  *httptest.Server
	relay   *switchboard
	members []*instance

	ctx    context.Context
	cancel context.CancelFunc

	public *http.Client

	upload   chan string
	canceled chan string
	writes   atomic.Int64

	// flaky holds one one-shot failure switch per instance, used to inject a
	// transport failure at a known candidate.
	flaky []*atomic.Bool
	// appHealthy holds the application health verdict of each instance. It is per
	// instance because a test has to be able to fail one application and watch what
	// the deployment does with the instance that still answers.
	appHealthy []*atomic.Bool

	revision uint64
	last     activated
	// previous is the release the last publication replaced, kept so a test can
	// present a straggler that names a retired bundle.
	previous activated
}

type clusterSpec struct {
	builds  []string
	tune    func(*gogw.Config)
	offline bool
}

type clusterOption func(*clusterSpec)

// withBuilds replaces the default stable and canary builds. The instance name of
// build b at index i is "b-i", so a repeated build gets a distinct identity.
func withBuilds(builds ...string) clusterOption {
	return func(spec *clusterSpec) { spec.builds = builds }
}

// withConfig adjusts every gateway configuration before the gateway is built.
func withConfig(tune func(*gogw.Config)) clusterOption {
	return func(spec *clusterSpec) { spec.tune = tune }
}

// withOfflineControlPlane starts the gateways while the control plane address is
// black-holed, which is how a gateway starts before the control plane is
// routable.
func withOfflineControlPlane() clusterOption {
	return func(spec *clusterSpec) { spec.offline = true }
}

func newCluster(t *testing.T, opts ...clusterOption) *cluster {
	t.Helper()
	spec := clusterSpec{builds: []string{"stable", "canary"}}
	for _, opt := range opts {
		opt(&spec)
	}
	ctx, cancel := context.WithCancel(t.Context())
	c := &cluster{
		ctx: ctx, cancel: cancel,
		scope:    agent.Scope{WorkspaceID: "demo", EnvironmentID: "test", ServiceKey: "checkout"},
		secret:   []byte(strings.Repeat("s", 32)),
		issuer:   "test-auth",
		upload:   make(chan string, 8),
		canceled: make(chan string, 32),
	}
	c.ca = newAuthority(t)

	_, signing, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	c.signing = signing
	c.control, err = mock.New(mock.Options{
		Scope: c.scope, Token: "test-token", KeyID: "mock", SigningKey: signing,
		Heartbeat: 200 * time.Millisecond,
	})
	require.NoError(t, err)
	c.server = httptest.NewUnstartedServer(c.control.Handler())
	c.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{c.ca.issue(t, "control", t.TempDir()).pair}}
	c.server.StartTLS()
	c.relay = newSwitchboard(t, c.server.Listener.Addr().String())
	if spec.offline {
		c.relay.cut()
	}
	c.control.SetOrigin(c.relay.origin())

	c.public = &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: c.ca.pool, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true},
		Timeout:   30 * time.Second,
	}

	for index, build := range spec.builds {
		c.members = append(c.members, c.newInstance(t, spec, index, build))
	}
	for _, in := range c.members {
		in.start(ctx, t)
	}
	// The health probe owns the first health verdict, and an unprobed instance is
	// not eligible. A test that reads eligibility, registration or a membership
	// would otherwise observe the probe instead of the state it means to assert, so
	// the cluster is not returned until every gateway has a verdict.
	for _, in := range c.members {
		await(t, "the health verdict of "+in.name, func() bool {
			return in.gateway.Diagnostics().Healthy
		})
	}

	t.Cleanup(func() {
		for _, in := range c.members {
			in.stop(t)
		}
		cancel()
		c.public.CloseIdleConnections()
		for _, in := range c.members {
			in.server.Close()
			in.app.Close()
		}
		c.control.Close()
		c.server.Close()
	})
	return c
}

func (c *cluster) newInstance(t *testing.T, spec clusterSpec, index int, build string) *instance {
	t.Helper()
	name := fmt.Sprintf("%s-%d", build, index)
	dir := t.TempDir()
	c.flaky = append(c.flaky, &atomic.Bool{})
	app := httptest.NewServer(c.appHandler(build, name, index))
	c.appHealthy = append(c.appHealthy, &atomic.Bool{})
	c.appHealthy[index].Store(true)

	serving := c.ca.issue(t, name, dir)
	var handler atomic.Pointer[http.Handler]
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		active := handler.Load()
		if active == nil {
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		(*active).ServeHTTP(rw, req)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serving.pair},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    c.ca.pool,
	}
	server.StartTLS()

	secretFile := filepath.Join(dir, "identity")
	tokenFile := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(secretFile, c.secret, 0o600))
	require.NoError(t, os.WriteFile(tokenFile, []byte("test-token"), 0o600))
	port, err := strconv.Atoi(strings.TrimPrefix(server.URL, "https://127.0.0.1:"))
	require.NoError(t, err)

	cfg := gogw.Config{
		Service: "checkout", Scope: c.scope, Instance: name, Boot: name + "-boot", Build: build,
		LocalURL: app.URL, HealthPath: "/health", GraylingURL: "wss://" + c.relay.addr(), TokenFile: tokenFile,
		StateFile: filepath.Join(dir, "state"), AdvertiseAddress: "127.0.0.1", AdvertisePort: port,
		CertFile: serving.certFile, KeyFile: serving.keyFile, CAFile: c.ca.path,
		PolicyKeyID: c.control.KeyID(), PolicyPublicKey: hex.EncodeToString(c.control.PublicKey()),
		IdentitySecretFile: secretFile, IdentityIssuer: c.issuer,
		// New does not apply the defaults Load applies, so every window and
		// capacity is set explicitly: a zero window would force-close a stream
		// immediately and a zero session capacity would evict every binding.
		PreparedTTLSeconds: 300, DrainGraceSeconds: 5, CertificateOverlapSeconds: 60,
		SessionCompatibilitySeconds: 120, MaxTrackedSessions: 4096, MaxRetainedViews: 4,
	}
	if spec.tune != nil {
		spec.tune(&cfg)
	}
	gateway, err := gogw.New(cfg)
	require.NoError(t, err)

	factory := &service.ManagerFactory{}
	factory.AddServiceBuilder(gateway)
	built, err := factory.Build(&runtime.Configuration{}).BuildHTTP(c.ctx, "checkout@gogw")
	require.NoError(t, err)
	require.NotNil(t, built)
	handler.Store(&built)

	return &instance{
		build: build, name: name, boot: cfg.Boot,
		app: app, server: server, handler: &handler, cfg: cfg, gateway: gateway, dir: dir,
		current: serving,
	}
}

// appHandler is the application the gateway fronts. It reports the identity and
// the build it was reached with, and it offers the streaming, cancellation and
// ambiguous-write surfaces the acceptance matrix needs.
func (c *cluster) appHandler(build, name string, index int) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/health":
			if !c.appHealthy[index].Load() {
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			rw.WriteHeader(http.StatusNoContent)
			return
		case "/upload":
			first := make([]byte, 1)
			if _, err := io.ReadFull(req.Body, first); err != nil {
				rw.WriteHeader(http.StatusBadRequest)
				return
			}
			// The upload reports the same identity as every other surface, so a test
			// can assert the hop of a streamed request too.
			rw.Header().Set("X-Actual-Build", build)
			rw.Header().Set("X-Actual-Instance", name)
			rw.Header().Set("X-Actual-Hop", hopOf(req))
			c.upload <- build
			rest, err := io.ReadAll(req.Body)
			if err != nil {
				rw.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = rw.Write(append(first, rest...))
			return
		case "/sse":
			rw.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(rw, "data: %s\n\n", build)
			rw.(http.Flusher).Flush()
			<-req.Context().Done()
			select {
			case c.canceled <- build:
			default:
			}
			return
		}
		if req.Method == http.MethodPost {
			c.writes.Add(1)
		}
		if req.URL.Path == "/ambiguous" {
			// The write is applied and the acknowledgement is lost: a response
			// that never arrives is exactly the case a retry must not repeat.
			if conn, _, err := rw.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		}
		if req.URL.Path == "/flaky" && c.flaky[index].CompareAndSwap(true, false) {
			if conn, _, err := rw.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		}
		rw.Header().Set("X-Actual-Build", build)
		rw.Header().Set("X-Actual-Instance", name)
		rw.Header().Set("X-Actual-Subject", req.Header.Get("X-Gogw-Subject"))
		rw.Header().Set("X-Actual-Hop", hopOf(req))
		_, _ = io.WriteString(rw, req.URL.RequestURI())
	}
}

// hopOf reports how a request reached the application, as the gateway of the
// serving process marked it. A marker no gateway set is reported as unmarked, so
// a missing hop never reads like a direct request.
func hopOf(req *http.Request) string {
	switch value := req.Header.Get(hopHeaderName); value {
	case "0":
		return "local"
	case "1":
		return "1"
	case "":
		return "unmarked"
	default:
		return "malformed"
	}
}

// nextRevision returns a discovery revision that strictly advances, which is
// what the resource watermark requires.
func (c *cluster) nextRevision() uint64 {
	c.revision++
	return c.revision
}

// publish uploads one release bundle. Nothing is servable yet: a bundle is an
// approved policy, not a membership.
func (c *cluster) publish(t *testing.T, release mock.Release) activated {
	t.Helper()
	bundle, err := c.control.PublishBundle(release)
	require.NoError(t, err)
	c.previous = c.last
	c.last = activated{release: release, bundle: bundle, hash: hex.EncodeToString(bundle.Hash[:])}
	return c.last
}

// awaitRegistered waits until every instance holds a lease.
func (c *cluster) awaitRegistered(t *testing.T) {
	t.Helper()
	for _, in := range c.members {
		await(t, "lease of "+in.name, func() bool {
			state, ok := c.control.Instance(in.name)
			return ok && state.LeaseEpoch > 0
		})
	}
}

// prepare sends one Prepare per instance and waits for the evidence to be
// reported back, which is what makes a membership artifact acceptable.
func (c *cluster) prepare(t *testing.T) {
	t.Helper()
	c.awaitRegistered(t)
	hash := c.last.hash
	for _, in := range c.members {
		require.NoError(t, c.control.Prepare(in.name, c.last.bundle, time.Minute))
	}
	for _, in := range c.members {
		await(t, "prepared evidence of "+in.name, func() bool {
			state, ok := c.control.Instance(in.name)
			return ok && state.PreparedHash == hash
		})
	}
	for _, in := range c.members {
		await(t, "prepared report of "+in.name, func() bool { return in.gateway.Diagnostics().Prepared })
	}
}

// awaitConverged waits until the control plane's view of every instance agrees
// with what that instance advertises. Eligibility travels out of band on its own
// cadence, so a membership artifact published before it arrives names instances
// the control plane still describes with the previous state — a membership that
// does not say what the test means it to say.
func (c *cluster) awaitConverged(t *testing.T) {
	t.Helper()
	for _, in := range c.members {
		await(t, "the control plane's view of "+in.name, func() bool {
			state, ok := c.control.Instance(in.name)
			diagnostics := in.gateway.Diagnostics()
			if !ok {
				// An instance the control plane no longer holds is converged once
				// it stopped advertising itself.
				return !diagnostics.Registered
			}
			return state.Ready == diagnostics.Eligible && state.Draining == diagnostics.Draining
		})
	}
}

// membership publishes the membership of the current bundle. It does not wait
// for a view: an unpublished Activate must leave the release unserved, so the
// caller decides what to observe next.
func (c *cluster) membership(t *testing.T, edits ...memberEdit) uint64 {
	t.Helper()
	return c.publishMembership(t, 10*time.Minute, edits...)
}

// publishMembership publishes the membership with a validity the caller picks,
// so an expiry can be observed on the discovery artifact itself rather than on
// the policy the release carries.
func (c *cluster) publishMembership(t *testing.T, ttl time.Duration, edits ...memberEdit) uint64 {
	t.Helper()
	c.awaitConverged(t)
	revision := c.nextRevision()
	_, err := c.control.PublishDiscovery(c.last.bundle.Hash, revision, ttl, c.membersWith(edits...))
	require.NoError(t, err)
	c.last.revision = revision
	return revision
}

// updateMembership republishes the membership of the release that is already
// serving and waits until every gateway serves the new revision.
func (c *cluster) updateMembership(t *testing.T, edits ...memberEdit) {
	t.Helper()
	revision := c.membership(t, edits...)
	for _, in := range c.members {
		await(t, "membership revision on "+in.name, func() bool {
			return in.gateway.Diagnostics().DiscoveryRevision == revision
		})
	}
}

// membersWith renders the membership of the current bundle: the mock's registry
// view, with the address and the certificate identity this test process actually
// serves substituted for every registered instance. A control plane cannot
// observe a served certificate, so the digest is supplied out of band exactly as
// a release file does in production.
func (c *cluster) membersWith(edits ...memberEdit) []gogw.Member {
	overlay := make([]gogw.Member, 0, len(c.members))
	for _, in := range c.members {
		overlay = append(overlay, gogw.Member{
			InstanceID: in.name, BootID: in.boot, BuildID: in.build,
			URL: in.server.URL, TLSServerName: in.name,
			Certificate: gogw.CertificateIdentity{SHA256: in.current.digest},
		})
	}
	members := mock.OverlayMembers(c.control.Members(c.last.bundle.Hash), overlay)
	for _, edit := range edits {
		members = edit(members)
	}
	return members
}

// activate drives one release to serving on every instance.
func (c *cluster) activate(t *testing.T, release mock.Release, edits ...memberEdit) activated {
	t.Helper()
	published := c.publish(t, release)
	c.prepare(t)
	c.membership(t, edits...)
	c.awaitServing(t)
	return published
}

// awaitServing waits until every gateway serves the current release.
func (c *cluster) awaitServing(t *testing.T) {
	t.Helper()
	hash := c.last.hash
	for _, in := range c.members {
		await(t, "an active view on "+in.name, func() bool {
			diagnostics := in.gateway.Diagnostics()
			return diagnostics.Ready && diagnostics.BundleHash == hash
		})
	}
}

func await(t *testing.T, what string, condition func() bool) {
	t.Helper()
	require.Eventuallyf(t, condition, awaitTimeout, awaitTick, "timed out waiting for %s", what)
}

// settled asserts that a condition still holds after a short settle period. It
// is used only where a negative must be observed, never to prove a positive.
func settled(condition func() bool) bool {
	time.Sleep(500 * time.Millisecond)
	return condition()
}

type memberEdit func([]gogw.Member) []gogw.Member

// onlyMembers keeps the named instances in the membership.
func onlyMembers(instances ...string) memberEdit {
	return func(members []gogw.Member) []gogw.Member {
		kept := members[:0]
		for _, member := range members {
			if slices.Contains(instances, member.InstanceID) {
				kept = append(kept, member)
			}
		}
		return kept
	}
}

// drainingMembers marks the named instances draining, which is what a member
// converging out of service advertises.
func drainingMembers(instances ...string) memberEdit {
	return func(members []gogw.Member) []gogw.Member {
		for index := range members {
			if slices.Contains(instances, members[index].InstanceID) {
				members[index].Draining = true
			}
		}
		return members
	}
}

// notReadyMembers clears the readiness of the named instances.
func notReadyMembers(instances ...string) memberEdit {
	return func(members []gogw.Member) []gogw.Member {
		for index := range members {
			if slices.Contains(instances, members[index].InstanceID) {
				members[index].Ready = false
			}
		}
		return members
	}
}

// certificateMembers publishes an explicit certificate identity for one
// instance. During a certificate rotation the previous digest and its overlap
// deadline are what let a peer keep accepting the retiring certificate.
func certificateMembers(instance, digest, previous string, previousUntil time.Time) memberEdit {
	return func(members []gogw.Member) []gogw.Member {
		for index := range members {
			if members[index].InstanceID != instance {
				continue
			}
			members[index].Certificate = gogw.CertificateIdentity{SHA256: digest, PreviousSHA256: previous}
			if !previousUntil.IsZero() {
				members[index].Certificate.PreviousValidUntilUnixMs = previousUntil.UnixMilli()
			}
		}
		return members
	}
}

// request sends one authenticated business request through one gateway.
func (c *cluster) request(t *testing.T, index int, method, path, subject, tenant string, headers http.Header) *http.Response {
	t.Helper()
	response, err := c.public.Do(c.newRequest(t, index, method, path, subject, tenant, nil, headers))
	require.NoError(t, err)
	return response
}

// requestBody is request with a body, for the streaming cases.
func (c *cluster) requestBody(t *testing.T, index int, method, path, subject, tenant string, body io.Reader, headers http.Header) *http.Response {
	t.Helper()
	response, err := c.public.Do(c.newRequest(t, index, method, path, subject, tenant, body, headers))
	require.NoError(t, err)
	return response
}

// raw sends a request without an identity, for the rejection cases.
func (c *cluster) raw(t *testing.T, index int, method, path string, headers http.Header) *http.Response {
	t.Helper()
	return c.do(t, index, method, path, nil, headers)
}

func (c *cluster) do(t *testing.T, index int, method, path string, body io.Reader, headers http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(c.ctx, method, c.members[index].server.URL+path, body)
	require.NoError(t, err)
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	response, err := c.public.Do(req)
	require.NoError(t, err)
	return response
}

func (c *cluster) newRequest(t *testing.T, index int, method, path, subject, tenant string, body io.Reader, headers http.Header) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(c.ctx, method, c.members[index].server.URL+path, body)
	require.NoError(t, err)
	claims := jwt.MapClaims{
		"iss": c.issuer, "aud": c.scope.ServiceKey, "sub": subject, "tenant": tenant,
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(c.secret)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+signed)
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	return req
}

// bearerToken mints one identity token, so a test can send an invalid one.
func (c *cluster) bearerToken(t *testing.T, claims jwt.MapClaims, secret []byte) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	require.NoError(t, err)
	return signed
}

// body reads and closes a response body.
func body(t *testing.T, response *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	return string(raw)
}

// counter reports one bounded metric counter.
func counter(diagnostics gogw.Diagnostics, phase, label string) int64 {
	var total int64
	for _, sample := range diagnostics.Counters {
		if sample.Phase == phase && sample.Label == label {
			total += sample.Count
		}
	}
	return total
}

// release builds one publishable release over the two builds of the cluster. A
// nil flags argument keeps the routing policy that sends the canary cohort to
// the canary build.
func release(generation uint64, ramp *gogw.Ramp, flags map[string]*model.Flag) mock.Release {
	if flags == nil {
		flags = targetingFlags()
	}
	return mock.Release{
		ReleaseID:              fmt.Sprintf("release-%d", generation),
		Generation:             generation,
		Flag:                   "routing",
		DefaultBuild:           "stable",
		Builds:                 map[string]gogw.BuildDescriptor{"stable": {ImageDigest: digestOf("stable")}, "canary": {ImageDigest: digestOf("canary")}},
		Ramp:                   ramp,
		Policy:                 policy(generation, flags),
		MinimumProtocolVersion: 1,
		DiscoveryMaxAgeSeconds: 600,
	}
}

// digestOf is the image digest of one build. It is a bare hexadecimal digest:
// the release document carries no algorithm prefix.
func digestOf(build string) string {
	sum := sha256.Sum256([]byte(build))
	return hex.EncodeToString(sum[:])
}

// policy is the approved policy snapshot. The manifest revision tracks the
// release generation, which is what an operator reviewing the rollout sees.
func policy(revision uint64, flags map[string]*model.Flag) model.Snapshot {
	if flags == nil {
		flags = targetingFlags()
	}
	return model.Snapshot{
		SchemaVersion: 1, Workspace: "demo", Environment: "test", ManifestRevision: int64(revision),
		Flags:    flags,
		Segments: map[string]*model.Segment{},
	}
}

// targetingFlags sends the canary cohort to the canary build: one explicit
// targeting key and one entire tenant. Every other subject stays on the default
// build, so an unexpected canary answer is a real allocation defect.
func targetingFlags() map[string]*model.Flag {
	return map[string]*model.Flag{"routing": routingFlag(model.Rule{Variation: "stable"}, []model.Rule{
		{Constraints: []model.Constraint{{Field: "targetingKey", Op: model.OpEq, Value: "canary-user"}}, Variation: "canary"},
		{Constraints: []model.Constraint{{Field: "tenant", Op: model.OpEq, Value: "early"}}, Variation: "canary"},
	})}
}

// percentageFlags is the ramp-by-ratio policy. The split is not prefix stable by
// contract, so it is used to prove that the partitioning is a function of the
// subject alone and not of the number of instances.
func percentageFlags(canary, stable float64) map[string]*model.Flag {
	return map[string]*model.Flag{"routing": routingFlag(model.Rule{Percentage: map[string]float64{"canary": canary, "stable": stable}}, nil)}
}

func routingFlag(defaultRule model.Rule, targeting []model.Rule) *model.Flag {
	return &model.Flag{
		SchemaVersion: 1, Key: "routing", Type: model.FlagString,
		Bucketing:   &model.Bucketing{Algorithm: bucketing.AlgorithmID, Unit: "targetingKey", Salt: "fixed"},
		Fields:      []string{"tenant", "tier", "client_ip"},
		Variations:  map[string]any{"stable": "stable", "canary": "canary"},
		DefaultRule: &defaultRule,
		Targeting:   targeting,
	}
}

// ticketClaims mirrors the wire form of a final forwarding ticket. It is
// duplicated here so the test signs exactly what a peer gateway signs: the
// receiver rejects an unknown member, so this type is also an assertion on the
// frozen field names.
type ticketClaims struct {
	Issuer      string `json:"iss"`
	IssuerBoot  string `json:"iboot"`
	Subject     string `json:"sub"`
	SubjectBoot string `json:"sboot"`
	Build       string `json:"bld"`
	Bundle      string `json:"bnd"`
	Generation  uint64 `json:"gen"`
	Method      string `json:"m"`
	Authority   string `json:"aud"`
	URI         string `json:"uri"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	Final       bool   `json:"fin"`
	Hop         int    `json:"hop"`
	Principal   string `json:"prn"`
	Tenant      string `json:"tnt"`
	DecisionID  string `json:"dec,omitempty"`
}

func signTestTicket(t *testing.T, key ed25519.PrivateKey, claims ticketClaims) string {
	t.Helper()
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}{Algorithm: "EdDSA", Type: "gogw-final+jwt"})
	require.NoError(t, err)
	body, err := json.Marshal(claims)
	require.NoError(t, err)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signing)))
}

// peerClient is the client a peer gateway is: it presents one client
// certificate and trusts the test authority.
func (c *cluster) peerClient(pair tls.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: c.ca.pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
		Timeout: 10 * time.Second,
	}
}

// peerRequest sends one request carrying a hand-minted final ticket, which is
// how the internal gateway-to-gateway surface is addressed directly.
func (c *cluster) peerRequest(t *testing.T, index int, pair tls.Certificate, method, path string, headers http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(c.ctx, method, c.members[index].server.URL+path, nil)
	require.NoError(t, err)
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	client := c.peerClient(pair)
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	require.NoError(t, err)
	return response
}

// journalContains reports whether the control plane recorded one inbound message
// kind for an instance.
func (c *cluster) journalContains(kind, instance string) bool {
	for _, entry := range c.control.Journal() {
		if entry.Kind == kind && (instance == "" || entry.InstanceID == instance) {
			return true
		}
	}
	return false
}

// journalSince lists the entries the control plane recorded after a journal
// position, so a test can tell a message of a new session or a new revision from
// the identical one its predecessor left behind.
func (c *cluster) journalSince(from int) []mock.Entry {
	entries := c.control.Journal()
	return entries[min(from, len(entries)):]
}
