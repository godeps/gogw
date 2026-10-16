package gogw_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
	"github.com/saker-ai/grayling/pkg/bucketing"
	"github.com/saker-ai/grayling/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/runtime"
	"github.com/traefik/traefik/v3/pkg/gogw"
	"github.com/traefik/traefik/v3/pkg/gogw/mock"
	"github.com/traefik/traefik/v3/pkg/server/service"
	"google.golang.org/protobuf/proto"
)

type cluster struct {
	upload      chan struct{}
	control     *mock.Server
	controlHTTP *httptest.Server
	gateways    []*gogw.Gateway
	servers     []*httptest.Server
	apps        []*httptest.Server
	cfgs        []gogw.Config
	bundle      gogw.Bundle
	public      *http.Client
	peer        *http.Client
	secret      []byte
	cancel      context.CancelFunc
	done        []chan struct{}
	canceled    chan string
	writes      atomic.Int64
	healthy     atomic.Bool
}

type authority struct {
	cert   *x509.Certificate
	key    ed25519.PrivateKey
	path   string
	pool   *x509.CertPool
	serial int64
}

func newAuthority(t *testing.T) *authority {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gogw-test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &authority{cert: cert, key: key, path: path, pool: pool, serial: 1}
}

func (a *authority) issue(t *testing.T, name string) (tls.Certificate, string, string, string) {
	t.Helper()
	a.serial++
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(a.serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: a.cert.NotBefore, NotAfter: a.cert.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, pub, a.key)
	require.NoError(t, err)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	digest := sha256.Sum256(der)
	return pair, certPath, keyPath, hex.EncodeToString(digest[:])
}

func newCluster(t *testing.T, extra ...string) *cluster {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	c := &cluster{secret: []byte(strings.Repeat("s", 32)), cancel: cancel, canceled: make(chan string, 20), upload: make(chan struct{}, 1)}
	c.healthy.Store(true)
	ca := newAuthority(t)
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	c.control = &mock.Server{Scope: agent.Scope{WorkspaceID: "demo", EnvironmentID: "test", ServiceKey: "checkout"}, Service: "checkout", Token: "test-token", KeyID: "mock", PrivateKey: signing, ValidFor: time.Minute}
	controlPair, controlCert, controlKey, controlDigest := ca.issue(t, "control")
	_ = controlCert
	_ = controlKey
	_ = controlDigest
	c.controlHTTP = httptest.NewUnstartedServer(c.control)
	c.controlHTTP.TLS = &tls.Config{Certificates: []tls.Certificate{controlPair}, MinVersion: tls.VersionTLS12}
	c.controlHTTP.StartTLS()
	c.public = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true}, Timeout: 5 * time.Second}
	builds := append([]string{"stable", "canary"}, extra...)
	for i, build := range builds {
		instance := build
		if i >= 2 {
			instance = fmt.Sprintf("%s-%d", build, i)
		}
		app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				if !c.healthy.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
				return
			}
			if r.URL.Path == "/upload" {
				first := make([]byte, 1)
				if _, err := io.ReadFull(r.Body, first); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				c.upload <- struct{}{}
				rest, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				_, _ = w.Write(append(first, rest...))
				return
			}
			if r.URL.Path == "/sse" {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprintf(w, "data: %s\n\n", build)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				c.canceled <- build
				return
			}
			if r.Method == http.MethodPost {
				c.writes.Add(1)
			}
			if r.URL.Path == "/ambiguous" {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			w.Header().Set("X-Actual-Build", build)
			w.Header().Set("X-Actual-Instance", instance)
			w.Header().Set("X-Actual-Subject", r.Header.Get("X-Gogw-Subject"))
			_, _ = io.WriteString(w, r.URL.RequestURI())
		}))
		c.apps = append(c.apps, app)
		pair, cert, key, digest := ca.issue(t, instance)
		var handler atomic.Pointer[http.Handler]
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := handler.Load()
			if h == nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			(*h).ServeHTTP(w, r)
		}))
		server.EnableHTTP2 = true
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.pool}
		server.StartTLS()
		c.servers = append(c.servers, server)
		dir := t.TempDir()
		secret := filepath.Join(dir, "identity")
		token := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(secret, c.secret, 0o600))
		require.NoError(t, os.WriteFile(token, []byte("test-token"), 0o600))
		cfg := gogw.Config{Service: "checkout", Scope: c.control.Scope, Instance: instance, Boot: instance + "-boot", Build: build, LocalURL: app.URL, GraylingURL: "wss" + strings.TrimPrefix(c.controlHTTP.URL, "https"), TokenFile: token, StateFile: filepath.Join(dir, "state"), CertFile: cert, KeyFile: key, CAFile: ca.path, PolicyKeyID: "mock", PolicyPublicKey: mock.PublicKey(signing), IdentitySecretFile: secret, IdentityIssuer: "test-auth"}
		g, err := gogw.New(cfg)
		require.NoError(t, err)
		c.gateways = append(c.gateways, g)
		c.cfgs = append(c.cfgs, cfg)
		factory := &service.ManagerFactory{}
		factory.AddServiceBuilder(g)
		h, err := factory.Build(&runtime.Configuration{}).BuildHTTP(ctx, "checkout@gogw")
		require.NoError(t, err)
		require.NotNil(t, h)
		handler.Store(&h)
		c.bundle.Endpoints = append(c.bundle.Endpoints, gogw.Endpoint{Instance: instance, Boot: instance + "-boot", Build: build, URL: server.URL, ServerName: instance, CertificateSHA256: digest, Ready: true, Prepared: true, ExpiresUnix: time.Now().Add(time.Minute).Unix()})
		if c.peer == nil {
			c.peer = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}, Timeout: time.Second}
		}
	}
	c.bundle.Schema = 1
	c.bundle.Generation = 1
	c.bundle.DiscoveryRevision = 1
	c.bundle.DiscoveryExpiresUnix = time.Now().Add(time.Minute).Unix()
	c.bundle.Flag = "routing"
	c.bundle.Policy = model.Snapshot{SchemaVersion: 1, Workspace: "demo", Environment: "test", ManifestRevision: 1, Flags: map[string]*model.Flag{"routing": {SchemaVersion: 1, Key: "routing", Type: model.FlagString, Bucketing: &model.Bucketing{Algorithm: bucketing.AlgorithmID, Unit: "targetingKey", Salt: "fixed"}, Fields: []string{"tenant", "tier", "client_ip"}, Variations: map[string]any{"stable": "stable", "canary": "canary"}, DefaultRule: &model.Rule{Variation: "stable"}, Targeting: []model.Rule{{Constraints: []model.Constraint{{Field: "targetingKey", Op: model.OpEq, Value: "canary-user"}}, Variation: "canary"}, {Constraints: []model.Constraint{{Field: "tenant", Op: model.OpEq, Value: "early"}}, Variation: "canary"}}}}, Segments: map[string]*model.Segment{}}
	require.NoError(t, c.control.Publish(c.bundle))
	for _, g := range c.gateways {
		done := make(chan struct{})
		c.done = append(c.done, done)
		go func() { defer close(done); g.Run(ctx) }()
	}
	t.Cleanup(func() {
		cancel()
		c.control.Close()
		for _, done := range c.done {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("Agent did not stop")
			}
		}
		c.public.CloseIdleConnections()
		c.peer.CloseIdleConnections()
		for _, s := range c.servers {
			s.Close()
		}
		for _, app := range c.apps {
			app.Close()
		}
		c.controlHTTP.Close()
	})
	require.Eventually(t, func() bool {
		return c.control.Applied.Load() >= int64(len(builds)) && c.gateways[0].Ready() && c.gateways[1].Ready()
	}, 5*time.Second, 10*time.Millisecond)
	return c
}

func (c *cluster) request(t *testing.T, index int, method, path, subject, tenant string, headers http.Header) *http.Response {
	t.Helper()
	claims := jwt.MapClaims{"iss": "test-auth", "aud": "checkout", "sub": subject, "tenant": tenant, "exp": time.Now().Add(time.Minute).Unix()}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(c.secret)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), method, c.servers[index].URL+path, nil)
	require.NoError(t, err)
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Authorization", "Bearer "+raw)
	response, err := c.public.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

func TestLocalAndSingleHop(t *testing.T) {
	c := newCluster(t)
	for _, tt := range []struct{ subject, tenant, build string }{{"ordinary", "", "stable"}, {"canary-user", "", "canary"}, {"ordinary", "early", "canary"}} {
		response := c.request(t, 0, http.MethodGet, "/a%2Fb?q=x%2Fy", tt.subject, tt.tenant, http.Header{"X-Gogw-Subject": []string{"forged"}})
		require.Equal(t, 200, response.StatusCode)
		assert.Equal(t, tt.build, response.Header.Get("X-Actual-Build"))
		assert.Equal(t, tt.subject, response.Header.Get("X-Actual-Subject"))
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		assert.Equal(t, "/a%2Fb?q=x%2Fy", string(body))
	}
	response := c.request(t, 0, http.MethodPost, "/write", "canary-user", "", nil)
	require.Equal(t, 200, response.StatusCode)
	assert.EqualValues(t, 1, c.writes.Load())
	response = c.request(t, 1, http.MethodGet, "/reverse", "ordinary", "", nil)
	require.Equal(t, 200, response.StatusCode)
	assert.Equal(t, "stable", response.Header.Get("X-Actual-Build"))
}

func TestUntrustedRequests(t *testing.T) {
	c := newCluster(t)
	response := c.request(t, 0, http.MethodGet, "/", "ordinary", "", http.Header{"X-Gogw-Ticket": []string{"forged"}})
	assert.Equal(t, 403, response.StatusCode)
	response, err := c.peer.Get(c.servers[1].URL)
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, 403, response.StatusCode)
	response, err = c.public.Get(c.servers[0].URL)
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, 401, response.StatusCode)
	unsupported := c.request(t, 0, http.MethodGet, "/", "ordinary", "", http.Header{"Content-Type": []string{"application/grpc"}})
	assert.Equal(t, http.StatusNotImplemented, unsupported.StatusCode)
	response = c.request(t, 0, http.MethodGet, "/?a=1;b=2", "ordinary", "", nil)
	assert.Equal(t, 400, response.StatusCode)
}

func TestSSECancelAndDrain(t *testing.T) {
	c := newCluster(t)
	response := c.request(t, 0, http.MethodGet, "/sse", "canary-user", "", nil)
	require.Equal(t, 200, response.StatusCode)
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "data: canary\n", line)
	c.gateways[0].Drain()
	assert.False(t, c.gateways[0].Ready())
	assert.EqualValues(t, 1, c.gateways[0].ActiveRequests())
	denied := c.request(t, 0, http.MethodGet, "/", "ordinary", "", nil)
	assert.Equal(t, 503, denied.StatusCode)
	require.NoError(t, response.Body.Close())
	select {
	case build := <-c.canceled:
		assert.Equal(t, "canary", build)
	case <-time.After(time.Second):
		t.Fatal("upstream cancellation did not propagate")
	}
	require.Eventually(t, func() bool { return c.gateways[0].ActiveRequests() == 0 && c.gateways[1].ActiveRequests() == 0 }, time.Second, time.Millisecond)
}

func cloneBundle(t *testing.T, b gogw.Bundle) gogw.Bundle {
	t.Helper()
	data, err := json.Marshal(b)
	require.NoError(t, err)
	var cloned gogw.Bundle
	require.NoError(t, json.Unmarshal(data, &cloned))
	return cloned
}

func (c *cluster) publish(t *testing.T, b gogw.Bundle) {
	t.Helper()
	before := c.control.Applied.Load()
	require.NoError(t, c.control.Publish(b))
	require.Eventually(t, func() bool { return c.control.Applied.Load() >= before+2 }, 3*time.Second, 10*time.Millisecond)
}

func TestUpdatesRollbackAndFailures(t *testing.T) {
	c := newCluster(t)
	b := cloneBundle(t, c.bundle)
	b.Generation = 2
	b.Policy.ManifestRevision = 2
	b.DiscoveryRevision = 2
	b.Policy.Flags["routing"].DefaultRule = &model.Rule{Variation: "canary"}
	c.publish(t, b)
	response := c.request(t, 0, http.MethodGet, "/", "ordinary", "", nil)
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
	rejected := c.control.Rejected.Load()
	require.NoError(t, c.control.Publish(c.bundle))
	require.Eventually(t, func() bool { return c.control.Rejected.Load() >= rejected+2 }, 3*time.Second, 10*time.Millisecond)
	response = c.request(t, 0, http.MethodGet, "/", "ordinary", "", nil)
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
	b.Generation = 3
	b.Policy.ManifestRevision = 3
	b.DiscoveryRevision = 3
	b.Endpoints[1].Draining = true
	// Local candidate readiness is mandatory, so the canary gateway rejects this
	// view while the stable gateway removes canary from its eligible set.
	before := c.control.Applied.Load()
	require.NoError(t, c.control.Publish(b))
	require.Eventually(t, func() bool { return c.control.Applied.Load() > before }, 3*time.Second, 10*time.Millisecond)
	response = c.request(t, 0, http.MethodGet, "/", "ordinary", "", nil)
	assert.Equal(t, 503, response.StatusCode)
}

func TestControlDisconnectAndHealth(t *testing.T) {
	c := newCluster(t)
	c.control.Close()
	c.controlHTTP.Close()
	response := c.request(t, 0, http.MethodGet, "/", "canary-user", "", nil)
	assert.Equal(t, 200, response.StatusCode)
	c.healthy.Store(false)
	require.Eventually(t, func() bool { return !c.gateways[0].Ready() && !c.gateways[1].Ready() }, 3*time.Second, 10*time.Millisecond)
	response = c.request(t, 0, http.MethodGet, "/", "ordinary", "", nil)
	assert.Equal(t, 503, response.StatusCode)
}

func TestStableBuckets(t *testing.T) {
	c := newCluster(t)
	b := cloneBundle(t, c.bundle)
	b.Generation = 2
	b.Policy.ManifestRevision = 2
	b.DiscoveryRevision = 2
	b.Policy.Flags["routing"].DefaultRule = &model.Rule{Percentage: map[string]float64{"canary": 20, "stable": 80}}
	c.publish(t, b)
	selected := make(map[string]bool)
	for i := range 80 {
		subject := fmt.Sprintf("user-%d", i)
		response := c.request(t, 0, http.MethodGet, "/", subject, "", nil)
		require.Equal(t, 200, response.StatusCode)
		selected[subject] = response.Header.Get("X-Actual-Build") == "canary"
		response.Body.Close()
	}
	b.Generation = 3
	b.Policy.ManifestRevision = 3
	b.DiscoveryRevision = 3
	b.Policy.Flags["routing"].DefaultRule = &model.Rule{Percentage: map[string]float64{"canary": 60, "stable": 40}}
	c.publish(t, b)
	count := 0
	for i := range 80 {
		subject := fmt.Sprintf("user-%d", i)
		response := c.request(t, 0, http.MethodGet, "/", subject, "", nil)
		require.Equal(t, 200, response.StatusCode)
		canary := response.Header.Get("X-Actual-Build") == "canary"
		if selected[subject] {
			assert.True(t, canary)
		}
		if canary {
			count++
		}
		response.Body.Close()
	}
	assert.Greater(t, count, 20)
	assert.Less(t, count, 70)
}

func TestBootMismatch(t *testing.T) {
	c := newCluster(t)
	b := cloneBundle(t, c.bundle)
	b.Generation = 2
	b.Policy.ManifestRevision = 2
	b.DiscoveryRevision = 2
	b.Endpoints[1].Boot = "replacement-boot"
	before := c.control.Applied.Load()
	require.NoError(t, c.control.Publish(b))
	require.Eventually(t, func() bool { return c.control.Applied.Load() > before && c.control.Rejected.Load() > 0 }, 3*time.Second, 10*time.Millisecond)
	response := c.request(t, 0, http.MethodPost, "/write", "canary-user", "", nil)
	assert.Equal(t, 403, response.StatusCode)
	assert.Zero(t, c.writes.Load())
}

func TestExpiredView(t *testing.T) {
	c := newCluster(t)
	c.control.ValidFor = 1500 * time.Millisecond
	b := cloneBundle(t, c.bundle)
	b.Generation = 2
	b.Policy.ManifestRevision = 2
	b.DiscoveryRevision = 2
	c.publish(t, b)
	require.Eventually(t, func() bool { return !c.gateways[0].Ready() }, 3*time.Second, 20*time.Millisecond)
	response := c.request(t, 0, http.MethodGet, "/", "ordinary", "", nil)
	assert.Equal(t, 503, response.StatusCode)
}

func TestPersistedView(t *testing.T) {
	c := newCluster(t)
	c.cancel()
	for _, done := range c.done {
		<-done
	}
	restored, err := gogw.New(c.cfgs[0])
	require.NoError(t, err)
	assert.False(t, restored.Ready())
	// An offline cold start never becomes ready merely from a cached bundle.
	cfg := c.cfgs[0]
	require.NoError(t, os.WriteFile(cfg.StateFile, []byte("corrupt"), 0o600))
	_, err = gogw.New(cfg)
	assert.Error(t, err)
}

func TestTicketBindings(t *testing.T) {
	c := newCluster(t)
	data, err := os.ReadFile(c.cfgs[0].StateFile)
	require.NoError(t, err)
	signed := new(agentv1.SignedResource)
	require.NoError(t, proto.Unmarshal(data, signed))
	claims, err := agent.ParseClaims(signed.GetClaims())
	require.NoError(t, err)
	pair, err := tls.LoadX509KeyPair(c.cfgs[0].CertFile, c.cfgs[0].KeyFile)
	require.NoError(t, err)
	authority := strings.TrimPrefix(c.servers[1].URL, "https://")
	cases := map[string]func(jwt.MapClaims){
		"valid":       func(jwt.MapClaims) {},
		"boot":        func(m jwt.MapClaims) { m["boot"] = "old" },
		"build":       func(m jwt.MapClaims) { m["build"] = "stable" },
		"scope":       func(m jwt.MapClaims) { m["environment"] = "other" },
		"bundle":      func(m jwt.MapClaims) { m["bundle"] = "wrong" },
		"generation":  func(m jwt.MapClaims) { m["generation"] = 2 },
		"method":      func(m jwt.MapClaims) { m["method"] = "POST" },
		"path":        func(m jwt.MapClaims) { m["uri"] = "/other" },
		"host":        func(m jwt.MapClaims) { m["authority"] = "other.invalid" },
		"issuer-boot": func(m jwt.MapClaims) { m["issuerBoot"] = "old" },
		"audience":    func(m jwt.MapClaims) { m["aud"] = "stable" },
		"hop":         func(m jwt.MapClaims) { m["hop"] = 2 },
		"final":       func(m jwt.MapClaims) { m["final"] = false },
		"expired":     func(m jwt.MapClaims) { m["exp"] = time.Now().Add(-time.Second).Unix() },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			m := jwt.MapClaims{"iss": "stable", "sub": "trusted-user", "aud": "canary", "iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Second).Unix(), "jti": "test-ticket", "workspace": "demo", "environment": "test", "service": "checkout", "issuerBoot": "stable-boot", "boot": "canary-boot", "build": "canary", "bundle": hex.EncodeToString(claims.BundleHash[:]), "generation": 1, "method": "GET", "authority": authority, "uri": "/bound?q=1", "final": true, "hop": 1}
			edit(m)
			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, m)
			token.Header["typ"] = "gogw-final+jwt"
			raw, err := token.SignedString(pair.PrivateKey)
			require.NoError(t, err)
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, c.servers[1].URL+"/bound?q=1", nil)
			require.NoError(t, err)
			request.Header.Set("X-Gogw-Ticket", raw)
			response, err := c.peer.Do(request)
			require.NoError(t, err)
			defer response.Body.Close()
			if name == "valid" {
				assert.Equal(t, 200, response.StatusCode)
				assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
			} else {
				assert.Equal(t, 403, response.StatusCode)
			}
		})
	}
}

func TestUntrustedPolicyKey(t *testing.T) {
	c := newCluster(t)
	cfg := c.cfgs[0]
	cfg.PolicyPublicKey = hex.EncodeToString(make([]byte, ed25519.PublicKeySize))
	cfg.StateFile = filepath.Join(t.TempDir(), "state")
	g, err := gogw.New(cfg)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); g.Run(ctx) }()
	defer func() { cancel(); <-done }()
	before := c.control.Rejected.Load()
	require.Eventually(t, func() bool { return c.control.Rejected.Load() > before }, 3*time.Second, 10*time.Millisecond)
	assert.False(t, g.Ready())
}

func TestTrustedIPAndViewReplacement(t *testing.T) {
	c := newCluster(t)
	stream := c.request(t, 0, http.MethodGet, "/sse", "canary-user", "", nil)
	line, err := bufio.NewReader(stream.Body).ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "data: canary\n", line)
	b := cloneBundle(t, c.bundle)
	b.Generation = 2
	b.Policy.ManifestRevision = 2
	b.DiscoveryRevision = 2
	b.Policy.Flags["routing"].Targeting = []model.Rule{{Constraints: []model.Constraint{{Field: "client_ip", Op: model.OpInCIDR, Value: "203.0.113.0/24"}}, Variation: "canary"}}
	c.publish(t, b)
	response := c.request(t, 0, http.MethodGet, "/", "ordinary", "", http.Header{"X-Forwarded-For": []string{"203.0.113.7"}})
	assert.Equal(t, "stable", response.Header.Get("X-Actual-Build"))
	// The old canary stream remains alive while new requests use the new view.
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Eventually(t, func() bool { return c.gateways[0].ActiveRequests() == 1 }, time.Second, time.Millisecond)
	require.NoError(t, stream.Body.Close())
	select {
	case <-c.canceled:
	case <-time.After(time.Second):
		t.Fatal("old view leaked stream")
	}
}

func TestScaleAndAmbiguousWrites(t *testing.T) {
	c := newCluster(t, "canary")
	instances := make(map[string]bool)
	for range 12 {
		response := c.request(t, 0, http.MethodGet, "/", "canary-user", "", nil)
		require.Equal(t, http.StatusOK, response.StatusCode)
		instances[response.Header.Get("X-Actual-Instance")] = true
		require.NoError(t, response.Body.Close())
	}
	assert.Len(t, instances, 2)
	response := c.request(t, 0, http.MethodPost, "/ambiguous", "canary-user", "", http.Header{"Idempotency-Key": []string{"business-key"}})
	assert.Equal(t, http.StatusBadGateway, response.StatusCode)
	assert.EqualValues(t, 1, c.writes.Load())
	b := cloneBundle(t, c.bundle)
	b.Generation = 2
	b.Policy.ManifestRevision = 2
	b.DiscoveryRevision = 2
	b.Endpoints = b.Endpoints[:2]
	before := c.control.Applied.Load()
	require.NoError(t, c.control.Publish(b))
	require.Eventually(t, func() bool { return c.control.Applied.Load() >= before+2 }, 3*time.Second, 10*time.Millisecond)
	for range 6 {
		response := c.request(t, 0, http.MethodGet, "/", "canary-user", "", nil)
		require.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, "canary", response.Header.Get("X-Actual-Instance"))
		require.NoError(t, response.Body.Close())
	}
}

func TestStreamingRequest(t *testing.T) {
	c := newCluster(t)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, c.servers[0].URL+"/upload", reader)
	require.NoError(t, err)
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": "test-auth", "aud": "checkout", "sub": "canary-user", "exp": time.Now().Add(time.Minute).Unix()}).SignedString(c.secret)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+raw)
	type result struct {
		response *http.Response
		err      error
	}
	done := make(chan result, 1)
	go func() { response, err := c.public.Do(request); done <- result{response: response, err: err} }()
	_, err = writer.Write([]byte("A"))
	require.NoError(t, err)
	select {
	case <-c.upload:
	case <-time.After(time.Second):
		t.Fatal("request was buffered before reaching application")
	}
	_, err = writer.Write([]byte("B"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	received := <-done
	require.NoError(t, received.err)
	defer received.response.Body.Close()
	assert.Equal(t, http.StatusOK, received.response.StatusCode)
	body, err := io.ReadAll(received.response.Body)
	require.NoError(t, err)
	assert.Equal(t, "AB", string(body))
}
