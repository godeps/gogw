package gogw

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
	"github.com/saker-ai/grayling/pkg/evaluation"
	"github.com/traefik/traefik/v3/pkg/server/service/loadbalancer/wrr"
	"google.golang.org/protobuf/proto"
)

type view struct {
	resource  *agentv1.SignedResource
	bundle    Bundle
	claims    agent.Claims
	hash      string
	evaluator *evaluation.Evaluator
	builds    map[string]http.Handler
	local     http.Handler
	peers     map[string]Endpoint
	pools     []*http.Transport
	mu        sync.Mutex
	refs      int
	retired   bool
}

func (v *view) acquire() { v.mu.Lock(); v.refs++; v.mu.Unlock() }
func (v *view) release() {
	v.mu.Lock()
	v.refs--
	closePools := v.retired && v.refs == 0
	v.mu.Unlock()
	if closePools {
		v.closePools()
	}
}

func (v *view) retire() {
	v.mu.Lock()
	v.retired = true
	closePools := v.refs == 0
	v.mu.Unlock()
	if closePools {
		v.closePools()
	}
}

func (v *view) closePools() {
	for _, p := range v.pools {
		p.CloseIdleConnections()
	}
}

type Gateway struct {
	cfg        Config
	verifier   *agent.Verifier
	key        ed25519.PrivateKey
	leaf       *x509.Certificate
	tls        *tls.Config
	secret     []byte
	localURL   *url.URL
	proxies    []*net.IPNet
	control    *http.Client
	mu         sync.Mutex
	active     *view
	candidate  *view
	mark       agent.Watermark
	generation uint64
	draining   atomic.Bool
	health     atomic.Bool
	inflight   atomic.Int64
}

// BuildHTTP implements Traefik's existing ServiceBuilder hook without extending
// its generated dynamic configuration or claiming a public service plugin API.
func (g *Gateway) BuildHTTP(_ context.Context, name string) (http.Handler, error) {
	if name != g.cfg.Service+"@gogw" {
		return nil, nil
	}
	return g, nil
}

func (g *Gateway) Ready() bool {
	v := g.capture()
	if v == nil {
		return false
	}
	defer v.release()
	return g.health.Load() && !g.draining.Load() && time.Now().UnixMilli() < v.claims.ExpiresUnixMs
}
func (g *Gateway) Drain()                { g.draining.Store(true) }
func (g *Gateway) ActiveRequests() int64 { return g.inflight.Load() }

func (g *Gateway) capture() *view {
	g.mu.Lock()
	defer g.mu.Unlock()
	v := g.active
	if v != nil {
		v.acquire()
	}
	return v
}

func (g *Gateway) compile(r *agentv1.SignedResource) (*view, error) {
	if !g.health.Load() {
		return nil, errors.New("local application is unhealthy")
	}
	claims, err := g.verifier.Verify(r, g.cfg.Scope, agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, g.cfg.Service, g.mark, time.Now())
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err = json.Unmarshal(r.GetPayload(), &b, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if claims.BundleHash != claims.PayloadHash || b.Schema != 1 || b.Policy.ManifestRevision <= 0 || b.Generation == 0 || b.Generation < g.generation || b.DiscoveryRevision == 0 || b.DiscoveryExpiresUnix <= time.Now().Unix() || b.Flag == "" || len(b.Endpoints) > 1024 || b.Policy.Workspace != g.cfg.Scope.WorkspaceID || b.Policy.Environment != g.cfg.Scope.EnvironmentID || b.Policy.ManifestRevision != int64(claims.Revision) {
		return nil, errors.New("invalid or stale bundle")
	}
	if b.Generation == g.generation && (claims.Revision != g.mark.Revision || claims.BundleHash != g.mark.BundleHash) {
		return nil, errors.New("generation reused for another bundle")
	}
	if g.candidate != nil && (claims.Revision < g.candidate.claims.Revision || b.Generation < g.candidate.bundle.Generation) {
		return nil, errors.New("candidate rollback")
	}
	evaluator, err := evaluation.NewEvaluator(&b.Policy)
	if err != nil {
		return nil, err
	}
	flag := b.Policy.Flags[b.Flag]
	if flag == nil {
		return nil, errors.New("routing flag missing")
	}
	v := &view{bundle: b, resource: proto.Clone(r).(*agentv1.SignedResource), claims: claims, hash: hex.EncodeToString(claims.BundleHash[:]), evaluator: evaluator, builds: make(map[string]http.Handler), peers: make(map[string]Endpoint)}
	local, pool, err := newProxy(g.localURL, nil)
	if err != nil {
		return nil, err
	}
	v.local = local
	v.pools = append(v.pools, pool)
	complete := false
	defer func() {
		if !complete {
			v.closePools()
		}
	}()
	localFound := false
	for _, ep := range b.Endpoints {
		if ep.Instance == "" || ep.Boot == "" || ep.Build == "" || ep.ServerName == "" || len(ep.CertificateSHA256) != 64 {
			return nil, errors.New("invalid endpoint identity")
		}
		if _, exists := v.peers[ep.Instance]; exists {
			return nil, errors.New("duplicate instance")
		}
		u, err := endpointURL(ep.URL, false)
		if err != nil {
			return nil, err
		}
		if _, err = hex.DecodeString(ep.CertificateSHA256); err != nil {
			return nil, errors.New("invalid certificate digest")
		}
		v.peers[ep.Instance] = ep
		if ep.Instance == g.cfg.Instance {
			actual := sha256.Sum256(g.leaf.Raw)
			if ep.Boot != g.cfg.Boot || ep.Build != g.cfg.Build || ep.CertificateSHA256 != hex.EncodeToString(actual[:]) {
				return nil, errors.New("local identity mismatch")
			}
			localFound = ep.Ready && !ep.Draining && ep.Prepared && ep.ExpiresUnix > time.Now().Unix()
		}
		if !ep.Ready || ep.Draining || !ep.Prepared || ep.ExpiresUnix <= time.Now().Unix() {
			continue
		}
		lb, ok := v.builds[ep.Build].(*wrr.Balancer)
		if !ok {
			lb = wrr.New(nil, false)
			v.builds[ep.Build] = lb
		}
		var handler http.Handler
		if ep.Instance == g.cfg.Instance {
			handler = local
		} else {
			tlsConfig := g.tls.Clone()
			tlsConfig.ServerName = ep.ServerName
			expected := ep.CertificateSHA256
			tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
				digest := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if hex.EncodeToString(digest[:]) != expected {
					return errors.New("gateway certificate identity mismatch")
				}
				return nil
			}
			proxy, pool, err := newProxy(u, tlsConfig)
			if err != nil {
				return nil, err
			}
			v.pools = append(v.pools, pool)
			handler = g.remote(v, ep, proxy)
		}
		// Expiry is checked at dispatch, not only when the snapshot is constructed.
		lb.Add(ep.Instance, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ep.ExpiresUnix <= time.Now().Unix() {
				http.Error(w, "ENDPOINT_EXPIRED", http.StatusServiceUnavailable)
				return
			}
			handler.ServeHTTP(w, r)
		}), nil, false)
	}
	if !localFound {
		return nil, errors.New("local instance is not prepared and ready")
	}
	for _, value := range flag.Variations {
		if build, ok := value.(string); !ok || build == "" {
			return nil, errors.New("routing variations must be build strings")
		}
	}
	complete = true
	return v, nil
}

// prepare serializes resource verification and construction; no request observes
// a candidate until Activate matches its exact generation and bundle digest.
func (g *Gateway) prepare(r *agentv1.SignedResource) (*view, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	v, err := g.compile(r)
	if err != nil {
		return nil, err
	}
	if g.candidate != nil {
		g.candidate.retire()
	}
	g.candidate = v
	return v, nil
}

func (g *Gateway) activate(identity *agentv1.ReleaseIdentity) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	v := g.candidate
	if !g.health.Load() || identity == nil || v == nil || v.bundle.Generation != identity.GetGeneration() || v.hash != identity.GetBundleHash() || time.Now().UnixMilli() >= v.claims.ExpiresUnixMs {
		return errors.New("activation does not match prepared view")
	}
	if err := g.persist(v.resource); err != nil {
		return err
	}
	previous := g.active
	g.active = v
	g.candidate = nil
	g.mark = v.claims.Watermark()
	g.generation = v.bundle.Generation
	if previous != nil {
		previous.retire()
	}

	return nil
}

func (g *Gateway) persist(r *agentv1.SignedResource) error {
	data, err := proto.Marshal(r)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(g.cfg.StateFile), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(g.cfg.StateFile), ".gogw-view-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(file.Name(), g.cfg.StateFile); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(g.cfg.StateFile))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func (g *Gateway) restore() error {
	file, err := os.Open(g.cfg.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, agent.MaxResourceBytes+1))
	if err != nil {
		return err
	}
	if len(data) > agent.MaxResourceBytes {
		return errors.New("cached view too large")
	}
	r := new(agentv1.SignedResource)
	if err = proto.Unmarshal(data, r); err != nil {
		return err
	}
	claims, err := agent.ParseClaims(r.GetClaims())
	if err != nil {
		return err
	}
	// Even expired cached state preserves a verified monotonic watermark.
	_, err = g.verifier.Verify(r, g.cfg.Scope, agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, g.cfg.Service, agent.Watermark{}, time.UnixMilli(claims.IssuedUnixMs))
	if err != nil {
		return err
	}
	g.mark = claims.Watermark()
	var b Bundle
	if err = json.Unmarshal(r.GetPayload(), &b); err != nil {
		return err
	}
	g.generation = b.Generation
	// Cold restart requires fresh Prepared/Activate, even with a valid cache.
	return nil
}
