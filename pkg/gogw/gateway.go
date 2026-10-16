package gogw

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
)

const (
	// readinessPath is the only unauthenticated status endpoint.
	readinessPath = "/__gogw/ready"

	// diagnosticsPath is served only to an authenticated peer gateway.
	diagnosticsPath = "/__gogw/diagnostics"

	// sessionSweepInterval controls how often expired bindings, retained views
	// and isolated candidates are reclaimed.
	sessionSweepInterval = time.Second

	// certificateWatchInterval bounds how long a rotated gateway certificate
	// takes to be adopted.
	certificateWatchInterval = 5 * time.Second

	// healthProbeInterval and healthProbeTimeout bound how long the gateway keeps
	// advertising itself after the application stops answering.
	healthProbeInterval = time.Second
	healthProbeTimeout  = 2 * time.Second
)

// agentState names the control-plane session phase of this gateway.
type agentState string

const (
	stateDisconnected agentState = "disconnected"
	stateConnecting   agentState = "connecting"
	stateSyncing      agentState = "syncing"
	stateActive       agentState = "active"
	stateClosed       agentState = "closed"
)

// registration is the control-plane view of this instance.
type registration struct {
	state        agentState
	registered   bool
	leaseEpoch   uint64
	leaseExpires time.Time
	fenced       bool
	permanent    error
}

// Gateway is the co-deployed Grayling gateway. It is registered with Traefik as
// an extra service builder and owns one control-plane session, one active
// runtime view and the forwarding boundary between releases.
type Gateway struct {
	cfg    Config
	id     *identity
	trust  *verifier
	state  *journal
	caPool *x509.CertPool

	localURL *url.URL
	proxies  []*net.IPNet
	secret   []byte
	control  *http.Client

	localTransport *http.Transport

	metrics  *metrics
	streams  *streamRegistry
	sessions *sessionStore

	revocation *revocationState

	mu       sync.Mutex
	active   *view
	retired  []*view
	prepared *preparedRelease
	// disco is the membership artifact staged for the prepared release, and
	// discoHold is the newest artifact this instance verified for any release. A
	// re-delivered bundle reuses the held artifact instead of waiting for the
	// control plane to publish it again.
	disco     *collected
	discoHold *collected
	armed     bool

	statusMu sync.Mutex
	status   registration

	healthy  atomic.Bool
	draining atomic.Bool
	fenced   atomic.Bool
	inFlight atomic.Int64

	// forceClose is the instant the drain deadline ends existing streams, shared
	// between the sweep loop and a control-plane drain request.
	forceClose atomic.Int64

	// forcedCloses counts the streams ended by a deadline or a revocation rather
	// than by their own completion, which is the number the drain report publishes.
	forcedCloses atomic.Int64

	agent *agentSession
}

// preparedRelease is the release accepted at Prepare, before it is activated.
// The acceptance is evidence about one exact release identity, never a serving
// right: activation re-checkes the identity against the live control plane.
type preparedRelease struct {
	hash       [32]byte
	key        string
	claims     agent.Claims
	document   BundleDocument
	resource   *agentv1.SignedResource
	generation uint64
	expires    time.Time
	releaseID  string
}

// New builds a gateway from a validated configuration.
func New(cfg Config) (*Gateway, error) {
	now := time.Now()
	id, err := newIdentity(cfg.CertFile, cfg.KeyFile, time.Duration(cfg.CertificateOverlapSeconds)*time.Second, now)
	if err != nil {
		return nil, err
	}
	leaf := id.currentCertificate().leaf
	trust, err := newVerifier(cfg, leaf.NotBefore, leaf.NotAfter)
	if err != nil {
		return nil, err
	}
	state, err := openJournal(cfg.StateFile)
	if err != nil {
		return nil, err
	}
	caPool, err := roots(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	localURL, err := localEndpoint(cfg.LocalURL)
	if err != nil {
		return nil, err
	}
	secret, err := os.ReadFile(cfg.IdentitySecretFile)
	if err != nil {
		return nil, err
	}
	if len(secret) < 32 {
		return nil, errors.New("gogw: identity secret must contain at least 32 bytes")
	}
	proxies, err := parseProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	persisted := state.snapshot()
	g := &Gateway{
		cfg: cfg, id: id, trust: trust, state: state, caPool: caPool,
		localURL: localURL, proxies: proxies, secret: secret,
		localTransport: localTransport(),
		metrics:        newMetrics(), streams: newStreamRegistry(),
		sessions:   newSessionStore(secret, time.Duration(cfg.SessionCompatibilitySeconds)*time.Second, cfg.MaxTrackedSessions),
		revocation: newRevocationState(persisted.Revocation.Epoch, persisted.Revocation.Hashes),
		status:     registration{state: stateDisconnected},
	}
	g.control = newControlClient(caPool)
	g.agent = newAgentSession(g)
	if persisted.Generation > 0 {
		log.Info().Uint64("generation", persisted.Generation).Int("revokedReleases", len(persisted.Revocation.Hashes)).
			Msg("Restored gogw state; the release is re-verified before it serves again")
	}
	return g, nil
}

// restore re-installs the release persisted before the last restart; see
// prepare.go. A restart must not serve from memory alone.

// Run keeps the control-plane session, the health probe and the local reclaim
// loops alive until ctx is canceled. A permanent protocol failure stops the
// component instead of retrying forever.
func (g *Gateway) Run(ctx context.Context) {
	var wait sync.WaitGroup
	wait.Add(4)
	go func() { defer wait.Done(); g.id.watch(ctx, certificateWatchInterval) }()
	go func() { defer wait.Done(); g.sweep(ctx) }()
	go func() { defer wait.Done(); g.probe(ctx) }()
	go func() { defer wait.Done(); g.agent.run(ctx) }()
	g.restore(ctx)
	wait.Wait()
	g.localTransport.CloseIdleConnections()
	g.closeIdleControl()
	g.releaseActive()
}

// Ready reports whether the gateway may receive business traffic: registered,
// leased, prepared, healthy and serving an unexpired release it is part of.
func (g *Gateway) Ready() bool { return g.readyReason() == "" }

// ActiveRequests reports how many requests are being served.
func (g *Gateway) ActiveRequests() int { return int(g.inFlight.Load()) }

// Drain stops accepting work and gives existing streams the configured grace
// period to finish before they are closed.
func (g *Gateway) Drain() {
	g.beginDrain(time.Time{})
	g.awaitStreams()
	g.releaseActive()
}

// Shutdown drains the gateway and releases the lease it holds. Releasing the
// lease is what lets the control plane replace this instance immediately instead
// of waiting for the lease to expire, and it is registered as the Traefik
// shutdown hook so it runs before the pools are canceled.
func (g *Gateway) Shutdown() {
	g.Drain()
	g.agent.releaseLease()
}

// Diagnostics returns the operator-visible state of this gateway.
func (g *Gateway) Diagnostics() Diagnostics {
	now := time.Now()
	status := g.registration()
	prepared, preparedHash, preparedGeneration, preparedExpires := g.preparedStatus()
	eligible, eligibleReason := g.eligibility()
	snapshot := Diagnostics{
		Instance: g.cfg.Instance, Boot: g.cfg.Boot, Build: g.cfg.Build,
		AgentSession: string(status.state), Registered: status.registered,
		LeaseEpoch: status.leaseEpoch, LeaseExpiresUnixMs: msOf(status.leaseExpires),
		Eligible: eligible, EligibleReason: eligibleReason,
		Ready: g.Ready(), ReadyReason: g.readyReason(),
		Healthy: g.healthy.Load(), Draining: g.draining.Load(), Fenced: g.fenced.Load(),
		Prepared: prepared, PreparedHash: preparedHash, PreparedGeneration: preparedGeneration,
		PreparedExpiresUnixMs: msOf(preparedExpires),
		InFlight:              g.ActiveRequests(), Streams: g.streams.count(),
		Sessions: g.sessions.size(), Counters: g.metrics.snapshot(), Rejected: map[string]int{}, Isolated: map[string]int{},
	}
	epoch, hashes := g.revocation.snapshot()
	snapshot.RevocationEpoch, snapshot.RevokedReleases = epoch, len(hashes)
	snapshot.Operations = g.state.operations()
	snapshot.CertificateSHA256, snapshot.CertificatePreviousSHA256, snapshot.CertificatePreviousValidUntilUnixMs = g.id.advertisement(now)

	g.mu.Lock()
	active, retired := g.active, append([]*view(nil), g.retired...)
	g.mu.Unlock()
	snapshot.RetiredViews = len(retired)
	if active != nil {
		snapshot.Generation = active.generation
		snapshot.ReleaseID = active.bundle.ReleaseID
		snapshot.BundleHash = active.bundleHashHex()
		snapshot.DiscoveryRevision = active.discovery.Revision
		snapshot.PolicyExpiresUnixMs = msOf(active.policyAt)
		snapshot.DiscoveryExpiresUnixMs = msOf(active.discoAt)
		snapshot.Members = len(active.members)
		snapshot.Rejected = map[string]int{}
		maps.Copy(snapshot.Rejected, active.rejections)
		if active.ramp != nil {
			snapshot.RampThreshold = active.ramp.threshold
		}
		for build, dispatcher := range active.dispatchers {
			dispatcher.refresh(now)
			if isolated := dispatcher.isolated(); isolated > 0 {
				snapshot.Isolated[build] = isolated
			}
		}
	}
	return snapshot
}

// DiagnosticsJSON renders the diagnostics document served on the internal path.
func (g *Gateway) DiagnosticsJSON() []byte {
	raw, err := json.Marshal(g.Diagnostics())
	if err != nil {
		return []byte(`{"error":"unavailable"}`)
	}
	return raw
}

// probe tracks the health of the co-deployed application. Readiness is
// fail-closed: an instance that cannot prove its application is answering is not
// a candidate for business traffic.
func (g *Gateway) probe(ctx context.Context) {
	defer g.healthy.Store(false)
	client := &http.Client{
		Timeout:       healthProbeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	target := g.localURL.JoinPath(g.cfg.HealthPath)
	ticker := time.NewTicker(healthProbeInterval)
	defer ticker.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			g.healthy.Store(false)
			return
		}
		response, err := client.Do(req)
		healthy := err == nil && response.StatusCode >= 200 && response.StatusCode < 400
		if response != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<16))
			response.Body.Close()
		}
		if !g.healthy.Swap(healthy) {
			log.Ctx(ctx).Info().Bool("healthy", healthy).Msg("Application health changed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweep reclaims expired bindings, retained views and isolated candidates, and
// enforces the drain deadline of long-lived requests.
func (g *Gateway) sweep(ctx context.Context) {
	ticker := time.NewTicker(sessionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			g.sessions.sweep(now, 0)
			g.reclaim()
			g.metrics.add(phaseExecution, "", "sweep")
			if g.draining.Load() && !now.Before(time.UnixMilli(g.forceClose.Load())) {
				if closed := g.streams.cancelAll(); closed > 0 {
					g.forcedCloses.Add(int64(closed))
					log.Ctx(ctx).Info().Int("streams", closed).Msg("Closing streams that outlived the drain deadline")
				}
				g.releaseActive()
			}
		}
	}
}

// reclaim drops retained views beyond the configured bound so an old release
// cannot pin connections for the lifetime of the process.
func (g *Gateway) reclaim() {
	g.mu.Lock()
	var forced []*view
	for len(g.retired) > g.cfg.MaxRetainedViews {
		oldest := g.retired[0]
		g.retired = g.retired[1:]
		forced = append(forced, oldest)
	}
	g.mu.Unlock()
	for _, v := range forced {
		g.streams.cancelView(v)
		v.release()
	}
}

// swap installs one compiled view as the active runtime view and retires the
// previous one, which stays alive only while a request or a bound session still
// holds it. The caller must own the reference to next; the reference to the
// previous view moves to the retired list and is dropped when it is reclaimed.
func (g *Gateway) swap(next *view, now time.Time) *view {
	g.mu.Lock()
	previous := g.active
	g.active = next
	if previous != nil {
		previous.retire(now)
		g.retired = append(g.retired, previous)
	}
	var drop *view
	if len(g.retired) > g.cfg.MaxRetainedViews+1 {
		drop, g.retired = g.retired[0], g.retired[1:]
	}
	g.mu.Unlock()
	if drop != nil {
		g.streams.cancelView(drop)
		drop.release()
	}
	return previous
}

func (g *Gateway) activeView() *view {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active != nil {
		g.active.acquire()
	}
	return g.active
}

// acceptsRelease reports whether a release identity may still serve requests,
// which includes a retained view inside its compatibility window.
func (g *Gateway) acceptsRelease(hash string, generation uint64, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active != nil && g.active.bundleHashHex() == hash && g.active.generation == generation {
		return true
	}
	for _, v := range g.retired {
		if v.bundleHashHex() != hash || v.generation != generation {
			continue
		}
		if now.Before(v.retirement().Add(time.Duration(g.cfg.SessionCompatibilitySeconds) * time.Second)) {
			return true
		}
	}
	return false
}

// peer returns the admitted candidate of one issuer, preferring the active view.
func (g *Gateway) peer(instance, boot string) (member, bool) {
	g.mu.Lock()
	views := append([]*view{g.active}, g.retired...)
	g.mu.Unlock()
	for _, v := range views {
		if v == nil {
			continue
		}
		candidate, ok := v.peers[instance]
		if ok && candidate.boot == boot {
			return candidate, true
		}
	}
	return member{}, false
}

// retainedView returns the retained view of one release identity while its
// compatibility window is open. A straggler that still carries an old ticket is
// served by the exact view that admitted it, never by the new one.
func (g *Gateway) retainedView(hash string, generation uint64, now time.Time) *view {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, v := range g.retired {
		if v.bundleHashHex() != hash || v.generation != generation {
			continue
		}
		if !now.Before(v.retirement().Add(time.Duration(g.cfg.SessionCompatibilitySeconds) * time.Second)) {
			continue
		}
		if accepted, _ := v.accepts(now); !accepted {
			continue
		}
		v.acquire()
		return v
	}
	return nil
}

// rampFloor resolves the durable monotone threshold of one ramp coordinate. A
// persistence failure is fatal to the compilation rather than silently reverting
// to the published threshold, because a lower threshold would pull an already
// exposed unit back out of the canary prefix.
func (g *Gateway) rampFloor(ramp *Ramp) (int, error) {
	key := rampFloorKey(g.cfg.Scope.WorkspaceID, g.cfg.Scope.EnvironmentID, ramp)
	return g.state.rampFloor(key, ramp.Threshold)
}

// token reads the control-plane bearer token. It is re-read before every dial so
// a rotated projected token is picked up without a restart.
func (g *Gateway) token() (string, error) {
	raw, err := os.ReadFile(g.cfg.TokenFile)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("gogw: control-plane token is empty")
	}
	return token, nil
}

// eligibility returns the first reason this instance cannot be a member of any
// release. It is the advertisement the control plane makes its membership
// decision from, so it covers the application, the drain state and the
// control-plane session, and deliberately excludes the release: the membership
// naming this instance is published before this instance can compile it, so a
// release-scoped condition here would deadlock every rollout. The parameters of
// a release are carried by the membership artifact instead, as prepared evidence
// this instance reports and the consumer re-checks.
func (g *Gateway) eligibility() (bool, string) {
	switch {
	case g.draining.Load():
		return false, codeDraining
	case g.fenced.Load():
		return false, "FENCED"
	case !g.healthy.Load():
		return false, "APPLICATION_UNHEALTHY"
	}
	status := g.registration()
	switch {
	case status.permanent != nil:
		return false, "FATAL"
	case status.state != stateActive:
		return false, "CONTROL_PLANE_" + strings.ToUpper(string(status.state))
	case !status.registered:
		return false, "UNREGISTERED"
	case status.leaseEpoch == 0 || !status.leaseExpires.After(time.Now()):
		return false, "LEASE_EXPIRED"
	}
	return true, ""
}

// readyReason returns the first reason this gateway cannot serve business
// traffic. It is for diagnostics only: response bodies never carry it.
func (g *Gateway) readyReason() string {
	if eligible, reason := g.eligibility(); !eligible {
		return reason
	}
	v := g.activeView()
	if v == nil {
		return codeNoView
	}
	defer v.release()
	now := time.Now()
	if ok, code := v.accepts(now); !ok {
		return code
	}
	if _, local := v.localRoute(); !local {
		return codeDiscoveryExpired
	}
	if prepared, _, _, expires := g.preparedStatus(); prepared && expires.After(now) {
		return ""
	}
	return "PREPARED_REQUIRED"
}

// preparedStatus reports the release this process holds ready for activation,
// read from the staged release itself: the evidence an operator and the readiness
// gate need is what the process holds, not what a session snapshot recorded.
func (g *Gateway) preparedStatus() (bool, string, uint64, time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.prepared == nil {
		return false, "", 0, time.Time{}
	}
	return true, hexDigest(g.prepared.hash), g.prepared.generation, g.prepared.expires
}

// beginDrain withdraws readiness and stops accepting new work. It never blocks:
// the deadline is what ends the streams that outlive the grace period, so a
// control-plane drain request cannot stall the session that carried it.
func (g *Gateway) beginDrain(forceClose time.Time) {
	if forceClose.IsZero() {
		forceClose = time.Now().Add(time.Duration(g.cfg.DrainGraceSeconds) * time.Second)
	}
	g.forceClose.Store(forceClose.UnixMilli())
	if g.draining.Swap(true) {
		return
	}
	log.Info().Int("requests", g.ActiveRequests()).Msg("Draining gogw gateway")
}

// awaitStreams waits for in-flight requests until the force-close deadline.
func (g *Gateway) awaitStreams() {
	deadline := time.UnixMilli(g.forceClose.Load())
	for time.Now().Before(deadline) {
		if g.ActiveRequests() == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if closed := g.streams.cancelAll(); closed > 0 {
		g.forcedCloses.Add(int64(closed))
		log.Warn().Int("streams", closed).Msg("Closing streams that outlived the drain grace period")
	}
}

// releaseActive drops the gateway's own reference to the active view and clears
// the pointer so a later request cannot use a drained view.
func (g *Gateway) releaseActive() {
	g.mu.Lock()
	active := g.active
	g.active = nil
	g.mu.Unlock()
	if active != nil {
		active.release()
	}
}

func (g *Gateway) registration() registration {
	g.statusMu.Lock()
	defer g.statusMu.Unlock()
	return g.status
}

func (g *Gateway) setRegistration(mutate func(*registration)) {
	g.statusMu.Lock()
	defer g.statusMu.Unlock()
	mutate(&g.status)
}

// closeIdleControl releases control-plane connections on shutdown.
func (g *Gateway) closeIdleControl() {
	if transport, ok := g.control.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func msOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// parseProxies resolves the trusted proxy networks.
func parseProxies(entries []string) ([]*net.IPNet, error) {
	proxies := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		if _, network, err := net.ParseCIDR(entry); err == nil {
			proxies = append(proxies, network)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, errors.New("gogw: invalid trusted proxy")
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		proxies = append(proxies, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return proxies, nil
}

// newControlClient builds the control-plane HTTP client. It never follows a
// redirect: the bearer token belongs to the configured origin only.
func newControlClient(caPool *x509.CertPool) *http.Client {
	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    caPool,
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
