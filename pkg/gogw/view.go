package gogw

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saker-ai/grayling/pkg/agent"
	"github.com/saker-ai/grayling/pkg/evaluation"
	"github.com/saker-ai/grayling/pkg/model"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/server/service/loadbalancer/wrr"
)

// Rejection reasons for a request that could not be dispatched. They come from
// a fixed set so response bodies stay bounded and leak no release detail.
const (
	codeNoView            = "NO_RUNTIME_VIEW"
	codePolicyExpired     = "POLICY_EXPIRED"
	codeDiscoveryExpired  = "DISCOVERY_EXPIRED"
	codePolicyError       = "POLICY_ERROR"
	codeBuildUnknown      = "BUILD_UNKNOWN"
	codeNoEligible        = "NO_ELIGIBLE_ENDPOINT"
	codeUpstreamFailed    = "UPSTREAM_FAILED"
	codeNotReady          = "NOT_READY"
	codeDraining          = "DRAINING"
	codeInternalOnly      = "INTERNAL_ONLY"
	codeUnauthenticated   = "UNAUTHENTICATED"
	codeTransportRejected = "TRANSPORT_UNSUPPORTED"
)

// allocation is the per-request build decision: what the approved policy and the
// monotone ramp resolved to, before any candidate was selected.
type allocation struct {
	build    string
	reason   string
	ramp     string
	bucket   int
	decision string
}

// view is one immutable runtime view: a verified bundle, the approved discovery
// artifact bound to it, and the compiled routing state derived from both.
// Requests take a reference before they read it, so a swap never changes the
// routing of a request already in flight.
type view struct {
	hash       [32]byte
	key        string
	claims     agent.Claims
	bundle     BundleDocument
	discovery  DiscoveryDocument
	evaluator  *evaluation.Evaluator
	ramp       *rampState
	generation uint64
	approved   time.Time
	rejections memberRejections

	caPool      *x509.CertPool
	dispatchers map[string]*buildDispatcher
	members     map[string]member
	peers       map[string]member

	local    member
	hasLocal bool

	refs      atomic.Int64
	closed    atomic.Bool
	retiredAt atomic.Int64
	policyAt  time.Time
	discoAt   time.Time
}

// viewInput carries the verified inputs of one view compilation.
type viewInput struct {
	g        *Gateway
	claims   agent.Claims
	document BundleDocument
	hash     [32]byte
	disco    DiscoveryDocument
	revoked  bool
	now      time.Time
}

// compileView validates the release against this instance and builds the
// per-build dispatch state. It never publishes anything: the caller decides when
// the view becomes active.
func compileView(in viewInput) (*view, error) {
	policy := in.document.Policy
	evaluator, err := evaluation.NewEvaluator(&policy)
	if err != nil {
		return nil, err
	}
	if _, ok := in.document.Builds[in.g.cfg.Build]; !ok {
		return nil, errors.New("gogw: release does not contain the configured build")
	}
	ramp, err := rampOf(in.document, in.g.rampFloor, evaluation.CanonicalUnitString)
	if err != nil {
		return nil, err
	}
	admitted, rejections := admittedMembers(in.disco, hexDigest(in.hash), in.document.Generation, in.document.Builds, in.document.MinimumProtocolVersion, in.revoked, in.now)
	v := &view{
		hash: in.hash, key: in.claims.Key, claims: in.claims,
		bundle: in.document, discovery: in.disco, evaluator: evaluator,
		ramp: ramp, generation: in.document.Generation, approved: in.now, rejections: rejections,
		caPool: in.g.caPool, dispatchers: map[string]*buildDispatcher{}, members: map[string]member{}, peers: map[string]member{},
		policyAt: policyExpiry(in.document, in.claims), discoAt: time.UnixMilli(in.disco.ExpiresUnixMs),
	}
	builds := map[string][]member{}
	for _, candidate := range admitted {
		v.members[candidate.id] = candidate
		builds[candidate.build] = append(builds[candidate.build], candidate)
	}
	for build, candidates := range builds {
		dispatcher := newBuildDispatcher(build, v, in.g)
		for _, candidate := range candidates {
			local := candidate.id == in.g.cfg.Instance && candidate.boot == in.g.cfg.Boot
			handler, err := newMemberHandler(in.g, v, build, candidate, local)
			if err != nil {
				return nil, err
			}
			if local {
				v.local, v.hasLocal = candidate, true
			} else if _, ok := v.peers[candidate.id]; !ok {
				v.peers[candidate.id] = candidate
			}
			dispatcher.add(candidate, handler, local)
		}
		v.dispatchers[build] = dispatcher
	}
	return v, nil
}

// policyExpiry is the earliest instant the release policy may no longer be used.
// The issue instant is a floor so a control plane clock behind the gateway
// cannot make a fresh release look stale.
func policyExpiry(document BundleDocument, claims agent.Claims) time.Time {
	base := document.Policy.GeneratedAt
	if issued := time.UnixMilli(claims.IssuedUnixMs); issued.After(base) {
		base = issued
	}
	if base.IsZero() {
		base = time.UnixMilli(claims.IssuedUnixMs)
	}
	return base.Add(time.Duration(document.PolicyMaxAgeSeconds) * time.Second)
}

// accepts reports whether the view may still serve new requests at now.
func (v *view) accepts(now time.Time) (bool, string) {
	if v == nil {
		return false, codeNoView
	}
	if !now.Before(v.policyAt) {
		return false, codePolicyExpired
	}
	if !now.Before(v.discoAt) {
		return false, codeDiscoveryExpired
	}
	return true, ""
}

// bundleHashHex is the hexadecimal release identity used in bindings and logs.
func (v *view) bundleHashHex() string { return hexDigest(v.hash) }

// localRoute reports the admitted discovery entry of this exact process boot.
func (v *view) localRoute() (member, bool) {
	return v.local, v.hasLocal
}

// allocate resolves the logical build for one evaluation context. The build
// depends only on the approved policy and the monotone ramp prefix, never on the
// current membership, so scaling cannot move a unit between builds.
func (v *view) allocate(ctx model.EvaluationContext) (allocation, string) {
	result := v.evaluator.Evaluate(v.bundle.Flag, ctx)
	if result.Failed {
		return allocation{reason: string(result.ErrorCode), decision: result.DecisionID}, codePolicyError
	}
	name, ok := result.Value.(string)
	if !ok {
		return allocation{reason: "VARIATION_TYPE", decision: result.DecisionID}, codePolicyError
	}
	choice := allocation{build: name, reason: string(result.Reason), decision: result.DecisionID}
	if v.ramp == nil || name != v.ramp.canary {
		if _, ok := v.bundle.Builds[choice.build]; !ok {
			return choice, codeBuildUnknown
		}
		return choice, ""
	}
	unit, ok := v.ramp.unitValue(ctx)
	if !ok {
		choice.build = v.bundle.DefaultBuild
		choice.ramp = "unit_missing"
		return choice, ""
	}
	bucket, err := rampBucket(v.bundle.Policy, v.ramp, unit)
	if err != nil {
		return choice, codePolicyError
	}
	choice.bucket = bucket
	if bucket < v.ramp.threshold {
		choice.ramp = "eligible"
		return choice, ""
	}
	choice.build = v.bundle.DefaultBuild
	choice.ramp = "gated"
	return choice, ""
}

// dispatcher returns the per-build dispatcher, or reports that no admitted
// candidate serves the build. There is deliberately no cross-build fallback.
func (v *view) dispatcher(build string) (*buildDispatcher, bool) {
	dispatcher, ok := v.dispatchers[build]
	return dispatcher, ok
}

func (v *view) acquire() {
	if v != nil {
		v.refs.Add(1)
	}
}

// release drops one reference and closes the view once nothing holds it.
func (v *view) release() {
	if v == nil {
		return
	}
	if v.refs.Add(-1) <= 0 {
		v.close()
	}
}

func (v *view) close() {
	if !v.closed.CompareAndSwap(false, true) {
		return
	}
	v.releasePools()
}

// retire records when the view stopped being active, which is what bounds the
// compatibility window of the sessions still pinned to it.
func (v *view) retire(now time.Time) {
	v.retiredAt.Store(now.UnixNano())
}

func (v *view) retirement() time.Time {
	nanos := v.retiredAt.Load()
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos)
}

// isolationWindow is how long a candidate stays out of rotation after a
// transport failure, which bounds both the blast radius and the recovery delay.
const isolationWindow = 5 * time.Second

// buildDispatcher is the per-build dispatch state: Traefik's native weighted
// round-robin over the admitted candidates of exactly one logical build, with
// fault isolation and a bounded retry that never leaves the build.
type buildDispatcher struct {
	build    string
	view     *view
	g        *Gateway
	maxTries int
	balancer *wrr.Balancer

	mu         sync.Mutex
	quarantine map[string]time.Time
	count      int
	local      bool
	handlers   []poolHolder

	// localHandler is the handler of this process' own candidate. The internal
	// path dispatches through it directly: a request that already crossed one
	// gateway boundary may not be handed to another candidate.
	localHandler http.Handler
}

// poolHolder is implemented by handlers that own a connection pool.
type poolHolder interface {
	closePools()
}

func newBuildDispatcher(build string, v *view, g *Gateway) *buildDispatcher {
	return &buildDispatcher{
		build: build, view: v, g: g, maxTries: 2,
		balancer:   wrr.New(nil, false),
		quarantine: map[string]time.Time{},
	}
}

func (d *buildDispatcher) add(candidate member, handler http.Handler, local bool) {
	d.balancer.AddServer(candidate.id, handler, dynamic.Server{URL: candidate.url})
	d.count++
	d.local = d.local || local
	if local {
		d.localHandler = handler
	}
	if holder, ok := handler.(poolHolder); ok {
		d.handlers = append(d.handlers, holder)
	}
}

// hasLocal reports whether this build contains the candidate of the current
// process, which is what makes the build servable by this instance itself.
func (d *buildDispatcher) hasLocal() bool { return d.local }

// release drops the connection pools of this build after the last holder of the
// view has finished.
func (d *buildDispatcher) release() {
	d.mu.Lock()
	handlers := append([]poolHolder(nil), d.handlers...)
	d.handlers = nil
	d.mu.Unlock()
	for _, holder := range handlers {
		holder.closePools()
	}
}

// hasHealthy reports whether at least one candidate is currently admitted by the
// isolation state, checked under the same lock that records quarantines.
func (d *buildDispatcher) hasHealthy(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refresh(now)
	return len(d.quarantine) < d.count
}

// refresh re-admits candidates whose isolation window has elapsed.
func (d *buildDispatcher) refresh(now time.Time) {
	for id, until := range d.quarantine {
		if now.Before(until) {
			continue
		}
		delete(d.quarantine, id)
		d.balancer.SetStatus(context.Background(), id, true)
	}
}

// isolate keeps one candidate out of rotation for a bounded window. The last
// admitted candidate stays selectable: the balancer answers a request it has no
// candidate for itself, and that answer is an internal detail the client must not
// receive. The retry loop reports the build as unavailable instead.
func (d *buildDispatcher) isolate(id string, now time.Time) {
	if id == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refresh(now)
	d.quarantine[id] = now.Add(isolationWindow)
	d.balancer.SetStatus(context.Background(), id, len(d.quarantine) < d.count)
}

func (d *buildDispatcher) isolated() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.quarantine)
}

// releasePools drops every pool the view created, which is what reclaims the
// connections of a retired view instead of leaking them.
func (v *view) releasePools() {
	for _, dispatcher := range v.dispatchers {
		dispatcher.release()
	}
}
