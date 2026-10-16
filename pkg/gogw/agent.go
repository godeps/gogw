package gogw

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/rs/zerolog/log"
	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
)

// errSessionClosing reports a download abandoned because the session context
// ended. A shutdown is not a delivery failure, so the caller must not log it as
// one and must not reconnect for it.
var errSessionClosing = errors.New("gogw: session closing")

const (
	// commandQueue bounds the control-plane command backlog. It is deliberately
	// small: the SDK stops a session whose event channel fills, so a command must
	// reach the worker faster than the control plane can produce them.
	commandQueue = 16

	// leaseRenewFraction is the share of the advertised lease lifetime a renewal
	// waits for, used only when the control plane advertises no interval.
	leaseRenewFraction = 2

	// minimumRenewInterval floors the renewal cadence so a control plane that
	// advertises a tiny lease cannot make the gateway spin.
	minimumRenewInterval = time.Second

	// readinessInterval is the minimum cadence of the application readiness
	// report, which is independent of the transport heartbeat and of the lease.
	readinessInterval = 5 * time.Second

	// maintainInterval is how often the session re-evaluates time-driven state:
	// drain progress, activation evidence and the readiness report.
	maintainInterval = time.Second

	// shutdownReportTimeout bounds the reports a shutdown sends, so a control plane
	// that stopped answering cannot delay the shutdown of the process.
	shutdownReportTimeout = 3 * time.Second
)

// delivery is one resource the control plane announced, waiting to be downloaded
// and applied. The envelope addressing is captured here because the envelope
// itself belongs to the SDK once it reaches the event channel.
type delivery struct {
	subscription string
	kind         agentv1.ResourceKind
	key          string
	revision     uint64
	ref          *agentv1.ResourceRef
}

// agentSession owns the single control-plane session: the registration, the
// lease, the subscriptions, the release commands and the reports the control
// plane derives its state from. Every report it sends is derived from something
// it holds, so the evidence it produces is never an assertion about a state it
// did not reach.
type agentSession struct {
	g *Gateway

	mu       sync.Mutex
	commands chan *agentv1.Envelope
	wake     chan struct{}
	lease    *agentv1.Lease
	client   *agent.Client

	// pending holds the references a subscription delivered and that the worker
	// must still download, keyed by subscription. Coalescing per subscription is
	// what keeps a delivery burst from overflowing the SDK event channel.
	pending map[string]delivery
	// applied tracks the highest revision announced per subscription, so a
	// re-delivered reference is not downloaded again.
	applied map[string]uint64
	// subscribed is the resource key each kind is currently subscribed under. A
	// kind already subscribed under the same key is not subscribed again, because
	// every subscribe is answered with a snapshot and applying that snapshot would
	// re-announce the release the subscription was just asked for.
	subscribed map[agentv1.ResourceKind]string

	// reported is the activation evidence already sent on this session. It is
	// reset per session, because a reconnect must re-assert what this instance
	// serves.
	reported           bool
	reportedHash       string
	reportedGeneration uint64

	lastReady     bool
	lastReason    string
	lastReport    time.Time
	drainReported bool
}

func newAgentSession(g *Gateway) *agentSession {
	return &agentSession{
		g: g, pending: map[string]delivery{}, applied: map[string]uint64{},
		subscribed: map[agentv1.ResourceKind]string{},
	}
}

// run keeps one authenticated session alive, reconnecting with bounded backoff
// until ctx is canceled or a permanent failure stops the component.
func (s *agentSession) run(ctx context.Context) {
	err := agent.Run(ctx, s.options, func(client *agent.Client) error { return s.serve(ctx, client) })
	if err != nil && ctx.Err() == nil {
		log.Ctx(ctx).Error().Err(err).Msg("Control-plane session stopped permanently")
		s.g.setRegistration(func(status *registration) {
			status.permanent = err
			status.state = stateClosed
			status.registered = false
			status.leaseEpoch = 0
		})
	}
}

// options rebuilds the dial options before every attempt, so a rotated token is
// picked up without a restart and the persisted cursors are replayed.
func (s *agentSession) options(ctx context.Context) (agent.Options, error) {
	g := s.g
	token, err := g.token()
	if err != nil {
		return agent.Options{}, err
	}
	if err := ctx.Err(); err != nil {
		return agent.Options{}, err
	}
	g.setRegistration(func(status *registration) { status.state = stateConnecting })
	return agent.Options{
		URL:        g.cfg.GraylingURL,
		Token:      token,
		HTTPClient: g.control,
		Hello: &agentv1.Hello{
			MinMinor: 0, MaxMinor: 0,
			AgentId: g.cfg.Instance, InstanceId: g.cfg.Instance, BootId: g.cfg.Boot,
			Cursors: s.cursors(),
		},
	}, nil
}

// serve is one authenticated session. It returns nil only when the gateway is
// shutting down; every other exit is returned so Run decides between a reconnect
// and a permanent stop.
func (s *agentSession) serve(ctx context.Context, client *agent.Client) error {
	g := s.g
	welcome := client.Welcome().GetWelcome()
	if welcome == nil {
		return errors.New("gogw: session without a welcome")
	}
	if err := s.checkWelcome(welcome); err != nil {
		// A scope mismatch is a configuration error, not a transient one: a
		// reconnect would keep failing and hide the misconfiguration behind retries.
		return &agent.RemoteError{Detail: &agentv1.Error{
			Code: agentv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, Reason: boundedReason(err.Error()),
		}}
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	commands := make(chan *agentv1.Envelope, commandQueue)
	wake := make(chan struct{}, 1)
	defer func() {
		cancel()
		s.mu.Lock()
		s.commands, s.wake, s.client = nil, nil, nil
		s.mu.Unlock()
		workers.Wait()
	}()
	s.mu.Lock()
	s.commands, s.wake, s.lease, s.client = commands, wake, nil, client
	s.pending, s.applied = map[string]delivery{}, map[string]uint64{}
	s.subscribed = map[agentv1.ResourceKind]string{}
	s.reported, s.reportedHash, s.reportedGeneration = false, "", 0
	s.lastReport, s.drainReported = time.Time{}, false
	s.lastReady, s.lastReason = false, ""
	s.mu.Unlock()

	registered, err := s.register(sessionCtx, client, welcome)
	if err != nil {
		return s.reset(client, err)
	}
	log.Ctx(ctx).Info().Uint64("leaseEpoch", registered.GetInstance().GetLease().GetEpoch()).
		Int64("leaseExpiresUnixMs", registered.GetInstance().GetLease().GetExpiresUnixMs()).
		Uint64("discoveryRevision", registered.GetDiscoveryRevision()).Msg("Registered with the control plane")

	if err := s.subscribe(sessionCtx, client); err != nil {
		return s.reset(client, err)
	}
	g.setRegistration(func(status *registration) { status.state = stateActive })

	workers.Add(2)
	go func() { defer workers.Done(); s.renewLoop(sessionCtx, client, welcome) }()
	go func() { defer workers.Done(); s.commandLoop(sessionCtx, client, commands, wake) }()

	// A release this instance already accepted is re-evaluated once the session is
	// up, so a restart does not depend on the control plane repeating Activate.
	if err := g.advance(sessionCtx, time.Now()); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("Release could not be activated after connecting")
	}

	ticker := time.NewTicker(maintainInterval)
	defer ticker.Stop()
	for {
		select {
		case <-sessionCtx.Done():
			return nil
		case <-client.Done():
			return client.Err()
		case event, ok := <-client.Events():
			if !ok {
				return client.Err()
			}
			if err := s.handle(sessionCtx, client, event); err != nil {
				return s.reset(client, err)
			}
		case now := <-ticker.C:
			if err := s.maintain(sessionCtx, client, now); err != nil {
				return s.reset(client, err)
			}
		}
	}
}

// reset stops a session so Run can reconnect. The client is closed first because
// the error the SDK compares against is the one the session recorded, and any
// other error would stop the component instead of retrying it.
func (s *agentSession) reset(client *agent.Client, err error) error {
	log.Warn().Err(err).Msg("Ending the control-plane session so it can be re-established")
	_ = client.Close()
	if sessionErr := client.Err(); sessionErr != nil {
		return errors.Join(err, sessionErr)
	}
	return err
}

// checkWelcome rejects a session that does not cover this exact scope, or that
// advertises limits this gateway could not obey.
func (s *agentSession) checkWelcome(welcome *agentv1.Welcome) error {
	g := s.g
	scope := welcome.GetScope()
	if scope.GetWorkspaceId() != g.cfg.Scope.WorkspaceID || scope.GetEnvironmentId() != g.cfg.Scope.EnvironmentID ||
		scope.GetServiceKey() != g.cfg.Scope.ServiceKey {
		return errors.New("gogw: control-plane scope mismatch")
	}
	limits := welcome.GetLimits()
	if limits.GetMaxSubscriptions() <= 0 || limits.GetLeaseTtlMs() <= 0 || limits.GetHeartbeatIntervalMs() <= 0 ||
		limits.GetMaxFrameBytes() <= 0 || limits.GetMaxResourceBytes() <= 0 {
		return errors.New("gogw: control plane advertises unusable limits")
	}
	return nil
}

// instance renders the record this instance registers with. The advertised
// endpoint is a request address, not an origin: the serving surface is the
// gateway's own TLS identity and never the application's.
func (s *agentSession) instance() *agentv1.Instance {
	g := s.g
	ready, _ := g.eligibility()
	return &agentv1.Instance{
		InstanceId:      g.cfg.Instance,
		BootId:          g.cfg.Boot,
		BuildId:         g.cfg.Build,
		ImageDigest:     g.cfg.ImageDigest,
		Address:         g.cfg.AdvertiseAddress,
		Port:            uint32(g.cfg.AdvertisePort),
		TlsServerName:   g.id.serverName(),
		Zone:            g.cfg.Zone,
		ProtocolVersion: agentv1.ProtocolMajor,
		Ready:           ready,
		Draining:        g.draining.Load(),
	}
}

// register claims the lease of this instance boot. A restart that keeps its boot
// identifier gets a fresh lease and the membership it is already part of, which
// is what makes an in-place restart a recovery path instead of a cold start.
func (s *agentSession) register(ctx context.Context, client *agent.Client, welcome *agentv1.Welcome) (*agentv1.Registered, error) {
	instance := s.instance()
	instance.Scope = welcome.GetScope()
	registered, err := client.Register(ctx, uuid.New().String(), &agentv1.Register{Instance: instance})
	if err != nil {
		return nil, err
	}
	lease := registered.GetInstance().GetLease()
	if lease == nil || lease.GetEpoch() == 0 || lease.GetExpiresUnixMs() <= time.Now().UnixMilli() {
		return nil, errors.New("gogw: control plane answered with an unusable lease")
	}
	s.mu.Lock()
	s.lease = lease
	s.mu.Unlock()
	// A granted lease is the control plane's admission that this boot holds the
	// instance again, which is the only thing that lifts a fencing.
	s.g.fenced.Store(false)
	s.g.setRegistration(func(status *registration) {
		status.state = stateSyncing
		status.registered = true
		status.leaseEpoch = lease.GetEpoch()
		status.leaseExpires = time.UnixMilli(lease.GetExpiresUnixMs())
		status.fenced = false
		status.permanent = nil
	})
	return registered, nil
}

// subscriptionKinds is the subscription order: safety state first, so a
// revocation delivered alongside a release is applied before the release.
var subscriptionKinds = []agentv1.ResourceKind{
	agentv1.ResourceKind_RESOURCE_KIND_REVOCATION,
	agentv1.ResourceKind_RESOURCE_KIND_BUNDLE,
	agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY,
}

// subscriptionID names the single subscription slot of one resource kind. One
// slot per kind is what makes a reconnect idempotent: re-subscribing replaces the
// previous delivery instead of duplicating it.
func subscriptionID(kind agentv1.ResourceKind) string {
	switch kind {
	case agentv1.ResourceKind_RESOURCE_KIND_BUNDLE:
		return subscriptionBundle
	case agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY:
		return subscriptionDiscovery
	case agentv1.ResourceKind_RESOURCE_KIND_REVOCATION:
		return subscriptionRevocation
	default:
		return ""
	}
}

// subscriptionKey derives the resource key of one subscription from the release
// this instance holds. A release-scoped key only exists once a release was
// accepted or restored, which is why a cold start begins with the safety
// subscription and the release subscriptions follow the release.
func (s *agentSession) subscriptionKey(kind agentv1.ResourceKind) string {
	switch kind {
	case agentv1.ResourceKind_RESOURCE_KIND_REVOCATION:
		return RevocationKey
	case agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY:
		prepared := s.g.preparedRelease()
		if prepared == nil {
			return ""
		}
		if kind == agentv1.ResourceKind_RESOURCE_KIND_BUNDLE {
			return prepared.key
		}
		return DiscoveryKey(prepared.hash)
	default:
		return ""
	}
}

// cursor renders the resume position of one subscription.
func (s *agentSession) cursor(kind agentv1.ResourceKind, key string) *agentv1.Cursor {
	mark := s.g.state.watermark(kind, key)
	cursor := &agentv1.Cursor{Kind: kind, Key: key, Revision: mark.Revision}
	if mark.Revision != 0 {
		cursor.Sha256 = hexDigest(mark.PayloadHash)
	}
	return cursor
}

// cursors reports what this instance already applied. A kind with no persisted
// watermark is left out, which asks the control plane for a complete snapshot
// instead of a delta the gateway could not place.
func (s *agentSession) cursors() []*agentv1.Cursor {
	var cursors []*agentv1.Cursor
	for _, kind := range subscriptionKinds {
		if key := s.subscriptionKey(kind); key != "" {
			cursors = append(cursors, s.cursor(kind, key))
		}
	}
	return cursors
}

// subscribe restores every subscription this instance can express. The SDK
// delivers a complete snapshot on subscribe, so a reconnect re-converges from the
// published state; only the cursors are resumed, because the published protocol
// has no server-to-client field that could carry a resume token. That gap is
// recorded in docs/acceptance/gogw-completion/STATUS.md.
func (s *agentSession) subscribe(ctx context.Context, client *agent.Client) error {
	// A resynchronization asks for every subscription again, so the record of what
	// is already subscribed is dropped before the pass.
	s.mu.Lock()
	s.subscribed = map[agentv1.ResourceKind]string{}
	s.mu.Unlock()
	for _, kind := range subscriptionKinds {
		if err := s.subscribeKind(ctx, client, kind); err != nil {
			return err
		}
	}
	return nil
}

func (s *agentSession) subscribeKind(ctx context.Context, client *agent.Client, kind agentv1.ResourceKind) error {
	id, key := subscriptionID(kind), s.subscriptionKey(kind)
	if id == "" || key == "" {
		return nil
	}
	s.mu.Lock()
	held := s.subscribed[kind]
	s.mu.Unlock()
	if held == key {
		return nil
	}
	if err := client.Subscribe(ctx, id, s.cursor(kind, key)); err != nil {
		return err
	}
	s.mu.Lock()
	s.subscribed[kind] = key
	s.mu.Unlock()
	return nil
}

// reconfigure re-subscribes the release-scoped kinds after a release was
// accepted, which turns a release learned from a Prepare command into a live
// subscription instead of a one-off download.
func (s *agentSession) reconfigure(ctx context.Context, client *agent.Client) error {
	for _, kind := range []agentv1.ResourceKind{
		agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY,
	} {
		if err := s.subscribeKind(ctx, client, kind); err != nil {
			return err
		}
	}
	return nil
}

// maintain re-evaluates the time-driven state: the activation evidence this
// instance owes the control plane, the drain progress, and the readiness the
// control plane derives from this instance.
func (s *agentSession) maintain(ctx context.Context, client *agent.Client, now time.Time) error {
	if err := s.reportActivation(ctx, client); err != nil {
		return err
	}
	if s.g.draining.Load() {
		return s.reportDrain(ctx, client)
	}
	return s.reportReadiness(ctx, client, now)
}

// reportActivation publishes the activation evidence of the release this
// instance serves. It is derived from the persisted activation, so it covers an
// activation performed by a command, by a membership delivery and by a restart,
// and it is re-sent once per session because a reconnect re-establishes the
// control plane's view of this instance.
func (s *agentSession) reportActivation(ctx context.Context, client *agent.Client) error {
	active := s.g.state.active()
	if active == nil {
		return nil
	}
	s.mu.Lock()
	settled := s.reported && s.reportedHash == active.Hash && s.reportedGeneration == active.Generation
	s.mu.Unlock()
	if settled {
		return nil
	}
	prepared, ok := s.g.preparedFor(&agentv1.ReleaseIdentity{
		ReleaseId: active.ReleaseID, Generation: active.Generation, BundleHash: active.Hash,
	})
	if !ok {
		// The release this instance serves is no longer staged, which is what a
		// revocation leaves behind. There is no honest evidence to report for it.
		return nil
	}
	epoch, _ := s.g.revocation.snapshot()
	applied := &agentv1.Applied{
		Release:           releaseIdentityOf(prepared),
		InstanceId:        s.g.cfg.Instance,
		BootId:            s.g.cfg.Boot,
		PolicyRevision:    prepared.claims.Revision,
		PreparedRevision:  prepared.claims.Revision,
		DiscoveryRevision: s.g.discoveryRevision(hexDigest(prepared.hash)),
		RevocationEpoch:   epoch,
	}
	if err := client.SendMessage(ctx, applied, agent.Metadata{OperationID: uuid.New().String()}); err != nil {
		return err
	}
	s.mu.Lock()
	s.reported, s.reportedHash, s.reportedGeneration = true, active.Hash, active.Generation
	s.mu.Unlock()
	s.g.metrics.add(phaseAllocation, prepared.releaseID, "activation_reported")
	log.Ctx(ctx).Info().Str("release", prepared.releaseID).Uint64("generation", prepared.generation).
		Uint64("revocationEpoch", epoch).Msg("Reported release activation")
	return nil
}

// reportReadiness publishes the eligibility of this instance, which is what the
// control plane filters its membership candidates on. It reports the
// instance-level advertisement rather than the business readiness: an instance
// cannot compile a release before the membership naming it is published, and the
// control plane will not publish membership for an instance that reports itself
// unready. The report is deliberately independent of the transport heartbeat: a
// gateway whose application is unhealthy stays connected while it reports itself
// unready, so a byte that never reaches the application is distinguishable from a
// peer that went away.
func (s *agentSession) reportReadiness(ctx context.Context, client *agent.Client, now time.Time) error {
	ready, reason := s.g.eligibility()
	s.mu.Lock()
	unchanged := s.lastReady == ready && s.lastReason == reason && now.Sub(s.lastReport) < readinessInterval
	s.mu.Unlock()
	if unchanged {
		return nil
	}
	if ready {
		reason = "ready"
	}
	s.mu.Lock()
	s.lastReady, s.lastReason, s.lastReport = ready, reason, now
	s.mu.Unlock()
	return client.SendMessage(ctx, &agentv1.ReadinessReport{
		InstanceId: s.g.cfg.Instance, BootId: s.g.cfg.Boot, Ready: ready, Reason: boundedReason(reason),
	}, agent.Metadata{OperationID: uuid.New().String()})
}

// reportDrain publishes the draining progress. Active streams are the blocker the
// control plane waits on, and a completed drain is reported once.
func (s *agentSession) reportDrain(ctx context.Context, client *agent.Client) error {
	active := s.g.streams.count() + s.g.ActiveRequests()
	complete := active == 0
	s.mu.Lock()
	redundant := s.drainReported == complete
	s.drainReported = complete
	s.mu.Unlock()
	if redundant {
		return nil
	}
	return client.SendMessage(ctx, &agentv1.DrainReport{
		InstanceId: s.g.cfg.Instance, BootId: s.g.cfg.Boot,
		ActiveStreams: uint64(active), ForcedCloses: uint64(s.g.forcedCloses.Load()), Complete: complete,
	}, agent.Metadata{OperationID: uuid.New().String()})
}

// renewLoop extends the lease of this boot. A fenced renewal stops the session,
// and stopping the session is what stops the component from serving on a lease it
// no longer holds.
func (s *agentSession) renewLoop(ctx context.Context, client *agent.Client, welcome *agentv1.Welcome) {
	limits := welcome.GetLimits()
	interval := time.Duration(limits.GetLeaseRenewIntervalMs()) * time.Millisecond
	if interval <= 0 {
		interval = time.Duration(limits.GetLeaseTtlMs()) * time.Millisecond / leaseRenewFraction
	}
	if interval < minimumRenewInterval {
		interval = minimumRenewInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.mu.Lock()
		current := s.lease
		s.mu.Unlock()
		if current == nil {
			return
		}
		renewed, err := client.RenewLease(ctx, uuid.New().String(), &agentv1.RenewLease{
			InstanceId: s.g.cfg.Instance, BootId: s.g.cfg.Boot, Lease: current,
		})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isFenced(err) {
				log.Error().Err(err).Msg("Lease fenced by the control plane")
				s.g.setRegistration(func(status *registration) { status.fenced = true })
				s.g.fenced.Store(true)
				// The session is closed so that serving requires a new registration,
				// and a registration the control plane accepts is what lifts the
				// fencing.
				s.fail(client, err)
				return
			}
			s.fail(client, err)
			return
		}
		next := renewed.GetLease()
		if next == nil || next.GetEpoch() != current.GetEpoch() || next.GetExpiresUnixMs() <= time.Now().UnixMilli() {
			s.fail(client, errors.New("gogw: control plane answered with an unusable lease renewal"))
			return
		}
		s.mu.Lock()
		s.lease = next
		s.mu.Unlock()
		s.g.setRegistration(func(status *registration) { status.leaseExpires = time.UnixMilli(next.GetExpiresUnixMs()) })
	}
}

// releaseLease gives the lease of this boot back, which is what lets the control
// plane replace this instance at shutdown instead of waiting for the lease to
// expire. It is bounded: a control plane that does not answer must not delay the
// shutdown of the process holding it.
func (s *agentSession) releaseLease() {
	s.mu.Lock()
	client, lease := s.client, s.lease
	s.mu.Unlock()
	if client == nil || lease == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), shutdownReportTimeout)
	defer cancel()
	// The protocol defines no response to a deregistration, so the write is the
	// whole report: correlating a reply would only turn a clean shutdown into a
	// timeout and lose the evidence that the lease was handed back.
	if err := client.SendMessage(ctx, &agentv1.Deregister{
		InstanceId: s.g.cfg.Instance, BootId: s.g.cfg.Boot, Lease: lease,
	}, agent.Metadata{OperationID: uuid.New().String()}); err != nil {
		log.Warn().Err(err).Msg("Lease could not be released at shutdown")
		return
	}
	s.g.metrics.add(phaseAllocation, "", "lease_released")
}

// isFenced reports whether a renewal failed because the control plane replaced
// this lease holder.
func isFenced(err error) bool {
	remote, ok := errors.AsType[*agent.RemoteError](err)
	return ok && remote.Detail.GetCode() == agentv1.ErrorCode_ERROR_CODE_FENCED
}

// fail stops a session so the reconnect logic of the SDK sees a session error.
func (s *agentSession) fail(client *agent.Client, err error) {
	if client.Err() != nil {
		return
	}
	log.Warn().Err(err).Msg("Closing the control-plane session")
	_ = client.Close()
}

// commandLoop applies control-plane commands and resource deliveries off the
// event loop, because a download blocks and a blocked event loop trips the SDK
// backpressure guard.
func (s *agentSession) commandLoop(ctx context.Context, client *agent.Client, commands <-chan *agentv1.Envelope, wake <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-commands:
			if event == nil {
				continue
			}
			if err := s.applyCommand(ctx, client, event); err != nil {
				if errors.Is(err, errSessionClosing) {
					return
				}
				log.Ctx(ctx).Warn().Err(err).Msg("Control-plane command failed")
				s.fail(client, err)
				return
			}
		case <-wake:
			if err := s.download(ctx, client); err != nil {
				if errors.Is(err, errSessionClosing) {
					return
				}
				log.Ctx(ctx).Warn().Err(err).Msg("Resource delivery failed")
				s.fail(client, err)
				return
			}
		}
	}
}

// download drains the coalesced deliveries. A reference the control plane
// published and that fails verification is reported as a rejection, so the
// control plane stops waiting for evidence instead of counting this instance as a
// candidate that will never apply the resource. A transport failure is left
// pending and stops the session: nothing about the resource was disproved, and a
// reconnect re-reads the published state.
func (s *agentSession) download(ctx context.Context, client *agent.Client) error {
	for {
		if ctx.Err() != nil {
			return errSessionClosing
		}
		s.mu.Lock()
		var next delivery
		found := false
		for id, item := range s.pending {
			next, found = item, true
			delete(s.pending, id)
			break
		}
		s.mu.Unlock()
		if !found {
			return nil
		}
		resource, err := client.Download(ctx, next.ref)
		if err != nil {
			if ctx.Err() != nil {
				return errSessionClosing
			}
			if !permanentResourceError(err) {
				s.requeue(next)
				return err
			}
			s.g.metrics.add(phaseAllocation, "", "download_refused")
			if reportErr := s.rejectResource(ctx, client, next, err); reportErr != nil {
				return reportErr
			}
			continue
		}
		if err := s.apply(ctx, client, next, resource); err != nil {
			return err
		}
	}
}

// permanentResourceError reports whether a download failure disproved the
// reference itself, rather than describing a transport that can be retried.
func permanentResourceError(err error) bool {
	return errors.Is(err, agent.ErrResource) || errors.Is(err, agent.ErrScope) ||
		errors.Is(err, agent.ErrExpired) || errors.Is(err, agent.ErrRollback) ||
		errors.Is(err, agent.ErrProtocol)
}

func (s *agentSession) requeue(item delivery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, held := s.pending[item.subscription]; !held {
		s.pending[item.subscription] = item
	}
}

// handle applies one delivery from the control plane. It never blocks: a command
// is queued and a reference is queued for download, which is what keeps the event
// channel drained while the worker is busy.
func (s *agentSession) handle(ctx context.Context, client *agent.Client, event *agentv1.Envelope) error {
	switch payload := event.GetPayload().(type) {
	case *agentv1.Envelope_Snapshot:
		return s.acceptSnapshot(ctx, client, event, payload.Snapshot)
	case *agentv1.Envelope_Delta:
		return s.queue(event, payload.Delta.GetReference())
	case *agentv1.Envelope_Invalidated:
		return s.invalidate(ctx, event, payload.Invalidated)
	case *agentv1.Envelope_ResyncRequired:
		log.Ctx(ctx).Warn().Str("reason", boundedReason(payload.ResyncRequired.GetReason())).
			Msg("Control plane asked for a resynchronization")
		return s.subscribe(ctx, client)
	case *agentv1.Envelope_ConfigInvalidated:
		// Configuration is not a resource this gateway caches; the next reconnect
		// re-reads the session state from the control plane.
		s.g.metrics.add(phaseAllocation, "", "config_invalidated")
		return nil
	case *agentv1.Envelope_InstanceChanged:
		s.g.metrics.add(phaseAllocation, "", "instance_changed")
		log.Ctx(ctx).Debug().Str("instance", payload.InstanceChanged.GetInstance().GetInstanceId()).
			Bool("removed", payload.InstanceChanged.GetRemoved()).Msg("Control plane announced an instance change")
		return nil
	case *agentv1.Envelope_GoAway, *agentv1.Envelope_Error:
		// The SDK treats both as terminal and stops the session once they are
		// delivered, so recording them here is all that is left to do.
		log.Ctx(ctx).Info().Str("payload", eventPayloadName(event)).Msg("Control plane ended the session")
		return nil
	case *agentv1.Envelope_Prepare, *agentv1.Envelope_Activate, *agentv1.Envelope_Abort,
		*agentv1.Envelope_Revoke, *agentv1.Envelope_DrainRequested:
		return s.enqueue(event)
	default:
		log.Ctx(ctx).Debug().Str("payload", eventPayloadName(event)).Msg("Ignoring an unsupported delivery")
		return nil
	}
}

// enqueue hands one command to the worker. A full queue stops the session instead
// of dropping a command: a control plane that outruns the handler is a session
// this gateway cannot keep consistent, and reconnecting re-reads the whole
// published state.
func (s *agentSession) enqueue(event *agentv1.Envelope) error {
	s.mu.Lock()
	commands := s.commands
	s.mu.Unlock()
	if commands == nil {
		return errors.New("gogw: command received without an active session")
	}
	select {
	case commands <- event:
		return nil
	default:
		return agent.ErrBackpressure
	}
}

// acceptSnapshot applies, or queues for download, the content of one snapshot.
func (s *agentSession) acceptSnapshot(ctx context.Context, client *agent.Client, event *agentv1.Envelope, snapshot *agentv1.Snapshot) error {
	switch content := snapshot.GetContent().(type) {
	case *agentv1.Snapshot_InlineResource:
		if content.InlineResource == nil {
			return errors.New("gogw: snapshot without a resource")
		}
		return s.apply(ctx, client, s.deliveryOf(event, snapshot.GetRevision(), nil), content.InlineResource)
	case *agentv1.Snapshot_Reference:
		return s.queue(event, content.Reference)
	default:
		// A subscription whose resource is gone is a withdrawal, not an empty
		// delivery.
		return s.invalidate(ctx, event, &agentv1.Invalidated{Revision: snapshot.GetRevision()})
	}
}

// queue records one reference for download. A reference that is not newer than
// the revision already applied is not downloaded again, which is what makes a
// re-delivery after a reconnect cheap.
func (s *agentSession) queue(event *agentv1.Envelope, ref *agentv1.ResourceRef) error {
	if ref == nil || ref.GetKey() == "" {
		return errors.New("gogw: delivery without a resource reference")
	}
	item := s.deliveryOf(event, ref.GetRevision(), ref)
	s.mu.Lock()
	if revision := s.applied[item.subscription]; revision != 0 && item.revision <= revision {
		s.mu.Unlock()
		return nil
	}
	s.pending[item.subscription] = item
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// deliveryOf captures the addressing of one delivery. The kind and the key travel
// on the envelope, because a signed payload does not repeat them.
func (s *agentSession) deliveryOf(event *agentv1.Envelope, revision uint64, ref *agentv1.ResourceRef) delivery {
	return delivery{
		subscription: event.GetSubscriptionId(),
		kind:         event.GetResourceKind(),
		key:          event.GetResourceKey(),
		revision:     revision,
		ref:          ref,
	}
}

// apply verifies one resource and reports the acceptance or the refusal.
func (s *agentSession) apply(ctx context.Context, client *agent.Client, item delivery, resource *agentv1.SignedResource) error {
	if resource == nil {
		return errors.New("gogw: empty signed resource")
	}
	kind := item.kind
	claims, err := agent.ParseClaims(resource.GetClaims())
	if err != nil {
		return errDocument
	}
	if kind == agentv1.ResourceKind_RESOURCE_KIND_UNSPECIFIED {
		// The envelope of an inline snapshot is not required to repeat the kind, so
		// it is read from the resource itself. The signature still decides.
		kind = claims.Kind
	}
	if s.settled(item, claims) {
		// The revision this subscription is already at was delivered again: applying
		// it a second time would re-announce a release the control plane has already
		// been told about.
		return nil
	}
	if item.key == "" {
		item.key = expectedKey(kind, claims)
	}
	item.kind = kind
	switch kind {
	case agentv1.ResourceKind_RESOURCE_KIND_BUNDLE:
		err = s.publishPrepared(ctx, client, resource, nil)
	case agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY:
		err = s.g.acceptDiscovery(ctx, resource, time.Now())
	case agentv1.ResourceKind_RESOURCE_KIND_REVOCATION:
		_, _, err = s.g.acceptRevocation(ctx, resource, time.Now())
	default:
		return errUnsupported
	}
	if err != nil {
		return s.rejectResource(ctx, client, item, err)
	}
	s.record(item, claims)
	return s.confirmResource(ctx, client, item, claims)
}

// publishPrepared accepts a release bundle, reports the acceptance evidence the
// control plane needs before it may approve the activation, and subscribes the
// release-scoped resources so a later membership artifact is delivered. A nil
// command means the release arrived through a subscription rather than a Prepare.
func (s *agentSession) publishPrepared(ctx context.Context, client *agent.Client, resource *agentv1.SignedResource, command *agentv1.Prepare) error {
	prepared, err := s.g.acceptBundle(ctx, resource, time.Now())
	if err != nil {
		return err
	}
	s.g.limitPrepared(prepared, command.GetExpiresUnixMs())
	if err := client.SendMessage(ctx, &agentv1.Prepared{
		Release:                 releaseIdentityOf(prepared),
		InstanceId:              s.g.cfg.Instance,
		BootId:                  s.g.cfg.Boot,
		BuildId:                 s.g.cfg.Build,
		AcceptedProtocolVersion: agentv1.ProtocolMajor,
		PreparedUnixMs:          time.Now().UnixMilli(),
		ExpiresUnixMs:           prepared.expires.UnixMilli(),
		AppliedGeneration:       prepared.generation,
	}, agent.Metadata{
		OperationID: uuid.New().String(), ResourceKind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, ResourceKey: prepared.key,
	}); err != nil {
		return err
	}
	return s.reconfigure(ctx, client)
}

// confirmResource reports the revision this instance installed. The digest is the
// payload digest of the accepted resource, which is what makes the evidence
// checkable against the published resource rather than self-asserted.
func (s *agentSession) confirmResource(ctx context.Context, client *agent.Client, item delivery, claims agent.Claims) error {
	return client.SendMessage(ctx, &agentv1.ResourceApplied{
		Revision: claims.Revision, Sha256: hexDigest(claims.PayloadHash),
	}, agent.Metadata{
		OperationID: uuid.New().String(), SubscriptionID: item.subscription,
		ResourceKind: item.kind, ResourceKey: item.key,
	})
}

// rejectResource reports a refusal with the protocol code that names it. A
// generic failure would be indistinguishable from a transient error, and the
// control plane counts these codes.
func (s *agentSession) rejectResource(ctx context.Context, client *agent.Client, item delivery, err error) error {
	log.Ctx(ctx).Warn().Err(err).Str("kind", item.kind.String()).Str("key", boundedReason(item.key)).
		Msg("Refused a control-plane resource")
	s.g.metrics.add(phaseAllocation, "", "resource_refused")
	return client.SendMessage(ctx, &agentv1.ResourceRejected{
		Revision: item.revision, Error: resourceError(err),
	}, agent.Metadata{
		OperationID: uuid.New().String(), SubscriptionID: item.subscription,
		ResourceKind: item.kind, ResourceKey: item.key,
	})
}

// settled reports whether one delivery is no newer than the revision this
// subscription already applied.
func (s *agentSession) settled(item delivery, claims agent.Claims) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return max(item.revision, claims.Revision) <= s.applied[item.subscription]
}

// record notes the revision one subscription reached, so a re-delivery of the
// same or an older revision is not applied again. The watermark is the resource's
// own revision, because an envelope is not required to repeat it.
func (s *agentSession) record(item delivery, claims agent.Claims) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision := max(item.revision, claims.Revision); revision > s.applied[item.subscription] {
		s.applied[item.subscription] = revision
	}
}

// invalidate drops the resource one subscription held. A withdrawn release must
// stop serving: keeping it would serve a policy the control plane no longer
// publishes, and no expiry can bound that.
func (s *agentSession) invalidate(ctx context.Context, event *agentv1.Envelope, body *agentv1.Invalidated) error {
	kind, key := event.GetResourceKind(), event.GetResourceKey()
	log.Ctx(ctx).Warn().Str("kind", kind.String()).Str("key", boundedReason(key)).
		Uint64("revision", body.GetRevision()).Msg("Control plane withdrew a resource")
	switch kind {
	case agentv1.ResourceKind_RESOURCE_KIND_BUNDLE:
		s.g.withdraw(key)
	case agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY:
		s.g.withdrawMembership(key)
	default:
		s.g.metrics.add(phaseAllocation, "", "withdrawn")
	}
	s.mu.Lock()
	delete(s.applied, event.GetSubscriptionId())
	delete(s.pending, event.GetSubscriptionId())
	s.mu.Unlock()
	return nil
}

// applyCommand routes one queued control-plane command and persists the outcome
// in the idempotency journal. The record is what tells a re-delivery of the same
// operation apart from a new transition, and what preserves the evidence of a
// handled command across a restart.
func (s *agentSession) applyCommand(ctx context.Context, client *agent.Client, event *agentv1.Envelope) error {
	operation := event.GetOperationId()
	if operation != "" {
		if record, ok := s.g.state.operation(operation); ok {
			// A re-delivery after a lost acknowledgement. The handler runs anyway,
			// because its own identity, watermark and epoch checks make a second
			// application a no-op, and the control plane still needs the report it
			// never received.
			s.g.metrics.add(phaseExecution, "", "command_replayed")
			log.Ctx(ctx).Debug().Str("operation", operation).Str("status", record.Status).
				Msg("Replaying a command this instance already handled")
		}
	}
	kind, generation, err := s.dispatchCommand(ctx, client, event)
	if operation != "" {
		status := "applied"
		if err != nil {
			status = "rejected"
		}
		record := operationRecord{ID: operation, Kind: kind, Generation: generation, Status: status, AtUnixMs: time.Now().UnixMilli()}
		if noteErr := s.g.state.noteOperation(record); noteErr != nil {
			// The transition itself is already applied and reported, so a journal
			// that cannot be written must not turn it into a failure.
			log.Ctx(ctx).Warn().Err(noteErr).Str("operation", operation).Msg("Could not record a handled command")
		}
	}
	return err
}

// dispatchCommand applies one command and reports what it was about, so the
// caller can journal the outcome without knowing the command types.
func (s *agentSession) dispatchCommand(ctx context.Context, client *agent.Client, event *agentv1.Envelope) (string, uint64, error) {
	switch payload := event.GetPayload().(type) {
	case *agentv1.Envelope_Prepare:
		return "Prepare", payload.Prepare.GetRelease().GetGeneration(), s.prepareRelease(ctx, client, payload.Prepare)
	case *agentv1.Envelope_Activate:
		return "Activate", payload.Activate.GetRelease().GetGeneration(), s.activateRelease(ctx, client, payload.Activate)
	case *agentv1.Envelope_Abort:
		return "Abort", payload.Abort.GetRelease().GetGeneration(), s.abortRelease(ctx, client, payload.Abort)
	case *agentv1.Envelope_Revoke:
		return "Revoke", payload.Revoke.GetEpoch(), s.revokeReleases(ctx, client, event, payload.Revoke)
	case *agentv1.Envelope_DrainRequested:
		return "DrainRequested", 0, s.drainInstance(ctx, client, payload.DrainRequested)
	default:
		return "", 0, nil
	}
}

// prepareRelease downloads and accepts the release the control plane prepared.
func (s *agentSession) prepareRelease(ctx context.Context, client *agent.Client, command *agentv1.Prepare) error {
	ref := command.GetBundle()
	if ref == nil {
		return s.rejectRelease(ctx, client, command.GetRelease(), errUndeclared)
	}
	resource, err := client.Download(ctx, ref)
	if err != nil {
		if ctx.Err() != nil {
			return errSessionClosing
		}
		if permanentResourceError(err) {
			return s.rejectRelease(ctx, client, command.GetRelease(), err)
		}
		// The reference was not disproved, only unreachable: reconnecting re-reads
		// the published state instead of reporting an acceptance that never happened.
		return err
	}
	if err := s.publishPrepared(ctx, client, resource, command); err != nil {
		return s.rejectRelease(ctx, client, command.GetRelease(), err)
	}
	// The command names the same reference the release subscription is about to
	// announce, so the revision is recorded here and the echo is not applied twice.
	s.record(delivery{subscription: subscriptionBundle, revision: ref.GetRevision()}, agent.Claims{})
	return nil
}

// activateRelease approves a prepared release and advances the release state
// machine. The activation itself is reported from the persisted activation, so an
// approval whose membership has not arrived yet is reported once it does, instead
// of being asserted at approval time.
func (s *agentSession) activateRelease(ctx context.Context, client *agent.Client, command *agentv1.Activate) error {
	release := command.GetRelease()
	if _, err := s.g.approve(release, command.GetPolicyRevision(), command.GetPreparedRevision()); err != nil {
		return s.rejectRelease(ctx, client, release, err)
	}
	if err := s.g.advance(ctx, time.Now()); err != nil {
		return s.rejectRelease(ctx, client, release, err)
	}
	return nil
}

// abortRelease cancels the approval of one release. A release that is already
// serving stays serving: aborting a candidate never withdraws a running release,
// because that would leave the instance serving nothing without being told to.
func (s *agentSession) abortRelease(ctx context.Context, client *agent.Client, command *agentv1.Abort) error {
	release := command.GetRelease()
	s.g.discharge(release.GetBundleHash())
	if active := s.g.state.active(); active != nil && active.Hash == release.GetBundleHash() {
		return nil
	}
	s.g.metrics.add(phaseAllocation, "", "activation_aborted")
	return s.rejectRelease(ctx, client, release, errors.New("aborted"))
}

// revokeReleases applies a revocation announced by a command. The command is
// authenticated by the session and the epoch is persisted before it takes effect,
// so a restart cannot resurrect a revoked release.
func (s *agentSession) revokeReleases(ctx context.Context, client *agent.Client, event *agentv1.Envelope, command *agentv1.Revoke) error {
	epoch, _, err := s.g.applyRevocation(command.GetEpoch(), command.GetBundleHashes(), command.GetCancelActiveStreams(), 0)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("Refused a revocation command")
		return client.SendMessage(ctx, &agentv1.ResourceRejected{
			Revision: command.GetEpoch(), Error: resourceError(err),
		}, agent.Metadata{
			OperationID: uuid.New().String(), SubscriptionID: event.GetSubscriptionId(),
			ResourceKind: agentv1.ResourceKind_RESOURCE_KIND_REVOCATION, ResourceKey: RevocationKey,
		})
	}
	return client.SendMessage(ctx, &agentv1.ResourceApplied{Revision: epoch}, agent.Metadata{
		OperationID: uuid.New().String(), SubscriptionID: event.GetSubscriptionId(),
		ResourceKind: agentv1.ResourceKind_RESOURCE_KIND_REVOCATION, ResourceKey: RevocationKey,
	})
}

// drainInstance withdraws readiness under the deadline the control plane set. The
// instance record is updated as well, so the control plane stops counting this
// instance as a candidate without waiting for the next readiness report.
func (s *agentSession) drainInstance(ctx context.Context, client *agent.Client, command *agentv1.DrainRequested) error {
	forceClose := time.Time{}
	if command.GetForceCloseUnixMs() > 0 {
		forceClose = time.UnixMilli(command.GetForceCloseUnixMs())
	}
	s.g.beginDrain(forceClose)
	s.g.metrics.add(phaseAllocation, "", "drain_requested")
	return client.SendMessage(ctx, &agentv1.UpdateInstance{Instance: s.instance()}, agent.Metadata{OperationID: uuid.New().String()})
}

// rejectRelease reports a release this instance will not activate, with the code
// that names why.
func (s *agentSession) rejectRelease(ctx context.Context, client *agent.Client, release *agentv1.ReleaseIdentity, err error) error {
	log.Ctx(ctx).Warn().Err(err).Str("release", release.GetReleaseId()).Msg("Refused a release command")
	return client.SendMessage(ctx, &agentv1.Rejected{Release: release, Error: resourceError(err)},
		agent.Metadata{OperationID: uuid.New().String(), ResourceKind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE})
}

// releaseIdentityOf renders the identity a report names. The bundle hash is the
// release payload digest, which is the identity every related resource signs.
func releaseIdentityOf(prepared *preparedRelease) *agentv1.ReleaseIdentity {
	return &agentv1.ReleaseIdentity{
		ReleaseId: prepared.releaseID, Generation: prepared.generation, BundleHash: hexDigest(prepared.hash),
	}
}

// resourceError maps a collection failure onto the protocol error vocabulary. The
// codes are counted by the control plane, so they are not collapsed into a single
// generic failure.
func resourceError(err error) *agentv1.Error {
	code := agentv1.ErrorCode_ERROR_CODE_UNSPECIFIED
	switch {
	case errors.Is(err, errRevoked), errors.Is(err, agent.ErrScope):
		code = agentv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED
	case errors.Is(err, errDocument), errors.Is(err, errUndeclared), errors.Is(err, errUnsupported),
		errors.Is(err, agent.ErrResource):
		code = agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
	case errors.Is(err, agent.ErrRollback), errors.Is(err, errRegression):
		code = agentv1.ErrorCode_ERROR_CODE_STALE_REVISION
	case errors.Is(err, agent.ErrExpired):
		code = agentv1.ErrorCode_ERROR_CODE_RESOURCE_EXPIRED
	}
	return &agentv1.Error{Code: code, Reason: boundedReason(err.Error())}
}

// boundedReason keeps a diagnostic reason inside the protocol identifier bound
// and strips control characters, so an operator-visible field cannot become a
// carrier for a payload.
func boundedReason(reason string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, reason)
	if !validIdentifier(cleaned, maxIdentifier) {
		return "unavailable"
	}
	return cleaned
}

// eventPayloadName names the payload of one envelope for diagnostics.
func eventPayloadName(event *agentv1.Envelope) string {
	if event == nil || event.GetPayload() == nil {
		return "none"
	}
	name := fmt.Sprintf("%T", event.GetPayload())
	return strings.ToLower(strings.TrimPrefix(name, "*agentv1.Envelope_"))
}
