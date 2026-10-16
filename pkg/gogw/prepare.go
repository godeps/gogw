package gogw

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
)

// Subscription identifiers. One identifier per resource kind keeps a reconnect
// idempotent: re-subscribing the same identifier replaces the previous delivery.
const (
	subscriptionBundle     = "bundle"
	subscriptionDiscovery  = "discovery"
	subscriptionRevocation = "revocation"
)

// Collection errors. They are distinct so the caller can report the exact
// protocol error code instead of a generic rejection.
var (
	errRevoked     = errors.New("gogw: release is revoked")
	errUndeclared  = errors.New("gogw: resource is not part of the prepared release")
	errUnsupported = errors.New("gogw: unsupported resource kind")
)

// collected is one verified artifact: the signed resource, its verified claims
// and the decoded payload of its kind.
type collected struct {
	resource *agentv1.SignedResource
	claims   agent.Claims
	key      string
	// hash is the payload digest for a bundle, which is the release identity the
	// control plane signs into every related resource, and the bundle digest for
	// a membership artifact.
	hash   [32]byte
	bundle *BundleDocument
	disco  *DiscoveryDocument
	revoke *RevocationDocument
}

// expectedKey derives the resource key one kind must be published under. The key
// is a function of the claims alone, so a resource cannot be published under a
// key that would let it collide with a different release.
func expectedKey(kind agentv1.ResourceKind, claims agent.Claims) string {
	switch kind {
	case agentv1.ResourceKind_RESOURCE_KIND_BUNDLE:
		return BundleKey(claims.PayloadHash)
	case agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY:
		return DiscoveryKey(claims.BundleHash)
	case agentv1.ResourceKind_RESOURCE_KIND_REVOCATION:
		return RevocationKey
	default:
		return ""
	}
}

// verifyResource checks one signed resource against its derived key, its kind,
// the configured scope, its validity window and the persisted watermark. The key
// is derived from the unverified claims and re-checked by the signature
// verifier, which is what keeps the derivation from being forgeable.
func (g *Gateway) verifyResource(resource *agentv1.SignedResource, kind agentv1.ResourceKind, now time.Time) (agent.Claims, string, error) {
	if resource == nil {
		return agent.Claims{}, "", errors.New("gogw: missing signed resource")
	}
	parsed, err := agent.ParseClaims(resource.GetClaims())
	if err != nil || parsed.Kind != kind {
		return agent.Claims{}, "", errDocument
	}
	key := expectedKey(kind, parsed)
	if key == "" || len(key) > maxIdentifier*4 {
		return agent.Claims{}, "", errUnsupported
	}
	claims, err := g.trust.verify(resource, g.cfg.Scope, kind, key, g.state.watermark(kind, key), now)
	if err != nil {
		return agent.Claims{}, "", err
	}
	return claims, key, nil
}

// collect verifies one resource and decodes the payload of its kind.
func (g *Gateway) collect(resource *agentv1.SignedResource, kind agentv1.ResourceKind, now time.Time) (*collected, error) {
	claims, key, err := g.verifyResource(resource, kind, now)
	if err != nil {
		return nil, err
	}
	item := &collected{resource: resource, claims: claims, key: key, hash: claims.PayloadHash}
	payload := resource.GetPayload()
	switch kind {
	case agentv1.ResourceKind_RESOURCE_KIND_BUNDLE:
		document, err := decodeBundle(payload, g.cfg.Scope)
		if err != nil {
			return nil, err
		}
		item.bundle = &document
	case agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY:
		document, err := decodeDiscovery(payload, hexDigest(claims.BundleHash), now)
		if err != nil {
			return nil, err
		}
		item.hash = claims.BundleHash
		item.disco = &document
	case agentv1.ResourceKind_RESOURCE_KIND_REVOCATION:
		document, err := decodeRevocation(payload, now)
		if err != nil {
			return nil, err
		}
		item.revoke = &document
	default:
		return nil, errUnsupported
	}
	return item, nil
}

// acceptBundle verifies, persists and stages one release bundle. Acceptance is
// not activation: the release waits for the control plane to approve it, and the
// persisted watermark is what stops a replay of an older release.
func (g *Gateway) acceptBundle(ctx context.Context, resource *agentv1.SignedResource, now time.Time) (*preparedRelease, error) {
	item, err := g.collect(resource, agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, now)
	if err != nil {
		return nil, err
	}
	hash := hexDigest(item.hash)
	if g.revocation.revoked(hash) {
		return nil, errRevoked
	}
	if err := g.state.accept(agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, item.key, item.bundle.Generation, item.claims, resource); err != nil {
		return nil, err
	}
	prepared := &preparedRelease{
		hash: item.hash, key: item.key, claims: item.claims, document: *item.bundle, resource: resource,
		generation: item.bundle.Generation, expires: time.UnixMilli(item.claims.ExpiresUnixMs), releaseID: item.bundle.ReleaseID,
	}
	g.mu.Lock()
	previous := g.prepared
	g.prepared, g.disco, g.armed = prepared, nil, false
	// A membership artifact already held for this release is reused, so a
	// re-delivery of the same bundle does not force a new membership round trip.
	if g.discoHold != nil && hexDigest(g.discoHold.hash) == hash {
		g.disco = g.discoHold
	}
	g.mu.Unlock()
	if previous != nil && hexDigest(previous.hash) != hash {
		g.metrics.add(phaseAllocation, "", "release_superseded")
	}
	log.Ctx(ctx).Info().Str("release", prepared.releaseID).Uint64("generation", prepared.generation).
		Str("bundleHash", hash).Msg("Accepted gogw release")
	return prepared, nil
}

// acceptDiscovery verifies, persists and applies one membership artifact. The
// artifact is bound to one release, so it is applied to the release this instance
// holds for that bundle and ignored otherwise.
func (g *Gateway) acceptDiscovery(ctx context.Context, resource *agentv1.SignedResource, now time.Time) error {
	item, err := g.collect(resource, agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY, now)
	if err != nil {
		return err
	}
	if err := g.state.accept(agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY, item.key, 0, item.claims, resource); err != nil {
		return err
	}
	hash := hexDigest(item.hash)
	g.mu.Lock()
	if g.discoHold != nil && hexDigest(g.discoHold.hash) == hash && g.discoHold.claims.Revision >= item.claims.Revision {
		stale := g.discoHold.claims.Revision > item.claims.Revision
		g.mu.Unlock()
		if stale {
			log.Ctx(ctx).Warn().Uint64("revision", item.claims.Revision).Msg("Ignoring an older membership artifact")
		}
		return nil
	}
	g.discoHold = item
	if g.prepared != nil && hexDigest(g.prepared.hash) == hash {
		g.disco = item
	}
	g.mu.Unlock()
	log.Ctx(ctx).Info().Uint64("revision", item.disco.Revision).Int("members", len(item.disco.Members)).
		Str("bundleHash", hash).Msg("Accepted gogw membership artifact")
	return g.advance(ctx, now)
}

// acceptRevocation merges one revocation document, persists the epoch before it
// takes effect and tears down whatever the merge revoked.
func (g *Gateway) acceptRevocation(ctx context.Context, resource *agentv1.SignedResource, now time.Time) (uint64, []string, error) {
	item, err := g.collect(resource, agentv1.ResourceKind_RESOURCE_KIND_REVOCATION, now)
	if err != nil {
		return 0, nil, err
	}
	document := item.revoke
	epoch, newly, err := g.applyRevocation(document.Epoch, document.BundleHashes, document.CancelActiveStreams, document.ExpiresUnixMs)
	if err != nil {
		return 0, nil, err
	}
	if err := g.state.accept(agentv1.ResourceKind_RESOURCE_KIND_REVOCATION, item.key, 0, item.claims, resource); err != nil {
		return 0, nil, err
	}
	if len(newly) > 0 {
		log.Ctx(ctx).Warn().Uint64("epoch", document.Epoch).Int("releases", len(newly)).
			Bool("cancelActiveStreams", document.CancelActiveStreams).Msg("Applied a revocation epoch")
	}
	return epoch, newly, nil
}

// applyRevocation merges a cumulative revocation state announced by a signed
// document or by an authenticated command. The epoch is persisted before it takes
// effect, and the merge is a union, so a forgotten or replayed revocation cannot
// resurrect a revoked release.
func (g *Gateway) applyRevocation(epoch uint64, hashes []string, cancelStreams bool, expiresUnixMs int64) (uint64, []string, error) {
	merged, err := g.state.mergeRevocation(epoch, hashes)
	if err != nil {
		return 0, nil, err
	}
	expires := time.Time{}
	if expiresUnixMs > 0 {
		expires = time.UnixMilli(expiresUnixMs)
	}
	newly, err := g.revocation.merge(merged.Epoch, merged.Hashes, expires)
	if err != nil {
		return 0, nil, err
	}
	for _, hash := range newly {
		g.revokeRelease(hash, cancelStreams)
	}
	return merged.Epoch, newly, nil
}

// revokeRelease drops every use of one revoked release: the prepared slot, the
// active view and, when the control plane asked for it, the streams serving it.
func (g *Gateway) revokeRelease(hash string, cancelStreams bool) {
	g.mu.Lock()
	if g.prepared != nil && hexDigest(g.prepared.hash) == hash {
		g.prepared, g.disco, g.armed = nil, nil, false
	}
	var revoked []*view
	if g.active != nil && g.active.bundleHashHex() == hash {
		revoked = append(revoked, g.active)
		g.active = nil
	}
	for _, v := range g.retired {
		if v.bundleHashHex() == hash {
			revoked = append(revoked, v)
		}
	}
	g.mu.Unlock()
	for _, v := range revoked {
		if cancelStreams {
			g.streams.cancelView(v)
		}
	}
	if len(revoked) > 0 {
		// The revoked views are dropped from the gateway's own lists, so their
		// references are released here; a request still holding one keeps it alive
		// until it finishes or is canceled.
		g.releaseRevoked(revoked)
	}
}

func (g *Gateway) releaseRevoked(revoked []*view) {
	g.mu.Lock()
	remaining := g.retired[:0]
	for _, v := range g.retired {
		if !slices.Contains(revoked, v) {
			remaining = append(remaining, v)
		}
	}
	g.retired = remaining
	g.mu.Unlock()
	for _, v := range revoked {
		v.release()
	}
}

// advance moves the release state machine forward after any state change:
// a membership artifact of the active release re-compiles it, and an approved
// prepared release becomes active as soon as its membership is available.
func (g *Gateway) advance(ctx context.Context, now time.Time) error {
	g.mu.Lock()
	prepared, disco, armed, active := g.prepared, g.disco, g.armed, g.active
	g.mu.Unlock()

	if active != nil && disco != nil && active.bundleHashHex() == hexDigest(disco.hash) {
		if err := g.refresh(active, disco, now); err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("Refreshing the active release failed, keeping the current membership")
		}
	}
	if !armed || prepared == nil || disco == nil || hexDigest(disco.hash) != hexDigest(prepared.hash) {
		return nil
	}
	return g.activate(ctx, prepared, disco, now)
}

// refresh re-compiles the active release against a newer membership artifact.
// Compilation happens before the swap, so a rejected artifact leaves the current
// routing untouched instead of emptying it. A request already in flight keeps the
// view it started on; a bound unit follows the replacement.
func (g *Gateway) refresh(active *view, disco *collected, now time.Time) error {
	next, err := compileView(viewInput{
		g: g, claims: active.claims, document: active.bundle, hash: active.hash,
		disco: *disco.disco, revoked: g.revocation.revoked(active.bundleHashHex()), now: now,
	})
	if err != nil {
		return err
	}
	next.acquire()
	previous := g.swap(next, now)
	if previous != nil {
		g.sessions.rebind(previous, next)
	}
	return nil
}

// activate installs an approved prepared release. The exact release identity is
// re-checked here against the approved discovery artifact, so approval for one
// release can never activate another.
func (g *Gateway) activate(ctx context.Context, prepared *preparedRelease, disco *collected, now time.Time) error {
	hash := hexDigest(prepared.hash)
	if g.revocation.revoked(hash) {
		return errRevoked
	}
	if !now.Before(prepared.expires) {
		return errors.New("gogw: prepared release expired before activation")
	}
	next, err := compileView(viewInput{
		g: g, claims: prepared.claims, document: prepared.document, hash: prepared.hash,
		disco: *disco.disco, revoked: false, now: now,
	})
	if err != nil {
		return err
	}
	if err := g.state.setActive(&activeRecord{Hash: hash, Key: prepared.key, ReleaseID: prepared.releaseID, Generation: prepared.generation}); err != nil {
		return err
	}
	next.acquire()
	previous := g.swap(next, now)
	if previous != nil {
		// Sessions pinned to the previous release survive inside the compatibility
		// window; the streams that were already running on it are not interrupted.
		g.metrics.add(phaseAllocation, "", "release_activated")
	}
	g.metrics.add(phaseAllocation, "", "release_activated")
	log.Ctx(ctx).Info().Str("release", prepared.releaseID).Uint64("generation", prepared.generation).
		Str("bundleHash", hash).Uint64("members", uint64(len(next.members))).Msg("Activated gogw release")
	return nil
}

// discharge clears the approval of one prepared release, which is what Abort
// does: the release stops being a candidate without disturbing what is serving.
func (g *Gateway) discharge(hash string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.prepared == nil || hexDigest(g.prepared.hash) != hash {
		return false
	}
	g.armed = false
	return true
}

// preparedFor returns the staged release when it matches one release identity.
func (g *Gateway) preparedFor(release *agentv1.ReleaseIdentity) (*preparedRelease, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	prepared := g.prepared
	if prepared == nil {
		return nil, false
	}
	if prepared.releaseID != release.GetReleaseId() || prepared.generation != release.GetGeneration() ||
		hexDigest(prepared.hash) != release.GetBundleHash() {
		return nil, false
	}
	return prepared, true
}

// preparedRelease returns the staged release, which is what makes the
// release-scoped resource keys addressable.
func (g *Gateway) preparedRelease() *preparedRelease {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.prepared
}

// limitPrepared narrows the acceptance window of a prepared release to the
// deadline the control plane set for the Prepare command, so an acceptance can
// never outlive the approval window that produced it.
func (g *Gateway) limitPrepared(prepared *preparedRelease, expiresUnixMs int64) {
	if prepared == nil || expiresUnixMs <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.prepared != prepared {
		return
	}
	if limit := time.UnixMilli(expiresUnixMs); limit.Before(prepared.expires) {
		prepared.expires = limit
	}
}

// discoveryRevision reports the revision of the membership artifact held for one
// release, which is the revision an activation report must name.
func (g *Gateway) discoveryRevision(hash string) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.disco == nil || hexDigest(g.disco.hash) != hash {
		return 0
	}
	return g.disco.claims.Revision
}

// withdraw drops a released resource the control plane withdrew. A bundle that is
// no longer published must stop serving: keeping it would serve a policy the
// control plane no longer signs, and no expiry can bound that.
func (g *Gateway) withdraw(key string) {
	g.mu.Lock()
	var revoked []*view
	if g.prepared != nil && g.prepared.key == key {
		hash := hexDigest(g.prepared.hash)
		g.prepared, g.disco, g.armed = nil, nil, false
		if g.active != nil && g.active.bundleHashHex() == hash {
			revoked = append(revoked, g.active)
			g.active = nil
		}
		for _, v := range g.retired {
			if v.bundleHashHex() == hash {
				revoked = append(revoked, v)
			}
		}
	}
	g.mu.Unlock()
	for _, v := range revoked {
		g.streams.cancelView(v)
	}
	g.releaseRevoked(revoked)
	if len(revoked) > 0 {
		g.metrics.add(phaseAllocation, "", "release_withdrawn")
		log.Warn().Str("key", key).Int("views", len(revoked)).Msg("Withdrew a release the control plane no longer publishes")
	}
}

// withdrawMembership drops the membership artifact of one release. The release
// stops being servable until a newer artifact is published, because a stale
// membership would keep routing to members the control plane already replaced.
func (g *Gateway) withdrawMembership(key string) {
	hash := strings.TrimPrefix(key, "discovery/")
	g.mu.Lock()
	withdrawn := false
	if g.discoHold != nil && hexDigest(g.discoHold.hash) == hash {
		g.discoHold, withdrawn = nil, true
	}
	if g.disco != nil && hexDigest(g.disco.hash) == hash {
		g.disco, withdrawn = nil, true
	}
	g.mu.Unlock()
	if withdrawn {
		g.metrics.add(phaseAllocation, "", "membership_withdrawn")
		log.Warn().Str("key", key).Msg("Withdrew the membership of a release")
	}
}

// approve arms the prepared release for activation. The identity is re-checked
// against the staged release, and the revision the control plane answered is
// compared with the revision this instance accepted, so an approval that names a
// different release can never activate one.
func (g *Gateway) approve(release *agentv1.ReleaseIdentity, policyRevision, preparedRevision uint64) (*preparedRelease, error) {
	prepared, ok := g.preparedFor(release)
	if !ok {
		return nil, errUndeclared
	}
	if preparedRevision != 0 && preparedRevision != prepared.claims.Revision {
		return nil, errors.New("gogw: activation names a different prepared revision")
	}
	if policyRevision != 0 && policyRevision != prepared.claims.Revision {
		return nil, errors.New("gogw: activation names a different policy revision")
	}
	if !time.Now().Before(prepared.expires) {
		return nil, errors.New("gogw: prepared release has expired")
	}
	g.mu.Lock()
	g.armed = true
	g.mu.Unlock()
	return prepared, nil
}

// restore re-installs the release persisted before the last restart. Restoring
// re-verifies the artifacts against the current trust keys and expiry, so a
// process that comes back after its release expired stays unready instead of
// reviving a stale policy.
func (g *Gateway) restore(ctx context.Context) {
	active := g.state.active()
	if active == nil {
		return
	}
	bundle, err := g.state.restore(agentv1.ResourceKind_RESOURCE_KIND_BUNDLE)
	if err != nil || bundle == nil {
		log.Ctx(ctx).Warn().Err(err).Msg("Persisted release is unreadable")
		return
	}
	now := time.Now()
	item, err := g.collect(bundle, agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, now)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("Persisted release is no longer verifiable")
		return
	}
	if hexDigest(item.hash) != active.Hash || g.revocation.revoked(active.Hash) {
		log.Ctx(ctx).Warn().Msg("Persisted release does not match the recorded activation")
		return
	}
	discovery, err := g.state.restore(agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY)
	if err != nil || discovery == nil {
		log.Ctx(ctx).Info().Msg("Persisted release has no persisted membership")
		return
	}
	disco, err := g.collect(discovery, agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY, now)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("Persisted membership is no longer verifiable")
		return
	}
	prepared := &preparedRelease{
		hash: item.hash, key: item.key, claims: item.claims, document: *item.bundle, resource: bundle,
		generation: item.bundle.Generation, expires: time.UnixMilli(item.claims.ExpiresUnixMs), releaseID: item.bundle.ReleaseID,
	}
	g.mu.Lock()
	g.prepared, g.disco, g.discoHold = prepared, disco, disco
	g.mu.Unlock()
	// A session still bound to this release survives the restart, and the
	// membership artifact decides again whether this instance may serve it.
	if err := g.advance(ctx, now); err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("Restored release could not be compiled")
		return
	}
	log.Ctx(ctx).Info().Str("release", prepared.releaseID).Uint64("generation", prepared.generation).
		Msg("Restored the activated release from the state file")
}
