package mock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/bucketing"
	"github.com/saker-ai/grayling/pkg/model"
	"github.com/traefik/traefik/v3/pkg/gogw"
	"google.golang.org/protobuf/proto"
)

const (
	// documentSchema is the only extended payload schema pkg/gogw verifies.
	documentSchema = 1

	// defaultDiscoveryMaxAge is the discovery validity a release omits.
	defaultDiscoveryMaxAge = 300

	// maxDiscoveryMembers and maxIdentifierSize mirror pkg/gogw's document
	// limits, so an oversized publication fails here instead of at a gateway.
	maxDiscoveryMembers = 1024
	maxIdentifierSize   = 256
)

// Release is one publishable release. Its document follows the extended bundle
// contract of pkg/gogw, which binds the payload hash to the resource key.
type Release struct {
	ReleaseID              string                          `json:"releaseId"`
	Generation             uint64                          `json:"generation"`
	Flag                   string                          `json:"flag"`
	DefaultBuild           string                          `json:"defaultBuild"`
	Builds                 map[string]gogw.BuildDescriptor `json:"builds"`
	Ramp                   *gogw.Ramp                      `json:"ramp,omitempty"`
	Policy                 model.Snapshot                  `json:"policy"`
	MinimumProtocolVersion uint32                          `json:"minimumProtocolVersion"`
	DiscoveryMaxAgeSeconds int64                           `json:"discoveryMaxAgeSeconds"`
}

// RevocationSpec is the service-scoped revocation state of a release file.
type RevocationSpec struct {
	Epoch               uint64   `json:"epoch"`
	BundleHashes        []string `json:"bundleHashes"`
	CancelActiveStreams bool     `json:"cancelActiveStreams"`
}

// BundleDigests decodes the revoked bundle digests.
func (r RevocationSpec) BundleDigests() ([][32]byte, error) {
	digests := make([][32]byte, 0, len(r.BundleHashes))
	for _, value := range r.BundleHashes {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != sha256.Size || value != strings.ToLower(value) {
			return nil, fmt.Errorf("mock: invalid revoked bundle hash %q", value)
		}
		var digest [32]byte
		copy(digest[:], raw)
		digests = append(digests, digest)
	}
	return digests, nil
}

// ReleaseFile is the reloadable input of the standalone mock: one release, the
// member overrides a control plane cannot observe, and an optional revocation.
type ReleaseFile struct {
	Release    Release         `json:"release"`
	Members    []gogw.Member   `json:"members"`
	Revocation *RevocationSpec `json:"revocation"`
}

// LoadReleaseFile reads and strictly decodes a release file. Unknown members are
// rejected so a typo cannot silently drop part of the release.
func LoadReleaseFile(path string) (ReleaseFile, error) {
	var file ReleaseFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return file, err
	}
	if err := json.Unmarshal(raw, &file, json.RejectUnknownMembers(true)); err != nil {
		return file, fmt.Errorf("mock: invalid release file: %w", err)
	}
	return file, nil
}

// buildBundle validates one release and renders its versioned document. Fields
// the release leaves empty are filled from the mock's own scope, because a
// gateway rejects a policy bound to another scope.
func (s *Server) buildBundle(release Release) (gogw.BundleDocument, []byte, error) {
	var document gogw.BundleDocument
	if !validText(release.ReleaseID) || len(release.ReleaseID) > maxIdentifierSize {
		return document, nil, fmt.Errorf("%w: invalid release id", ErrOptions)
	}
	if release.Generation == 0 {
		return document, nil, fmt.Errorf("%w: release generation must be positive", ErrOptions)
	}
	if !validText(release.Flag) || len(release.Flag) > maxIdentifierSize {
		return document, nil, fmt.Errorf("%w: invalid flag", ErrOptions)
	}
	if len(release.Builds) == 0 || len(release.Builds) > 64 {
		return document, nil, fmt.Errorf("%w: a release needs between 1 and 64 builds", ErrOptions)
	}
	for name, build := range release.Builds {
		if !validText(name) || len(name) > maxIdentifierSize {
			return document, nil, fmt.Errorf("%w: invalid build name", ErrOptions)
		}
		if build.ImageDigest != "" {
			raw, err := hex.DecodeString(build.ImageDigest)
			if err != nil || len(raw) != sha256.Size || build.ImageDigest != strings.ToLower(build.ImageDigest) {
				return document, nil, fmt.Errorf("%w: invalid image digest for build %q", ErrOptions, name)
			}
		}
	}
	if _, ok := release.Builds[release.DefaultBuild]; !ok {
		return document, nil, fmt.Errorf("%w: default build %q is not described", ErrOptions, release.DefaultBuild)
	}
	if ramp := release.Ramp; ramp != nil {
		if !validText(ramp.Key) || ramp.Threshold < 0 || ramp.Threshold > bucketing.Buckets || len(ramp.Salt) > model.MaxSaltLen || ramp.Unit == "" || ramp.CanaryBuild == release.DefaultBuild {
			return document, nil, fmt.Errorf("%w: invalid ramp", ErrOptions)
		}
		if _, ok := release.Builds[ramp.CanaryBuild]; !ok {
			return document, nil, fmt.Errorf("%w: canary build %q is not described", ErrOptions, ramp.CanaryBuild)
		}
	}
	if release.MinimumProtocolVersion > agentv1.ProtocolMajor {
		return document, nil, fmt.Errorf("%w: minimum protocol version %d exceeds the protocol this mock speaks", ErrOptions, release.MinimumProtocolVersion)
	}
	policy := release.Policy
	if policy.Workspace == "" {
		policy.Workspace = s.scope.WorkspaceID
	}
	if policy.Environment == "" {
		policy.Environment = s.scope.EnvironmentID
	}
	if policy.Workspace != s.scope.WorkspaceID || policy.Environment != s.scope.EnvironmentID {
		return document, nil, fmt.Errorf("%w: policy scope does not match the mock scope", ErrOptions)
	}
	if policy.ManifestRevision <= 0 {
		policy.ManifestRevision = int64(release.Generation)
	}
	maxAge := release.DiscoveryMaxAgeSeconds
	if maxAge <= 0 {
		maxAge = defaultDiscoveryMaxAge
	}
	document = gogw.BundleDocument{
		Schema:                 documentSchema,
		ReleaseID:              release.ReleaseID,
		Generation:             release.Generation,
		Flag:                   release.Flag,
		DefaultBuild:           release.DefaultBuild,
		Builds:                 release.Builds,
		Ramp:                   release.Ramp,
		Policy:                 policy,
		MinimumProtocolVersion: release.MinimumProtocolVersion,
		DiscoveryMaxAgeSeconds: maxAge,
		// The mock publishes one document per release and has no separate policy
		// refresh contract, so the policy window follows the membership window it
		// already advertises.
		PolicyMaxAgeSeconds: maxAge,
	}
	payload, err := json.Marshal(document, json.Deterministic(true))
	if err != nil {
		return document, nil, fmt.Errorf("mock: encoding bundle document: %w", err)
	}
	return document, payload, nil
}

// PublishBundle signs one release as an immutable bundle resource. The bundle is
// self-addressed: its resource key is derived from the payload digest, so a
// republication of identical content returns the stored resource unchanged.
func (s *Server) PublishBundle(release Release) (Resource, error) {
	_, payload, err := s.buildBundle(release)
	if err != nil {
		return Resource{}, err
	}
	hash := sha256.Sum256(payload)
	return s.publish(agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, gogw.BundleKey(hash), payload, PublishOptions{
		Revision:  release.Generation,
		ExpiresIn: defaultExpiresIn,
	})
}

// PublishDiscovery signs the membership artifact of one bundle. The revision is
// the caller's to advance; a lower one is rejected so a gateway watermark never
// sees a rollback. Members missing identifiers a gateway requires are completed
// here, and an unobservable certificate digest keeps a stable placeholder.
func (s *Server) PublishDiscovery(bundleHash [32]byte, revision uint64, ttl time.Duration, members []gogw.Member) (Resource, error) {
	if revision == 0 {
		return Resource{}, fmt.Errorf("%w: discovery revision must be positive", ErrOptions)
	}
	if ttl <= 0 {
		ttl = defaultExpiresIn
	}
	if len(members) > maxDiscoveryMembers {
		return Resource{}, fmt.Errorf("%w: too many discovery members", ErrOptions)
	}
	normalized := make([]gogw.Member, 0, len(members))
	seen := make(map[string]bool, len(members))
	for _, member := range members {
		member = normalizeMember(member, bundleHash)
		if err := validateMember(member, bundleHash); err != nil {
			return Resource{}, err
		}
		if seen[member.InstanceID] {
			return Resource{}, fmt.Errorf("%w: duplicate discovery member %q", ErrOptions, member.InstanceID)
		}
		seen[member.InstanceID] = true
		normalized = append(normalized, member)
	}
	document := gogw.DiscoveryDocument{
		Schema:        documentSchema,
		BundleHash:    hex.EncodeToString(bundleHash[:]),
		Revision:      revision,
		ExpiresUnixMs: s.now().Add(ttl).UnixMilli(),
		Members:       normalized,
	}
	payload, err := json.Marshal(document, json.Deterministic(true))
	if err != nil {
		return Resource{}, fmt.Errorf("mock: encoding discovery document: %w", err)
	}
	return s.publish(agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY, gogw.DiscoveryKey(bundleHash), payload, PublishOptions{
		Revision:   revision,
		ExpiresIn:  ttl,
		BundleHash: bundleHash,
	})
}

// PublishRevocation signs the cumulative revocation state. The epoch only ever
// advances; the digest set is a union, so an older document can never resurrect
// a revoked bundle. With cancelActiveStreams the sessions prepared on a revoked
// bundle are disconnected as well.
func (s *Server) PublishRevocation(epoch uint64, ttl time.Duration, cancelActiveStreams bool, revoked ...[32]byte) (Resource, error) {
	if epoch == 0 {
		return Resource{}, fmt.Errorf("%w: revocation epoch must be positive", ErrOptions)
	}
	if ttl <= 0 {
		ttl = defaultExpiresIn
	}
	s.mu.Lock()
	if epoch <= s.revEpoch {
		current := s.revEpoch
		s.mu.Unlock()
		return Resource{}, fmt.Errorf("%w: revocation epoch %d is already current", ErrRevision, current)
	}
	union := make(map[[32]byte]bool, len(s.revoked)+len(revoked))
	for hash := range s.revoked {
		union[hash] = true
	}
	for _, hash := range revoked {
		if hash == ([32]byte{}) {
			s.mu.Unlock()
			return Resource{}, fmt.Errorf("%w: empty revoked bundle hash", ErrOptions)
		}
		union[hash] = true
	}
	s.mu.Unlock()
	hashes := make([]string, 0, len(union))
	for hash := range union {
		hashes = append(hashes, hex.EncodeToString(hash[:]))
	}
	slices.Sort(hashes)
	document := gogw.RevocationDocument{
		Schema:              documentSchema,
		Epoch:               epoch,
		BundleHashes:        hashes,
		CancelActiveStreams: cancelActiveStreams,
		ExpiresUnixMs:       s.now().Add(ttl).UnixMilli(),
	}
	payload, err := json.Marshal(document, json.Deterministic(true))
	if err != nil {
		return Resource{}, fmt.Errorf("mock: encoding revocation document: %w", err)
	}
	resource, err := s.publish(agentv1.ResourceKind_RESOURCE_KIND_REVOCATION, gogw.RevocationKey, payload, PublishOptions{Revision: epoch, ExpiresIn: ttl})
	if err != nil {
		return Resource{}, err
	}
	s.mu.Lock()
	for hash := range union {
		s.revoked[hash] = true
	}
	s.revEpoch = epoch
	sessions := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	// An instance prepared on a revoked bundle is the one holding a stream that
	// must be canceled, so it is tracked by session rather than by instance.
	preparedOnRevoked := make(map[string]bool)
	for _, inst := range s.instances {
		if inst.PreparedHash == "" || !union[digestOf(inst.PreparedHash)] {
			continue
		}
		if inst.session != "" {
			preparedOnRevoked[inst.session] = true
		}
	}
	var live []string
	for hash := range union {
		key := gogw.BundleKey(hash)
		if _, ok := s.resources[resourceID{kind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, key: key}]; ok {
			live = append(live, key)
		}
	}
	s.mu.Unlock()
	// The resource is withdrawn and the command is sent separately: a gateway
	// that ignores Invalidated still cannot miss the revocation itself.
	for _, key := range live {
		s.invalidate(agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, key)
	}
	for _, sess := range sessions {
		sess.revoke(epoch, hashes, cancelActiveStreams && preparedOnRevoked[sess.id])
	}
	return resource, nil
}

// Members synthesizes the candidate members of one bundle from the registry and
// the prepared evidence it holds. A member without evidence is still listed: the
// evidence is a filter for the consumer, not a membership decision, and its
// absence is exactly what a rollout under test must tolerate.
func (s *Server) Members(bundleHash [32]byte) []gogw.Member {
	now := s.now().UnixMilli()
	hash := hex.EncodeToString(bundleHash[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	members := make([]gogw.Member, 0, len(s.instances))
	for _, instanceID := range slices.Sorted(maps.Keys(s.instances)) {
		inst := s.instances[instanceID]
		if inst.LeaseExpiresUnixMs <= now {
			continue
		}
		member := gogw.Member{
			InstanceID:         inst.InstanceID,
			BootID:             inst.BootID,
			BuildID:            inst.BuildID,
			ImageDigest:        inst.imageDigest,
			URL:                instanceURL(inst),
			TLSServerName:      inst.tlsServerName,
			Zone:               inst.zone,
			ProtocolVersion:    inst.protocolVersion,
			Ready:              inst.Ready,
			Draining:           inst.Draining,
			LeaseEpoch:         inst.LeaseEpoch,
			LeaseExpiresUnixMs: inst.LeaseExpiresUnixMs,
		}
		if inst.preparedRelease != nil && inst.preparedRelease.GetBundleHash() == hash &&
			inst.PreparedExpiresUnixMs > now && !s.faults.IgnorePrepared {
			member.Prepared = &gogw.PreparedEvidence{
				BundleHash:       hash,
				Generation:       inst.PreparedGeneration,
				PreparedRevision: inst.preparedPolicy,
				ExpiresUnixMs:    inst.PreparedExpiresUnixMs,
			}
		}
		members = append(members, normalizeMember(member, bundleHash))
	}
	return members
}

// OverlayMembers replaces the address and certificate identity of every member
// the given overrides name, in the order the registry produced them. A control
// plane cannot observe a gateway's served certificate, so a release file
// supplies it for the mock. An override that names no registered instance is
// appended: it is an authored endpoint, which is how a scenario publishes
// membership for an instance that never connects.
func OverlayMembers(members []gogw.Member, overrides []gogw.Member) []gogw.Member {
	if len(overrides) == 0 {
		return members
	}
	byInstance := make(map[string]gogw.Member, len(overrides))
	for _, override := range overrides {
		byInstance[override.InstanceID] = override
	}
	merged := make([]gogw.Member, 0, len(members)+len(overrides))
	merged = append(merged, members...)
	for i, member := range merged {
		override, ok := byInstance[member.InstanceID]
		if !ok {
			continue
		}
		delete(byInstance, member.InstanceID)
		if override.URL != "" {
			merged[i].URL = override.URL
		}
		if override.TLSServerName != "" {
			merged[i].TLSServerName = override.TLSServerName
		}
		if override.Zone != "" {
			merged[i].Zone = override.Zone
		}
		if override.Certificate.SHA256 != "" {
			merged[i].Certificate = override.Certificate
		}
	}
	for _, override := range overrides {
		if _, ok := byInstance[override.InstanceID]; ok {
			merged = append(merged, override)
		}
	}
	return merged
}

// Prepare sends one Prepare command to an instance's live session. The bundle
// must be downloadable, because the command carries a reference only.
func (s *Server) Prepare(instanceID string, bundle Resource, deadline time.Duration) error {
	if deadline <= 0 {
		deadline = defaultPrepareTimeout
	}
	s.mu.Lock()
	rec := s.recordOf(bundle.Kind, bundle.Key)
	if rec == nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: bundle %q", ErrUnknown, bundle.Key)
	}
	identity, err := releaseIdentity(rec)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	ref := s.resourceRef(rec)
	inst, ok := s.instances[instanceID]
	var sess *session
	if ok {
		sess = s.sessions[inst.session]
	}
	expires := s.now().Add(deadline).UnixMilli()
	s.mu.Unlock()
	if ref == nil {
		return fmt.Errorf("%w: bundle %q has no download address", ErrUnavailable, bundle.Key)
	}
	if !ok {
		return fmt.Errorf("%w: instance %q", ErrUnknown, instanceID)
	}
	if sess == nil {
		return fmt.Errorf("%w: instance %q has no session", ErrUnavailable, instanceID)
	}
	body := sess.newEnvelope()
	body.OperationId = uuid.New().String()
	body.Payload = &agentv1.Envelope_Prepare{Prepare: &agentv1.Prepare{Release: identity, Bundle: ref, ExpiresUnixMs: expires}}
	sess.enqueue(body, false)
	return nil
}

// Activate sends the activation of an already prepared release, which is how a
// withheld activation is triggered manually.
func (s *Server) Activate(instanceID string) error {
	s.mu.Lock()
	inst, ok := s.instances[instanceID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: instance %q", ErrUnknown, instanceID)
	}
	if inst.preparedRelease == nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: instance %q has not prepared a release", ErrUnavailable, instanceID)
	}
	release := proto.Clone(inst.preparedRelease).(*agentv1.ReleaseIdentity)
	prepared := inst.preparedPolicy
	sess := s.sessions[inst.session]
	revoked := s.revoked[digestOf(release.GetBundleHash())]
	s.mu.Unlock()
	if revoked {
		return fmt.Errorf("%w: release %q", ErrRevoked, release.GetReleaseId())
	}
	if sess == nil {
		return fmt.Errorf("%w: instance %q has no session", ErrUnavailable, instanceID)
	}
	sess.enqueue(activateEnvelope(sess, release, prepared), false)
	return nil
}

// Abort tells an instance to discard a prepared release.
func (s *Server) Abort(instanceID, reason string) error {
	s.mu.Lock()
	inst, ok := s.instances[instanceID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: instance %q", ErrUnknown, instanceID)
	}
	release := proto.Clone(inst.preparedRelease).(*agentv1.ReleaseIdentity)
	if release == nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: instance %q has no release to abort", ErrUnavailable, instanceID)
	}
	sess := s.sessions[inst.session]
	s.mu.Unlock()
	if sess == nil {
		return fmt.Errorf("%w: instance %q has no session", ErrUnavailable, instanceID)
	}
	body := sess.newEnvelope()
	body.OperationId = uuid.New().String()
	body.Payload = &agentv1.Envelope_Abort{Abort: &agentv1.Abort{Release: release, Reason: reason}}
	sess.enqueue(body, false)
	return nil
}

// Drain asks an instance to stop accepting new streams and to close the ones it
// holds after the grace period. The mock marks the instance draining at once so
// the discovery artifact stops advertising it as ready.
func (s *Server) Drain(instanceID string) error {
	s.mu.Lock()
	inst, ok := s.instances[instanceID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: instance %q", ErrUnknown, instanceID)
	}
	inst.Draining = true
	sess := s.sessions[inst.session]
	now := s.now()
	s.mu.Unlock()
	if sess == nil {
		return fmt.Errorf("%w: instance %q has no session", ErrUnavailable, instanceID)
	}
	body := sess.newEnvelope()
	body.OperationId = uuid.New().String()
	body.Payload = &agentv1.Envelope_DrainRequested{DrainRequested: &agentv1.DrainRequested{
		StopAcceptingUnixMs: now.UnixMilli(),
		ForceCloseUnixMs:    now.Add(defaultDrainGrace).UnixMilli(),
	}}
	sess.enqueue(body, false)
	return nil
}

// notePrepared records prepared evidence and reports whether the report moved
// the state forward. A replay or an out-of-order report is absorbed here, so a
// stale message can never un-prepare a newer release.
func (inst *instance) notePrepared(release *agentv1.ReleaseIdentity, bootID, buildID string, expiresUnixMs int64, policyRevision uint64) bool {
	if release.GetGeneration() == 0 || release.GetBundleHash() == "" {
		return false
	}
	if inst.PreparedGeneration != 0 && release.GetGeneration() < inst.PreparedGeneration {
		return false
	}
	if bootID != "" {
		inst.BootID = bootID
	}
	if buildID != "" {
		inst.BuildID = buildID
	}
	if policyRevision == 0 {
		policyRevision = release.GetGeneration()
	}
	inst.PreparedHash = release.GetBundleHash()
	inst.PreparedGeneration = release.GetGeneration()
	inst.PreparedExpiresUnixMs = expiresUnixMs
	inst.preparedPolicy = policyRevision
	inst.preparedRelease = proto.Clone(release).(*agentv1.ReleaseIdentity)
	return true
}

// noteApplied records an activation result and reports whether it advanced. Only
// a newer generation, or a newer revision of the same generation, is accepted.
func (inst *instance) noteApplied(release *agentv1.ReleaseIdentity, bootID string, policyRevision uint64) bool {
	if release.GetGeneration() == 0 {
		return false
	}
	if release.GetGeneration() < inst.AppliedGeneration {
		return false
	}
	if release.GetGeneration() == inst.AppliedGeneration && policyRevision != 0 && policyRevision < inst.AppliedRevision {
		return false
	}
	if bootID != "" {
		inst.BootID = bootID
	}
	inst.AppliedGeneration = release.GetGeneration()
	inst.AppliedRevision = policyRevision
	inst.appliedRelease = proto.Clone(release).(*agentv1.ReleaseIdentity)
	inst.RejectedCode = ""
	return true
}

// noteRejected records a rejection and reports whether it advanced. A rejection
// of a release this instance already applied is ignored, because the mock's view
// must not regress to a state the instance has moved past.
func (inst *instance) noteRejected(release *agentv1.ReleaseIdentity, code string) bool {
	if release.GetGeneration() == 0 || release.GetGeneration() < inst.AppliedGeneration {
		return false
	}
	inst.rejectedRelease = proto.Clone(release).(*agentv1.ReleaseIdentity)
	inst.RejectedCode = code
	return true
}

// bundleRevisionLocked reports the live revision of one bundle resource, or zero
// when the bundle is not published.
func (s *Server) bundleRevisionLocked(bundleHash string) uint64 {
	key := gogw.BundleKey(digestOf(bundleHash))
	if rec := s.resources[resourceID{kind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, key: key}]; rec != nil {
		return rec.revision
	}
	return 0
}

// discoveryRevisionLocked reports the live revision of the discovery artifact of
// one bundle, which is what tells a registering instance how current its
// membership view is. The caller must hold Server.mu.
func (s *Server) discoveryRevisionLocked(bundleHash string) uint64 {
	key := gogw.DiscoveryKey(digestOf(bundleHash))
	if rec := s.resources[resourceID{kind: agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY, key: key}]; rec != nil {
		return rec.revision
	}
	return 0
}

// releaseIdentity decodes the release a bundle resource announces. The mock
// rendered the payload itself, so the document is trusted here.
func releaseIdentity(rec *record) (*agentv1.ReleaseIdentity, error) {
	if rec.id.kind != agentv1.ResourceKind_RESOURCE_KIND_BUNDLE {
		return nil, fmt.Errorf("%w: %q is not a bundle", ErrOptions, rec.id.key)
	}
	var document gogw.BundleDocument
	if err := json.Unmarshal(rec.payload, &document); err != nil {
		return nil, fmt.Errorf("mock: invalid bundle payload: %w", err)
	}
	return &agentv1.ReleaseIdentity{
		ReleaseId:  document.ReleaseID,
		Generation: document.Generation,
		BundleHash: hex.EncodeToString(rec.hash[:]),
	}, nil
}

// activateEnvelope builds one Activate command for a prepared instance. The mock
// publishes one revision per bundle, so the policy revision and the prepared
// revision an instance reports back are the same number.
func activateEnvelope(sess *session, release *agentv1.ReleaseIdentity, preparedRevision uint64) *agentv1.Envelope {
	body := sess.newEnvelope()
	body.OperationId = uuid.New().String()
	body.Payload = &agentv1.Envelope_Activate{Activate: &agentv1.Activate{
		Release:          release,
		PolicyRevision:   preparedRevision,
		PreparedRevision: preparedRevision,
	}}
	return body
}

// releaseStatus aggregates what instances reported about one release. Every
// field is derived from a report: the mock never invents an applied instance,
// and a release with no reports is only VALIDATED.
func (s *Server) releaseStatus(releaseID string) *agentv1.ReleaseStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := &agentv1.ReleaseStatus{Release: &agentv1.ReleaseIdentity{ReleaseId: releaseID}}
	applied, rejected, prepared := 0, 0, 0
	for _, instanceID := range slices.Sorted(maps.Keys(s.instances)) {
		inst := s.instances[instanceID]
		if identity := inst.preparedRelease; identity != nil && identity.GetReleaseId() == releaseID {
			if status.GetRelease().GetGeneration() == 0 {
				status.Release.Generation = identity.GetGeneration()
				status.Release.BundleHash = identity.GetBundleHash()
			}
			if inst.AppliedGeneration < identity.GetGeneration() {
				prepared++
			}
		}
		if identity := inst.appliedRelease; identity != nil && identity.GetReleaseId() == releaseID {
			applied++
			status.Applied = append(status.Applied, &agentv1.Applied{
				Release:          proto.Clone(identity).(*agentv1.ReleaseIdentity),
				InstanceId:       inst.InstanceID,
				BootId:           inst.BootID,
				PolicyRevision:   inst.AppliedRevision,
				PreparedRevision: inst.preparedPolicy,
				RevocationEpoch:  s.revEpoch,
			})
		}
		if identity := inst.rejectedRelease; identity != nil && identity.GetReleaseId() == releaseID && inst.RejectedCode != "" && inst.AppliedGeneration < identity.GetGeneration() {
			rejected++
			status.Rejected = append(status.Rejected, &agentv1.Rejected{
				Release: proto.Clone(identity).(*agentv1.ReleaseIdentity),
				Error:   &agentv1.Error{Code: errorCodeOf(inst.RejectedCode), Reason: inst.RejectedCode},
			})
		}
	}
	switch {
	case applied > 0 && rejected == 0:
		status.State = agentv1.ReleaseState_RELEASE_STATE_ACTIVE
	case applied > 0:
		status.State = agentv1.ReleaseState_RELEASE_STATE_VERIFYING
	case rejected > 0:
		status.State = agentv1.ReleaseState_RELEASE_STATE_FAILED
	case prepared > 0:
		status.State = agentv1.ReleaseState_RELEASE_STATE_PREPARED
	default:
		status.State = agentv1.ReleaseState_RELEASE_STATE_VALIDATED
	}
	return status
}

// normalizeMember completes one member with the identifiers a gateway requires
// and a stable placeholder for the certificate it cannot observe. A release
// file overlays the real digest before publication.
func normalizeMember(member gogw.Member, bundleHash [32]byte) gogw.Member {
	if member.TLSServerName == "" {
		member.TLSServerName = hostOf(member.URL)
	}
	if member.TLSServerName == "" {
		member.TLSServerName = member.InstanceID
	}
	if member.Certificate.SHA256 == "" {
		sum := sha256.Sum256([]byte("mock-certificate\x00" + member.InstanceID + "\x00" + member.BootID))
		member.Certificate.SHA256 = hex.EncodeToString(sum[:])
	}
	if member.ProtocolVersion == 0 {
		member.ProtocolVersion = agentv1.ProtocolMajor
	}
	if member.Prepared != nil {
		if member.Prepared.BundleHash == "" {
			member.Prepared.BundleHash = hex.EncodeToString(bundleHash[:])
		}
		if member.Prepared.PreparedRevision == 0 {
			member.Prepared.PreparedRevision = member.Prepared.Generation
		}
		if member.Prepared.Generation == 0 {
			member.Prepared.Generation = member.Prepared.PreparedRevision
		}
	}
	return member
}

// validateMember rejects a member a gateway would refuse to dispatch to.
func validateMember(member gogw.Member, bundleHash [32]byte) error {
	hash := hex.EncodeToString(bundleHash[:])
	for _, field := range []struct {
		name  string
		value string
	}{
		{"instance id", member.InstanceID},
		{"boot id", member.BootID},
		{"build id", member.BuildID},
		{"tls server name", member.TLSServerName},
	} {
		if !validText(field.value) || len(field.value) > maxIdentifierSize {
			return fmt.Errorf("%w: invalid discovery member %s", ErrOptions, field.name)
		}
	}
	if member.Zone != "" && (!validText(member.Zone) || len(member.Zone) > maxIdentifierSize) {
		return fmt.Errorf("%w: invalid discovery member zone", ErrOptions)
	}
	if !digestString(member.Certificate.SHA256) {
		return fmt.Errorf("%w: invalid discovery member certificate digest", ErrOptions)
	}
	if previous := member.Certificate.PreviousSHA256; previous != "" {
		if !digestString(previous) || member.Certificate.PreviousValidUntilUnixMs <= 0 {
			return fmt.Errorf("%w: invalid discovery member certificate overlap", ErrOptions)
		}
	}
	if prepared := member.Prepared; prepared != nil {
		if prepared.BundleHash != hash || prepared.Generation == 0 || prepared.PreparedRevision == 0 {
			return fmt.Errorf("%w: prepared evidence does not match the discovery bundle", ErrOptions)
		}
	}
	if member.URL != "" {
		target, err := url.Parse(member.URL)
		if err != nil || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || (target.Scheme != "https" && target.Scheme != "http") {
			return fmt.Errorf("%w: invalid discovery member url %q", ErrOptions, member.URL)
		}
	}
	return nil
}

// instanceURL renders the address an instance registered, defaulting to the
// scheme a gateway serves.
func instanceURL(inst *instance) string {
	if inst.address == "" {
		return ""
	}
	if inst.port == 0 || strings.Contains(inst.address, ":") {
		return "https://" + inst.address
	}
	return "https://" + net.JoinHostPort(inst.address, strconv.Itoa(int(inst.port)))
}

// hostOf extracts a bare host name from a URL, which is what a TLS server name
// must be; a port never belongs in it.
func hostOf(raw string) string {
	if raw == "" {
		return ""
	}
	target, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return target.Hostname()
}

// digestString reports whether a value is a lowercase SHA-256 digest.
func digestString(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && value == strings.ToLower(value)
}

// digestOf decodes a hexadecimal bundle hash, tolerating an invalid one by
// returning the zero digest, which never matches a registered revocation.
func digestOf(value string) [32]byte {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != sha256.Size {
		return [32]byte{}
	}
	var digest [32]byte
	copy(digest[:], raw)
	return digest
}

// errorCodeOf maps a recorded rejection reason back to a protocol code.
func errorCodeOf(value string) agentv1.ErrorCode {
	if code, ok := agentv1.ErrorCode_value[value]; ok {
		return agentv1.ErrorCode(code)
	}
	return agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
}
