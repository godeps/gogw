package gogw_test

// gateway_test.go covers the lifecycle requirements: registration, lease
// renewal, control-plane outage and recovery, the Prepare/Activate/Abort state
// machine, persisted activation, revocation, release rollback, certificate and
// trust-key rotation, draining and shutdown.
//
// Every assertion here is on an observable of the running system — a response, a
// diagnostic, a message the control plane recorded — never on an internal flag,
// so a test cannot pass because it agrees with the implementation.

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/gogw"
	"github.com/traefik/traefik/v3/pkg/gogw/mock"
)

// withTTL narrows the validity of a release, which bounds how long a gateway may
// keep serving it after the control plane became unreachable.
func withTTL(release mock.Release, seconds int64) mock.Release {
	release.DiscoveryMaxAgeSeconds = seconds
	return release
}

// subject is one authenticated principal of a population large enough to show
// that the metric label space does not grow with it.
func subject(index int) string { return "subject-" + strconv.Itoa(index) }

func tenant(index int) string { return "tenant-" + strconv.Itoa(index) }

// signingKey mints one release signing key, for the rotation cases.
func signingKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key
}

// revokeAs publishes one cumulative revocation document signed by an arbitrary
// key, which is how a test exercises the trust a control plane must hold. The
// revision is the caller's, so a document can be delivered with a newer revision
// and an older epoch — the rollback a gateway has to refuse.
func (c *cluster) revokeAs(t *testing.T, keyID string, key ed25519.PrivateKey, epoch, revision uint64, hashes ...string) {
	t.Helper()
	document := gogw.RevocationDocument{
		Schema: 1, Epoch: epoch, BundleHashes: hashes,
		ExpiresUnixMs: time.Now().Add(time.Hour).UnixMilli(),
	}
	payload, err := json.Marshal(document)
	require.NoError(t, err)
	_, err = c.control.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_REVOCATION, gogw.RevocationKey, payload, mock.PublishOptions{
		Revision: revision, KeyID: keyID, SigningKey: key,
	})
	require.NoError(t, err)
}

// TestRegistrationReadinessAndEligibility separates eligibility from readiness:
// an instance that reached the control plane is a candidate the control plane may
// select, while readiness is this instance claiming it can serve a release.
func TestRegistrationReadinessAndEligibility(t *testing.T) {
	c := newCluster(t)
	c.awaitRegistered(t)

	state, ok := c.control.Instance("stable-0")
	require.True(t, ok)
	assert.Positive(t, state.LeaseEpoch)
	assert.Greater(t, state.LeaseExpiresUnixMs, time.Now().UnixMilli())

	// The control plane selects candidates by the readiness report, so an
	// instance that can serve must also say so.
	await(t, "the readiness report of stable-0", func() bool {
		state, ok := c.control.Instance("stable-0")
		return ok && state.Ready
	})
	report := c.members[0].gateway.Diagnostics()
	assert.True(t, report.Registered)
	assert.True(t, report.Eligible)
	assert.Empty(t, report.EligibleReason)
	assert.True(t, report.Healthy)

	// No release has been approved, so nothing may be served yet.
	assert.False(t, report.Ready)
	assert.Equal(t, "NO_RUNTIME_VIEW", report.ReadyReason)
	assert.Zero(t, report.Generation)
	assert.Empty(t, report.BundleHash)

	ready := c.raw(t, 0, http.MethodGet, "/__gogw/ready", nil)
	assert.Equal(t, http.StatusServiceUnavailable, ready.StatusCode)
	assert.Equal(t, "NOT_READY\n", body(t, ready))

	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
	assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
	assert.Equal(t, "NO_RUNTIME_VIEW\n", body(t, response))

	published := c.activate(t, release(1, nil, nil))
	report = c.members[0].gateway.Diagnostics()
	assert.True(t, report.Ready)
	assert.Empty(t, report.ReadyReason)
	assert.Equal(t, uint64(1), report.Generation)
	assert.Equal(t, published.hash, report.BundleHash)
	assert.Equal(t, "release-1", report.ReleaseID)
	assert.Positive(t, report.Members)

	ready = c.raw(t, 0, http.MethodGet, "/__gogw/ready", nil)
	assert.Equal(t, http.StatusNoContent, ready.StatusCode)
	assert.Empty(t, body(t, ready))
}

// TestStartupWithoutControlPlane proves an instance that never reached the
// control plane stays isolated: it holds no lease, so it must not serve, and it
// must not claim readiness while it is still reconnecting.
func TestStartupWithoutControlPlane(t *testing.T) {
	c := newCluster(t, withOfflineControlPlane())

	report := c.members[0].gateway.Diagnostics()
	assert.False(t, report.Registered)
	assert.False(t, report.Eligible)
	assert.Equal(t, "CONTROL_PLANE_CONNECTING", report.EligibleReason)
	assert.False(t, report.Ready)

	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
	assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
	assert.Equal(t, "NO_RUNTIME_VIEW\n", body(t, response))

	ready := c.raw(t, 0, http.MethodGet, "/__gogw/ready", nil)
	assert.Equal(t, http.StatusServiceUnavailable, ready.StatusCode)
	body(t, ready)

	// Everything the instance needs arrives through the session, so the rollout
	// is driven only after the control plane is routable again.
	c.relay.restore()
	c.activate(t, release(1, nil, nil))
	assert.True(t, c.members[0].gateway.Ready())
}

// TestControlOutageAndExpiry covers the two distinct windows of an outage: the
// instance withdraws eligibility at once, but the approved release stays servable
// until it expires, and then it is refused as well.
func TestControlOutageAndExpiry(t *testing.T) {
	c := newCluster(t)
	published := c.activate(t, withTTL(release(1, nil, nil), 6))

	c.relay.cut()

	// Readiness is fail-closed: an instance that cannot renew its lease must not
	// be selected for new traffic.
	await(t, "the withdrawn eligibility", func() bool {
		return !c.members[0].gateway.Diagnostics().Eligible
	})
	report := c.members[0].gateway.Diagnostics()
	assert.Contains(t, []string{"CONTROL_PLANE_CONNECTING", "CONTROL_PLANE_CLOSED", "LEASE_EXPIRED"}, report.EligibleReason)
	assert.False(t, report.Ready)
	ready := c.raw(t, 0, http.MethodGet, "/__gogw/ready", nil)
	assert.Equal(t, http.StatusServiceUnavailable, ready.StatusCode)
	body(t, ready)

	// The approved release is still valid, so traffic that was already routed here
	// is served from it instead of being dropped mid-flight.
	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "stable", response.Header.Get("X-Actual-Build"))
	body(t, response)

	// Offline validity is bounded: once the approved release expires the instance
	// refuses traffic rather than serving a policy the control plane can no longer
	// confirm. The readiness reason names the outage for as long as it lasts —
	// eligibility is withdrawn already — so the expiry is observed where it acts,
	// on the traffic, and on the instant the diagnostics report for it.
	var status int
	var refusal string
	require.Positive(t, report.PolicyExpiresUnixMs)
	await(t, "the expired release", func() bool {
		response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
		status, refusal = response.StatusCode, body(t, response)
		return status == http.StatusServiceUnavailable && refusal == "POLICY_EXPIRED\n"
	})
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "POLICY_EXPIRED\n", refusal)
	assert.LessOrEqual(t, c.members[0].gateway.Diagnostics().PolicyExpiresUnixMs, time.Now().UnixMilli())

	// A reconnect is a new session rather than a wake-up: the instance registers
	// again, reads the published state again, and renews the lease it was given, so
	// the control plane holds a live registration instead of the record of one that
	// went quiet. The rollout then continues where it stopped.
	mark := len(c.control.Journal())
	c.relay.restore()
	await(t, "re-registration", func() bool {
		report := c.members[0].gateway.Diagnostics()
		return report.Registered && report.Eligible
	})
	assert.True(t, c.journalContains("Register", "stable-0"))
	await(t, "the renewed lease of the new session", func() bool {
		return slices.ContainsFunc(c.journalSince(mark), func(entry mock.Entry) bool {
			return entry.Kind == "RenewLease" && entry.InstanceID == "stable-0"
		})
	})

	second := c.activate(t, release(2, nil, nil))
	assert.NotEqual(t, published.hash, second.hash)
	assert.Equal(t, uint64(2), c.members[0].gateway.Diagnostics().Generation)
}

// TestDiscoveryExpiryStopsServingWithoutPolicyExpiry separates the two offline
// validities: an expired membership artifact refuses new traffic with
// DISCOVERY_EXPIRED while the release policy the instance already holds is still
// valid, so an operator reading the refusal learns which artifact went stale.
func TestDiscoveryExpiryStopsServingWithoutPolicyExpiry(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	// The release carries a ten-minute policy; only the membership is short-lived,
	// which is what a control plane that stopped republishing looks like.
	c.publishMembership(t, 2*time.Second)
	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "tenant", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	body(t, response)

	var status int
	var refusal string
	await(t, "the expired membership", func() bool {
		response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "tenant", nil)
		status, refusal = response.StatusCode, body(t, response)
		return status == http.StatusServiceUnavailable && refusal == "DISCOVERY_EXPIRED\n"
	})
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "DISCOVERY_EXPIRED\n", refusal)
	assert.Greater(t, c.members[0].gateway.Diagnostics().PolicyExpiresUnixMs, time.Now().UnixMilli())
	assert.False(t, c.members[0].gateway.Ready())

	// A republished membership restores service without a new release, which is
	// what makes the expiry a validity window rather than a revocation.
	c.membership(t)
	c.awaitServing(t)
	response = c.request(t, 0, http.MethodGet, "/orders", "user-1", "tenant", nil)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	body(t, response)
}

// TestPrepareActivateAbortStateMachine drives the three commands explicitly and
// asserts what each one is allowed to change.
func TestPrepareActivateAbortStateMachine(t *testing.T) {
	c := newCluster(t)
	// The activation is withheld so the test decides when it happens: a prepared
	// release that was never activated must not serve.
	c.control.SetFaults(mock.Faults{WithholdActivate: true})

	c.publish(t, release(1, nil, nil))
	c.prepare(t)
	c.membership(t)

	report := c.members[0].gateway.Diagnostics()
	assert.True(t, report.Prepared)
	assert.Equal(t, uint64(1), report.PreparedGeneration)
	assert.Positive(t, report.PreparedExpiresUnixMs)
	assert.Zero(t, report.Generation)
	assert.False(t, report.Ready)

	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
	assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
	assert.Equal(t, "NO_RUNTIME_VIEW\n", body(t, response))

	// Only an explicit Activate approves the release.
	for _, in := range c.members {
		require.NoError(t, c.control.Activate(in.name))
	}
	c.awaitServing(t)
	assert.True(t, c.members[0].gateway.Ready())

	// A prepared release is a candidate, not a right: aborting it must leave the
	// serving release untouched and must be reported to the control plane.
	c.publish(t, release(2, nil, nil))
	c.prepare(t)
	c.membership(t)
	require.NoError(t, c.control.Abort("stable-0", "rollout withdrawn"))
	await(t, "the abort of stable-0", func() bool {
		state, ok := c.control.Instance("stable-0")
		return ok && state.RejectedCode != ""
	})
	assert.True(t, c.journalContains("Rejected", ""))

	report = c.members[0].gateway.Diagnostics()
	assert.Equal(t, uint64(1), report.Generation)
	assert.True(t, report.Ready)
	assert.Equal(t, "release-1", c.members[0].gateway.Diagnostics().ReleaseID)

	// The abort withdrew the approval, not the release: a fresh activation is
	// still the control plane's call, and republication of identical content is
	// the same immutable bundle.
	c.control.SetFaults(mock.Faults{})
	c.activate(t, release(2, nil, nil))
	report = c.members[0].gateway.Diagnostics()
	assert.Equal(t, uint64(2), report.Generation)
	assert.Equal(t, c.last.hash, report.BundleHash)
	assert.True(t, report.Ready)
	assert.Positive(t, report.Operations)
}

// TestRestartReusesActivationWithoutRepublishing proves the persisted activation
// is enough to restore the release state, and that a restart restores nothing the
// control plane never confirmed to this process.
func TestRestartReusesActivationWithoutRepublishing(t *testing.T) {
	c := newCluster(t)
	published := c.activate(t, release(1, nil, nil))
	in := c.members[0]
	operations := in.gateway.Diagnostics().Operations
	require.Positive(t, operations)

	// With the control plane black-holed the only source of the release state is
	// the state file, so a restart that restored anything restored it from disk.
	c.relay.cut()
	in.stop(t)
	in.start(c.ctx, t)

	await(t, "the restored activation", func() bool {
		return in.gateway.Diagnostics().Generation == 1
	})
	report := in.gateway.Diagnostics()
	assert.Equal(t, published.hash, report.BundleHash)
	assert.Equal(t, "release-1", report.ReleaseID)
	assert.True(t, report.Prepared)
	assert.Equal(t, uint64(1), report.PreparedGeneration)
	assert.GreaterOrEqual(t, report.Operations, operations)
	assert.False(t, report.Eligible)

	// The release was never republished, so an instance that serves again did not
	// need the control plane to repeat itself.
	c.relay.restore()
	c.awaitServing(t)
	report = in.gateway.Diagnostics()
	assert.Equal(t, uint64(1), report.Generation)
	assert.True(t, report.Ready)
	assert.Equal(t, published.hash, report.BundleHash)
}

// TestRevocationIsPersistedAndIrreversible covers the revocation contract: a live
// stream is canceled, the release is withdrawn, a lower epoch is refused, and a
// restart cannot resurrect the revoked release.
func TestRevocationIsPersistedAndIrreversible(t *testing.T) {
	c := newCluster(t)
	published := c.activate(t, release(1, nil, nil))

	stream := c.stream(t, 0, "/sse", "user-1")
	assert.Equal(t, "stable", event(t, stream))

	// The control plane revokes the release that is serving and asks for its
	// active streams to be canceled.
	_, err := c.control.PublishRevocation(1, 10*time.Minute, true, published.bundle.Hash)
	require.NoError(t, err)

	select {
	case build := <-c.canceled:
		assert.Equal(t, "stable", build)
	case <-time.After(awaitTimeout):
		t.Fatal("the revoked release kept its stream open")
	}
	_ = stream.Body.Close()

	await(t, "the withdrawn release", func() bool {
		return c.members[0].gateway.Diagnostics().Generation == 0
	})
	report := c.members[0].gateway.Diagnostics()
	assert.Equal(t, uint64(1), report.RevocationEpoch)
	assert.Equal(t, 1, report.RevokedReleases)
	assert.False(t, report.Ready)

	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
	assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
	assert.Equal(t, "NO_RUNTIME_VIEW\n", body(t, response))

	// The epoch is cumulative and persisted, so a control plane that lost its own
	// state cannot roll it back.
	_, err = c.control.PublishRevocation(2, 10*time.Minute, false)
	require.NoError(t, err)
	await(t, "the persisted epoch", func() bool {
		return c.members[0].gateway.Diagnostics().RevocationEpoch == 2
	})

	// A lower epoch is a rollback, and it is reported instead of being silently
	// ignored. The document carries a newer revision than the one that set the
	// epoch, so only the persisted epoch can identify it as older.
	c.revokeAs(t, c.control.KeyID(), c.signing, 1, 3)
	await(t, "the refused rollback", func() bool {
		return c.journalContains("ResourceRejected", "")
	})
	assert.Equal(t, uint64(2), c.members[0].gateway.Diagnostics().RevocationEpoch)

	// A revoked release may not be offered again: the control plane withdrew the
	// bundle, so even a Prepare for it is refused before it reaches the instance.
	// The gate the instance owns — a control plane that announces the revocation
	// while still handing the release out — is covered in
	// TestRevokedReleaseIsRefusedWhenRedelivered, which is the case that needs one.
	require.ErrorIs(t, c.control.Prepare("stable-0", published.bundle, time.Minute), mock.ErrUnknown)
	report = c.members[0].gateway.Diagnostics()
	assert.Zero(t, report.Generation)
	assert.False(t, report.Ready)

	// A restart re-reads the persisted revocation before it re-reads the persisted
	// release, so the release is not restored even while the control plane is
	// unreachable and cannot correct it.
	c.relay.cut()
	in := c.members[0]
	in.stop(t)
	in.start(c.ctx, t)
	assert.True(t, settled(func() bool {
		report := in.gateway.Diagnostics()
		return report.RevocationEpoch == 2 && report.Generation == 0 && !report.Prepared && !report.Ready
	}), "the restart resurrected a revoked release")
}

// reofferBundle publishes one bundle payload again under a revision above the one
// the instance already holds, which is the only way a release the control plane
// has not withdrawn can be delivered a second time. The copy just published is
// returned, so a test can offer the same release yet again from the newest
// revision without the store seeing a rollback.
func (c *cluster) reofferBundle(t *testing.T, previous mock.Resource) (mock.Resource, uint64) {
	t.Helper()
	require.NotNil(t, previous.Ref)
	revision := previous.Ref.GetRevision() + 1
	resource, err := c.control.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, previous.Key,
		previous.Signed.GetPayload(), mock.PublishOptions{Revision: revision})
	require.NoError(t, err)
	return resource, revision
}

// TestRevokedReleaseIsRefusedWhenRedelivered covers the gate the instance owns
// instead of delegating to the control plane: a release it has revoked must be
// refused even while the control plane keeps offering it.
//
// The epoch is announced as a signed document rather than through the mock's
// PublishRevocation, which additionally withdraws the bundle and refuses to
// publish its payload again. A control plane that announces a revocation while its
// own store still hands the release out is the case the instance has to survive on
// its own, and it is the only case where the revocation set is what identifies the
// release.
func TestRevokedReleaseIsRefusedWhenRedelivered(t *testing.T) {
	c := newCluster(t)
	published := c.activate(t, release(1, nil, nil))

	// The control case comes first: the same re-delivery is accepted while the
	// release is not revoked, so the refusal below is the revocation and not the
	// fact that a release arrived a second time.
	mark := len(c.control.Journal())
	redelivered, revision := c.reofferBundle(t, published.bundle)
	await(t, "the accepted re-delivery", func() bool {
		return slices.ContainsFunc(c.journalSince(mark), func(entry mock.Entry) bool {
			return entry.Kind == "ResourceApplied" && entry.Generation == revision
		})
	})

	// The epoch arrives on the revocation subscription, which is how a control plane
	// withdraws a release it has already published.
	c.revokeAs(t, c.control.KeyID(), c.signing, 1, 1, published.hash)
	await(t, "the withdrawn release", func() bool {
		report := c.members[0].gateway.Diagnostics()
		return report.RevocationEpoch == 1 && report.Generation == 0 && !report.Prepared
	})

	// The release is offered again, at a revision above the one the instance
	// accepted, with the same payload hash, key and signer: nothing but the
	// revocation set can identify it as revoked.
	mark = len(c.control.Journal())
	offered, revision := c.reofferBundle(t, redelivered)
	await(t, "the refusal of the revoked bundle", func() bool {
		return slices.ContainsFunc(c.journalSince(mark), func(entry mock.Entry) bool {
			return entry.Kind == "ResourceRejected" && entry.Generation == revision
		})
	})
	report := c.members[0].gateway.Diagnostics()
	assert.Zero(t, report.Generation)
	assert.False(t, report.Prepared)
	assert.False(t, report.Ready)

	// The same release through the command path is refused on the same ground: a
	// control plane that prepares it is told why instead of being left waiting.
	mark = len(c.control.Journal())
	require.NoError(t, c.control.Prepare("stable-0", offered, time.Minute))
	await(t, "the refused prepare of the revoked release", func() bool {
		return slices.ContainsFunc(c.journalSince(mark), func(entry mock.Entry) bool {
			return entry.Kind == "Rejected" && entry.Key == published.release.ReleaseID
		})
	})
	assert.Zero(t, c.members[0].gateway.Diagnostics().Generation)
}

// TestReleaseRollbackRejected proves a bundle older than the one already applied
// is refused, so a control plane that lost its state cannot move an instance
// backwards.
func TestReleaseRollbackRejected(t *testing.T) {
	c := newCluster(t)
	applied := c.activate(t, release(2, nil, nil))

	// The rollback is a distinct document, so it is a distinct bundle key: only
	// the persisted generation can identify it as a rollback.
	rollback := release(1, nil, nil)
	rollback.ReleaseID = "release-1-replayed"
	resource, err := c.control.PublishBundle(rollback)
	require.NoError(t, err)
	require.NotEqual(t, applied.hash, hex.EncodeToString(resource.Hash[:]))

	// The refusal is reported and it names the release, so a control plane that lost
	// its own state learns from it that this instance will not move backwards. The
	// mock records no rejection for a release older than the one an instance has
	// applied — its own record of the instance may not regress either — so the report
	// is observed where the control plane received it.
	mark := len(c.control.Journal())
	require.NoError(t, c.control.Prepare("stable-0", resource, time.Minute))
	await(t, "the reported refusal of the rollback", func() bool {
		return slices.ContainsFunc(c.journalSince(mark), func(entry mock.Entry) bool {
			return entry.Kind == "Rejected" && entry.Key == rollback.ReleaseID
		})
	})
	report := c.members[0].gateway.Diagnostics()
	assert.Equal(t, uint64(2), report.Generation)
	assert.Equal(t, applied.hash, report.BundleHash)
	assert.True(t, report.Ready)
	state, ok := c.control.Instance("stable-0")
	require.True(t, ok)
	assert.Equal(t, uint64(2), state.AppliedGeneration)
	assert.Empty(t, state.RejectedCode)
}

// TestCertificateRotationOverlap covers certificate rotation in the order the
// protocol requires: the instance advertises its overlap window, the control
// plane publishes both digests for the length of that window, and the retiring
// certificate stops being accepted once the window is over.
func TestCertificateRotationOverlap(t *testing.T) {
	c := newCluster(t, withConfig(func(cfg *gogw.Config) { cfg.CertificateOverlapSeconds = 6 }))
	c.activate(t, release(1, nil, nil))

	// The canary build is not served by stable-0, so a canary request is the
	// forwarded single hop that exercises the peer certificate path.
	response := c.request(t, 0, http.MethodGet, "/orders", "canary-user", "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
	assert.Equal(t, "1", response.Header.Get("X-Actual-Hop"))
	body(t, response)

	in, peer := c.members[0], c.members[1]
	retiring := in.current
	in.rotate(t, c.ca)

	// The instance reports the digests the control plane must advertise: a release
	// file cannot observe a served certificate, so this is the operator contract
	// that keeps the two in step.
	await(t, "the adopted certificate", func() bool {
		return in.gateway.Diagnostics().CertificateSHA256 == in.current.digest
	})
	report := in.gateway.Diagnostics()
	require.Equal(t, retiring.digest, report.CertificatePreviousSHA256)
	require.Greater(t, report.CertificatePreviousValidUntilUnixMs, time.Now().UnixMilli())

	// Publishing both digests keeps the rotation transparent: the peer accepts the
	// retiring certificate for exactly as long as the instance advertises it.
	overlap := time.UnixMilli(report.CertificatePreviousValidUntilUnixMs)
	c.updateMembership(t, certificateMembers(in.name, in.current.digest, retiring.digest, overlap))
	ticket := c.finalTicket(t, in, retiring.key, peer, http.MethodGet, "/orders")
	response = c.finalRequest(t, 1, retiring.pair, http.MethodGet, "/orders", ticket)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "1", response.Header.Get("X-Actual-Hop"))
	body(t, response)

	// Once the overlap is over the instance stops advertising the retiring digest,
	// and a peer that still presents it is refused.
	await(t, "the closed overlap", func() bool {
		return in.gateway.Diagnostics().CertificatePreviousSHA256 == ""
	})
	c.updateMembership(t, certificateMembers(in.name, in.current.digest, "", time.Time{}))
	ticket = c.finalTicket(t, in, retiring.key, peer, http.MethodGet, "/orders")
	response = c.finalRequest(t, 1, retiring.pair, http.MethodGet, "/orders", ticket)
	assert.Equal(t, http.StatusForbidden, response.StatusCode)
	assert.Equal(t, "INTERNAL_ONLY\n", body(t, response))

	// The current certificate keeps working through the same path, so the refusal
	// above was the overlap closing and not the internal surface breaking.
	ticket = c.finalTicket(t, in, in.current.key, peer, http.MethodGet, "/orders")
	response = c.finalRequest(t, 1, in.current.pair, http.MethodGet, "/orders", ticket)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "1", response.Header.Get("X-Actual-Hop"))
	body(t, response)
}

// TestTrustKeyRotation covers the release signing key: a resource signed by a key
// this instance does not trust is refused, trusting a second key is what makes a
// rotation possible, and a configured window is what retires the old key.
func TestTrustKeyRotation(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	stranger := signingKey(t)
	c.revokeAs(t, "stranger", stranger, 1, 1, c.last.hash)

	// The document is signed, well formed and delivered: only the trust decision
	// rejects it, and the rejection is reported to the control plane.
	await(t, "the refusal of an untrusted key", func() bool {
		return c.journalContains("ResourceRejected", "")
	})
	report := c.members[0].gateway.Diagnostics()
	assert.Zero(t, report.RevocationEpoch)
	assert.True(t, report.Ready)

	// The trusted key publishes a newer epoch and it takes effect.
	_, err := c.control.PublishRevocation(2, 10*time.Minute, false)
	require.NoError(t, err)
	await(t, "the trusted revocation", func() bool {
		return c.members[0].gateway.Diagnostics().RevocationEpoch == 2
	})

	// A gateway that trusts both keys accepts the rotated signature, while a key
	// whose window closed is refused even though it is listed.
	rotated := signingKey(t)
	expired := time.Now().Add(-time.Hour).UnixMilli()
	peer := newCluster(t, withConfig(func(cfg *gogw.Config) {
		cfg.PolicyKeys = []gogw.TrustKey{
			{KeyID: cfg.PolicyKeyID, PublicKey: cfg.PolicyPublicKey},
			{KeyID: "rotated", PublicKey: hex.EncodeToString(rotated.Public().(ed25519.PublicKey))},
			{KeyID: "retired", PublicKey: hex.EncodeToString(rotated.Public().(ed25519.PublicKey)), NotAfterUnixMs: expired},
		}
	}))
	peer.activate(t, release(1, nil, nil))
	peer.revokeAs(t, "rotated", rotated, 1, 1, peer.last.hash)
	await(t, "the accepted rotation", func() bool {
		return peer.members[0].gateway.Diagnostics().RevocationEpoch == 1
	})

	peer.revokeAs(t, "retired", rotated, 2, 2, peer.last.hash)
	assert.True(t, settled(func() bool {
		return peer.members[0].gateway.Diagnostics().RevocationEpoch == 1
	}), "a key outside its trusted window was accepted")

	// The refused document changed nothing, while the revocation the trusted key
	// did publish took effect: the release it names is no longer served, which is
	// what readiness reports.
	report = peer.members[0].gateway.Diagnostics()
	assert.Equal(t, uint64(1), report.RevocationEpoch)
	assert.False(t, report.Ready)
	assert.Equal(t, "NO_RUNTIME_VIEW", report.ReadyReason)
}

// TestGracefulShutdownReleasesLease proves shutdown releases the lease instead of
// leaving the control plane to wait for it to expire.
func TestGracefulShutdownReleasesLease(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))
	in := c.members[0]

	in.gateway.Shutdown()

	await(t, "the released lease", func() bool {
		return c.journalContains("Deregister", in.name)
	})
	report := in.gateway.Diagnostics()
	assert.True(t, report.Draining)
	assert.False(t, report.Ready)
	assert.False(t, report.Eligible)
	assert.Equal(t, "DRAINING", report.EligibleReason)
	assert.Positive(t, counter(report, "allocation", "lease_released"))

	// The control plane dropped the instance at once, which is the whole point of
	// releasing a lease instead of waiting for it to expire.
	assert.True(t, settled(func() bool {
		_, ok := c.control.Instance(in.name)
		return !ok
	}), "the control plane kept a gracefully stopped instance")
}

// TestDrainGraceAndForceClose covers both ends of draining: a control-plane drain
// request gives the running streams the grace period the control plane granted,
// and a local drain ends them at the configured deadline.
func TestDrainGraceAndForceClose(t *testing.T) {
	c := newCluster(t, withConfig(func(cfg *gogw.Config) { cfg.DrainGraceSeconds = 2 }))
	c.activate(t, release(1, nil, nil))

	stream := c.stream(t, 0, "/sse", "user-1")
	assert.Equal(t, "stable", event(t, stream))

	// A control-plane drain stops new work while the running stream keeps its
	// grace period: the force-close deadline is the control plane's to set.
	require.NoError(t, c.control.Drain("stable-0"))
	await(t, "the drain request", func() bool {
		return c.members[0].gateway.Diagnostics().Draining
	})
	c.updateMembership(t, drainingMembers("stable-0"))

	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
	assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
	assert.Equal(t, "DRAINING\n", body(t, response))

	select {
	case build := <-c.canceled:
		t.Fatalf("the drain request closed a stream inside its grace period: %s", build)
	case <-time.After(time.Second):
	}
	require.NoError(t, stream.Body.Close())
	select {
	case build := <-c.canceled:
		assert.Equal(t, "stable", build)
	case <-time.After(awaitTimeout):
		t.Fatal("the closed stream was not canceled upstream")
	}

	// A local drain ends the streams at the configured deadline instead of waiting
	// for the control plane to force them closed.
	in := c.members[1]
	streams := c.stream(t, 1, "/sse", "canary-user")
	assert.Equal(t, "canary", event(t, streams))
	start := time.Now()
	in.gateway.Drain()
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, time.Second)
	assert.Less(t, elapsed, 10*time.Second)

	select {
	case build := <-c.canceled:
		assert.Equal(t, "canary", build)
	case <-time.After(5 * time.Second):
		t.Fatal("the drained gateway did not close its stream")
	}
	_ = streams.Body.Close()

	report := in.gateway.Diagnostics()
	assert.True(t, report.Draining)
	assert.Zero(t, report.InFlight)
	assert.Zero(t, report.Streams)
	assert.False(t, report.Ready)
}

// TestApplicationFailureAndRecovery couples the gateway to the application it
// fronts: readiness is fail-closed while the probe cannot reach the application,
// no new business traffic starts, the failure stays inside the instance that has
// it, and the instance rejoins the rotation once the application answers again.
func TestApplicationFailureAndRecovery(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	body(t, response)

	// The application of one instance stops answering. Nothing tells that gateway:
	// the probe is the only observer, so the instance has to converge on its own.
	c.appHealthy[0].Store(false)
	await(t, "the instance to notice its application", func() bool {
		return !c.members[0].gateway.Diagnostics().Healthy
	})
	report := c.members[0].gateway.Diagnostics()
	assert.False(t, report.Ready)
	assert.Equal(t, "APPLICATION_UNHEALTHY", report.ReadyReason)
	assert.False(t, report.Eligible)
	assert.Equal(t, "APPLICATION_UNHEALTHY", report.EligibleReason)

	// Readiness is the gate a deployment reads, and a refusal never says which of
	// the reasons it was.
	ready := c.raw(t, 0, http.MethodGet, "/__gogw/ready", nil)
	assert.Equal(t, http.StatusServiceUnavailable, ready.StatusCode)
	assert.Equal(t, "NOT_READY\n", body(t, ready))

	// The refusal is the state of the instance, not of the request: the same
	// request that was served a moment ago is now refused, and the body names the
	// application rather than a drain that is not in progress.
	response = c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
	assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
	assert.Equal(t, "NOT_READY\n", body(t, response))

	// The failure is bounded by the instance: the peer serves both its own traffic
	// and the traffic this instance may no longer take.
	response = c.request(t, 1, http.MethodGet, "/orders", "canary-user", "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
	body(t, response)

	// Recovery is the same path in reverse and needs no restart, so a rolling
	// failure of one application does not turn into a rollout.
	c.appHealthy[0].Store(true)
	await(t, "the recovery of the instance", func() bool {
		current := c.members[0].gateway.Diagnostics()
		return current.Healthy && current.Ready && current.Eligible
	})
	ready = c.raw(t, 0, http.MethodGet, "/__gogw/ready", nil)
	assert.Equal(t, http.StatusNoContent, ready.StatusCode)
	response = c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "stable", response.Header.Get("X-Actual-Build"))
	body(t, response)
}

// TestMetricsAndDiagnostics is the diagnostics contract: counters are tagged by
// phase, the document carries no identity or secret, and its cardinality is
// bounded by the fixed label vocabulary instead of by the request population.
func TestMetricsAndDiagnostics(t *testing.T) {
	c := newCluster(t)
	published := c.activate(t, release(1, nil, nil))

	const population = 24
	for index := range population {
		response := c.request(t, 0, http.MethodGet, "/orders", subject(index), tenant(index), nil)
		require.Equal(t, http.StatusOK, response.StatusCode)
		body(t, response)
	}
	// A canary subject is allocated on the canary build, so a single report
	// carries counters of two builds.
	response := c.request(t, 0, http.MethodGet, "/orders", "canary-user", tenant(0), nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	body(t, response)

	report := c.members[0].gateway.Diagnostics()
	assert.Equal(t, uint64(1), report.Generation)
	assert.Equal(t, published.hash, report.BundleHash)
	assert.Equal(t, "release-1", report.ReleaseID)
	assert.Zero(t, report.InFlight)
	assert.Zero(t, report.Streams)
	assert.Equal(t, population+1, report.Sessions)
	assert.Equal(t, int64(population+1), counter(report, "execution", "served"))
	assert.Equal(t, int64(population+1), counter(report, "exposure", "delivered"))
	assert.Equal(t, int64(population+1), counter(report, "exposure", "exposed"))
	// The allocation phase separates the activation of a release from the
	// allocation of one unit, and the reason an evaluator reports comes from its
	// closed enumeration, so neither grows with the traffic.
	assert.Positive(t, counter(report, "allocation", "release_activated"))
	assert.Positive(t, counter(report, "allocation", string(model.ReasonTargetingMatch)))
	assert.Positive(t, counter(report, "allocation", string(model.ReasonDefault)))
	assert.Zero(t, counter(report, "execution", "transport_error"))

	document := string(c.members[0].gateway.DiagnosticsJSON())
	assert.NotContains(t, document, "test-token")
	assert.NotContains(t, document, string(c.secret))
	assert.NotContains(t, document, subject(0))
	assert.NotContains(t, document, tenant(0))
	assert.NotContains(t, document, "canary-user")
	assert.NotContains(t, document, "/sse")

	// The label space is a function of the fixed vocabulary, not of the traffic:
	// every subject above shares one label per phase and build.
	labels := map[string]bool{}
	for _, sample := range report.Counters {
		labels[sample.Phase+"/"+sample.Build+"/"+sample.Label] = true
	}
	assert.Less(t, len(labels), 64)
}

// stream opens one server-sent event stream.
func (c *cluster) stream(t *testing.T, index int, path, subject string) *http.Response {
	t.Helper()
	response := c.request(t, index, http.MethodGet, path, subject, "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "text/event-stream", response.Header.Get("Content-Type"))
	return response
}

// event reads one server-sent event payload.
func event(t *testing.T, response *http.Response) string {
	t.Helper()
	reader := bufio.NewReader(response.Body)
	for range 16 {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if payload, ok := strings.CutPrefix(line, "data: "); ok {
			return strings.TrimSpace(payload)
		}
	}
	t.Fatal("the stream carried no event")
	return ""
}
