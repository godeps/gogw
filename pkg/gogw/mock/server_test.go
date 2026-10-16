package mock

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/coder/websocket"
	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
	"github.com/saker-ai/grayling/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/gogw"
	"google.golang.org/protobuf/proto"
)

const (
	testToken = "agent-token"

	// testHeartbeat is short so the enforced heartbeat deadline is observable
	// inside a test instead of after a production-sized wait.
	testHeartbeat = 50 * time.Millisecond
	testRequest   = 2 * time.Second
	testWait      = 3 * time.Second

	// zeroSessionID is a well-formed session id that belongs to no session, which
	// is what a stale frame carries.
	zeroSessionID = "00000000-0000-0000-0000-000000000000"
)

// harness is one mock control plane behind a listening TLS server, with the
// published SDK client as the peer: the acceptance path is the real client, not
// a hand-written WebSocket peer.
type harness struct {
	t      *testing.T
	server *Server
	http   *httptest.Server
	scope  agent.Scope
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	scope := agent.Scope{WorkspaceID: "ws", EnvironmentID: "env", ServiceKey: "checkout"}
	server, err := New(Options{Scope: scope, Token: testToken, KeyID: "mock", SigningKey: private, Heartbeat: testHeartbeat})
	require.NoError(t, err)
	srv := httptest.NewTLSServer(server.Handler())
	t.Cleanup(srv.Close)
	server.SetOrigin(strings.TrimSuffix(srv.URL, "/"))
	t.Cleanup(server.Close)
	return &harness{t: t, server: server, http: srv, scope: scope}
}

// connectURL is the WebSocket URL the SDK dials the mock on.
func (h *harness) connectURL() string {
	return strings.Replace(h.http.URL, "https://", "wss://", 1)
}

// websocketURL is the raw connect endpoint, which the SDK derives from the URL
// it is given.
func (h *harness) websocketURL() string {
	return h.connectURL() + agentv1.ConnectPath
}

// dial connects one SDK agent and closes it when the test ends.
func (h *harness) dial(instanceID, bootID string) *agent.Client {
	h.t.Helper()
	client, err := h.dialWith(agent.Options{
		Token:            testToken,
		Hello:            &agentv1.Hello{AgentId: "agent", InstanceId: instanceID, BootId: bootID},
		HandshakeTimeout: testWait,
		RequestTimeout:   testRequest,
	})
	require.NoError(h.t, err)
	h.t.Cleanup(func() { _ = client.Close() })
	return client
}

// dialWith completes one set of client options with the harness endpoint.
func (h *harness) dialWith(options agent.Options) (*agent.Client, error) {
	options.URL = h.connectURL()
	options.HTTPClient = h.http.Client()
	return agent.Dial(context.Background(), options)
}

// register registers one instance and returns the granted lease.
func (h *harness) register(client *agent.Client, instanceID, bootID, operationID string) *agentv1.Registered {
	h.t.Helper()
	registered, err := client.Register(context.Background(), operationID, &agentv1.Register{Instance: &agentv1.Instance{
		Scope:           h.scopeProto(),
		InstanceId:      instanceID,
		BootId:          bootID,
		BuildId:         "build-1",
		Address:         "127.0.0.1",
		Port:            8443,
		TlsServerName:   "localhost",
		ProtocolVersion: agentv1.ProtocolMajor,
		Ready:           true,
	}})
	require.NoError(h.t, err)
	return registered
}

func (h *harness) scopeProto() *agentv1.Scope {
	return &agentv1.Scope{WorkspaceId: h.scope.WorkspaceID, EnvironmentId: h.scope.EnvironmentID, ServiceKey: h.scope.ServiceKey}
}

// release describes one minimal valid release.
func (h *harness) release(id string, generation uint64) Release {
	return Release{
		ReleaseID:    id,
		Generation:   generation,
		Flag:         "checkout",
		DefaultBuild: "stable",
		Builds:       map[string]gogw.BuildDescriptor{"stable": {}, "canary": {}},
	}
}

// event waits for the first server message that matches, discarding the ones the
// test does not assert on.
func (h *harness) event(client *agent.Client, match func(*agentv1.Envelope) bool) *agentv1.Envelope {
	h.t.Helper()
	deadline := time.After(testWait)
	for {
		select {
		case envelope, ok := <-client.Events():
			require.True(h.t, ok, "the event stream closed before the expected message")
			if match(envelope) {
				return envelope
			}
		case <-deadline:
			h.t.Fatal("timed out waiting for a server message")
		}
	}
}

// noEvent asserts that no matching message arrives within the window, which is
// how a withheld command is observed.
func (h *harness) noEvent(client *agent.Client, match func(*agentv1.Envelope) bool, window time.Duration) {
	h.t.Helper()
	deadline := time.After(window)
	for {
		select {
		case envelope, ok := <-client.Events():
			require.True(h.t, ok, "the event stream closed early")
			if match(envelope) {
				h.t.Fatal("unexpected server message")
			}
		case <-deadline:
			return
		}
	}
}

// verifier checks a signed resource exactly as a gateway does, with the trust
// window the mock's claims fit inside.
func (h *harness) verifier() *agent.Verifier {
	h.t.Helper()
	verifier, err := agent.NewVerifier(map[string]agent.TrustKey{
		h.server.KeyID(): {PublicKey: h.server.PublicKey(), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)},
	})
	require.NoError(h.t, err)
	return verifier
}

// verify accepts one signed resource against a watermark and returns its claims.
func (h *harness) verify(signed *agentv1.SignedResource, kind agentv1.ResourceKind, key string, mark agent.Watermark) agent.Claims {
	h.t.Helper()
	claims, err := h.verifier().Verify(signed, h.scope, kind, key, mark, time.Now())
	require.NoError(h.t, err)
	return claims
}

// journalKinds lists the inbound message kinds the mock recorded, oldest first.
func (h *harness) journalKinds() []string {
	h.t.Helper()
	entries := h.server.Journal()
	kinds := make([]string, 0, len(entries))
	for _, entry := range entries {
		kinds = append(kinds, entry.Kind)
	}
	return kinds
}

// requireRemoteCode asserts that an error is the protocol error carrying code,
// which is how the SDK surfaces a correlated refusal.
func requireRemoteCode(t *testing.T, err error, code agentv1.ErrorCode) {
	t.Helper()
	var remote *agent.RemoteError
	require.ErrorAs(t, err, &remote)
	require.NotNil(t, remote.Detail)
	assert.Equal(t, code, remote.Detail.GetCode())
}

// waitDone blocks until the client session ended and returns its cause.
func waitDone(t *testing.T, client *agent.Client) error {
	t.Helper()
	select {
	case <-client.Done():
	case <-time.After(testWait):
		t.Fatal("the session did not end")
	}
	return client.Err()
}

// inlineResource is the resource a Snapshot carries inline.
func inlineResource(envelope *agentv1.Envelope) *agentv1.SignedResource {
	return envelope.GetSnapshot().GetInlineResource()
}

// mustDecode decodes one frame or fails the test.
func mustDecode(t *testing.T, frame []byte) *agentv1.Envelope {
	t.Helper()
	envelope, err := agentv1.Decode(frame)
	require.NoError(t, err)
	return envelope
}

// digestHex is the lowercase SHA-256 digest of raw, which is what a reference
// commits to.
func digestHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestHandshakeAuthenticationAndLimits(t *testing.T) {
	h := newHarness(t)

	_, err := h.dialWith(agent.Options{Token: "wrong", Hello: &agentv1.Hello{AgentId: "agent", InstanceId: "i", BootId: "b"}})
	var handshake *agent.HandshakeError
	require.ErrorAs(t, err, &handshake)
	assert.Equal(t, http.StatusUnauthorized, handshake.StatusCode)

	client := h.dial("inst-1", "boot-1")
	welcome := client.Welcome().GetWelcome()
	require.NotNil(t, welcome)
	assert.Equal(t, h.scopeProto(), welcome.GetScope())
	assert.Equal(t, uint64(controlPlaneEpoch), welcome.GetControlPlaneEpoch())
	assert.NotEmpty(t, welcome.GetCapabilities())
	limits := welcome.GetLimits()
	require.NotNil(t, limits)
	assert.Equal(t, uint32(maxFrameBytes), limits.GetMaxFrameBytes())
	assert.Equal(t, uint32(testHeartbeat.Milliseconds()), limits.GetHeartbeatIntervalMs())
	assert.Greater(t, limits.GetHeartbeatTimeoutMs(), limits.GetHeartbeatIntervalMs())
	assert.Equal(t, uint64(maxResourceBytes), limits.GetMaxResourceBytes())
	assert.Equal(t, uint32(maxSubscriptions), limits.GetMaxSubscriptions())
	assert.Equal(t, 1, h.server.Sessions())
	assert.Contains(t, h.journalKinds(), "Hello")
}

func TestRegisterFencingAndReplay(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	client := h.dial("inst-1", "boot-1")

	registered := h.register(client, "inst-1", "boot-1", "op-register")
	assert.Equal(t, "inst-1", registered.GetInstance().GetInstanceId())
	assert.Equal(t, "boot-1", registered.GetInstance().GetBootId())
	lease := registered.GetInstance().GetLease()
	require.NotNil(t, lease)
	assert.Equal(t, uint64(1), lease.GetEpoch())
	assert.Greater(t, lease.GetExpiresUnixMs(), time.Now().UnixMilli())

	// A retry of the same operation id is answered from the recorded result, so it
	// cannot advance the lease epoch a second time.
	replayed, err := client.CallMessage(ctx, &agentv1.Register{Instance: &agentv1.Instance{InstanceId: "inst-1", BootId: "boot-1"}}, agent.Metadata{OperationID: "op-register"})
	require.NoError(t, err)
	replayedLease := replayed.GetRegistered().GetInstance().GetLease()
	require.NotNil(t, replayedLease)
	assert.Equal(t, lease.GetEpoch(), replayedLease.GetEpoch())
	assert.Equal(t, lease.GetId(), replayedLease.GetId())

	renewed, err := client.RenewLease(ctx, "op-renew", &agentv1.RenewLease{InstanceId: "inst-1", BootId: "boot-1", Lease: proto.Clone(lease).(*agentv1.Lease)})
	require.NoError(t, err)
	require.NotNil(t, renewed.GetLease())
	assert.Equal(t, lease.GetEpoch(), renewed.GetLease().GetEpoch())
	assert.GreaterOrEqual(t, renewed.GetLease().GetExpiresUnixMs(), lease.GetExpiresUnixMs())

	// A stale epoch belongs to a holder the registry has already fenced.
	stale := proto.Clone(lease).(*agentv1.Lease)
	stale.Epoch++
	_, err = client.RenewLease(ctx, "op-renew-stale", &agentv1.RenewLease{InstanceId: "inst-1", BootId: "boot-1", Lease: stale})
	requireRemoteCode(t, err, agentv1.ErrorCode_ERROR_CODE_FENCED)

	// Registering again grants a new epoch, which fences the previous holder.
	second := h.register(client, "inst-1", "boot-1", "op-register-2")
	assert.Equal(t, uint64(2), second.GetInstance().GetLease().GetEpoch())
	_, err = client.RenewLease(ctx, "op-renew-fenced", &agentv1.RenewLease{InstanceId: "inst-1", BootId: "boot-1", Lease: proto.Clone(lease).(*agentv1.Lease)})
	requireRemoteCode(t, err, agentv1.ErrorCode_ERROR_CODE_FENCED)

	state, ok := h.server.Instance("inst-1")
	require.True(t, ok)
	assert.Equal(t, uint64(2), state.LeaseEpoch)
	assert.Equal(t, "boot-1", state.BootID)
	assert.Equal(t, "build-1", state.BuildID)
	assert.True(t, state.Ready)

	// A new boot clears the release state the previous process reported.
	h.register(client, "inst-1", "boot-2", "op-register-3")
	state, ok = h.server.Instance("inst-1")
	require.True(t, ok)
	assert.Equal(t, "boot-2", state.BootID)
	assert.Zero(t, state.AppliedGeneration)
	assert.Zero(t, state.PreparedGeneration)

	require.NoError(t, client.SendMessage(ctx, &agentv1.Deregister{InstanceId: "inst-1", BootId: "boot-2"}, agent.Metadata{OperationID: "op-deregister"}))
	require.Eventually(t, func() bool {
		_, exists := h.server.Instance("inst-1")
		return !exists
	}, testWait, 10*time.Millisecond)
	assert.Equal(t, 1, h.server.Sessions(), "deregister must not end the session")

	kinds := h.journalKinds()
	assert.Contains(t, kinds, "Register")
	assert.Contains(t, kinds, "RenewLease")
	assert.Contains(t, kinds, "Deregister")
}

func TestSubscribeSnapshotDeltaAndResync(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	client := h.dial("inst-1", "boot-1")

	// The revocation resource is a stable key, which is what a Delta needs: a
	// bundle is self-addressed, so its next generation is a different resource.
	key := gogw.RevocationKey
	require.NoError(t, client.Subscribe(ctx, "sub-revocation", &agentv1.Cursor{Kind: agentv1.ResourceKind_RESOURCE_KIND_REVOCATION, Key: key}))
	h.noEvent(client, func(e *agentv1.Envelope) bool { return e.GetSnapshot() != nil }, 200*time.Millisecond)

	first, err := h.server.PublishRevocation(1, time.Minute, false)
	require.NoError(t, err)
	snapshot := h.event(client, func(e *agentv1.Envelope) bool { return e.GetSnapshot() != nil })
	assert.Equal(t, "sub-revocation", snapshot.GetSubscriptionId())
	assert.Equal(t, uint64(1), snapshot.GetSnapshot().GetRevision())
	claims := h.verify(inlineResource(snapshot), first.Kind, first.Key, agent.Watermark{})

	// A publication that continues the cursor is delivered as a download
	// reference, and the downloaded bytes verify against its claims.
	second, err := h.server.PublishRevocation(2, time.Minute, false)
	require.NoError(t, err)
	delta := h.event(client, func(e *agentv1.Envelope) bool { return e.GetDelta() != nil })
	assert.Equal(t, uint64(1), delta.GetDelta().GetBaseRevision())
	ref := delta.GetDelta().GetReference()
	require.NotNil(t, ref)
	assert.Equal(t, second.Key, ref.GetKey())
	assert.Equal(t, uint64(2), ref.GetRevision())
	downloaded, err := client.Download(ctx, ref)
	require.NoError(t, err)
	next := h.verify(downloaded, second.Kind, second.Key, claims.Watermark())
	assert.Equal(t, uint64(2), next.Revision)
	assert.Equal(t, second.Hash, next.PayloadHash)
	assert.NotEqual(t, first.Hash, second.Hash)

	// A withdrawal invalidates the cursor, and the next publication is a complete
	// Snapshot rather than a Delta from a revision that is gone.
	h.server.Unpublish(agentv1.ResourceKind_RESOURCE_KIND_REVOCATION, key)
	invalidated := h.event(client, func(e *agentv1.Envelope) bool { return e.GetInvalidated() != nil })
	assert.Equal(t, uint64(2), invalidated.GetInvalidated().GetRevision())
	assert.Equal(t, key, invalidated.GetResourceKey())
	third, err := h.server.PublishRevocation(3, time.Minute, false)
	require.NoError(t, err)
	resnapshot := h.event(client, func(e *agentv1.Envelope) bool { return e.GetSnapshot() != nil })
	assert.Equal(t, uint64(3), resnapshot.GetSnapshot().GetRevision())
	h.verify(inlineResource(resnapshot), third.Kind, third.Key, next.Watermark())

	// The published protocol has no server-to-client field that could carry a
	// resume token, so an unknown token forces an explicit resync and the
	// subscription identifier is accepted as the token the mock handed out.
	require.NoError(t, client.Resume(ctx, "sub-revocation", []byte("stale-token")))
	resync := h.event(client, func(e *agentv1.Envelope) bool { return e.GetResyncRequired() != nil })
	assert.Equal(t, "sub-revocation", resync.GetSubscriptionId())
	assert.NotEmpty(t, resync.GetResyncRequired().GetReason())

	require.NoError(t, client.Resume(ctx, "sub-revocation", []byte("sub-revocation")))
	again := h.event(client, func(e *agentv1.Envelope) bool { return e.GetSnapshot() != nil })
	assert.Equal(t, uint64(3), again.GetSnapshot().GetRevision())

	// An injected resync is delivered whatever the token says.
	h.server.SetFaults(Faults{ForceResync: true})
	require.NoError(t, client.Resume(ctx, "sub-revocation", []byte("sub-revocation")))
	h.event(client, func(e *agentv1.Envelope) bool { return e.GetResyncRequired() != nil })
	h.server.SetFaults(Faults{})

	// Unsubscribing stops delivery. Resuming the dropped subscription is answered
	// with a resync, which also proves the withdrawal was processed before the
	// next publication is delivered.
	require.NoError(t, client.Unsubscribe(ctx, "sub-revocation"))
	require.NoError(t, client.Resume(ctx, "sub-revocation", []byte("sub-revocation")))
	resync = h.event(client, func(e *agentv1.Envelope) bool { return e.GetResyncRequired() != nil })
	assert.Equal(t, "sub-revocation", resync.GetSubscriptionId())
	_, err = h.server.PublishRevocation(4, time.Minute, false)
	require.NoError(t, err)
	h.noEvent(client, func(e *agentv1.Envelope) bool { return e.GetSnapshot() != nil || e.GetDelta() != nil }, 300*time.Millisecond)
}

func TestRevisionMonotonicity(t *testing.T) {
	h := newHarness(t)

	key := "policy/checkout"
	first, err := h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, key, []byte(`{"schema":1,"revision":1}`), PublishOptions{Revision: 1})
	require.NoError(t, err)

	// A byte-identical republication is the stored resource, not a new revision.
	identical, err := h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, key, []byte(`{"schema":1,"revision":1}`), PublishOptions{Revision: 1})
	require.NoError(t, err)
	assert.Equal(t, first.Hash, identical.Hash)
	assert.Equal(t, first.Ref.GetSha256(), identical.Ref.GetSha256())

	// Different content must advance the revision.
	_, err = h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, key, []byte(`{"schema":1,"revision":2}`), PublishOptions{Revision: 1})
	require.ErrorIs(t, err, ErrRevision)
	advanced, err := h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, key, []byte(`{"schema":1,"revision":2}`), PublishOptions{Revision: 2})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), advanced.Ref.GetRevision())

	// A withdrawn revision is not reusable either.
	h.server.Unpublish(agentv1.ResourceKind_RESOURCE_KIND_POLICY, key)
	_, err = h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, key, []byte(`{"schema":1,"revision":1}`), PublishOptions{Revision: 1})
	require.ErrorIs(t, err, ErrRevision)

	// A bundle is self-addressed by its payload digest, so an identical release is
	// the same resource while a new generation is a different one.
	bundle, err := h.server.PublishBundle(h.release("rel-1", 5))
	require.NoError(t, err)
	repeated, err := h.server.PublishBundle(h.release("rel-1", 5))
	require.NoError(t, err)
	assert.Equal(t, bundle.Hash, repeated.Hash)
	assert.Equal(t, bundle.Key, repeated.Key)
	assert.Equal(t, uint64(5), repeated.Ref.GetRevision())
	next, err := h.server.PublishBundle(h.release("rel-1", 6))
	require.NoError(t, err)
	assert.NotEqual(t, bundle.Key, next.Key)
	assert.NotEqual(t, bundle.Hash, next.Hash)
	assert.Equal(t, uint64(6), next.Ref.GetRevision())
}

func TestDownloadValidationAndTampering(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	client := h.dial("inst-1", "boot-1")

	intact, err := h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, "policy/intact", []byte(`{"schema":1}`), PublishOptions{Revision: 1})
	require.NoError(t, err)
	require.NotNil(t, intact.Ref)

	downloaded, err := client.Download(ctx, intact.Ref)
	require.NoError(t, err)
	claims := h.verify(downloaded, intact.Kind, intact.Key, agent.Watermark{})
	assert.Equal(t, intact.Hash, claims.PayloadHash)
	assert.Equal(t, h.server.KeyID(), claims.KeyID)
	assert.Equal(t, uint64(controlPlaneEpoch), claims.ControlPlaneEpoch)
	assert.Equal(t, uint64(1), claims.Revision)

	// The served bytes are the serialized resource the reference committed to, so
	// a gateway's digest check passes before verification runs.
	wire, err := proto.Marshal(downloaded)
	require.NoError(t, err)
	assert.Equal(t, digestHex(wire), intact.Ref.GetSha256())
	assert.Equal(t, uint64(len(wire)), intact.Ref.GetSizeBytes())

	// A tampered publication commits its claims to the pristine payload, so the
	// served bytes decode but fail verification.
	tampered, err := h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, "policy/tampered", []byte(`{"schema":1}`), PublishOptions{Revision: 1, TamperPayload: true})
	require.NoError(t, err)
	require.NotNil(t, tampered.Ref)
	served, err := client.Download(ctx, tampered.Ref)
	require.NoError(t, err)
	servedClaims, err := agent.ParseClaims(served.GetClaims())
	require.NoError(t, err)
	assert.NotEqual(t, servedClaims.PayloadHash, sha256.Sum256(served.GetPayload()))
	_, err = h.verifier().Verify(served, h.scope, tampered.Kind, tampered.Key, agent.Watermark{}, time.Now())
	require.ErrorIs(t, err, agent.ErrResource)

	// A resource published without a download address is refused explicitly
	// instead of being advertised with an empty reference.
	inline, err := h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, "policy/inline", []byte(`{"schema":1}`), PublishOptions{Revision: 1, NoDownload: true})
	require.NoError(t, err)
	assert.Nil(t, inline.Ref)
	_, err = client.FetchResource(ctx, &agentv1.FetchResource{Kind: inline.Kind, Key: inline.Key})
	requireRemoteCode(t, err, agentv1.ErrorCode_ERROR_CODE_NOT_READY)

	// A published resource is fetchable without a subscription, and an
	// unpublished one is reported as expired rather than as an empty reference.
	fetched, err := client.FetchResource(ctx, &agentv1.FetchResource{Kind: intact.Kind, Key: intact.Key})
	require.NoError(t, err)
	assert.Equal(t, intact.Ref.GetSha256(), fetched.GetSha256())
	_, err = client.FetchResource(ctx, &agentv1.FetchResource{Kind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, Key: "bundle/absent"})
	requireRemoteCode(t, err, agentv1.ErrorCode_ERROR_CODE_RESOURCE_EXPIRED)

	// The download endpoint itself requires the agent token.
	response, err := h.http.Client().Get(intact.Ref.GetHttpsUrl())
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
	authorized, err := http.NewRequest(http.MethodGet, intact.Ref.GetHttpsUrl(), nil)
	require.NoError(t, err)
	authorized.Header.Set("Authorization", "Bearer "+testToken)
	response, err = h.http.Client().Do(authorized)
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func TestPrepareActivateApplyAndStatus(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	client := h.dial("inst-1", "boot-1")
	h.register(client, "inst-1", "boot-1", "op-register")

	bundle, err := h.server.PublishBundle(h.release("rel-1", 1))
	require.NoError(t, err)
	require.NoError(t, h.server.Prepare("inst-1", bundle, 0))

	prepare := h.event(client, func(e *agentv1.Envelope) bool { return e.GetPrepare() != nil }).GetPrepare()
	assert.Equal(t, "rel-1", prepare.GetRelease().GetReleaseId())
	assert.Equal(t, uint64(1), prepare.GetRelease().GetGeneration())
	assert.Equal(t, hex.EncodeToString(bundle.Hash[:]), prepare.GetRelease().GetBundleHash())
	require.NotNil(t, prepare.GetBundle())
	assert.Greater(t, prepare.GetExpiresUnixMs(), time.Now().UnixMilli())
	downloaded, err := client.Download(ctx, prepare.GetBundle())
	require.NoError(t, err)
	h.verify(downloaded, bundle.Kind, bundle.Key, agent.Watermark{})

	// Prepared evidence is synthesized into the membership artifact.
	require.NoError(t, client.SendMessage(ctx, &agentv1.Prepared{
		Release:       prepare.GetRelease(),
		InstanceId:    "inst-1",
		BootId:        "boot-1",
		BuildId:       "build-1",
		ExpiresUnixMs: time.Now().Add(time.Minute).UnixMilli(),
	}, agent.Metadata{OperationID: "op-prepared"}))
	require.Eventually(t, func() bool {
		members := h.server.Members(bundle.Hash)
		return len(members) == 1 && members[0].Prepared != nil
	}, testWait, 10*time.Millisecond)
	members := h.server.Members(bundle.Hash)
	assert.Equal(t, hex.EncodeToString(bundle.Hash[:]), members[0].Prepared.BundleHash)
	assert.Equal(t, uint64(1), members[0].Prepared.PreparedRevision)
	assert.Equal(t, uint64(1), members[0].Prepared.Generation)
	assert.Greater(t, members[0].Prepared.ExpiresUnixMs, time.Now().UnixMilli())

	// The mock activates a prepared release by itself.
	activated := h.event(client, func(e *agentv1.Envelope) bool { return e.GetActivate() != nil }).GetActivate()
	assert.Equal(t, "rel-1", activated.GetRelease().GetReleaseId())
	assert.Equal(t, uint64(1), activated.GetPreparedRevision())
	assert.Equal(t, uint64(1), activated.GetPolicyRevision())

	require.NoError(t, client.SendMessage(ctx, &agentv1.Applied{
		Release:          activated.GetRelease(),
		InstanceId:       "inst-1",
		BootId:           "boot-1",
		PolicyRevision:   activated.GetPolicyRevision(),
		PreparedRevision: activated.GetPreparedRevision(),
	}, agent.Metadata{OperationID: "op-applied"}))
	require.Eventually(t, func() bool {
		state, ok := h.server.Instance("inst-1")
		return ok && state.AppliedGeneration == 1 && state.AppliedRevision == 1
	}, testWait, 10*time.Millisecond)

	status, err := client.ReleaseStatus(ctx, &agentv1.ReleaseStatusQuery{ReleaseId: "rel-1"})
	require.NoError(t, err)
	assert.Equal(t, agentv1.ReleaseState_RELEASE_STATE_ACTIVE, status.GetState())
	assert.Equal(t, uint64(1), status.GetRelease().GetGeneration())
	require.Len(t, status.GetApplied(), 1)
	assert.Equal(t, "inst-1", status.GetApplied()[0].GetInstanceId())
	assert.Equal(t, uint64(1), status.GetApplied()[0].GetPolicyRevision())

	// A late replay of an older report cannot regress the applied state.
	older := proto.Clone(activated.GetRelease()).(*agentv1.ReleaseIdentity)
	older.Generation = 0
	require.NoError(t, client.SendMessage(ctx, &agentv1.Applied{Release: older, InstanceId: "inst-1"}, agent.Metadata{OperationID: "op-applied-stale"}))
	state, ok := h.server.Instance("inst-1")
	require.True(t, ok)
	assert.Equal(t, uint64(1), state.AppliedGeneration)
	assert.Equal(t, uint64(1), state.AppliedRevision)

	kinds := h.journalKinds()
	for _, kind := range []string{"Prepared", "Applied", "ReleaseStatusQuery"} {
		assert.Contains(t, kinds, kind)
	}
}

func TestWithheldActivationAbortAndRejection(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	client := h.dial("inst-1", "boot-1")
	h.register(client, "inst-1", "boot-1", "op-register")

	bundle, err := h.server.PublishBundle(h.release("rel-1", 1))
	require.NoError(t, err)
	isActivate := func(e *agentv1.Envelope) bool { return e.GetActivate() != nil }

	// WithholdActivate keeps the activation in the control plane's hands.
	h.server.SetFaults(Faults{WithholdActivate: true})
	require.NoError(t, h.server.Prepare("inst-1", bundle, 0))
	prepare := h.event(client, func(e *agentv1.Envelope) bool { return e.GetPrepare() != nil }).GetPrepare()
	require.NoError(t, client.SendMessage(ctx, &agentv1.Prepared{Release: prepare.GetRelease(), InstanceId: "inst-1"}, agent.Metadata{OperationID: "op-prepared"}))
	h.noEvent(client, isActivate, 300*time.Millisecond)

	// An activation outside the injected subset is withheld as well.
	h.server.SetFaults(Faults{ActivateSubset: []string{"inst-other"}})
	require.NoError(t, h.server.Prepare("inst-1", bundle, 0))
	prepare = h.event(client, func(e *agentv1.Envelope) bool { return e.GetPrepare() != nil }).GetPrepare()
	require.NoError(t, client.SendMessage(ctx, &agentv1.Prepared{Release: prepare.GetRelease(), InstanceId: "inst-1"}, agent.Metadata{OperationID: "op-prepared-2"}))
	h.noEvent(client, isActivate, 300*time.Millisecond)

	// The explicit activation reaches the instance.
	h.server.SetFaults(Faults{})
	require.NoError(t, h.server.Activate("inst-1"))
	activated := h.event(client, isActivate).GetActivate()
	assert.Equal(t, "rel-1", activated.GetRelease().GetReleaseId())

	// AbortAfterPrepare aborts instead of activating.
	h.server.SetFaults(Faults{AbortAfterPrepare: []string{"inst-1"}})
	require.NoError(t, h.server.Prepare("inst-1", bundle, 0))
	prepare = h.event(client, func(e *agentv1.Envelope) bool { return e.GetPrepare() != nil }).GetPrepare()
	require.NoError(t, client.SendMessage(ctx, &agentv1.Prepared{Release: prepare.GetRelease(), InstanceId: "inst-1"}, agent.Metadata{OperationID: "op-prepared-3"}))
	abort := h.event(client, func(e *agentv1.Envelope) bool { return e.GetAbort() != nil }).GetAbort()
	assert.Equal(t, "rel-1", abort.GetRelease().GetReleaseId())
	assert.NotEmpty(t, abort.GetReason())
	h.noEvent(client, isActivate, 200*time.Millisecond)

	// A rejection is recorded and reported as a failed release.
	h.server.SetFaults(Faults{})
	require.NoError(t, client.SendMessage(ctx, &agentv1.Rejected{
		Release: prepare.GetRelease(),
		Error:   &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_STALE_REVISION, Reason: "unsupported build"},
	}, agent.Metadata{OperationID: "op-rejected"}))
	require.Eventually(t, func() bool {
		state, ok := h.server.Instance("inst-1")
		return ok && state.RejectedCode == agentv1.ErrorCode_ERROR_CODE_STALE_REVISION.String()
	}, testWait, 10*time.Millisecond)
	status, err := client.ReleaseStatus(ctx, &agentv1.ReleaseStatusQuery{ReleaseId: "rel-1"})
	require.NoError(t, err)
	assert.Equal(t, agentv1.ReleaseState_RELEASE_STATE_FAILED, status.GetState())
	require.Len(t, status.GetRejected(), 1)
	assert.Equal(t, agentv1.ErrorCode_ERROR_CODE_STALE_REVISION, status.GetRejected()[0].GetError().GetCode())

	// A drain request is deliverable and leaves the instance not ready.
	require.NoError(t, h.server.Drain("inst-1"))
	h.event(client, func(e *agentv1.Envelope) bool { return e.GetDrainRequested() != nil })
	require.NoError(t, client.SendMessage(ctx, &agentv1.DrainReport{InstanceId: "inst-1", Complete: true}, agent.Metadata{OperationID: "op-drain"}))
	require.Eventually(t, func() bool {
		state, ok := h.server.Instance("inst-1")
		return ok && state.Draining && !state.Ready
	}, testWait, 10*time.Millisecond)

	// A readiness report is recorded on its own and clears the drain state.
	require.NoError(t, client.SendMessage(ctx, &agentv1.ReadinessReport{InstanceId: "inst-1", Ready: true}, agent.Metadata{OperationID: "op-ready"}))
	require.Eventually(t, func() bool {
		state, ok := h.server.Instance("inst-1")
		return ok && state.Ready && !state.Draining
	}, testWait, 10*time.Millisecond)

	kinds := h.journalKinds()
	for _, kind := range []string{"Prepared", "Rejected", "DrainReport", "ReadinessReport"} {
		assert.Contains(t, kinds, kind)
	}
}

func TestRevocationBroadcastAndMonotonicity(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	client := h.dial("inst-1", "boot-1")
	h.register(client, "inst-1", "boot-1", "op-register")

	bundle, err := h.server.PublishBundle(h.release("rel-1", 1))
	require.NoError(t, err)
	require.NoError(t, client.Subscribe(ctx, "sub-bundle", &agentv1.Cursor{Kind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, Key: bundle.Key}))
	h.event(client, func(e *agentv1.Envelope) bool { return e.GetSnapshot() != nil })

	require.NoError(t, h.server.Prepare("inst-1", bundle, 0))
	prepare := h.event(client, func(e *agentv1.Envelope) bool { return e.GetPrepare() != nil }).GetPrepare()
	require.NoError(t, client.SendMessage(ctx, &agentv1.Prepared{Release: prepare.GetRelease(), InstanceId: "inst-1"}, agent.Metadata{OperationID: "op-prepared"}))
	h.event(client, func(e *agentv1.Envelope) bool { return e.GetActivate() != nil })

	revocation, err := h.server.PublishRevocation(1, time.Minute, true, bundle.Hash)
	require.NoError(t, err)
	assert.Equal(t, agentv1.ResourceKind_RESOURCE_KIND_REVOCATION, revocation.Kind)

	// A subscriber of a revoked bundle is told the resource is gone, and every
	// session receives the command because a revocation is service scoped.
	invalidated := h.event(client, func(e *agentv1.Envelope) bool { return e.GetInvalidated() != nil })
	assert.Equal(t, bundle.Key, invalidated.GetResourceKey())
	revoke := h.event(client, func(e *agentv1.Envelope) bool { return e.GetRevoke() != nil }).GetRevoke()
	assert.Equal(t, uint64(1), revoke.GetEpoch())
	assert.Equal(t, []string{hex.EncodeToString(bundle.Hash[:])}, revoke.GetBundleHashes())
	assert.True(t, revoke.GetCancelActiveStreams())

	// Canceling the revoked stream ends the session of the instance that prepared
	// it, so a gateway cannot keep serving a revoked release.
	var gone *agent.GoAwayError
	require.ErrorAs(t, waitDone(t, client), &gone)

	// The epoch only advances, and a revoked bundle can no longer be activated.
	_, err = h.server.PublishRevocation(1, time.Minute, false, bundle.Hash)
	require.ErrorIs(t, err, ErrRevision)
	_, err = h.server.PublishBundle(h.release("rel-1", 1))
	require.ErrorIs(t, err, ErrRevoked)
	require.ErrorIs(t, h.server.Activate("inst-1"), ErrRevoked)
	require.ErrorIs(t, h.server.Prepare("inst-1", bundle, 0), ErrUnknown)

	// The digest set is a union, so a later epoch keeps the earlier revocation.
	second, err := h.server.PublishRevocation(2, time.Minute, false)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), second.Ref.GetRevision())
	document := gogw.RevocationDocument{}
	require.NoError(t, json.Unmarshal(second.Signed.GetPayload(), &document, json.RejectUnknownMembers(true)))
	assert.Equal(t, documentSchema, document.Schema)
	assert.Equal(t, uint64(2), document.Epoch)
	assert.Equal(t, []string{hex.EncodeToString(bundle.Hash[:])}, document.BundleHashes)
	assert.False(t, document.CancelActiveStreams)
	assert.Greater(t, document.ExpiresUnixMs, time.Now().UnixMilli())
}

func TestFaults(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A refused registration is a correlated error, and because an operation is
	// idempotent the recorded failure is replayed even once the fault is gone.
	h.server.SetFaults(Faults{RegisterError: &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_BACKEND_UNAVAILABLE, Reason: "registry down", Retryable: true}})
	client := h.dial("inst-1", "boot-1")
	register := func(operationID string) error {
		_, err := client.Register(ctx, operationID, &agentv1.Register{Instance: &agentv1.Instance{InstanceId: "inst-1", BootId: "boot-1"}})
		return err
	}
	requireRemoteCode(t, register("op-register"), agentv1.ErrorCode_ERROR_CODE_BACKEND_UNAVAILABLE)
	h.server.SetFaults(Faults{})
	requireRemoteCode(t, register("op-register"), agentv1.ErrorCode_ERROR_CODE_BACKEND_UNAVAILABLE)

	// A fresh operation id registers once the fault is cleared.
	h.register(client, "inst-1", "boot-1", "op-register-2")
	h.server.SetFaults(Faults{RenewError: &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_BACKEND_UNAVAILABLE, Retryable: true}})
	_, err := client.RenewLease(ctx, "op-renew", &agentv1.RenewLease{InstanceId: "inst-1", BootId: "boot-1"})
	requireRemoteCode(t, err, agentv1.ErrorCode_ERROR_CODE_BACKEND_UNAVAILABLE)
	h.server.SetFaults(Faults{DropRenew: true})
	_, err = client.RenewLease(ctx, "op-renew-drop", &agentv1.RenewLease{InstanceId: "inst-1", BootId: "boot-1"})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	h.server.SetFaults(Faults{})

	// A refused subscription ends the session: a subscription has no correlated
	// refusal, and an unsolicited error is terminal for a conforming client.
	h.server.SetFaults(Faults{SubscribeError: &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_RATE_LIMITED, Retryable: true, RetryAfterMs: 50}})
	require.NoError(t, client.Subscribe(ctx, "sub-lost", &agentv1.Cursor{Kind: agentv1.ResourceKind_RESOURCE_KIND_REVOCATION, Key: gogw.RevocationKey}))
	var remote *agent.RemoteError
	require.ErrorAs(t, waitDone(t, client), &remote)
	assert.Equal(t, agentv1.ErrorCode_ERROR_CODE_RATE_LIMITED, remote.Detail.GetCode())
	require.Eventually(t, func() bool { return h.server.Sessions() == 0 }, testWait, 10*time.Millisecond)
	h.server.SetFaults(Faults{})

	// A dropped snapshot withholds the initial delivery but keeps the session and
	// the subscription, so the next publication is still a complete snapshot.
	h.server.SetFaults(Faults{DropSnapshot: true})
	bundle, err := h.server.PublishBundle(h.release("rel-1", 1))
	require.NoError(t, err)
	silent := h.dial("inst-2", "boot-1")
	require.NoError(t, silent.Subscribe(ctx, "sub-bundle", &agentv1.Cursor{Kind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, Key: bundle.Key}))
	h.noEvent(silent, func(e *agentv1.Envelope) bool { return e.GetSnapshot() != nil }, 300*time.Millisecond)
	h.server.SetFaults(Faults{})
	assert.Equal(t, 1, h.server.Sessions(), "a withheld snapshot kept the session alive")

	// The connection lifetime fault sends GoAway and disconnects after the
	// injected number of inbound messages, with the requested reconnect delay.
	h.server.SetFaults(Faults{GoAwayAfter: 2, GoAwayRetryAfter: 2 * time.Second})
	away := h.dial("inst-3", "boot-1")
	h.register(away, "inst-3", "boot-1", "op-register-3")
	require.NoError(t, away.SendMessage(ctx, &agentv1.ReadinessReport{InstanceId: "inst-3", Ready: true}, agent.Metadata{OperationID: "op-ready"}))
	var gone *agent.GoAwayError
	require.ErrorAs(t, waitDone(t, away), &gone)
	assert.Equal(t, 2*time.Second, gone.RetryAfter)
	h.server.SetFaults(Faults{})

	// The instance registry survives the disconnect, so a reconnect is judged by
	// the lease rather than by the transport that created it.
	state, ok := h.server.Instance("inst-3")
	require.True(t, ok)
	assert.Greater(t, state.LeaseExpiresUnixMs, time.Now().UnixMilli())
	reconnected := h.dial("inst-3", "boot-1")
	registered := h.register(reconnected, "inst-3", "boot-1", "op-register-again")
	assert.Equal(t, uint64(2), registered.GetInstance().GetLease().GetEpoch())
}

func TestDiscoveryPublication(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	first := h.dial("inst-1", "boot-1")
	h.register(first, "inst-1", "boot-1", "op-register-1")
	second := h.dial("inst-2", "boot-1")
	h.register(second, "inst-2", "boot-1", "op-register-2")

	bundle, err := h.server.PublishBundle(h.release("rel-1", 1))
	require.NoError(t, err)
	members := h.server.Members(bundle.Hash)
	require.Len(t, members, 2)
	assert.Equal(t, "inst-1", members[0].InstanceID)
	assert.Equal(t, "inst-2", members[1].InstanceID)
	for _, member := range members {
		assert.Equal(t, "https://127.0.0.1:8443", member.URL)
		assert.Equal(t, "localhost", member.TLSServerName)
		assert.Equal(t, "build-1", member.BuildID)
		assert.Equal(t, uint32(agentv1.ProtocolMajor), member.ProtocolVersion)
		assert.True(t, member.Ready)
		assert.False(t, member.Draining)
		assert.Equal(t, uint64(1), member.LeaseEpoch)
		assert.Greater(t, member.LeaseExpiresUnixMs, time.Now().UnixMilli())
		assert.Nil(t, member.Prepared)
		assert.True(t, digestString(member.Certificate.SHA256), "the placeholder certificate identity keeps a member dispatchable")
	}

	// Prepared evidence is attached only to the instance that reported it.
	require.NoError(t, h.server.Prepare("inst-2", bundle, 0))
	prepare := h.event(second, func(e *agentv1.Envelope) bool { return e.GetPrepare() != nil }).GetPrepare()
	require.NoError(t, second.SendMessage(ctx, &agentv1.Prepared{Release: prepare.GetRelease(), InstanceId: "inst-2", ExpiresUnixMs: time.Now().Add(time.Minute).UnixMilli()}, agent.Metadata{OperationID: "op-prepared"}))
	require.Eventually(t, func() bool {
		for _, member := range h.server.Members(bundle.Hash) {
			if member.InstanceID == "inst-2" {
				return member.Prepared != nil
			}
		}
		return false
	}, testWait, 10*time.Millisecond)
	for _, member := range h.server.Members(bundle.Hash) {
		if member.InstanceID == "inst-1" {
			assert.Nil(t, member.Prepared)
		}
	}

	// IgnorePrepared withholds the evidence without changing membership.
	h.server.SetFaults(Faults{IgnorePrepared: true})
	for _, member := range h.server.Members(bundle.Hash) {
		assert.Nil(t, member.Prepared)
	}
	h.server.SetFaults(Faults{})
	assert.Len(t, h.server.Members(bundle.Hash), 2)

	// A release file overrides the endpoint it names and appends an authored one
	// for an instance the mock never observed.
	overridden := OverlayMembers(members, []gogw.Member{{
		InstanceID:    "inst-1",
		URL:           "https://10.0.0.10:9443",
		TLSServerName: "gateway.example",
		Certificate:   gogw.CertificateIdentity{SHA256: strings.Repeat("ab", 32)},
	}, {
		InstanceID:    "inst-3",
		BootID:        "boot-3",
		BuildID:       "build-1",
		URL:           "https://10.0.0.11:9443",
		TLSServerName: "gateway.example",
		Certificate:   gogw.CertificateIdentity{SHA256: strings.Repeat("cd", 32)},
	}})
	require.Len(t, overridden, 3)
	assert.Equal(t, "https://10.0.0.10:9443", overridden[0].URL)
	assert.Equal(t, "gateway.example", overridden[0].TLSServerName)
	assert.Equal(t, strings.Repeat("ab", 32), overridden[0].Certificate.SHA256)
	assert.Equal(t, "inst-3", overridden[2].InstanceID)

	resource, err := h.server.PublishDiscovery(bundle.Hash, 1, time.Minute, overridden)
	require.NoError(t, err)
	document := gogw.DiscoveryDocument{}
	require.NoError(t, json.Unmarshal(resource.Signed.GetPayload(), &document, json.RejectUnknownMembers(true)))
	assert.Equal(t, documentSchema, document.Schema)
	assert.Equal(t, hex.EncodeToString(bundle.Hash[:]), document.BundleHash)
	assert.Equal(t, uint64(1), document.Revision)
	assert.Len(t, document.Members, 3)
	assert.Greater(t, document.ExpiresUnixMs, time.Now().UnixMilli())

	// A changed document must advance the revision, which is the rollback a
	// gateway watermark refuses, and empty membership is a valid document, which
	// is what a release with no registered instance publishes.
	_, err = h.server.PublishDiscovery(bundle.Hash, 1, time.Minute, overridden[1:])
	require.ErrorIs(t, err, ErrRevision)
	empty, err := h.server.PublishDiscovery(bundle.Hash, 2, time.Minute, nil)
	require.NoError(t, err)
	document = gogw.DiscoveryDocument{}
	require.NoError(t, json.Unmarshal(empty.Signed.GetPayload(), &document, json.RejectUnknownMembers(true)))
	assert.Empty(t, document.Members)

	// A member a gateway could not dispatch to is refused at publication.
	_, err = h.server.PublishDiscovery(bundle.Hash, 3, time.Minute, []gogw.Member{{
		InstanceID:    "inst-4",
		BootID:        "boot-4",
		BuildID:       "build-1",
		TLSServerName: "gateway.example",
		URL:           "https://gateway.example/api?token=1",
	}})
	require.ErrorIs(t, err, ErrOptions)

	// Discovery reaches a subscriber of the bundle's membership key.
	watcher := h.dial("inst-4", "boot-1")
	require.NoError(t, watcher.Subscribe(ctx, "sub-discovery", &agentv1.Cursor{Kind: agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY, Key: gogw.DiscoveryKey(bundle.Hash)}))
	snapshot := h.event(watcher, func(e *agentv1.Envelope) bool { return e.GetSnapshot() != nil })
	document = gogw.DiscoveryDocument{}
	require.NoError(t, json.Unmarshal(inlineResource(snapshot).GetPayload(), &document, json.RejectUnknownMembers(true)))
	assert.Equal(t, uint64(2), document.Revision)
	assert.Empty(t, document.Members)
}

func TestReleaseFileReload(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "release.json")
	digest := strings.Repeat("ef", 32)

	file := map[string]any{
		"release": map[string]any{
			"releaseId":              "rel-1",
			"generation":             1,
			"flag":                   "checkout",
			"defaultBuild":           "stable",
			"builds":                 map[string]any{"stable": map[string]any{}, "canary": map[string]any{"imageDigest": strings.Repeat("ab", 32)}},
			"policy":                 map[string]any{"schemaVersion": 1, "workspace": "ws", "environment": "env", "manifestRevision": 1, "generatedAt": time.Now().UTC(), "flags": map[string]any{}},
			"discoveryMaxAgeSeconds": 120,
		},
		"members": []map[string]any{{
			"instanceId":    "inst-1",
			"bootId":        "boot-1",
			"buildId":       "build-1",
			"url":           "https://10.0.0.10:9443",
			"tlsServerName": "gateway.example",
			"certificate":   map[string]any{"sha256": strings.Repeat("ab", 32)},
		}},
		"revocation": map[string]any{"epoch": 1, "bundleHashes": []string{digest}, "cancelActiveStreams": true},
	}
	raw, err := json.Marshal(file)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	loaded, err := LoadReleaseFile(path)
	require.NoError(t, err)
	assert.Equal(t, "rel-1", loaded.Release.ReleaseID)
	assert.Equal(t, uint64(1), loaded.Release.Generation)
	assert.Equal(t, int64(120), loaded.Release.DiscoveryMaxAgeSeconds)
	assert.Equal(t, "ws", loaded.Release.Policy.Workspace)
	require.Len(t, loaded.Members, 1)
	assert.Equal(t, "gateway.example", loaded.Members[0].TLSServerName)
	require.NotNil(t, loaded.Revocation)
	assert.Equal(t, uint64(1), loaded.Revocation.Epoch)
	assert.True(t, loaded.Revocation.CancelActiveStreams)
	digests, err := loaded.Revocation.BundleDigests()
	require.NoError(t, err)
	require.Len(t, digests, 1)
	assert.Equal(t, digest, hex.EncodeToString(digests[0][:]))

	// The published bundle carries the document contract a gateway verifies,
	// including the policy window a release that omits it never states.
	bundle, err := h.server.PublishBundle(loaded.Release)
	require.NoError(t, err)
	document := gogw.BundleDocument{}
	require.NoError(t, json.Unmarshal(bundle.Signed.GetPayload(), &document, json.RejectUnknownMembers(true)))
	assert.Equal(t, documentSchema, document.Schema)
	assert.Equal(t, int64(120), document.DiscoveryMaxAgeSeconds)
	assert.Equal(t, int64(120), document.PolicyMaxAgeSeconds)
	assert.Equal(t, "ws", document.Policy.Workspace)

	// An omitted window falls back to the documented default instead of zero.
	bare, err := h.server.PublishBundle(h.release("rel-2", 2))
	require.NoError(t, err)
	document = gogw.BundleDocument{}
	require.NoError(t, json.Unmarshal(bare.Signed.GetPayload(), &document, json.RejectUnknownMembers(true)))
	assert.Equal(t, int64(defaultDiscoveryMaxAge), document.DiscoveryMaxAgeSeconds)
	assert.Equal(t, int64(defaultDiscoveryMaxAge), document.PolicyMaxAgeSeconds)

	// The reload is driven by the epoch only advancing.
	_, err = h.server.PublishRevocation(loaded.Revocation.Epoch, time.Minute, false)
	require.NoError(t, err)
	_, err = h.server.PublishRevocation(loaded.Revocation.Epoch, time.Minute, false)
	require.ErrorIs(t, err, ErrRevision)

	// An unknown member is rejected rather than silently dropped.
	require.NoError(t, os.WriteFile(path, []byte(`{"release":{"releaseId":"r","generation":1,"flag":"f","defaultBuild":"b","builds":{"b":{}}},"unknown":1}`), 0o600))
	_, err = LoadReleaseFile(path)
	require.Error(t, err)

	// The loader decodes the file; a malformed digest is refused when the file is
	// used, which is where a caller learns the revocation is unpublishable.
	require.NoError(t, os.WriteFile(path, []byte(`{"release":{"releaseId":"r","generation":1,"flag":"f","defaultBuild":"b","builds":{"b":{}}},"members":[],"revocation":{"epoch":1,"bundleHashes":["nothex"]}}`), 0o600))
	loaded, err = LoadReleaseFile(path)
	require.NoError(t, err)
	_, err = loaded.Revocation.BundleDigests()
	require.Error(t, err)
}

func TestHeartbeatTimeoutEndsSession(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, h.websocketURL(), &websocket.DialOptions{
		HTTPClient:   h.http.Client(),
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + testToken}},
		Subprotocols: []string{agentv1.Subprotocol},
	})
	require.NoError(t, err)
	defer func() { _ = conn.CloseNow() }()

	hello, err := agentv1.Encode(&agentv1.Envelope{
		ProtocolMajor: agentv1.ProtocolMajor,
		MessageId:     uuid.New().String(),
		Payload:       &agentv1.Envelope_Hello{Hello: &agentv1.Hello{AgentId: "agent", InstanceId: "inst-1", BootId: "boot-1"}},
	})
	require.NoError(t, err)
	require.NoError(t, conn.Write(ctx, websocket.MessageBinary, hello))
	_, frame, err := conn.Read(ctx)
	require.NoError(t, err)
	require.NotNil(t, mustDecode(t, frame).GetWelcome())
	require.Equal(t, 1, h.server.Sessions())

	// Silence past the advertised timeout ends the session, because a heartbeat is
	// the only liveness signal the protocol defines.
	for {
		if _, _, err := conn.Read(ctx); err != nil {
			assert.Equal(t, websocket.StatusPolicyViolation, websocket.CloseStatus(err))
			break
		}
	}
	assert.Eventually(t, func() bool { return h.server.Sessions() == 0 }, testWait, 10*time.Millisecond)

	// A frame that does not repeat this session's identity is a protocol violation.
	other, _, err := websocket.Dial(ctx, h.websocketURL(), &websocket.DialOptions{
		HTTPClient:   h.http.Client(),
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + testToken}},
		Subprotocols: []string{agentv1.Subprotocol},
	})
	require.NoError(t, err)
	defer func() { _ = other.CloseNow() }()
	require.NoError(t, other.Write(ctx, websocket.MessageBinary, hello))
	_, frame, err = other.Read(ctx)
	require.NoError(t, err)
	require.NotNil(t, mustDecode(t, frame).GetWelcome())

	stale, err := agentv1.Encode(&agentv1.Envelope{
		ProtocolMajor:   agentv1.ProtocolMajor,
		MessageId:       uuid.New().String(),
		SessionId:       zeroSessionID,
		ConnectionEpoch: 1,
		Payload:         &agentv1.Envelope_Heartbeat{Heartbeat: &agentv1.Heartbeat{Nonce: 1}},
	})
	require.NoError(t, err)
	require.NoError(t, other.Write(ctx, websocket.MessageBinary, stale))
	_, frame, err = other.Read(ctx)
	require.NoError(t, err)
	refusal := mustDecode(t, frame)
	require.NotNil(t, refusal.GetError())
	assert.Equal(t, agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, refusal.GetError().GetCode())
}

func TestConcurrentSessionsAndPublications(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	const agents = 8
	bundle, err := h.server.PublishBundle(h.release("rel-1", 1))
	require.NoError(t, err)

	clients := make([]*agent.Client, 0, agents)
	for i := range agents {
		clients = append(clients, h.dial(fmt.Sprintf("inst-%d", i), "boot-1"))
	}

	var group sync.WaitGroup
	var failures sync.Map
	for i, client := range clients {
		group.Go(func() {
			instanceID := fmt.Sprintf("inst-%d", i)
			registered, err := client.Register(ctx, "op-register-"+instanceID, &agentv1.Register{Instance: &agentv1.Instance{
				Scope:      h.scopeProto(),
				InstanceId: instanceID,
				BootId:     "boot-1",
				BuildId:    "build-1",
				Address:    "127.0.0.1",
				Port:       8443,
				Ready:      true,
			}})
			if err != nil {
				failures.Store(instanceID, err)
				return
			}
			lease := registered.GetInstance().GetLease()
			for round := range 5 {
				if _, err := client.RenewLease(ctx, fmt.Sprintf("op-renew-%s-%d", instanceID, round), &agentv1.RenewLease{InstanceId: instanceID, BootId: "boot-1", Lease: lease}); err != nil {
					failures.Store(instanceID, err)
					return
				}
			}
			if err := client.Subscribe(ctx, "sub-"+instanceID, &agentv1.Cursor{Kind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, Key: bundle.Key}); err != nil {
				failures.Store(instanceID, err)
			}
		})
	}
	group.Go(func() {
		for revision := uint64(1); revision <= 5; revision++ {
			_, _ = h.server.PublishDiscovery(bundle.Hash, revision, time.Minute, h.server.Members(bundle.Hash))
			time.Sleep(5 * time.Millisecond)
		}
	})
	group.Wait()
	failures.Range(func(instanceID, err any) bool {
		t.Errorf("instance %v failed: %v", instanceID, err)
		return true
	})

	require.Eventually(t, func() bool {
		members := h.server.Members(bundle.Hash)
		if len(members) != agents {
			return false
		}
		for _, member := range members {
			if member.LeaseEpoch != 1 || member.BootID != "boot-1" {
				return false
			}
		}
		return true
	}, testWait, 20*time.Millisecond)

	// Every inbound message was journaled, and the registry survives the
	// disconnect because a lease is fenced by its epoch, not by its transport.
	registers, renewals := 0, 0
	for _, entry := range h.server.Journal() {
		switch entry.Kind {
		case "Register":
			registers++
		case "RenewLease":
			renewals++
		}
	}
	assert.Equal(t, agents, registers)
	assert.Equal(t, agents*5, renewals)

	for _, client := range clients {
		require.NoError(t, client.Close())
	}
	require.Eventually(t, func() bool { return h.server.Sessions() == 0 }, testWait, 10*time.Millisecond)
	assert.Len(t, h.server.Members(bundle.Hash), agents)
	for i := range agents {
		state, ok := h.server.Instance(fmt.Sprintf("inst-%d", i))
		require.True(t, ok)
		assert.Greater(t, state.LeaseExpiresUnixMs, time.Now().UnixMilli())
		assert.Empty(t, state.PreparedHash)
	}
}

func TestPublishRejectsInvalidInput(t *testing.T) {
	h := newHarness(t)
	_, err := New(Options{Scope: h.scope, Token: testToken, KeyID: "mock"})
	require.ErrorIs(t, err, ErrOptions)
	_, err = New(Options{Token: testToken, KeyID: "mock", SigningKey: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))})
	require.ErrorIs(t, err, ErrOptions)
	_, err = New(Options{Scope: h.scope, Token: "bad\ntoken", KeyID: "mock", SigningKey: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))})
	require.ErrorIs(t, err, ErrOptions)

	_, err = h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, "", []byte("{}"), PublishOptions{Revision: 1})
	require.ErrorIs(t, err, ErrOptions)
	_, err = h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_UNSPECIFIED, "policy/1", []byte("{}"), PublishOptions{Revision: 1})
	require.ErrorIs(t, err, ErrOptions)
	_, err = h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, "policy/1", nil, PublishOptions{Revision: 1})
	require.ErrorIs(t, err, ErrOptions)

	_, err = h.server.PublishBundle(Release{})
	require.ErrorIs(t, err, ErrOptions)
	_, err = h.server.PublishBundle(h.release("rel-1", 0))
	require.ErrorIs(t, err, ErrOptions)
	_, err = h.server.PublishDiscovery(sha256.Sum256(nil), 0, time.Minute, nil)
	require.ErrorIs(t, err, ErrOptions)
	_, err = h.server.PublishRevocation(0, time.Minute, false)
	require.ErrorIs(t, err, ErrOptions)
	_, err = h.server.PublishRevocation(1, time.Minute, false, [32]byte{})
	require.ErrorIs(t, err, ErrOptions)

	absentBuild := h.release("rel-1", 1)
	absentBuild.DefaultBuild = "absent"
	_, err = h.server.PublishBundle(absentBuild)
	require.ErrorIs(t, err, ErrOptions)
	otherScope := h.release("rel-1", 1)
	otherScope.Policy = model.Snapshot{Workspace: "other", Environment: "env"}
	_, err = h.server.PublishBundle(otherScope)
	require.ErrorIs(t, err, ErrOptions)
	badRamp := h.release("rel-1", 1)
	badRamp.Ramp = &gogw.Ramp{Key: "checkout", Unit: "session", Threshold: 1, CanaryBuild: "stable"}
	_, err = h.server.PublishBundle(badRamp)
	require.ErrorIs(t, err, ErrOptions)

	// A command for an instance the mock never registered is refused, and so is
	// one for an instance whose session is gone.
	require.ErrorIs(t, h.server.Prepare("inst-absent", Resource{}, 0), ErrUnknown)
	require.ErrorIs(t, h.server.Activate("inst-absent"), ErrUnknown)
	require.ErrorIs(t, h.server.Abort("inst-absent", "none"), ErrUnknown)
	require.ErrorIs(t, h.server.Drain("inst-absent"), ErrUnknown)

	orphan := h.dial("inst-orphan", "boot-1")
	h.register(orphan, "inst-orphan", "boot-1", "op-register")
	bundle, err := h.server.PublishBundle(h.release("rel-1", 1))
	require.NoError(t, err)
	require.NoError(t, orphan.Close())
	require.Eventually(t, func() bool { return h.server.Sessions() == 0 }, testWait, 10*time.Millisecond)
	require.ErrorIs(t, h.server.Prepare("inst-orphan", bundle, 0), ErrUnavailable)
	require.ErrorIs(t, h.server.Activate("inst-orphan"), ErrUnavailable)

	// A closed mock refuses new work, and a connect attempt is refused at the
	// handshake rather than being accepted and dropped.
	h.server.Close()
	_, err = h.server.PublishRaw(agentv1.ResourceKind_RESOURCE_KIND_POLICY, "policy/closed", []byte("{}"), PublishOptions{Revision: 1})
	require.ErrorIs(t, err, ErrClosed)
	_, err = h.dialWith(agent.Options{Token: testToken, Hello: &agentv1.Hello{AgentId: "agent", InstanceId: "inst-1", BootId: "boot-1"}})
	var handshake *agent.HandshakeError
	require.ErrorAs(t, err, &handshake)
	assert.Equal(t, http.StatusServiceUnavailable, handshake.StatusCode)
}
