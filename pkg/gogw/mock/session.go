package mock

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/coder/websocket"
	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"google.golang.org/protobuf/proto"
)

const (
	controlQueueItems   = 64
	resourceQueueItems  = 256
	telemetryQueueItems = 64
	queueBytes          = 8 << 20
	maxEventsPerBatch   = 32
	messagesPerSecond   = 1024

	// eventDedupWindow is how long the mock remembers an acknowledged telemetry
	// batch, matching the retention it advertises back to the client.
	eventDedupWindow = 5 * time.Minute

	// heartbeatChecksPerTimeout probes the heartbeat deadline this many times per
	// timeout, so a stalled link is dropped promptly without a per-session timer.
	heartbeatChecksPerTimeout = 4

	// reasonUnknownInstance is the refusal every command naming an instance the
	// registry does not hold answers with.
	reasonUnknownInstance = "unknown instance"
)

var capabilities = []string{"resources.v1", "leases.v1", "releases.v1", "revocation.v1", "streams.v1"}

// subscription is one accepted resource subscription of a session. Server.mu
// guards every field, because delivery walks the subscriptions of all sessions.
type subscription struct {
	id    string
	kind  agentv1.ResourceKind
	key   string
	token []byte
	// known is the revision of the last resource delivered on this subscription,
	// which decides whether the next publication is continuous enough for a Delta.
	known uint64
	// invalidated records that the resource was withdrawn, so the next delivery
	// must be a complete Snapshot instead of a Delta from a stale base.
	invalidated bool
}

// session is one live protocol connection. The reader runs on the HTTP handler
// goroutine while a writer goroutine owns the socket, so no two goroutines write
// at once and frames leave in the order they were queued.
type session struct {
	server *Server
	conn   *websocket.Conn

	id    string
	epoch uint64

	// subs is guarded by Server.mu.
	subs []*subscription

	out  chan *agentv1.Envelope
	done chan struct{}
	once sync.Once

	// closeCode and closeReason are decided once, by the first goroutine that
	// stops the session, and consumed by the writer's close frame.
	mu          sync.Mutex
	closeCode   websocket.StatusCode
	closeReason string

	// seen and seq are the heartbeat deadline and the inbound message count.
	seen atomic.Int64
	seq  atomic.Int64
}

// bind registers one accepted connection and allocates its session identity.
// The epoch is monotonic across sessions, so a peer can always tell how many
// connections the mock has admitted.
func (s *Server) bind(conn *websocket.Conn) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch++
	sess := &session{
		server: s,
		conn:   conn,
		id:     uuid.New().String(),
		epoch:  s.epoch,
		out:    make(chan *agentv1.Envelope, sessionQueue),
		done:   make(chan struct{}),
	}
	sess.seen.Store(s.now().UnixNano())
	s.sessions[sess.id] = sess
	return sess
}

// release drops one session and unbinds the instance it registered. The registry
// entry itself survives, because a lease is fenced by its epoch and its expiry,
// not by the transport that created it: a reconnect keeps its instance identity.
func (s *Server) release(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sess.id)
	for _, rec := range s.instances {
		if rec.session == sess.id {
			rec.session = ""
		}
	}
}

// newEnvelope stamps one outbound message with the session header. Every frame
// after the welcome repeats the session id, the connection epoch and the
// negotiated minor, or a conforming client ends the session as a protocol error.
func (sess *session) newEnvelope() *agentv1.Envelope {
	return &agentv1.Envelope{
		ProtocolMajor:   agentv1.ProtocolMajor,
		ProtocolMinor:   agentv1.ProtocolMinor,
		SessionId:       sess.id,
		ConnectionEpoch: sess.epoch,
		MessageId:       uuid.New().String(),
	}
}

// response copies one payload body into a correlated reply. A call made with the
// SDK's Call is matched by ReplyTo, so an uncorrelated answer would be dropped.
func (sess *session) response(request, body *agentv1.Envelope) *agentv1.Envelope {
	reply := sess.newEnvelope()
	reply.ReplyTo = request.GetMessageId()
	reply.OperationId = request.GetOperationId()
	reply.SubscriptionId = request.GetSubscriptionId()
	reply.ResourceKind = request.GetResourceKind()
	reply.ResourceKey = request.GetResourceKey()
	reply.Payload = body.GetPayload()
	return reply
}

// errorReply is the correlated refusal of one request.
func (sess *session) errorReply(request *agentv1.Envelope, err *agentv1.Error) *agentv1.Envelope {
	return sess.response(request, &agentv1.Envelope{Payload: &agentv1.Envelope_Error{Error: err}})
}

// replayOperation re-stamps one recorded reply for a retry of the same logical
// operation. Only transport identifiers change, so a gateway that retries after
// an unknown outcome observes the original result instead of a second effect.
func (sess *session) replayOperation(cached, request *agentv1.Envelope) *agentv1.Envelope {
	reply := proto.Clone(cached).(*agentv1.Envelope)
	reply.ProtocolMajor = agentv1.ProtocolMajor
	reply.ProtocolMinor = agentv1.ProtocolMinor
	reply.SessionId = sess.id
	reply.ConnectionEpoch = sess.epoch
	reply.MessageId = uuid.New().String()
	reply.ReplyTo = request.GetMessageId()
	return reply
}

// enqueue queues one outbound message. With drop it is best effort; otherwise a
// full queue means the peer stopped reading and the session is terminated,
// because silently losing a snapshot or a delta desynchronizes its cursor.
func (sess *session) enqueue(body *agentv1.Envelope, drop bool) {
	select {
	case sess.out <- body:
		return
	default:
	}
	if drop {
		return
	}
	sess.stop(websocket.StatusPolicyViolation, "outbound queue overflow")
}

// stop records how the session ended and signals the writer, which is the only
// goroutine that closes the socket. Only the first caller decides the reason.
func (sess *session) stop(code websocket.StatusCode, reason string) {
	sess.once.Do(func() {
		sess.mu.Lock()
		sess.closeCode, sess.closeReason = code, reason
		sess.mu.Unlock()
		close(sess.done)
	})
}

// closeInfo returns the recorded close frame of a stopped session.
func (sess *session) closeInfo() (websocket.StatusCode, string) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.closeCode, sess.closeReason
}

// stopped reports whether the session was already asked to end.
func (sess *session) stopped() bool {
	select {
	case <-sess.done:
		return true
	default:
		return false
	}
}

// shutdown asks the peer to reconnect: it queues a GoAway before stopping, so the
// writer still flushes the command that tells the client how long to wait.
func (sess *session) shutdown(reason string, retryAfter time.Duration) {
	if retryAfter < 0 {
		retryAfter = 0
	}
	body := sess.newEnvelope()
	body.Payload = &agentv1.Envelope_GoAway{GoAway: &agentv1.GoAway{
		Reason:       reason,
		RetryAfterMs: uint32(retryAfter / time.Millisecond),
		CloseUnixMs:  sess.server.now().Add(time.Second).UnixMilli(),
	}}
	sess.enqueue(body, true)
	sess.stop(websocket.StatusGoingAway, reason)
}

// failError sends one unsolicited Error and ends the session. A one-way report
// has no correlated refusal, and an unsolicited error is terminal for a
// conforming client, so the peer reconnects and resynchronizes explicitly.
func (sess *session) failError(err *agentv1.Error) {
	body := sess.newEnvelope()
	body.Payload = &agentv1.Envelope_Error{Error: err}
	sess.enqueue(body, true)
	sess.stop(websocket.StatusPolicyViolation, err.GetReason())
}

// fail is failError for a code and reason pair.
func (sess *session) fail(code agentv1.ErrorCode, reason string) {
	sess.failError(&agentv1.Error{Code: code, Reason: reason})
}

// revoke delivers one Revoke command. The command is service scoped, so every
// live session receives it; canceling streams additionally ends the session of
// an instance that holds a revoked bundle, so it cannot keep serving one.
func (sess *session) revoke(epoch uint64, hashes []string, cancel bool) {
	body := sess.newEnvelope()
	body.OperationId = uuid.New().String()
	body.Payload = &agentv1.Envelope_Revoke{Revoke: &agentv1.Revoke{Epoch: epoch, BundleHashes: hashes, CancelActiveStreams: cancel}}
	sess.enqueue(body, false)
	if cancel {
		sess.shutdown("revoked streams canceled", leaseRenewInterval)
	}
}

// subscription resolves the session's subscription of one resource. The protocol
// keys subscriptions by resource, so subscribing again updates the existing
// entry instead of stacking a duplicate delivery. Server.mu must be held.
func (sess *session) subscription(kind agentv1.ResourceKind, key string) *subscription {
	for _, sub := range sess.subs {
		if sub.kind == kind && sub.key == key {
			return sub
		}
	}
	sub := &subscription{kind: kind, key: key}
	sess.subs = append(sess.subs, sub)
	return sub
}

// subscriptionOf returns one subscription by the identifier the client chose.
// Server.mu must be held.
func (sess *session) subscriptionOf(id string) *subscription {
	for _, sub := range sess.subs {
		if sub.id == id {
			return sub
		}
	}
	return nil
}

// dropSubscription removes one subscription. Server.mu must be held.
func (sess *session) dropSubscription(id string) {
	sess.subs = slices.DeleteFunc(sess.subs, func(sub *subscription) bool { return sub.id == id })
}

// instanceLocked resolves the instance one report refers to: the one it names,
// or the one this session registered when the report leaves the identifier out.
// Server.mu must be held.
func (sess *session) instanceLocked(instanceID string) (*instance, bool) {
	if instanceID == "" {
		instanceID = sess.instanceID()
	}
	rec, ok := sess.server.instances[instanceID]
	return rec, ok
}

// instanceID reports the instance currently bound to this session. Server.mu
// must be held.
func (sess *session) instanceID() string {
	for _, rec := range sess.server.instances {
		if rec.session == sess.id {
			return rec.InstanceID
		}
	}
	return ""
}

// limits renders the advertised session limits.
func (s *Server) limits() *agentv1.Limits {
	interval := max(int64(1), s.heartbeat.Milliseconds())
	timeout := max(interval+1, s.timeout.Milliseconds())
	return &agentv1.Limits{
		MaxFrameBytes:        uint32(maxFrameBytes),
		MaxSubscriptions:     maxSubscriptions,
		HeartbeatIntervalMs:  uint32(interval),
		HeartbeatTimeoutMs:   uint32(timeout),
		LeaseTtlMs:           uint32(leaseTTL / time.Millisecond),
		LeaseRenewIntervalMs: uint32(leaseRenewInterval / time.Millisecond),
		MaxResourceBytes:     uint64(maxResourceBytes),
		ControlQueueItems:    controlQueueItems,
		ResourceQueueItems:   resourceQueueItems,
		TelemetryQueueItems:  telemetryQueueItems,
		QueueBytes:           queueBytes,
		MaxEventsPerBatch:    maxEventsPerBatch,
		MessagesPerSecond:    messagesPerSecond,
	}
}

// serveConnect upgrades one authenticated connection and owns it until it ends.
// The handler does not return while the session lives, which keeps the lifetime
// of a hijacked connection bound to a single goroutine.
func (s *Server) serveConnect(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="grayling.agent.v1"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		http.Error(w, "control plane closed", http.StatusServiceUnavailable)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{agentv1.Subprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	// The request context is unsafe to use after a hijack, so the session owns
	// its own cancellation: the socket and the session's done channel end it. Once
	// the session is bound the writer owns the socket and is the only goroutine
	// that closes it, so a frame queued on the way out still reaches the peer.
	conn.SetReadLimit(int64(maxFrameBytes))
	if conn.Subprotocol() != agentv1.Subprotocol {
		_ = conn.Close(websocket.StatusProtocolError, "subprotocol required")
		return
	}
	sess := s.bind(conn)
	defer s.release(sess)
	go sess.writeLoop()
	go sess.watchdog()
	if err := sess.handshake(); err != nil {
		return
	}
	sess.readLoop()
}

// handshake reads the one hello a session may send and answers it with the
// welcome that establishes the session identity and the negotiated minor.
func (sess *session) handshake() error {
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	typ, frame, err := sess.conn.Read(ctx)
	if err != nil {
		return err
	}
	sess.seen.Store(sess.server.now().UnixNano())
	if typ != websocket.MessageBinary {
		sess.fail(agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "binary frames only")
		return errors.New("mock: non binary handshake")
	}
	hello, err := agentv1.Decode(frame)
	if err != nil {
		sess.fail(protocolCode(err), protocolReason(err))
		return err
	}
	sess.server.noteInbound(hello)
	if hello.GetHello() == nil {
		sess.fail(agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_MESSAGE, "hello required")
		return errors.New("mock: missing hello")
	}
	if hello.GetHello().GetMinMinor() > 0 {
		sess.fail(agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_MESSAGE, "unsupported minor")
		return errors.New("mock: unsupported minor")
	}
	welcome := sess.newEnvelope()
	welcome.ReplyTo = hello.GetMessageId()
	welcome.Payload = &agentv1.Envelope_Welcome{Welcome: &agentv1.Welcome{
		Scope:             sess.server.scopeProto(),
		ServerUnixMs:      sess.server.now().UnixMilli(),
		Capabilities:      capabilities,
		Limits:            sess.server.limits(),
		ControlPlaneEpoch: controlPlaneEpoch,
	}}
	if err := sess.flush(welcome); err != nil {
		return err
	}
	sess.seq.Store(1)
	return nil
}

// readLoop dispatches every frame until the connection or the session ends.
func (sess *session) readLoop() {
	for {
		typ, frame, err := sess.conn.Read(context.Background())
		if err != nil {
			sess.stop(websocket.StatusNormalClosure, "read end")
			return
		}
		sess.seen.Store(sess.server.now().UnixNano())
		if typ != websocket.MessageBinary {
			sess.fail(agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "binary frames only")
			return
		}
		body, err := agentv1.Decode(frame)
		if err != nil {
			sess.fail(protocolCode(err), protocolReason(err))
			return
		}
		if body.GetSessionId() != sess.id || body.GetConnectionEpoch() != sess.epoch {
			sess.fail(agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "unknown session")
			return
		}
		if body.GetHello() != nil || body.GetWelcome() != nil {
			sess.fail(agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_MESSAGE, "handshake repeated")
			return
		}
		faults := sess.server.currentFaults()
		if faults.GoAwayAfter > 0 && int(sess.seq.Add(1)) > faults.GoAwayAfter {
			sess.shutdown("connection lifetime reached", faults.GoAwayRetryAfter)
			return
		}
		sess.dispatch(body)
		if sess.stopped() {
			return
		}
	}
}

// writeLoop owns the socket. It drains what the stop path queued before closing,
// so a GoAway or a final command still reaches the peer.
func (sess *session) writeLoop() {
	defer func() { _ = sess.conn.CloseNow() }()
	for {
		select {
		case <-sess.done:
			for {
				select {
				case body := <-sess.out:
					if err := sess.flush(body); err != nil {
						return
					}
					continue
				default:
				}
				break
			}
			code, reason := sess.closeInfo()
			if code == 0 {
				code = websocket.StatusNormalClosure
			}
			_ = sess.conn.Close(code, reason)
			return
		case body := <-sess.out:
			if err := sess.flush(body); err != nil {
				sess.stop(websocket.StatusInternalError, "write failed")
				return
			}
		}
	}
}

// flush writes one frame under a bounded deadline, so a stalled peer cannot hold
// the session's writer open indefinitely.
func (sess *session) flush(body *agentv1.Envelope) error {
	frame, err := agentv1.Encode(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return sess.conn.Write(ctx, websocket.MessageBinary, frame)
}

// watchdog drops a link that stopped heartbeating. The advertised timeout is the
// deadline, and the heartbeat is the only liveness signal the protocol defines.
func (sess *session) watchdog() {
	interval := sess.server.timeout / heartbeatChecksPerTimeout
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-sess.done:
			return
		case <-ticker.C:
			if sess.server.now().UnixNano()-sess.seen.Load() > sess.server.timeout.Nanoseconds() {
				sess.stop(websocket.StatusPolicyViolation, "heartbeat timeout")
				return
			}
		}
	}
}

// dispatch executes one inbound message at most once. A message carrying an
// operation id is replayed from its recorded result, so a retry after an unknown
// outcome cannot duplicate a side effect such as a lease bump or an activation.
func (sess *session) dispatch(body *agentv1.Envelope) {
	s := sess.server
	s.noteInbound(body)
	if body.GetOperationId() != "" {
		if cached, ok := s.cachedOperation(body.GetOperationId()); ok {
			if cached != nil {
				sess.enqueue(sess.replayOperation(cached, body), false)
			}
			return
		}
	}
	reply := sess.handle(body)
	if reply != nil {
		sess.enqueue(reply, false)
	}
	if body.GetOperationId() != "" {
		s.rememberOperation(body.GetOperationId(), reply)
	}
}

// handle executes one message and returns the correlated reply the protocol
// defines for it, or nil when the message is a one-way report.
func (sess *session) handle(body *agentv1.Envelope) *agentv1.Envelope {
	switch {
	case body.GetHeartbeat() != nil:
		return sess.onHeartbeat(body)
	case body.GetGoodbye() != nil:
		sess.shutdown("client goodbye", 0)
		return nil
	case body.GetSubscribe() != nil:
		return sess.onSubscribe(body)
	case body.GetUnsubscribe() != nil:
		return sess.onUnsubscribe(body)
	case body.GetResume() != nil:
		return sess.onResume(body)
	case body.GetRegister() != nil:
		return sess.onRegister(body)
	case body.GetRenewLease() != nil:
		return sess.onRenewLease(body)
	case body.GetUpdateInstance() != nil:
		return sess.onUpdateInstance(body)
	case body.GetDeregister() != nil:
		return sess.onDeregister(body)
	case body.GetFetchResource() != nil:
		return sess.onFetchResource(body)
	case body.GetResourceApplied() != nil, body.GetResourceRejected() != nil:
		// Resource acceptance is recorded in the journal only: the mock owns no
		// policy revision to reconcile against a gateway's applied resource.
		return nil
	case body.GetPrepared() != nil:
		return sess.onPrepared(body)
	case body.GetApplied() != nil:
		return sess.onApplied(body)
	case body.GetRejected() != nil:
		return sess.onRejected(body)
	case body.GetReleaseStatusQuery() != nil:
		return sess.onReleaseStatusQuery(body)
	case body.GetReadinessReport() != nil:
		return sess.onReadinessReport(body)
	case body.GetDrainReport() != nil:
		return sess.onDrainReport(body)
	case body.GetEventBatch() != nil:
		return sess.onEventBatch(body)
	default:
		sess.fail(agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_MESSAGE, "unsupported message")
		return nil
	}
}

func (sess *session) onHeartbeat(body *agentv1.Envelope) *agentv1.Envelope {
	return sess.response(body, &agentv1.Envelope{Payload: &agentv1.Envelope_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
		Nonce:        body.GetHeartbeat().GetNonce(),
		ServerUnixMs: sess.server.now().UnixMilli(),
	}}})
}

// onSubscribe accepts one subscription and answers with the current resource. A
// resource that is not published yet is not an error: the first publication
// delivers a Snapshot, which is exactly what an empty cursor asks for.
func (sess *session) onSubscribe(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	subscribe := body.GetSubscribe()
	cursor := subscribe.GetCursor()
	if cursor.GetKind() < agentv1.ResourceKind_RESOURCE_KIND_POLICY || cursor.GetKind() > agentv1.ResourceKind_RESOURCE_KIND_REVOCATION || !validResourceKey(cursor.GetKey()) {
		sess.fail(agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "invalid cursor")
		return nil
	}
	if scope := subscribe.GetScope(); scope != nil && !s.matches(scope) {
		sess.fail(agentv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "scope mismatch")
		return nil
	}
	if !validSubscriptionID(body.GetSubscriptionId()) {
		sess.fail(agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "invalid subscription id")
		return nil
	}
	faults := s.currentFaults()
	if faults.SubscribeError != nil {
		sess.failError(proto.Clone(faults.SubscribeError).(*agentv1.Error))
		return nil
	}
	var out *agentv1.Envelope
	s.mu.Lock()
	sub := sess.subscription(cursor.GetKind(), cursor.GetKey())
	if sub.id == "" && len(sess.subs) > maxSubscriptions {
		s.mu.Unlock()
		sess.fail(agentv1.ErrorCode_ERROR_CODE_RATE_LIMITED, "subscription limit exceeded")
		return nil
	}
	sub.id = body.GetSubscriptionId()
	sub.token = append(sub.token[:0], cursor.GetResumeToken()...)
	sub.known = 0
	sub.invalidated = false
	if rec := s.recordOf(cursor.GetKind(), cursor.GetKey()); rec != nil && !faults.DropSnapshot {
		out = sess.snapshot(sub.id, rec)
		sub.known = rec.revision
	}
	s.mu.Unlock()
	if out != nil {
		sess.enqueue(out, false)
	}
	return nil
}

func (sess *session) onUnsubscribe(body *agentv1.Envelope) *agentv1.Envelope {
	sess.server.mu.Lock()
	sess.dropSubscription(body.GetSubscriptionId())
	sess.server.mu.Unlock()
	return nil
}

// onResume re-sends the current resource when the token belongs to the session's
// subscription. An unknown token, or an injected resync, must send the client
// back to a complete Snapshot rather than a Delta it cannot apply.
func (sess *session) onResume(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	if !validSubscriptionID(body.GetSubscriptionId()) {
		sess.fail(agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "invalid subscription id")
		return nil
	}
	faults := s.currentFaults()
	var out *agentv1.Envelope
	s.mu.Lock()
	sub := sess.subscriptionOf(body.GetSubscriptionId())
	switch {
	case faults.ForceResync:
		out = sess.resync(sess.newEnvelope(), "resync forced by the control plane")
	case sub == nil:
		out = sess.resync(sess.newEnvelope(), "unknown subscription")
	case !sub.resumable(body.GetResume().GetToken()):
		out = sess.resync(sess.newEnvelope(), "unknown resume token")
	default:
		rec := s.recordOf(sub.kind, sub.key)
		if rec == nil {
			out = sess.resync(sess.newEnvelope(), "no current resource")
			break
		}
		out = sess.snapshot(sub.id, rec)
		sub.known = rec.revision
		sub.invalidated = false
	}
	s.mu.Unlock()
	out.SubscriptionId = body.GetSubscriptionId()
	sess.enqueue(out, false)
	return nil
}

// resumable reports whether a resume token belongs to this subscription. The
// published protocol has no server-to-client field that could carry a token, so
// the mock accepts the token the client supplied at subscribe time and, as a
// convenience, the subscription identifier itself.
func (sub *subscription) resumable(token []byte) bool {
	if len(token) == 0 {
		return false
	}
	return bytes.Equal(sub.token, token) || string(token) == sub.id
}

// snapshot renders one complete delivery of a resource for a subscription.
// Server.mu must be held.
func (sess *session) snapshot(subscriptionID string, rec *record) *agentv1.Envelope {
	body := sess.newEnvelope()
	body.SubscriptionId = subscriptionID
	body.ResourceKind = rec.id.kind
	body.ResourceKey = rec.id.key
	body.ResourceRevision = rec.revision
	body.Payload = &agentv1.Envelope_Snapshot{Snapshot: &agentv1.Snapshot{
		Scope:    sess.server.scopeProto(),
		Revision: rec.revision,
		Content:  &agentv1.Snapshot_InlineResource{InlineResource: rec.signed},
	}}
	return body
}

// resync is the unsolicited command that sends a subscription back to a full
// snapshot.
func (sess *session) resync(body *agentv1.Envelope, reason string) *agentv1.Envelope {
	body.Payload = &agentv1.Envelope_ResyncRequired{ResyncRequired: &agentv1.ResyncRequired{Reason: reason}}
	return body
}

// onRegister allocates a fresh fenced lease. A new boot replaces the reported
// release state, because the process that reported it no longer exists.
func (sess *session) onRegister(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	register := body.GetRegister()
	registered := register.GetInstance()
	if faults := s.currentFaults(); faults.RegisterError != nil {
		return sess.errorReply(body, proto.Clone(faults.RegisterError).(*agentv1.Error))
	}
	if !validText(registered.GetInstanceId()) || len(registered.GetInstanceId()) > maxIdentifier ||
		!validText(registered.GetBootId()) || len(registered.GetBootId()) > maxIdentifier {
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Reason: "invalid instance identity"})
	}
	if scope := registered.GetScope(); scope != nil && !s.matches(scope) {
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, Reason: "scope mismatch"})
	}
	instanceID := registered.GetInstanceId()
	now := s.now()
	s.mu.Lock()
	rec, ok := s.instances[instanceID]
	if !ok {
		rec = &instance{}
		s.instances[instanceID] = rec
	} else if rec.BootID != registered.GetBootId() {
		rec.reset()
	}
	rec.InstanceState.InstanceID = instanceID
	rec.BootID = registered.GetBootId()
	rec.BuildID = registered.GetBuildId()
	rec.imageDigest = registered.GetImageDigest()
	rec.address = registered.GetAddress()
	rec.port = registered.GetPort()
	rec.tlsServerName = registered.GetTlsServerName()
	rec.zone = registered.GetZone()
	rec.protocolVersion = registered.GetProtocolVersion()
	rec.Ready = registered.GetReady()
	rec.Draining = registered.GetDraining()
	rec.scope = proto.Clone(registered.GetScope()).(*agentv1.Scope)
	rec.LeaseEpoch++
	rec.lease = &agentv1.Lease{Id: uuid.New().String(), Epoch: rec.LeaseEpoch, ExpiresUnixMs: now.Add(leaseTTL).UnixMilli()}
	rec.LeaseExpiresUnixMs = rec.lease.GetExpiresUnixMs()
	rec.session = sess.id
	echo := proto.Clone(registered).(*agentv1.Instance)
	echo.Lease = proto.Clone(rec.lease).(*agentv1.Lease)
	discovery := s.discoveryRevisionLocked(rec.PreparedHash)
	s.mu.Unlock()
	return sess.response(body, &agentv1.Envelope{Payload: &agentv1.Envelope_Registered{Registered: &agentv1.Registered{
		Instance:          echo,
		DiscoveryRevision: discovery,
	}}})
}

// onRenewLease extends the lease of the same epoch. A different epoch is a stale
// holder and must be refused, which is the whole point of fencing a lease.
func (sess *session) onRenewLease(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	renew := body.GetRenewLease()
	if faults := s.currentFaults(); faults.RenewError != nil {
		return sess.errorReply(body, proto.Clone(faults.RenewError).(*agentv1.Error))
	}
	if faults := s.currentFaults(); faults.DropRenew {
		// The reply is withheld on purpose, so a caller observes a timeout.
		return nil
	}
	s.mu.Lock()
	rec, ok := s.instances[renew.GetInstanceId()]
	if !ok {
		s.mu.Unlock()
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Reason: reasonUnknownInstance})
	}
	lease := renew.GetLease()
	fenced := "lease epoch fenced"
	switch {
	case !validText(renew.GetBootId()) || rec.BootID != renew.GetBootId():
		fenced = "boot fenced"
	case lease != nil && lease.GetEpoch() != rec.LeaseEpoch:
	case lease == nil && rec.session != sess.id:
	case lease != nil && lease.GetId() != "" && lease.GetId() != rec.lease.GetId():
		fenced = "lease id fenced"
	default:
		fenced = ""
	}
	if fenced != "" {
		s.mu.Unlock()
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_FENCED, Reason: fenced})
	}
	rec.LeaseExpiresUnixMs = s.now().Add(leaseTTL).UnixMilli()
	rec.lease.ExpiresUnixMs = rec.LeaseExpiresUnixMs
	rec.session = sess.id
	renewed := proto.Clone(rec.lease).(*agentv1.Lease)
	discovery := s.discoveryRevisionLocked(rec.PreparedHash)
	s.mu.Unlock()
	return sess.response(body, &agentv1.Envelope{Payload: &agentv1.Envelope_LeaseRenewed{LeaseRenewed: &agentv1.LeaseRenewed{
		Lease:             renewed,
		DiscoveryRevision: discovery,
	}}})
}

// onUpdateInstance records a self-reported change of the registered instance.
func (sess *session) onUpdateInstance(body *agentv1.Envelope) *agentv1.Envelope {
	update := body.GetUpdateInstance().GetInstance()
	if scope := update.GetScope(); scope != nil && !sess.server.matches(scope) {
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, Reason: "scope mismatch"})
	}
	s := sess.server
	s.mu.Lock()
	rec, ok := s.instances[update.GetInstanceId()]
	if !ok {
		s.mu.Unlock()
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Reason: reasonUnknownInstance})
	}
	if update.GetBootId() != "" {
		rec.BootID = update.GetBootId()
	}
	if update.GetBuildId() != "" {
		rec.BuildID = update.GetBuildId()
	}
	if update.GetAddress() != "" {
		rec.address = update.GetAddress()
	}
	if update.GetPort() != 0 {
		rec.port = update.GetPort()
	}
	if update.GetTlsServerName() != "" {
		rec.tlsServerName = update.GetTlsServerName()
	}
	if update.GetZone() != "" {
		rec.zone = update.GetZone()
	}
	if update.GetImageDigest() != "" {
		rec.imageDigest = update.GetImageDigest()
	}
	if update.GetProtocolVersion() != 0 {
		rec.protocolVersion = update.GetProtocolVersion()
	}
	rec.Ready = update.GetReady()
	rec.Draining = update.GetDraining()
	s.mu.Unlock()
	return nil
}

// onDeregister removes one instance from the registry. The protocol defines no
// response, so success is silent and only a fenced request is refused.
func (sess *session) onDeregister(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	deregister := body.GetDeregister()
	s.mu.Lock()
	rec, ok := s.instances[deregister.GetInstanceId()]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	lease := deregister.GetLease()
	fenced := ""
	switch {
	case deregister.GetBootId() != "" && rec.BootID != deregister.GetBootId():
		fenced = "boot fenced"
	case lease != nil && lease.GetEpoch() != rec.LeaseEpoch:
		fenced = "lease epoch fenced"
	}
	if fenced == "" {
		delete(s.instances, rec.InstanceID)
	}
	s.mu.Unlock()
	if fenced != "" {
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_FENCED, Reason: fenced})
	}
	return nil
}

// onFetchResource answers the reference of a resource the client learned about
// through a Delta. A resource without a download address cannot be fetched, and
// an unpublished one is reported as expired rather than as an empty reference.
func (sess *session) onFetchResource(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	fetch := body.GetFetchResource()
	s.mu.Lock()
	rec := s.recordOf(fetch.GetKind(), fetch.GetKey())
	var ref *agentv1.ResourceRef
	if rec != nil {
		ref = s.resourceRef(rec)
	}
	s.mu.Unlock()
	switch {
	case rec == nil:
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_RESOURCE_EXPIRED, Reason: "resource is not published"})
	case ref == nil:
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_NOT_READY, Reason: "resource has no download address"})
	default:
		return sess.response(body, &agentv1.Envelope{Payload: &agentv1.Envelope_ResourceRef{ResourceRef: ref}})
	}
}

// onPrepared records prepared evidence and, unless withheld, activates it. A
// replay or a stale report changes nothing, so a duplicate can neither re-arm an
// activation nor pull the instance back to an older generation.
func (sess *session) onPrepared(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	prepared := body.GetPrepared()
	release := prepared.GetRelease()
	s.mu.Lock()
	rec, ok := sess.instanceLocked(prepared.GetInstanceId())
	if !ok {
		s.mu.Unlock()
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Reason: reasonUnknownInstance})
	}
	instanceID := rec.InstanceID
	changed := rec.notePrepared(release, prepared.GetBootId(), prepared.GetBuildId(), prepared.GetExpiresUnixMs(), s.bundleRevisionLocked(release.GetBundleHash()))
	if prepared.GetAppliedGeneration() > rec.AppliedGeneration {
		rec.AppliedGeneration = prepared.GetAppliedGeneration()
	}
	revoked := s.revoked[digestOf(release.GetBundleHash())]
	faults := s.faults
	preparedRevision := rec.preparedPolicy
	identity := proto.Clone(rec.preparedRelease).(*agentv1.ReleaseIdentity)
	s.mu.Unlock()
	if !changed || identity == nil {
		return nil
	}
	switch {
	case revoked:
		sess.command(abortEnvelope(sess, identity, "release revoked"), false)
	case slices.Contains(faults.AbortAfterPrepare, instanceID):
		sess.command(abortEnvelope(sess, identity, "abort injected by fault"), false)
	case faults.WithholdActivate:
	case len(faults.ActivateSubset) > 0 && !slices.Contains(faults.ActivateSubset, instanceID):
	default:
		sess.command(activateEnvelope(sess, identity, preparedRevision), false)
	}
	return nil
}

// onApplied records an activation result. Only a newer generation advances the
// stored state, so a late report can never overwrite a newer one.
func (sess *session) onApplied(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	applied := body.GetApplied()
	s.mu.Lock()
	rec, ok := sess.instanceLocked(applied.GetInstanceId())
	if !ok {
		s.mu.Unlock()
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Reason: reasonUnknownInstance})
	}
	rec.noteApplied(applied.GetRelease(), applied.GetBootId(), applied.GetPolicyRevision())
	s.mu.Unlock()
	return nil
}

// onRejected records why an instance refused a release.
func (sess *session) onRejected(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	rejected := body.GetRejected()
	code := rejected.GetError().GetCode().String()
	s.mu.Lock()
	rec, ok := sess.instanceLocked("")
	if !ok {
		s.mu.Unlock()
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Reason: reasonUnknownInstance})
	}
	rec.noteRejected(rejected.GetRelease(), code)
	s.mu.Unlock()
	return nil
}

// onReleaseStatusQuery answers the aggregate the mock derived from the reports it
// received, never a state it invented.
func (sess *session) onReleaseStatusQuery(body *agentv1.Envelope) *agentv1.Envelope {
	status := sess.server.releaseStatus(body.GetReleaseStatusQuery().GetReleaseId())
	return sess.response(body, &agentv1.Envelope{Payload: &agentv1.Envelope_ReleaseStatus{ReleaseStatus: status}})
}

// onReadinessReport records the application readiness an instance reports, which
// is independent of link readiness and of lease validity.
func (sess *session) onReadinessReport(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	report := body.GetReadinessReport()
	s.mu.Lock()
	rec, ok := sess.instanceLocked(report.GetInstanceId())
	if !ok {
		s.mu.Unlock()
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Reason: reasonUnknownInstance})
	}
	rec.Ready = report.GetReady()
	if report.GetReady() {
		rec.Draining = false
	}
	s.mu.Unlock()
	return nil
}

// onDrainReport records the progress of a drain. A completed drain leaves the
// instance in discovery as draining and not ready, until it deregisters.
func (sess *session) onDrainReport(body *agentv1.Envelope) *agentv1.Envelope {
	s := sess.server
	report := body.GetDrainReport()
	s.mu.Lock()
	rec, ok := sess.instanceLocked(report.GetInstanceId())
	if !ok {
		s.mu.Unlock()
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Reason: reasonUnknownInstance})
	}
	if report.GetComplete() {
		rec.Draining = true
		rec.Ready = false
	}
	s.mu.Unlock()
	return nil
}

// onEventBatch acknowledges one telemetry batch. The mock implements no event
// pipeline, so acceptance is the only outcome it can honestly report.
func (sess *session) onEventBatch(body *agentv1.Envelope) *agentv1.Envelope {
	batch := body.GetEventBatch()
	if len(batch.GetEvents()) == 0 || len(batch.GetEvents()) > maxEventsPerBatch {
		return sess.errorReply(body, &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Reason: "invalid event batch"})
	}
	results := make([]*agentv1.EventResult, 0, len(batch.GetEvents()))
	for _, event := range batch.GetEvents() {
		results = append(results, &agentv1.EventResult{EventId: event.GetEventId(), Accepted: true})
	}
	return sess.response(body, &agentv1.Envelope{Payload: &agentv1.Envelope_EventBatchAck{EventBatchAck: &agentv1.EventBatchAck{
		Results:            results,
		DedupExpiresUnixMs: sess.server.now().Add(eventDedupWindow).UnixMilli(),
	}}})
}

// command queues one unsolicited control-plane command. A command is never a
// reply, so it carries no ReplyTo and reaches the client's event stream.
func (sess *session) command(body *agentv1.Envelope, drop bool) {
	sess.enqueue(body, drop)
}

// validSubscriptionID bounds the client-chosen subscription identifier, which
// every reply echoes inside a field the protocol caps at 128 bytes.
func validSubscriptionID(id string) bool {
	return id != "" && len(id) <= 128
}

// validResourceKey bounds a resource key the same way the envelope validator
// does, so an oversized key cannot make the mock fail to encode its own reply.
func validResourceKey(key string) bool {
	return validText(key) && len(key) <= maxResourceKey
}

// matches reports whether an advertised scope is this mock's scope.
func (s *Server) matches(scope *agentv1.Scope) bool {
	return scope.GetWorkspaceId() == s.scope.WorkspaceID && scope.GetEnvironmentId() == s.scope.EnvironmentID && scope.GetServiceKey() == s.scope.ServiceKey
}

// reset clears the reported release state of an instance. It runs when a new
// boot replaces the process that reported it.
func (rec *instance) reset() {
	rec.InstanceState = InstanceState{InstanceID: rec.InstanceID}
	rec.lease = nil
	rec.preparedRelease = nil
	rec.preparedPolicy = 0
	rec.appliedRelease = nil
	rec.rejectedRelease = nil
}

// abortEnvelope builds one Abort command for a prepared release.
func abortEnvelope(sess *session, release *agentv1.ReleaseIdentity, reason string) *agentv1.Envelope {
	body := sess.newEnvelope()
	body.OperationId = uuid.New().String()
	body.Payload = &agentv1.Envelope_Abort{Abort: &agentv1.Abort{Release: release, Reason: reason}}
	return body
}

// noteInbound records one inbound message in the journal. The journal is the
// mock's evidence trail, so every message is recorded, including the reports a
// test asserts on after the fact.
func (s *Server) noteInbound(body *agentv1.Envelope) {
	entry := Entry{OperationID: body.GetOperationId(), Key: body.GetResourceKey(), At: s.now()}
	switch payload := body.GetPayload().(type) {
	case *agentv1.Envelope_Hello:
		entry.Kind = "Hello"
		entry.InstanceID = payload.Hello.GetInstanceId()
	case *agentv1.Envelope_Heartbeat:
		entry.Kind = "Heartbeat"
	case *agentv1.Envelope_Goodbye:
		entry.Kind = "Goodbye"
	case *agentv1.Envelope_Subscribe:
		entry.Kind = "Subscribe"
		entry.Key = payload.Subscribe.GetCursor().GetKey()
	case *agentv1.Envelope_Unsubscribe:
		entry.Kind = "Unsubscribe"
	case *agentv1.Envelope_Resume:
		entry.Kind = "Resume"
	case *agentv1.Envelope_Register:
		entry.Kind = "Register"
		entry.InstanceID = payload.Register.GetInstance().GetInstanceId()
	case *agentv1.Envelope_RenewLease:
		entry.Kind = "RenewLease"
		entry.InstanceID = payload.RenewLease.GetInstanceId()
	case *agentv1.Envelope_UpdateInstance:
		entry.Kind = "UpdateInstance"
		entry.InstanceID = payload.UpdateInstance.GetInstance().GetInstanceId()
	case *agentv1.Envelope_Deregister:
		entry.Kind = "Deregister"
		entry.InstanceID = payload.Deregister.GetInstanceId()
	case *agentv1.Envelope_FetchResource:
		entry.Kind = "FetchResource"
		entry.Key = payload.FetchResource.GetKey()
	case *agentv1.Envelope_ResourceApplied:
		entry.Kind = "ResourceApplied"
		entry.Generation = payload.ResourceApplied.GetRevision()
	case *agentv1.Envelope_ResourceRejected:
		entry.Kind = "ResourceRejected"
		entry.Generation = payload.ResourceRejected.GetRevision()
	case *agentv1.Envelope_Prepared:
		entry.Kind = "Prepared"
		entry.InstanceID = payload.Prepared.GetInstanceId()
		entry.Key = payload.Prepared.GetRelease().GetReleaseId()
		entry.Generation = payload.Prepared.GetRelease().GetGeneration()
	case *agentv1.Envelope_Applied:
		entry.Kind = "Applied"
		entry.InstanceID = payload.Applied.GetInstanceId()
		entry.Key = payload.Applied.GetRelease().GetReleaseId()
		entry.Generation = payload.Applied.GetRelease().GetGeneration()
	case *agentv1.Envelope_Rejected:
		entry.Kind = "Rejected"
		entry.Key = payload.Rejected.GetRelease().GetReleaseId()
		entry.Generation = payload.Rejected.GetRelease().GetGeneration()
	case *agentv1.Envelope_ReleaseStatusQuery:
		entry.Kind = "ReleaseStatusQuery"
		entry.Key = payload.ReleaseStatusQuery.GetReleaseId()
	case *agentv1.Envelope_ReadinessReport:
		entry.Kind = "ReadinessReport"
		entry.InstanceID = payload.ReadinessReport.GetInstanceId()
	case *agentv1.Envelope_DrainReport:
		entry.Kind = "DrainReport"
		entry.InstanceID = payload.DrainReport.GetInstanceId()
	case *agentv1.Envelope_EventBatch:
		entry.Kind = "EventBatch"
	default:
		entry.Kind = "Unknown"
	}
	s.mu.Lock()
	s.appendJournal(entry)
	s.mu.Unlock()
}

// protocolCode maps a decode failure onto the error code the peer must be told.
func protocolCode(err error) agentv1.ErrorCode {
	if failure, ok := errors.AsType[*agentv1.ProtocolError](err); ok {
		return failure.Code
	}
	return agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
}

// protocolReason maps a decode failure onto a peer-safe reason.
func protocolReason(err error) string {
	if failure, ok := errors.AsType[*agentv1.ProtocolError](err); ok {
		return failure.Reason
	}
	return fmt.Sprintf("malformed frame: %v", err)
}
