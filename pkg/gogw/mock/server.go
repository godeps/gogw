// Package mock implements the published Grayling Agent protocol v1 control
// plane in memory: authenticated WebSocket sessions, signed resource delivery,
// lease fencing and the release negotiation state machine. It exists to exercise
// the gogw gateway without a production registry, approval service or durable
// revocation store, and it must never be deployed in their place.
//
// The signed payloads follow pkg/gogw's versioned document contract, so a
// gateway that accepts this mock accepts the control plane it emulates, but only
// for the protocol surface this package actually implements.
package mock

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
	"google.golang.org/protobuf/proto"
)

const (
	// controlPlaneEpoch is the only control-plane generation this mock serves.
	// A restart keeps it, because the mock never seeds a durable epoch store.
	controlPlaneEpoch = 1

	// defaultHeartbeat is the advertised heartbeat interval; the enforced
	// timeout is heartbeatFactor times that interval, so the default is 2s.
	defaultHeartbeat = 200 * time.Millisecond
	heartbeatFactor  = 10

	// maxFrameBytes and maxResourceBytes mirror the frozen protocol limits and
	// stay within what the SDK advertises, so the handshake never over-promises.
	maxFrameBytes    = agentv1.MaxFrameBytes
	maxResourceBytes = agent.MaxResourceBytes

	defaultExpiresIn      = 5 * time.Minute
	defaultPrepareTimeout = 30 * time.Second
	defaultDrainGrace     = time.Minute

	// leaseTTL and leaseRenewInterval are advertised in Limits; the mock fences
	// on the epoch and lets expiry only remove an instance from discovery.
	leaseTTL           = 30 * time.Second
	leaseRenewInterval = 10 * time.Second

	maxSubscriptions = 64
	sessionQueue     = 64
	maxJournal       = 8192
	maxOperations    = 8192
	maxIdentifier    = 256

	// maxResourceKey is the envelope limit on a resource key, which bounds every
	// key the mock echoes back inside a reply.
	maxResourceKey = 1024

	handshakeTimeout = 5 * time.Second
	writeTimeout     = 5 * time.Second

	// downloadPrefix is part of the advertised ResourceRef URL and must match
	// the route mounted by Handler; the SDK refuses any other origin.
	downloadPrefix = "/api/v1/agent/resources/"

	// healthPath is the only unauthenticated route, for readiness probes.
	healthPath = "/__mock/health"
)

var (
	// ErrOptions reports an unusable Options value.
	ErrOptions = errors.New("mock: invalid options")

	// ErrRevision reports a publication that does not advance the resource
	// revision, which a gateway watermark would reject as a rollback.
	ErrRevision = errors.New("mock: resource revision must advance")

	// ErrRevoked reports an attempt to publish or activate a revoked bundle.
	ErrRevoked = errors.New("mock: resource is revoked")

	// ErrUnknown reports an unknown instance or an unpublished resource.
	ErrUnknown = errors.New("mock: unknown instance or resource")

	// ErrUnavailable reports a control-plane command with no live session or no
	// downloadable resource, so the command could not be delivered.
	ErrUnavailable = errors.New("mock: resource or session unavailable")

	// ErrClosed reports a publication against a closed server.
	ErrClosed = errors.New("mock: server closed")
)

// Options configures New. Scope, Token and SigningKey are required.
type Options struct {
	// Scope is the immutable scope every advertised resource is bound to.
	Scope agent.Scope

	// Token is the bearer token a connection and a download must present.
	Token string

	// KeyID identifies SigningKey in resource claims.
	KeyID string

	// SigningKey signs every resource claim.
	SigningKey ed25519.PrivateKey

	// Heartbeat is the advertised heartbeat interval; it defaults to 200ms and
	// the enforced timeout is ten intervals.
	Heartbeat time.Duration

	// Now injects a clock. Keep it close to wall time: SDK clients verify
	// resource and lease expiries against their own clock.
	Now func() time.Time
}

// Resource is one signed, deliverable resource. Ref is stamped with the origin
// known when the resource is published and again on every delivery, so it can be
// nil when the resource has no download address.
type Resource struct {
	Kind   agentv1.ResourceKind
	Key    string
	Hash   [32]byte
	Ref    *agentv1.ResourceRef
	Signed *agentv1.SignedResource
}

// PublishOptions tunes one raw publication. Zero values keep the defaults: a
// self-addressed bundle hash, a five minute validity and an advancing revision.
type PublishOptions struct {
	ExpiresIn time.Duration

	// Key overrides the resource key; the caller normally passes it directly.
	Key string

	// KeyID and SigningKey override the server defaults for this publication.
	KeyID      string
	SigningKey ed25519.PrivateKey

	// Revision is the claims revision. Zero derives the next revision, which is
	// the only way to keep the gateway watermark strictly advancing.
	Revision uint64

	// BundleHash and PayloadHash override the derived claims digests. Both
	// default to the digest of payload.
	BundleHash  [32]byte
	PayloadHash [32]byte

	// TamperPayload flips one payload byte after signing, so the served bytes
	// decode but fail signature verification: the rejection path under test.
	TamperPayload bool

	// NoDownload withholds the download address and forces inline delivery.
	NoDownload bool
}

// Entry records one inbound message for assertions.
type Entry struct {
	Kind        string
	InstanceID  string
	OperationID string
	Key         string
	Generation  uint64
	At          time.Time
}

// InstanceState is the registered state of one instance. It survives the
// disconnect that ends a session, so a reconnecting gateway keeps its lease.
type InstanceState struct {
	InstanceID, BootID, BuildID string
	Ready, Draining             bool
	LeaseEpoch                  uint64
	LeaseExpiresUnixMs          int64
	PreparedHash                string
	PreparedGeneration          uint64
	PreparedExpiresUnixMs       int64
	AppliedRevision             uint64
	AppliedGeneration           uint64
	RejectedCode                string
}

// Faults injects control-plane failures. Every field defaults to healthy.
type Faults struct {
	// RegisterError replies Error instead of Registered.
	RegisterError *agentv1.Error

	// RenewError replies Error instead of LeaseRenewed.
	RenewError *agentv1.Error

	// SubscribeError replies Error instead of accepting a subscription.
	SubscribeError *agentv1.Error

	// GoAwayAfter sends GoAway and disconnects after N inbound messages; 0
	// disables the fault. The counter is per connection.
	GoAwayAfter int

	// GoAwayRetryAfter is the reconnect delay advertised in GoAway.
	GoAwayRetryAfter time.Duration

	// DropSnapshot accepts a subscription without sending the initial Snapshot,
	// so the next publication delivers a Snapshot instead of a Delta.
	DropSnapshot bool

	// ForceResync replies ResyncRequired to every Resume.
	ForceResync bool

	// WithholdActivate stops the automatic Activate after Prepared.
	WithholdActivate bool

	// ActivateSubset restricts the automatic Activate to these instance IDs.
	ActivateSubset []string

	// AbortAfterPrepare aborts these instance IDs as soon as they prepare.
	AbortAfterPrepare []string

	// DropRenew ignores RenewLease without a reply, so the caller times out.
	DropRenew bool

	// IgnorePrepared omits prepared evidence from discovery members.
	IgnorePrepared bool
}

// Server is one in-memory control plane. Every method is safe for concurrent
// use; exported values returned by value are copies, but Signed and Ref are
// shared and must be treated as read-only.
type Server struct {
	scope     agent.Scope
	token     string
	keyID     string
	signing   ed25519.PrivateKey
	heartbeat time.Duration
	timeout   time.Duration
	now       func() time.Time

	mu        sync.Mutex
	origin    string
	closed    bool
	epoch     uint64
	sessions  map[string]*session
	instances map[string]*instance
	resources map[resourceID]*record
	retired   map[resourceID]uint64
	wires     map[[32]byte]*record
	revoked   map[[32]byte]bool
	revEpoch  uint64
	journal   []Entry
	ops       map[string]*agentv1.Envelope
	opOrder   []string
	faults    Faults
}

// resourceID identifies one published resource.
type resourceID struct {
	kind agentv1.ResourceKind
	key  string
}

// delivery is one message queued for one session while Server.mu was held.
type delivery struct {
	sess *session
	body *agentv1.Envelope
}

// record is one signed resource the mock has published.
type record struct {
	id       resourceID
	revision uint64
	hash     [32]byte
	wire     []byte
	wireHash [32]byte
	signed   *agentv1.SignedResource
	claims   agent.Claims
	payload  []byte
	download bool
}

// instance is the registry entry for one gateway. The embedded state is the
// exported projection; the remaining fields stay internal.
type instance struct {
	InstanceState

	scope           *agentv1.Scope
	address         string
	port            uint32
	tlsServerName   string
	zone            string
	imageDigest     string
	protocolVersion uint32
	lease           *agentv1.Lease
	session         string
	preparedRelease *agentv1.ReleaseIdentity
	// preparedPolicy is the bundle revision the instance prepared, which is also
	// the revision an activation carries back to it.
	preparedPolicy  uint64
	appliedRelease  *agentv1.ReleaseIdentity
	rejectedRelease *agentv1.ReleaseIdentity
}

// New validates the options and returns an idle server. It opens no listener:
// the caller mounts Handler on its own TLS listener and then calls SetOrigin.
func New(opts Options) (*Server, error) {
	if len(opts.SigningKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signing key must be an Ed25519 private key", ErrOptions)
	}
	if opts.Token == "" || strings.ContainsAny(opts.Token, "\r\n") {
		return nil, fmt.Errorf("%w: missing or invalid token", ErrOptions)
	}
	if !validText(opts.KeyID) {
		return nil, fmt.Errorf("%w: invalid key id", ErrOptions)
	}
	if !validText(opts.Scope.WorkspaceID) || !validText(opts.Scope.EnvironmentID) || !validText(opts.Scope.ServiceKey) {
		return nil, fmt.Errorf("%w: invalid scope", ErrOptions)
	}
	heartbeat := opts.Heartbeat
	if heartbeat <= 0 {
		heartbeat = defaultHeartbeat
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Server{
		scope:     opts.Scope,
		token:     opts.Token,
		keyID:     opts.KeyID,
		signing:   opts.SigningKey,
		heartbeat: heartbeat,
		timeout:   heartbeat * heartbeatFactor,
		now:       now,
		sessions:  make(map[string]*session),
		instances: make(map[string]*instance),
		resources: make(map[resourceID]*record),
		retired:   make(map[resourceID]uint64),
		wires:     make(map[[32]byte]*record),
		revoked:   make(map[[32]byte]bool),
		ops:       make(map[string]*agentv1.Envelope),
	}, nil
}

// KeyID returns the resource signing key id.
func (s *Server) KeyID() string { return s.keyID }

// PublicKey returns the Ed25519 public key a gateway must trust.
func (s *Server) PublicKey() ed25519.PublicKey {
	return s.signing.Public().(ed25519.PublicKey)
}

// SetOrigin records the externally reachable origin, such as
// https://127.0.0.1:9443, that delivery stamps into every ResourceRef. The SDK
// requires the ref to share the connect origin's host and to use https for wss.
func (s *Server) SetOrigin(origin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.origin = strings.TrimSuffix(origin, "/")
}

// Handler returns the mock's routes: the WSS connect path, the authenticated
// resource download endpoint and an unauthenticated health probe.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(agentv1.ConnectPath, s.serveConnect)
	mux.HandleFunc(downloadPrefix, s.serveDownload)
	mux.HandleFunc(healthPath, s.serveHealth)
	return mux
}

// Close terminates every session and refuses further publication. Registered
// instances and the journal stay readable, so a caller can still inspect the
// state the mock observed after its sessions ended.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	sessions := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		sess.shutdown("mock shutdown", 0)
	}
}

// Sessions returns the number of live connections.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Journal returns a copy of the inbound message log, oldest first.
func (s *Server) Journal() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Entry(nil), s.journal...)
}

// Instance returns a copy of one registry entry.
func (s *Server) Instance(instanceID string) (InstanceState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.instances[instanceID]
	if !ok {
		return InstanceState{}, false
	}
	return record.InstanceState, true
}

// SetFaults replaces the injected faults and returns the previous value.
func (s *Server) SetFaults(faults Faults) Faults {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.faults
	s.faults = faults
	return previous
}

// PublishRaw signs and stores one resource payload under the given key, then
// notifies its subscribers. A byte-identical republication returns the stored
// resource, and any other publication must advance the revision.
func (s *Server) PublishRaw(kind agentv1.ResourceKind, key string, payload []byte, opts PublishOptions) (Resource, error) {
	if opts.Key != "" {
		key = opts.Key
	}
	return s.publish(kind, key, payload, opts)
}

// Unpublish retires one resource and invalidates it for every subscriber. The
// retired revision is kept, so a later publication cannot regress it.
func (s *Server) Unpublish(kind agentv1.ResourceKind, key string) {
	s.invalidate(kind, key)
}

// faults returns a copy of the injected faults.
func (s *Server) currentFaults() Faults {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.faults
}

// publish is the shared implementation of every publication. Signing happens
// while the lock is held so that concurrent publishers cannot interleave a
// revision check with the store that follows it.
func (s *Server) publish(kind agentv1.ResourceKind, key string, payload []byte, opts PublishOptions) (Resource, error) {
	if kind < agentv1.ResourceKind_RESOURCE_KIND_POLICY || kind > agentv1.ResourceKind_RESOURCE_KIND_REVOCATION {
		return Resource{}, fmt.Errorf("%w: invalid resource kind", ErrOptions)
	}
	if !validText(key) {
		return Resource{}, fmt.Errorf("%w: invalid resource key", ErrOptions)
	}
	if len(payload) == 0 || len(payload) > maxResourceBytes {
		return Resource{}, fmt.Errorf("%w: invalid payload size", ErrOptions)
	}
	expiresIn := opts.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = defaultExpiresIn
	}
	keyID := opts.KeyID
	if keyID == "" {
		keyID = s.keyID
	}
	signing := opts.SigningKey
	if len(signing) == 0 {
		signing = s.signing
	}
	payloadHash := opts.PayloadHash
	if payloadHash == ([32]byte{}) {
		payloadHash = sha256.Sum256(payload)
	}
	bundleHash := opts.BundleHash
	if bundleHash == ([32]byte{}) {
		bundleHash = payloadHash
	}
	now := s.now()
	id := resourceID{kind: kind, key: key}

	s.mu.Lock()
	// The publication is queued under the lock and sent after it is released, so
	// a subscriber never observes a message before the store it describes.
	var out []delivery
	defer func() {
		s.mu.Unlock()
		deliverAll(out)
	}()
	if s.closed {
		return Resource{}, ErrClosed
	}
	if s.revoked[payloadHash] {
		return Resource{}, ErrRevoked
	}
	live := s.resources[id]
	last := s.retired[id]
	if live != nil {
		last = live.revision
		if live.hash == payloadHash && (opts.Revision == 0 || opts.Revision == live.revision) {
			return s.resourceOf(live), nil
		}
	}
	revision := opts.Revision
	if revision == 0 {
		revision = last + 1
	}
	if revision <= last {
		return Resource{}, fmt.Errorf("%w: %s/%s at revision %d", ErrRevision, kind, key, last)
	}
	claims, err := agent.MarshalClaims(agent.Claims{
		Scope:             s.scope,
		Kind:              kind,
		Key:               key,
		ControlPlaneEpoch: controlPlaneEpoch,
		Revision:          revision,
		BundleHash:        bundleHash,
		IssuedUnixMs:      now.Add(-time.Second).UnixMilli(),
		ExpiresUnixMs:     now.Add(expiresIn).UnixMilli(),
		KeyID:             keyID,
		PayloadHash:       payloadHash,
	})
	if err != nil {
		return Resource{}, err
	}
	served := payload
	if opts.TamperPayload {
		served = append([]byte(nil), payload...)
		served[len(served)/2] ^= 0xff
	}
	signed := &agentv1.SignedResource{Claims: claims, Payload: served, KeyId: keyID, Signature: ed25519.Sign(signing, append([]byte(agent.SignatureDomain), claims...))}
	wire, err := proto.Marshal(signed)
	if err != nil {
		return Resource{}, err
	}
	stored, err := agent.ParseClaims(claims)
	if err != nil {
		return Resource{}, err
	}
	storedRecord := &record{
		id:       id,
		revision: revision,
		hash:     payloadHash,
		wire:     wire,
		wireHash: sha256.Sum256(wire),
		signed:   signed,
		claims:   stored,
		payload:  payload,
		download: !opts.NoDownload,
	}
	s.resources[id] = storedRecord
	delete(s.retired, id)
	s.wires[storedRecord.wireHash] = storedRecord
	out = s.deliverLocked(storedRecord)
	return s.resourceOf(storedRecord), nil
}

// invalidate withdraws one published resource: its subscribers are told it is
// gone, and the revision is retired so a republish cannot regress it.
func (s *Server) invalidate(kind agentv1.ResourceKind, key string) {
	id := resourceID{kind: kind, key: key}
	s.mu.Lock()
	rec := s.resources[id]
	if rec == nil {
		s.mu.Unlock()
		return
	}
	delete(s.resources, id)
	s.retired[id] = rec.revision
	out := s.invalidateLocked(id, rec.revision)
	s.mu.Unlock()
	deliverAll(out)
}

// invalidateLocked queues the withdrawal of one resource for each of its
// subscribers and marks them so the next publication sends a complete Snapshot.
// Server.mu must be held, and the caller delivers the result after unlocking.
func (s *Server) invalidateLocked(id resourceID, revision uint64) []delivery {
	var out []delivery
	for _, sess := range s.sessions {
		for _, sub := range sess.subs {
			if sub.kind != id.kind || sub.key != id.key {
				continue
			}
			sub.invalidated = true
			body := sess.newEnvelope()
			body.SubscriptionId = sub.id
			body.ResourceKind = id.kind
			body.ResourceKey = id.key
			body.ResourceRevision = revision
			body.Payload = &agentv1.Envelope_Invalidated{Invalidated: &agentv1.Invalidated{Revision: revision}}
			out = append(out, delivery{sess, body})
		}
	}
	return out
}

// deliverLocked notifies every subscriber of one publication. A subscriber that
// is exactly one revision behind receives a Delta reference; everyone else needs
// a complete Snapshot, which is also what a retired subscription asks for.
// Server.mu must be held, and the caller sends the result after unlocking.
func (s *Server) deliverLocked(rec *record) []delivery {
	var out []delivery
	ref := s.resourceRef(rec)
	for _, sess := range s.sessions {
		for _, sub := range sess.subs {
			if sub.kind != rec.id.kind || sub.key != rec.id.key {
				continue
			}
			body := sess.newEnvelope()
			body.SubscriptionId = sub.id
			body.ResourceKind = rec.id.kind
			body.ResourceKey = rec.id.key
			body.ResourceRevision = rec.revision
			if ref != nil && !sub.invalidated && sub.known != 0 && rec.revision == sub.known+1 {
				body.Payload = &agentv1.Envelope_Delta{Delta: &agentv1.Delta{BaseRevision: sub.known, Reference: ref}}
			} else {
				body.Payload = &agentv1.Envelope_Snapshot{Snapshot: &agentv1.Snapshot{
					Scope:    s.scopeProto(),
					Revision: rec.revision,
					Content:  &agentv1.Snapshot_InlineResource{InlineResource: rec.signed},
				}}
			}
			sub.known = rec.revision
			sub.invalidated = false
			out = append(out, delivery{sess, body})
		}
	}
	return out
}

// deliverAll sends a batch of messages queued while Server.mu was held.
func deliverAll(out []delivery) {
	for _, item := range out {
		item.sess.enqueue(item.body, false)
	}
}

// resourceOf projects one stored record for the caller. The lock must be held.
func (s *Server) resourceOf(rec *record) Resource {
	return Resource{Kind: rec.id.kind, Key: rec.id.key, Hash: rec.hash, Ref: s.resourceRef(rec), Signed: rec.signed}
}

// resourceRef stamps a download reference with the current origin. The lock
// must be held; a nil result means the resource is inline-only.
func (s *Server) resourceRef(rec *record) *agentv1.ResourceRef {
	if !rec.download || s.origin == "" {
		return nil
	}
	return &agentv1.ResourceRef{
		Scope:         s.scopeProto(),
		Kind:          rec.id.kind,
		Key:           rec.id.key,
		Revision:      rec.revision,
		HttpsUrl:      s.origin + downloadPath(rec.wireHash),
		Sha256:        hex.EncodeToString(rec.wireHash[:]),
		SizeBytes:     uint64(len(rec.wire)),
		ExpiresUnixMs: rec.claims.ExpiresUnixMs,
	}
}

// recordOf returns one live record. The lock must be held.
func (s *Server) recordOf(kind agentv1.ResourceKind, key string) *record {
	return s.resources[resourceID{kind: kind, key: key}]
}

// scopeProto renders the immutable scope for advertisement.
func (s *Server) scopeProto() *agentv1.Scope {
	return &agentv1.Scope{WorkspaceId: s.scope.WorkspaceID, EnvironmentId: s.scope.EnvironmentID, ServiceKey: s.scope.ServiceKey}
}

// downloadPath is the authenticated download route of one serialized resource.
func downloadPath(hash [32]byte) string {
	return downloadPrefix + hex.EncodeToString(hash[:])
}

// serveHealth answers the unauthenticated readiness probe.
func (s *Server) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte("ok\n"))
	}
}

// serveDownload serves one serialized SignedResource. The body length and
// digest are exactly the values advertised in the matching ResourceRef, because
// the SDK rejects any other response before verification.
func (s *Server) serveDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(r.URL.Path, downloadPrefix))
	if err != nil || len(raw) != sha256.Size {
		http.NotFound(w, r)
		return
	}
	var hash [32]byte
	copy(hash[:], raw)
	s.mu.Lock()
	rec := s.wires[hash]
	var body []byte
	if rec != nil {
		body = rec.wire
	}
	s.mu.Unlock()
	if rec == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// appendJournal records one inbound message. The lock must be held.
func (s *Server) appendJournal(entry Entry) {
	s.journal = append(s.journal, entry)
	if len(s.journal) > maxJournal {
		s.journal = s.journal[len(s.journal)-maxJournal:]
	}
}

// cachedOperation returns the recorded reply of a replayed operation.
func (s *Server) cachedOperation(id string) (*agentv1.Envelope, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reply, ok := s.ops[id]
	return reply, ok
}

// rememberOperation stores one reply for replay. The cache is bounded and
// evicted oldest first, which keeps a long acceptance run's memory flat.
func (s *Server) rememberOperation(id string, reply *agentv1.Envelope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ops[id]; ok {
		return
	}
	s.ops[id] = reply
	s.opOrder = append(s.opOrder, id)
	for len(s.opOrder) > maxOperations {
		delete(s.ops, s.opOrder[0])
		s.opOrder = s.opOrder[1:]
	}
}

// validText mirrors the SDK's claim text rules, so an invalid identifier fails
// at publication instead of being rejected by the gateway later.
func validText(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
