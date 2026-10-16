// Package mock provides an in-memory Grayling protocol test double. Its signed
// whole-view payload exercises gogw, not production registration or approvals.
package mock

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/coder/websocket"
	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
	"github.com/traefik/traefik/v3/pkg/gogw"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	Scope      agent.Scope
	Service    string
	Token      string
	KeyID      string
	PrivateKey ed25519.PrivateKey
	ValidFor   time.Duration
	Applied    atomic.Int64
	Rejected   atomic.Int64
	mu         sync.Mutex
	current    *agentv1.SignedResource
	clients    map[*websocket.Conn]chan *agentv1.SignedResource
	epoch      atomic.Uint64
}

// Publish replaces the mock's complete view and broadcasts it. The same signed
// bytes go to all gateways; instance changes do not change hash coordinates.
func (s *Server) Publish(bundle gogw.Bundle) error {
	if len(s.PrivateKey) != ed25519.PrivateKeySize || s.Token == "" || s.Service == "" || bundle.Policy.ManifestRevision <= 0 {
		return errors.New("invalid mock configuration")
	}
	b, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(b)
	now := time.Now()
	duration := s.ValidFor
	if duration == 0 {
		duration = 5 * time.Minute
	}
	claims, err := agent.MarshalClaims(agent.Claims{Scope: s.Scope, Kind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, Key: s.Service, ControlPlaneEpoch: 1, Revision: uint64(bundle.Policy.ManifestRevision), BundleHash: hash, PayloadHash: hash, IssuedUnixMs: now.Add(-time.Second).UnixMilli(), ExpiresUnixMs: now.Add(duration).UnixMilli(), KeyID: s.KeyID})
	if err != nil {
		return err
	}
	resource := &agentv1.SignedResource{Claims: claims, Payload: b, KeyId: s.KeyID, Signature: ed25519.Sign(s.PrivateKey, append([]byte(agent.SignatureDomain), claims...))}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clients == nil {
		s.clients = make(map[*websocket.Conn]chan *agentv1.SignedResource)
	}
	s.current = resource
	for conn, ch := range s.clients {
		select {
		case ch <- resource:
		default:
			_ = conn.CloseNow()
		}
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != agentv1.ConnectPath || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.Token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{agentv1.Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(agentv1.MaxFrameBytes)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	handshake, stop := context.WithTimeout(ctx, 5*time.Second)
	hello, err := read(handshake, conn)
	stop()
	if err != nil || hello.GetHello() == nil {
		return
	}
	session := uuid.New().String()
	epoch := s.epoch.Add(1)
	send := func(ctx context.Context, body *agentv1.Envelope) error {
		body.ProtocolMajor = 1
		body.SessionId = session
		body.ConnectionEpoch = epoch
		body.MessageId = uuid.New().String()
		b, err := agentv1.Encode(body)
		if err != nil {
			return err
		}
		budget, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return conn.Write(budget, websocket.MessageBinary, b)
	}
	if err = send(ctx, &agentv1.Envelope{ReplyTo: hello.GetMessageId(), Payload: &agentv1.Envelope_Welcome{Welcome: &agentv1.Welcome{Scope: &agentv1.Scope{WorkspaceId: s.Scope.WorkspaceID, EnvironmentId: s.Scope.EnvironmentID, ServiceKey: s.Scope.ServiceKey}, ControlPlaneEpoch: 1, ServerUnixMs: time.Now().UnixMilli(), Limits: &agentv1.Limits{MaxFrameBytes: agentv1.MaxFrameBytes, HeartbeatIntervalMs: 100, HeartbeatTimeoutMs: 1000, MaxResourceBytes: agent.MaxResourceBytes}}}}); err != nil {
		return
	}
	updates := make(chan *agentv1.SignedResource, 8)
	defer func() { s.mu.Lock(); delete(s.clients, conn); s.mu.Unlock() }()
	group, run := errgroup.WithContext(ctx)
	group.Go(func() error {
		for {
			select {
			case <-run.Done():
				return run.Err()
			case resource := <-updates:
				claims, err := agent.ParseClaims(resource.GetClaims())
				if err != nil {
					return err
				}
				if err = send(run, &agentv1.Envelope{SubscriptionId: "runtime", ResourceKind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, ResourceKey: s.Service, ResourceRevision: claims.Revision, Payload: &agentv1.Envelope_Snapshot{Snapshot: &agentv1.Snapshot{Scope: &agentv1.Scope{WorkspaceId: s.Scope.WorkspaceID, EnvironmentId: s.Scope.EnvironmentID, ServiceKey: s.Scope.ServiceKey}, Revision: claims.Revision, Content: &agentv1.Snapshot_InlineResource{InlineResource: resource}}}}); err != nil {
					return err
				}
			}
		}
	})
	group.Go(func() error {
		for {
			e, err := read(run, conn)
			if err != nil {
				return err
			}
			if e.GetSessionId() != session || e.GetConnectionEpoch() != epoch {
				return errors.New("invalid session")
			}
			switch {
			case e.GetHeartbeat() != nil:
				if err = send(run, &agentv1.Envelope{ReplyTo: e.GetMessageId(), Payload: &agentv1.Envelope_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{Nonce: e.GetHeartbeat().GetNonce(), ServerUnixMs: time.Now().UnixMilli()}}}); err != nil {
					return err
				}
			case e.GetSubscribe() != nil:
				if e.GetSubscribe().GetCursor().GetKey() != s.Service || e.GetSubscribe().GetCursor().GetKind() != agentv1.ResourceKind_RESOURCE_KIND_BUNDLE {
					return errors.New("invalid subscription")
				}
				s.mu.Lock()
				s.clients[conn] = updates
				resource := s.current
				s.mu.Unlock()
				if resource == nil {
					return errors.New("no bundle")
				}
				select {
				case updates <- resource:
				case <-run.Done():
					return run.Err()
				}
			case e.GetPrepared() != nil:
				p := e.GetPrepared()
				if p.GetInstanceId() != hello.GetHello().GetInstanceId() || p.GetBootId() != hello.GetHello().GetBootId() {
					return errors.New("prepared identity mismatch")
				}
				if err = send(run, &agentv1.Envelope{OperationId: uuid.New().String(), Payload: &agentv1.Envelope_Activate{Activate: &agentv1.Activate{Release: p.GetRelease()}}}); err != nil {
					return err
				}
			case e.GetApplied() != nil:
				s.Applied.Add(1)
			case e.GetResourceRejected() != nil:
				s.Rejected.Add(1)
			}
		}
	})
	_ = group.Wait()
}

func read(ctx context.Context, conn *websocket.Conn) (*agentv1.Envelope, error) {
	typ, b, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, errors.New("binary frame required")
	}
	return agentv1.Decode(b)
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.clients {
		_ = conn.CloseNow()
	}
}

func PublicKey(key ed25519.PrivateKey) string {
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}
