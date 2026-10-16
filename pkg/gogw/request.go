package gogw

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/saker-ai/grayling/pkg/model"
	"github.com/traefik/traefik/v3/pkg/server/service/loadbalancer/wrr"
)

const ticketHeader = "X-Gogw-Ticket"

type principal struct {
	jwt.RegisteredClaims

	Tenant string `json:"tenant,omitempty"`
	Tier   string `json:"tier,omitempty"`
}
type ticket struct {
	jwt.RegisteredClaims

	Workspace   string `json:"workspace"`
	Environment string `json:"environment"`
	Service     string `json:"service"`
	IssuerBoot  string `json:"issuerBoot"`
	Boot        string `json:"boot"`
	Build       string `json:"build"`
	Bundle      string `json:"bundle"`
	Generation  uint64 `json:"generation"`
	Method      string `json:"method"`
	Authority   string `json:"authority"`
	URI         string `json:"uri"`
	Tenant      string `json:"tenant,omitempty"`
	Final       bool   `json:"final"`
	Hop         int    `json:"hop"`
}
type (
	decisionKey struct{}
	decision    struct{ subject, tenant string }
)

func (g *Gateway) trusted(ip net.IP) bool {
	for _, network := range g.proxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (g *Gateway) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if !g.trusted(ip) {
		return ip.String()
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for _, address := range slices.Backward(chain) {
		next := net.ParseIP(strings.TrimSpace(address))
		if next == nil {
			return ""
		}
		ip = next
		if !g.trusted(ip) {
			break
		}
	}
	return ip.String()
}

func (g *Gateway) authenticate(r *http.Request) (*principal, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return nil, errors.New("missing identity")
	}
	claims := new(principal)
	_, err := jwt.ParseWithClaims(strings.TrimPrefix(values[0], "Bearer "), claims, func(*jwt.Token) (any, error) { return g.secret, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(g.cfg.IdentityIssuer), jwt.WithAudience(g.cfg.Scope.ServiceKey), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || claims.Subject == "" || len(claims.Subject) > 256 {
		return nil, errors.New("invalid identity")
	}
	return claims, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "" || strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		http.Error(w, "UNSUPPORTED_PROTOCOL", http.StatusNotImplemented)
		return
	}
	if r.URL.Path == "/__gogw/ready" {
		if !g.Ready() {
			http.Error(w, "NOT_READY", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if g.draining.Load() || !g.health.Load() {
		http.Error(w, "DRAINING", http.StatusServiceUnavailable)
		return
	}
	// Traefik rewrites semicolon query separators; reject rather than signing a
	// different authority/path/query from what the target is going to receive.
	if strings.Contains(r.URL.RawQuery, ";") || r.URL.Opaque != "" {
		http.Error(w, "INVALID_REQUEST_TARGET", http.StatusBadRequest)
		return
	}
	v := g.capture()
	if v == nil {
		http.Error(w, "NOT_READY", http.StatusServiceUnavailable)
		return
	}
	defer v.release()
	if time.Now().UnixMilli() >= v.claims.ExpiresUnixMs {
		http.Error(w, "POLICY_EXPIRED", http.StatusServiceUnavailable)
		return
	}
	r = r.Clone(r.Context())
	r.RequestURI = r.URL.RequestURI()
	internal := len(r.Header.Values(ticketHeader)) > 0
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		internal = true
	}
	g.inflight.Add(1)
	defer g.inflight.Add(-1)
	if internal {
		claims, err := g.verifyTicket(v, r)
		if err != nil {
			http.Error(w, "INVALID_INTERNAL_REQUEST", http.StatusForbidden)
			return
		}
		sanitize(r)
		r.Header.Set("X-Gogw-Subject", claims.Subject)
		r.Header.Set("X-Gogw-Tenant", claims.Tenant)
		v.local.ServeHTTP(w, r)
		return
	}
	identity, err := g.authenticate(r)
	if err != nil {
		http.Error(w, "UNAUTHENTICATED", http.StatusUnauthorized)
		return
	}
	attrs := map[string]any{"tenant": identity.Tenant, "tier": identity.Tier, "client_ip": g.clientIP(r)}
	result := v.evaluator.Evaluate(v.bundle.Flag, model.EvaluationContext{TargetingKey: identity.Subject, Attributes: attrs})
	if result.Failed {
		http.Error(w, "POLICY_DECISION_FAILED", http.StatusServiceUnavailable)
		return
	}
	build, ok := result.Value.(string)
	if !ok {
		http.Error(w, "INVALID_BUILD", http.StatusServiceUnavailable)
		return
	}
	sanitize(r)
	r.Header.Set("X-Gogw-Subject", identity.Subject)
	r.Header.Set("X-Gogw-Tenant", identity.Tenant)
	if build == g.cfg.Build {
		v.local.ServeHTTP(w, r)
		return
	}
	if time.Now().Unix() >= v.bundle.DiscoveryExpiresUnix {
		http.Error(w, "DISCOVERY_EXPIRED", http.StatusServiceUnavailable)
		return
	}
	handler := v.builds[build]
	if handler == nil {
		http.Error(w, "NO_ELIGIBLE_ENDPOINT", http.StatusServiceUnavailable)
		return
	}
	if lb, ok := handler.(*wrr.Balancer); ok {
		for _, ep := range v.bundle.Endpoints {
			if ep.Build == build && ep.ExpiresUnix <= time.Now().Unix() {
				lb.SetStatus(r.Context(), ep.Instance, false)
			}
		}
	}
	r = r.WithContext(context.WithValue(r.Context(), decisionKey{}, decision{subject: identity.Subject, tenant: identity.Tenant}))
	handler.ServeHTTP(w, r)
}

func sanitize(r *http.Request) {
	for key := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-gogw-") {
			r.Header.Del(key)
		}
	}
}

func (g *Gateway) remote(v *view, ep Endpoint, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := r.Context().Value(decisionKey{}).(decision)
		if !ok {
			http.Error(w, "MISSING_DECISION", http.StatusInternalServerError)
			return
		}
		now := time.Now()
		claims := ticket{ID: uuid.New().String(), Issuer: g.cfg.Instance, Subject: d.subject, Audience: jwt.ClaimStrings{ep.Instance}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Second)), Workspace: g.cfg.Scope.WorkspaceID, Environment: g.cfg.Scope.EnvironmentID, Service: g.cfg.Scope.ServiceKey, IssuerBoot: g.cfg.Boot, Boot: ep.Boot, Build: ep.Build, Bundle: v.hash, Generation: v.bundle.Generation, Method: r.Method, Authority: r.Host, URI: r.URL.RequestURI(), Tenant: d.tenant, Final: true, Hop: 1}
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		token.Header["typ"] = "gogw-final+jwt"
		raw, err := token.SignedString(g.key)
		if err != nil {
			http.Error(w, "TICKET_FAILED", http.StatusInternalServerError)
			return
		}
		r = r.Clone(r.Context())
		r.Header.Set(ticketHeader, raw)
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) verifyTicket(v *view, r *http.Request) (*ticket, error) {
	values := r.Header.Values(ticketHeader)
	if len(values) != 1 || len(values[0]) > 8192 || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("missing peer or ticket")
	}
	leaf := r.TLS.PeerCertificates[0]
	key, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("invalid peer key")
	}
	claims := new(ticket)
	_, err := jwt.ParseWithClaims(values[0], claims, func(token *jwt.Token) (any, error) {
		if token.Header["typ"] != "gogw-final+jwt" {
			return nil, errors.New("invalid ticket type")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithAudience(g.cfg.Instance), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, errors.New("invalid ticket signature")
	}
	ep, exists := v.peers[claims.Issuer]
	digest := sha256.Sum256(leaf.Raw)
	if !exists || ep.Boot != claims.IssuerBoot || ep.CertificateSHA256 != hex.EncodeToString(digest[:]) || claims.Workspace != g.cfg.Scope.WorkspaceID || claims.Environment != g.cfg.Scope.EnvironmentID || claims.Service != g.cfg.Scope.ServiceKey || claims.Boot != g.cfg.Boot || claims.Build != g.cfg.Build || claims.Bundle != v.hash || claims.Generation != v.bundle.Generation || claims.Method != r.Method || claims.Authority != r.Host || claims.URI != r.URL.RequestURI() || !claims.Final || claims.Hop != 1 || claims.Subject == "" || claims.ID == "" || claims.IssuedAt == nil || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 15*time.Second {
		return nil, errors.New("ticket binding mismatch")
	}
	return claims, nil
}
