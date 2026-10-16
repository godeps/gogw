package gogw

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/saker-ai/grayling/pkg/model"
)

// routing is the authorized decision of one request: who it belongs to and which
// logical build it resolved to. It is what the forwarding layer signs.
type routing struct {
	subject  string
	tenant   string
	build    string
	decision string
}

// hopHeader tells the application how many gateway boundaries a request already
// crossed: zero when the gateway of this process dispatched it, one when it
// arrived on the internal surface under a verified final ticket. The value is a
// count, so an application can assert the at-most-one-hop invariant itself
// instead of trusting that no gateway forwarded it further. Sanitize drops any
// client-supplied value first, and only the gateway of this process sets it.
const hopHeader = "X-Gogw-Hop"

const (
	hopDirect    = "0"
	hopForwarded = "1"
)

type routingKey struct{}

func routingFrom(req *http.Request) (routing, bool) {
	found, ok := req.Context().Value(routingKey{}).(routing)
	return found, ok
}

// principal is the authenticated identity of an ordinary request. The gateway
// never parses application tokens itself: the application authentication layer
// mints a short-lived bearer token signed with the shared identity secret.
type principal struct {
	jwt.RegisteredClaims

	Tenant string `json:"tenant,omitempty"`
	Tier   string `json:"tier,omitempty"`
}

// BuildHTTP implements Traefik's existing ServiceBuilder hook without extending
// its generated dynamic configuration or claiming a public service plugin API.
func (g *Gateway) BuildHTTP(_ context.Context, name string) (http.Handler, error) {
	if name != g.cfg.Service+"@gogw" {
		return nil, nil
	}
	return g, nil
}

// ServeHTTP is the single entry point of the gateway: readiness, the internal
// peer path, and ordinary business traffic all arrive here.
func (g *Gateway) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Upgrade") != "" || strings.HasPrefix(req.Header.Get("Content-Type"), "application/grpc") {
		writeError(rw, codeTransportRejected, http.StatusNotImplemented)
		return
	}
	if req.URL.Path == readinessPath {
		g.serveReady(rw)
		return
	}
	if g.draining.Load() {
		writeError(rw, codeDraining, http.StatusServiceUnavailable)
		return
	}
	// An instance whose application stopped answering starts no new work either, and
	// the refusal names that state instead of the drain it is not in: the two are
	// different operator problems, and a client reading the body is the one who has
	// to tell them apart.
	if !g.healthy.Load() {
		writeError(rw, codeNotReady, http.StatusServiceUnavailable)
		return
	}
	// Traefik rewrites semicolon query separators, so a signed target would not
	// be the target the application receives.
	if strings.Contains(req.URL.RawQuery, ";") || req.URL.Opaque != "" {
		writeError(rw, codeInternalOnly, http.StatusBadRequest)
		return
	}
	req = req.Clone(req.Context())
	req.RequestURI = req.URL.RequestURI()
	if len(req.TLS.PeerCertificates) > 0 || len(req.Header.Values(ticketHeader)) > 0 {
		g.serveInternal(rw, req)
		return
	}
	g.serveBusiness(rw, req)
}

// serveReady reports readiness without revealing why the gateway is not ready.
func (g *Gateway) serveReady(rw http.ResponseWriter) {
	if !g.Ready() {
		writeError(rw, codeNotReady, http.StatusServiceUnavailable)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// serveBusiness authenticates one ordinary request, resolves its release and
// build, and dispatches it.
func (g *Gateway) serveBusiness(rw http.ResponseWriter, req *http.Request) {
	identity, err := g.authenticate(req)
	if err != nil {
		writeError(rw, codeUnauthenticated, http.StatusUnauthorized)
		return
	}
	now := time.Now()
	v := g.activeView()
	if v == nil {
		writeError(rw, codeNoView, http.StatusServiceUnavailable)
		return
	}
	defer v.release()
	if ok, code := v.accepts(now); !ok {
		writeError(rw, code, http.StatusServiceUnavailable)
		return
	}
	context := model.EvaluationContext{
		TargetingKey: identity.Subject,
		Attributes: map[string]any{
			"tenant": identity.Tenant, "tier": identity.Tier, "client_ip": g.clientIP(req),
		},
	}
	choice, code := v.allocate(context)
	if code != "" {
		g.metrics.add(phaseAllocation, choice.build, code)
		writeError(rw, code, http.StatusServiceUnavailable)
		return
	}
	g.metrics.add(phaseAllocation, choice.build, allocationLabel(choice))
	sanitize(req)
	req.Header.Set("X-Gogw-Subject", identity.Subject)
	req.Header.Set("X-Gogw-Tenant", identity.Tenant)
	req.Header.Set(hopHeader, hopDirect)
	g.route(rw, req, v, choice.build, identity.Subject, identity.Tenant, choice.decision, now)
}

// serveInternal serves a request that crossed the gateway identity boundary. A
// presented certificate is an internal marker: an invalid ticket is refused
// instead of falling back to ordinary authentication.
func (g *Gateway) serveInternal(rw http.ResponseWriter, req *http.Request) {
	now := time.Now()
	claims, verifier, err := g.verifyTicket(req, now)
	if err != nil {
		g.metrics.add(phaseExecution, "", "ticket_rejected")
		writeError(rw, codeInternalOnly, http.StatusForbidden)
		return
	}
	_ = verifier
	if req.URL.Path == diagnosticsPath {
		g.serveDiagnostics(rw, claims)
		return
	}
	if !g.acceptsRelease(claims.Bundle, claims.Generation, now) {
		writeError(rw, codeNoView, http.StatusServiceUnavailable)
		return
	}
	v := g.activeView()
	if v == nil || v.bundleHashHex() != claims.Bundle {
		// A retained view may still serve a straggler, but never outside its
		// compatibility window.
		if v != nil {
			v.release()
		}
		v = g.retainedView(claims.Bundle, claims.Generation, now)
	}
	if v == nil {
		writeError(rw, codeNoView, http.StatusServiceUnavailable)
		return
	}
	defer v.release()
	if ok, code := v.accepts(now); !ok {
		writeError(rw, code, http.StatusServiceUnavailable)
		return
	}
	sanitize(req)
	req.Header.Set("X-Gogw-Subject", claims.Principal)
	req.Header.Set("X-Gogw-Tenant", claims.Tenant)
	req.Header.Set(hopHeader, hopForwarded)
	dispatcher, ok := v.dispatcher(claims.Build)
	if !ok || !dispatcher.hasLocal() {
		writeError(rw, codeBuildUnknown, http.StatusServiceUnavailable)
		return
	}
	g.metrics.add(phaseAllocation, claims.Build, "internal")
	g.executeLocal(rw, req, v, dispatcher)
}

// serveDiagnostics answers the internal diagnostics path. Only an admitted peer
// with a valid final ticket reaches it, and the document carries state only.
func (g *Gateway) serveDiagnostics(rw http.ResponseWriter, claims ticketClaims) {
	body := g.DiagnosticsJSON()
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(http.StatusOK)
	if _, err := rw.Write(body); err != nil {
		return
	}
	_ = claims
}

// route binds one authenticated unit to a release and build, then dispatches.
// The binding is what keeps a unit on the same build across a release change for
// the length of the compatibility window.
func (g *Gateway) route(rw http.ResponseWriter, req *http.Request, v *view, build, subject, tenant, decision string, now time.Time) {
	// The signed ticket is minted from this decision, so every path below needs it
	// in the context — a bound session dispatching to a peer is the same forward as
	// a fresh one, and a missing decision is a forward the receiver cannot verify.
	req = req.WithContext(context.WithValue(req.Context(), routingKey{}, routing{subject: subject, tenant: tenant, build: build, decision: decision}))
	key := g.sessions.key(g.cfg.Service, tenant, subject)
	if binding, ok := g.sessions.lookup(key); ok && withinWindow(binding.view, g.sessions.compat, now) {
		if accepted, _ := binding.view.accepts(now); accepted {
			if dispatcher, found := binding.view.dispatcher(binding.build); found {
				g.sessions.touch(binding, now)
				g.metrics.add(phaseExecution, binding.build, "bound")
				g.execute(rw, req, binding.view, dispatcher, binding.build)
				return
			}
		}
		g.sessions.forget(key)
	}
	dispatcher, ok := v.dispatcher(build)
	if !ok {
		g.metrics.add(phaseExecution, build, codeNoEligible)
		writeError(rw, codeNoEligible, http.StatusServiceUnavailable)
		return
	}
	_, exposed := g.sessions.bind(key, v, build, now)
	if exposed {
		g.metrics.add(phaseExposure, build, "exposed")
	}
	g.execute(rw, req, v, dispatcher, build)
}

// execute runs one dispatch inside the stream registry, so revocation and the
// drain deadline can terminate a response that outlives its release.
func (g *Gateway) execute(rw http.ResponseWriter, req *http.Request, v *view, dispatcher *buildDispatcher, build string) {
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	handle := g.streams.add(v, cancel)
	defer g.streams.remove(handle)
	progress := &progressWriter{next: rw}
	dispatcher.serve(progress, req.WithContext(ctx))
	if progress.committed {
		g.metrics.add(phaseExposure, build, "delivered")
	}
}

// executeLocal runs one internal request against the application of this
// instance, under the same stream registry as ordinary traffic so a revoked
// release can terminate it too.
func (g *Gateway) executeLocal(rw http.ResponseWriter, req *http.Request, v *view, dispatcher *buildDispatcher) {
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	handle := g.streams.add(v, cancel)
	defer g.streams.remove(handle)
	dispatcher.serveLocal(rw, req.WithContext(ctx))
}

// authenticate verifies the short-lived bearer token minted by the application
// authentication layer with the shared identity secret.
func (g *Gateway) authenticate(req *http.Request) (*principal, error) {
	values := req.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return nil, errors.New("gogw: missing identity")
	}
	claims := new(principal)
	_, err := jwt.ParseWithClaims(strings.TrimPrefix(values[0], "Bearer "), claims,
		func(*jwt.Token) (any, error) { return g.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(g.cfg.IdentityIssuer),
		jwt.WithAudience(g.cfg.Scope.ServiceKey), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || claims.Subject == "" || len(claims.Subject) > maxIdentifier {
		return nil, errors.New("gogw: invalid identity")
	}
	return claims, nil
}

// verifyTicket checks a final forwarding ticket against this instance, the
// certificate the sender presented and the release this gateway accepts. The
// signature key is the peer certificate itself, which the approved discovery
// artifact pins by digest, so no second key distribution channel is needed.
func (g *Gateway) verifyTicket(req *http.Request, now time.Time) (ticketClaims, ticketVerifier, error) {
	var claims ticketClaims
	var verifier ticketVerifier
	values := req.Header.Values(ticketHeader)
	if len(values) != 1 || len(values[0]) > maxTicketBytes || req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return claims, verifier, errTicket
	}
	claims, verifier, err := decodeTicket(values[0])
	if err != nil {
		return claims, verifier, err
	}
	digest, ok := peerDigest(req.TLS)
	if !ok {
		return claims, verifier, errTicket
	}
	candidate, ok := g.peer(claims.Issuer, claims.IssuerBoot)
	if !ok {
		return claims, verifier, errTicket
	}
	if digest != candidate.digests[0] && !slices.Contains(candidate.digests, digest) {
		return claims, verifier, errTicket
	}
	public, ok := peerKey(req.TLS)
	if !ok || !verifier.verify(public) {
		return claims, verifier, errTicket
	}
	issued := time.UnixMilli(claims.IssuedAt)
	expires := time.UnixMilli(claims.ExpiresAt)
	switch {
	case claims.Subject != g.cfg.Instance, claims.SubjectBoot != g.cfg.Boot:
		return claims, verifier, errTicket
	case claims.Build != g.cfg.Build, claims.Bundle == "", claims.Generation == 0:
		return claims, verifier, errTicket
	case claims.Method != req.Method, claims.Authority != req.Host, claims.URI != req.URL.RequestURI():
		return claims, verifier, errTicket
	case claims.Principal == "" || len(claims.Principal) > maxIdentifier:
		return claims, verifier, errTicket
	case len(claims.Tenant) > maxIdentifier:
		return claims, verifier, errTicket
	case claims.IssuedAt == 0 || now.Add(ticketLeeway).Before(issued), now.After(expires.Add(ticketLeeway)):
		return claims, verifier, errTicket
	case expires.Sub(issued) <= 0 || expires.Sub(issued) > ticketTTL:
		return claims, verifier, errTicket
	}
	return claims, verifier, nil
}

// sanitize drops every gateway-owned header so a client cannot inject an
// identity or a decision the gateway is about to set itself.
func sanitize(req *http.Request) {
	for name := range req.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-gogw-") {
			req.Header.Del(name)
		}
	}
	for _, name := range hopHeaders {
		req.Header.Del(name)
	}
}

// trusted reports whether an address belongs to a configured proxy.
func (g *Gateway) trusted(ip net.IP) bool {
	for _, network := range g.proxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP resolves the caller address behind a trusted proxy chain. An
// untrusted peer cannot assert an address: its own address wins.
func (g *Gateway) clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if !g.trusted(ip) {
		return ip.String()
	}
	for _, entry := range slices.Backward(strings.Split(req.Header.Get("X-Forwarded-For"), ",")) {
		next := net.ParseIP(strings.TrimSpace(entry))
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

// writeError writes one bounded error body. Every rejection code comes from a
// fixed vocabulary, so a body never carries release, member or principal data.
func writeError(rw http.ResponseWriter, code string, status int) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(status)
	if _, err := rw.Write([]byte(code + "\n")); err != nil {
		return
	}
}

// allocationLabel renders the bounded metric label of one allocation.
func allocationLabel(choice allocation) string {
	if choice.ramp != "" {
		return choice.ramp
	}
	if choice.reason == "" {
		return "policy"
	}
	if !validIdentifier(choice.reason, 64) {
		return overflowLabel
	}
	return choice.reason
}
