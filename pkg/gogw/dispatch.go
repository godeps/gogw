package gogw

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// hopHeaders are connection-scoped headers that end at this hop. Transfer and
// content length are deliberately absent: the standard library owns them.
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Upgrade",
}

// attemptKey carries the per-attempt state from the retry loop to the member
// handler that the balancer selects.
type attemptKey struct{}

// attempt is the state of one dispatch attempt. A retry is only safe when the
// transport failed before any response byte reached the client.
type attempt struct {
	id              string
	transportFailed bool
}

func attemptFrom(req *http.Request) *attempt {
	found, _ := req.Context().Value(attemptKey{}).(*attempt)
	return found
}

// memberHandler forwards every request it receives to exactly one candidate,
// either the co-deployed application over loopback or a peer gateway over pinned
// mTLS. A handler owns one connection pool, which the view reclaims when it is
// closed.
type memberHandler struct {
	g         *Gateway
	view      *view
	build     string
	candidate member
	local     bool

	target    *url.URL
	client    *http.Client
	transport *http.Transport
}

// newMemberHandler builds the handler of one candidate. A candidate that cannot
// be addressed is not created at all, so a handler never dials an unverified
// origin.
func newMemberHandler(g *Gateway, v *view, build string, candidate member, local bool) (http.Handler, error) {
	var target *url.URL
	if local {
		// The co-deployed application is reached at its configured loopback
		// endpoint, not at the address the discovery artifact advertises for this
		// instance: that one names the gateway's own internal surface, and dialing it
		// would put the request through a second gateway hop nobody authorized.
		target = g.localURL
	} else {
		advertised, err := memberURL(candidate.url)
		if err != nil {
			return nil, err
		}
		target = advertised
	}
	var transport *http.Transport
	if local {
		transport = g.localTransport
	} else {
		transport = memberTransport(g.caPool, g.id, candidate)
	}
	client := &http.Client{
		Transport: noReplay{next: transport},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// A redirect would move the request, and any signed ticket with it, to
			// an origin that was never verified as a candidate.
			return http.ErrUseLastResponse
		},
	}
	return &memberHandler{g: g, view: v, build: build, candidate: candidate, local: local, target: target, client: client, transport: transport}, nil
}

func (h *memberHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	attempt := attemptFrom(req)
	if attempt != nil {
		attempt.id = h.candidate.id
	}
	outbound := req.Clone(req.Context())
	outbound.RequestURI = ""
	outbound.URL.Scheme = h.target.Scheme
	outbound.URL.Host = h.target.Host
	outbound.URL.RawQuery = req.URL.RawQuery
	outbound.URL.Opaque = ""
	outbound.URL.Fragment = ""
	outbound.URL.User = nil
	// The application must keep seeing the authority the client addressed.
	outbound.Host = req.Host
	outbound.Close = false
	for _, name := range hopHeaders {
		outbound.Header.Del(name)
	}
	if h.local {
		outbound.Header.Del(ticketHeader)
	} else {
		token, err := h.ticket(req)
		if err != nil {
			h.attemptFailed(attempt)
			writeError(rw, codeUpstreamFailed, http.StatusInternalServerError)
			return
		}
		outbound.Header.Set(ticketHeader, token)
	}
	h.g.inFlight.Add(1)
	defer h.g.inFlight.Add(-1)
	response, err := h.client.Do(outbound)
	if err != nil {
		h.attemptFailed(attempt)
		if req.Context().Err() != nil {
			// The client or the drain deadline canceled the request; the status no
			// longer reaches anyone.
			return
		}
		h.g.metrics.add(phaseExecution, h.build, "transport_error")
		if attempt != nil {
			// The retry layer owns the response: this failure is only final once no
			// candidate of the build is left to try.
			return
		}
		writeError(rw, codeUpstreamFailed, http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	h.g.metrics.add(phaseExecution, h.build, "served")
	copyResponse(rw, response)
}

// attemptFailed marks the attempt as a transport failure, which is the only kind
// of failure a retry may follow.
func (h *memberHandler) attemptFailed(attempt *attempt) {
	if attempt != nil {
		attempt.transportFailed = true
	}
}

// ticket signs the exact request this handler is about to send. The receiver
// resolves the key from its own approved discovery artifact, so the ticket needs
// no second key distribution channel.
func (h *memberHandler) ticket(req *http.Request) (string, error) {
	route, ok := routingFrom(req)
	if !ok {
		return "", errors.New("gogw: missing routing decision")
	}
	now := time.Now()
	claims := ticketClaims{
		Issuer: h.g.cfg.Instance, IssuerBoot: h.g.cfg.Boot,
		// The subject is the instance this ticket may be presented to, so a ticket
		// captured from one member cannot be replayed against another one.
		Subject: h.candidate.id, SubjectBoot: h.candidate.boot,
		Build: h.candidate.build, Bundle: h.view.bundleHashHex(), Generation: h.view.generation,
		Method: req.Method, Authority: req.Host, URI: req.URL.RequestURI(),
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(ticketTTL).UnixMilli(),
		Final: true, Hop: 1, Principal: route.subject, Tenant: route.tenant,
		DecisionID: route.decision,
	}
	key := h.g.id.signer()
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("gogw: gateway identity is unavailable")
	}
	return signTicket(key, claims)
}

// closePools releases the connections this handler owns.
func (h *memberHandler) closePools() {
	if h.transport != nil && !h.local {
		h.transport.CloseIdleConnections()
	}
}

// serve dispatches one request through the balancer with a bounded retry that
// never leaves the build and never repeats a write whose result is unknown.
func (d *buildDispatcher) serve(rw http.ResponseWriter, req *http.Request) {
	if !d.hasHealthy(time.Now()) {
		d.g.metrics.add(phaseExecution, d.build, "no_candidate")
		writeError(rw, codeNoEligible, http.StatusServiceUnavailable)
		return
	}
	tries := 1
	if replayable(req) {
		tries = d.maxTries
	}
	for try := range tries {
		if try > 0 && !d.hasHealthy(time.Now()) {
			// Every candidate of the build is isolated: the loop ends on its own
			// bounded error rather than on an answer from the balancer.
			break
		}
		attempt := new(attempt)
		progress := &progressWriter{next: rw}
		request := req.WithContext(contextWithAttempt(req.Context(), attempt))
		d.balancer.ServeHTTP(progress, request)
		if progress.committed {
			// A response has already reached the client: retrying could duplicate
			// an effect whose outcome the client has seen.
			return
		}
		if !attempt.transportFailed {
			// No handler ran at all, so every candidate was isolated at once.
			writeError(rw, codeNoEligible, http.StatusServiceUnavailable)
			return
		}
		d.isolate(attempt.id, time.Now())
		d.g.metrics.add(phaseExecution, d.build, "isolated")
	}
	writeError(rw, codeUpstreamFailed, http.StatusBadGateway)
}

// serveLocal dispatches one internal request to the application of this process.
// The ticket the request carries names this receiver, so the local candidate is
// the only one it may reach: forwarding it further would put it in front of an
// instance that never verified the ticket and cannot sign a successor.
func (d *buildDispatcher) serveLocal(rw http.ResponseWriter, req *http.Request) {
	tries := 1
	if replayable(req) {
		tries = d.maxTries
	}
	for range tries {
		attempt := new(attempt)
		progress := &progressWriter{next: rw}
		d.localHandler.ServeHTTP(progress, req.WithContext(contextWithAttempt(req.Context(), attempt)))
		if progress.committed {
			return
		}
		if attempt.transportFailed {
			continue
		}
		// The handler answered nothing and reported no transport failure, so there
		// is nothing left for this build to try.
		writeError(rw, codeUpstreamFailed, http.StatusBadGateway)
		return
	}
	writeError(rw, codeUpstreamFailed, http.StatusBadGateway)
}

func contextWithAttempt(ctx context.Context, attempt *attempt) context.Context {
	return context.WithValue(ctx, attemptKey{}, attempt)
}

// progressWriter records whether a response has started. Once it has, no retry
// may follow, because the client already observed this attempt.
type progressWriter struct {
	next      http.ResponseWriter
	committed bool
}

func (p *progressWriter) Header() http.Header { return p.next.Header() }

func (p *progressWriter) WriteHeader(status int) {
	p.committed = true
	p.next.WriteHeader(status)
}

func (p *progressWriter) Write(payload []byte) (int, error) {
	p.committed = true
	return p.next.Write(payload)
}

// Flush forwards flushing so a streaming handler keeps its latency without
// needing the retry layer to know about it.
func (p *progressWriter) Flush() {
	p.committed = true
	if flusher, ok := p.next.(http.Flusher); ok {
		flusher.Flush()
	}
}

// copyResponse streams one upstream response to the client, flushing as it goes
// so server-sent events and long-polling bodies are not buffered.
func copyResponse(rw http.ResponseWriter, response *http.Response) {
	header := rw.Header()
	for name, values := range response.Header {
		if isHopHeader(name) {
			continue
		}
		header.Del(name)
		for _, value := range values {
			header.Add(name, value)
		}
	}
	rw.WriteHeader(response.StatusCode)
	if response.Body == nil {
		return
	}
	controller := http.NewResponseController(rw)
	buffer := make([]byte, 32<<10)
	for {
		read, err := response.Body.Read(buffer)
		if read > 0 {
			if _, writeErr := rw.Write(buffer[:read]); writeErr != nil {
				return
			}
			_ = controller.Flush()
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				// The response is already committed, so the only signal left is the
				// truncated body the client sees.
				return
			}
			return
		}
	}
}

func isHopHeader(name string) bool {
	for _, candidate := range hopHeaders {
		if strings.EqualFold(candidate, name) {
			return true
		}
	}
	return false
}
