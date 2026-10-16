package gogw_test

// routing_test.go covers the traffic requirements: the internal single-hop
// surface, ticket bindings, policy allocation and the monotone ramp, session
// binding across a release change, retry and isolation, unknown writes, the
// absence of a cross-build fallback, streaming, and capacity bounds.
//
// The tests here are as close to black-box as the topology allows: they drive the
// gateway over HTTP and read responses, the application's view of the request and
// the control plane's journal.

import (
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/saker-ai/grayling/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/gogw"
	"github.com/traefik/traefik/v3/pkg/gogw/mock"
)

// ticketHeaderName is the frozen wire name of the final forwarding ticket. It is
// repeated here so a rename in the package fails these tests instead of silently
// changing the protocol.
const ticketHeaderName = "X-Gogw-Ticket"

// hopHeaderName is the header the gateway of the serving process uses to tell the
// application how many gateway boundaries the request already crossed. It is
// repeated here for the same reason as the ticket name.
const hopHeaderName = "X-Gogw-Hop"

// finalTicket mints a final forwarding ticket exactly as a peer gateway does, so
// a test can address the internal surface of one instance directly. The ticket
// names the newest published release.
func (c *cluster) finalTicket(t *testing.T, from *instance, key ed25519.PrivateKey, to *instance, method, uri string) string {
	t.Helper()
	return c.finalTicketOn(t, from, key, to, c.last, method, uri)
}

// finalTicketOn mints the same ticket against a named publication, so a test can
// present a request bound to a release the receiver has already retired.
func (c *cluster) finalTicketOn(t *testing.T, from *instance, key ed25519.PrivateKey, to *instance, on activated, method, uri string) string {
	t.Helper()
	now := time.Now()
	return signTestTicket(t, key, ticketClaims{
		Issuer: from.name, IssuerBoot: from.boot,
		// The subject is the instance the ticket may be presented to.
		Subject: to.name, SubjectBoot: to.boot,
		Build: to.build, Bundle: on.hash, Generation: on.release.Generation,
		Method: method, Authority: strings.TrimPrefix(to.server.URL, "https://"), URI: uri,
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(5 * time.Second).UnixMilli(),
		Final: true, Hop: 1, Principal: "peer-user", Tenant: "peer-tenant",
	})
}

// finalRequest presents one hand-minted ticket with one client certificate.
func (c *cluster) finalRequest(t *testing.T, to int, pair tls.Certificate, method, uri, ticket string) *http.Response {
	t.Helper()
	return c.peerRequest(t, to, pair, method, uri, http.Header{ticketHeaderName: []string{ticket}})
}

// TestLocalAndSingleHop is the hop contract: the co-deployed application is
// reached directly by the gateways that serve it, and any other candidate is
// reached over pinned mTLS with exactly one final ticket.
func TestLocalAndSingleHop(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	// The stable build of this instance is its own application.
	response := c.request(t, 0, http.MethodGet, "/orders?page=2", "user-1", "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "stable", response.Header.Get("X-Actual-Build"))
	assert.Equal(t, "stable-0", response.Header.Get("X-Actual-Instance"))
	assert.Equal(t, "local", response.Header.Get("X-Actual-Hop"))
	assert.Equal(t, "user-1", response.Header.Get("X-Actual-Subject"))
	assert.Equal(t, "/orders?page=2", body(t, response))

	// The canary build is another instance, so the request crosses the gateway
	// boundary with one final ticket and arrives with a hop count of one.
	response = c.request(t, 0, http.MethodGet, "/orders?page=2", "canary-user", "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
	assert.Equal(t, "canary-1", response.Header.Get("X-Actual-Instance"))
	assert.Equal(t, "1", response.Header.Get("X-Actual-Hop"))
	assert.Equal(t, "canary-user", response.Header.Get("X-Actual-Subject"))
	assert.Equal(t, "/orders?page=2", body(t, response))

	// The receiving instance answers on the internal surface, which is the proof
	// that the forward itself is what the ticket authorized.
	assert.Positive(t, counter(c.members[1].gateway.Diagnostics(), "allocation", "internal"))

	// The same holds in the other direction.
	response = c.request(t, 1, http.MethodGet, "/orders", "user-1", "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "stable", response.Header.Get("X-Actual-Build"))
	assert.Equal(t, "stable-0", response.Header.Get("X-Actual-Instance"))
	assert.Equal(t, "1", response.Header.Get("X-Actual-Hop"))
	assert.Equal(t, "/orders", body(t, response))
}

// TestUntrustedRequests is the unauthenticated surface: a business request needs
// a valid identity token, and nothing a client sends can reach the internal
// surface or an unsupported transport.
func TestUntrustedRequests(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	// No token at all, and every token that is not this gateway's identity.
	for _, headers := range []http.Header{
		nil,
		{"Authorization": []string{"Bearer "}},
		{"Authorization": []string{"Bearer " + c.bearerToken(t, map[string]any{"iss": c.issuer, "aud": c.scope.ServiceKey, "sub": "user-1", "exp": time.Now().Add(time.Minute).Unix()}, []byte(strings.Repeat("x", 32)))}},
		{"Authorization": []string{"Bearer " + c.bearerToken(t, map[string]any{"iss": c.issuer, "aud": "other-service", "sub": "user-1", "exp": time.Now().Add(time.Minute).Unix()}, c.secret)}},
		{"Authorization": []string{"Bearer " + c.bearerToken(t, map[string]any{"iss": "other-issuer", "aud": c.scope.ServiceKey, "sub": "user-1", "exp": time.Now().Add(time.Minute).Unix()}, c.secret)}},
		{"Authorization": []string{"Bearer " + c.bearerToken(t, map[string]any{"iss": c.issuer, "aud": c.scope.ServiceKey, "sub": "user-1", "exp": time.Now().Add(-time.Minute).Unix()}, c.secret)}},
	} {
		response := c.raw(t, 0, http.MethodGet, "/orders", headers)
		assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
		assert.Equal(t, "UNAUTHENTICATED\n", body(t, response))
	}

	// A gateway-owned header a client sends is dropped, so an identity cannot be
	// injected.
	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", http.Header{
		"X-Gogw-Subject": {"attacker"},
		"X-Gogw-Tenant":  {"attacker-tenant"},
	})
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "user-1", response.Header.Get("X-Actual-Subject"))
	body(t, response)

	// The internal surface is not addressable from the business path.
	response = c.request(t, 0, http.MethodGet, "/orders?a=;b", "user-1", "", nil)
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	assert.Equal(t, "INTERNAL_ONLY\n", body(t, response))

	// A ticket without a client certificate is refused instead of falling back to
	// ordinary authentication.
	response = c.raw(t, 0, http.MethodGet, "/orders", http.Header{ticketHeaderName: {"forged"}})
	assert.Equal(t, http.StatusForbidden, response.StatusCode)
	assert.Equal(t, "INTERNAL_ONLY\n", body(t, response))

	// A transport the gateway does not proxy is refused explicitly rather than
	// forwarded as a plain request.
	response = c.raw(t, 0, http.MethodGet, "/orders", http.Header{
		"Connection": {"Upgrade"}, "Upgrade": {"websocket"},
	})
	assert.Equal(t, http.StatusNotImplemented, response.StatusCode)
	assert.Equal(t, "TRANSPORT_UNSUPPORTED\n", body(t, response))
}

// TestTicketBindings is the internal authorization contract: a final ticket is
// bound to one method, one URI, one authority, one receiver and one validity
// window, and it is signed by the key of the certificate that presents it.
func TestTicketBindings(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))
	from, to := c.members[0], c.members[1]

	// The unmodified ticket is accepted, so every refusal below is the binding
	// under test and not the surface being broken.
	ticket := c.finalTicket(t, from, from.current.key, to, http.MethodGet, "/orders")
	response := c.finalRequest(t, 1, from.current.pair, http.MethodGet, "/orders", ticket)
	require.Equal(t, http.StatusOK, response.StatusCode)
	body(t, response)

	cases := map[string]struct {
		ticket   string
		method   string
		uri      string
		pair     tls.Certificate
		expected string
	}{
		"another uri": {
			ticket: c.finalTicket(t, from, from.current.key, to, http.MethodGet, "/orders"), method: http.MethodGet, uri: "/orders/1",
			pair: from.current.pair, expected: "INTERNAL_ONLY\n",
		},
		"another method": {
			ticket: c.finalTicket(t, from, from.current.key, to, http.MethodPost, "/orders"), method: http.MethodGet, uri: "/orders",
			pair: from.current.pair, expected: "INTERNAL_ONLY\n",
		},
		"another receiver": func() struct {
			ticket   string
			method   string
			uri      string
			pair     tls.Certificate
			expected string
		} {
			// A ticket addressed to the other instance cannot be presented here.
			other := c.finalTicket(t, from, from.current.key, from, http.MethodGet, "/orders")
			return struct {
				ticket   string
				method   string
				uri      string
				pair     tls.Certificate
				expected string
			}{other, http.MethodGet, "/orders", from.current.pair, "INTERNAL_ONLY\n"}
		}(),
		"another certificate": {
			ticket: c.finalTicket(t, from, from.current.key, to, http.MethodGet, "/orders"), method: http.MethodGet, uri: "/orders",
			pair: to.current.pair, expected: "INTERNAL_ONLY\n",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			response := c.finalRequest(t, 1, tc.pair, tc.method, tc.uri, tc.ticket)
			assert.Equal(t, http.StatusForbidden, response.StatusCode)
			assert.Equal(t, tc.expected, body(t, response))
		})
	}

	// A signature that does not match the presented certificate is refused, so a
	// captured ticket is worthless without the private key.
	forged := c.finalTicket(t, from, signingKey(t), to, http.MethodGet, "/orders")
	response = c.finalRequest(t, 1, from.current.pair, http.MethodGet, "/orders", forged)
	assert.Equal(t, http.StatusForbidden, response.StatusCode)
	assert.Equal(t, "INTERNAL_ONLY\n", body(t, response))

	// A ticket outside the protocol's validity window is refused: the window is
	// bounded in both directions.
	now := time.Now()
	stale := signTestTicket(t, from.current.key, ticketClaims{
		Issuer: from.name, IssuerBoot: from.boot, Subject: to.name, SubjectBoot: to.boot,
		Build: to.build, Bundle: c.last.hash, Generation: c.last.release.Generation,
		Method: http.MethodGet, Authority: strings.TrimPrefix(to.server.URL, "https://"), URI: "/orders",
		IssuedAt: now.Add(-time.Minute).UnixMilli(), ExpiresAt: now.Add(-time.Minute).Add(5 * time.Second).UnixMilli(),
		Final: true, Hop: 1, Principal: "peer-user",
	})
	response = c.finalRequest(t, 1, from.current.pair, http.MethodGet, "/orders", stale)
	assert.Equal(t, http.StatusForbidden, response.StatusCode)
	body(t, response)

	// A ticket whose window is longer than the protocol allows is refused as well.
	long := signTestTicket(t, from.current.key, ticketClaims{
		Issuer: from.name, IssuerBoot: from.boot, Subject: to.name, SubjectBoot: to.boot,
		Build: to.build, Bundle: c.last.hash, Generation: c.last.release.Generation,
		Method: http.MethodGet, Authority: strings.TrimPrefix(to.server.URL, "https://"), URI: "/orders",
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(time.Hour).UnixMilli(),
		Final: true, Hop: 1, Principal: "peer-user",
	})
	response = c.finalRequest(t, 1, from.current.pair, http.MethodGet, "/orders", long)
	assert.Equal(t, http.StatusForbidden, response.StatusCode)
	body(t, response)

	// A ticket that is not final is refused, which is what keeps the chain at one
	// hop.
	chained := signTestTicket(t, from.current.key, ticketClaims{
		Issuer: from.name, IssuerBoot: from.boot, Subject: to.name, SubjectBoot: to.boot,
		Build: to.build, Bundle: c.last.hash, Generation: c.last.release.Generation,
		Method: http.MethodGet, Authority: strings.TrimPrefix(to.server.URL, "https://"), URI: "/orders",
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(5 * time.Second).UnixMilli(),
		Final: false, Hop: 1, Principal: "peer-user",
	})
	response = c.finalRequest(t, 1, from.current.pair, http.MethodGet, "/orders", chained)
	assert.Equal(t, http.StatusForbidden, response.StatusCode)
	body(t, response)
	assert.Positive(t, counter(c.members[1].gateway.Diagnostics(), "execution", "ticket_rejected"))
}

// TestStableBucketsAndScaleInvariantAllocation proves the allocation is a
// function of the approved policy and the unit alone: two deployments of
// different size, given the same approved policy, send every unit to the same
// build. A partition that depended on the number of instances would drift here.
func TestStableBucketsAndScaleInvariantAllocation(t *testing.T) {
	flags := percentageFlags(30, 70)
	small := newCluster(t, withBuilds("stable", "canary"))
	small.activate(t, release(1, nil, flags))
	large := newCluster(t, withBuilds("stable", "canary", "stable"))
	large.activate(t, release(1, nil, flags))

	const population = 48
	allocation := func(c *cluster) map[string]string {
		builds := map[string]string{}
		for index := range population {
			subject := fmt.Sprintf("bucket-%02d", index)
			// One request per subject, so every answer is a fresh decision of the
			// policy rather than a binding.
			response := c.request(t, 0, http.MethodGet, "/orders", subject, "tenant", nil)
			require.Equal(t, http.StatusOK, response.StatusCode)
			body(t, response)
			builds[subject] = response.Header.Get("X-Actual-Build")
		}
		return builds
	}
	first, second := allocation(small), allocation(large)
	assert.Equal(t, first, second)

	// The split is not degenerate: both builds carry part of the population, so
	// an accidental single-build answer could not pass.
	canary := 0
	for _, build := range first {
		if build == "canary" {
			canary++
		}
	}
	assert.Greater(t, canary, population/10)
	assert.Less(t, canary, population-population/10)

	// Scaling out does not move a unit: adding a third instance to the large
	// deployment keeps every binding on its build.
	large.updateMembership(t, func(members []gogw.Member) []gogw.Member { return members })
	for index := range population {
		subject := fmt.Sprintf("bucket-%02d", index)
		response := large.request(t, 0, http.MethodGet, "/orders", subject, "tenant", nil)
		require.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, first[subject], response.Header.Get("X-Actual-Build"))
		body(t, response)
	}
}

// rampRelease sends every unit to the canary variation and lets the monotone
// eligibility prefix decide which units are allowed to use it.
func rampRelease(generation uint64, threshold int) mock.Release {
	return release(generation, &gogw.Ramp{
		Key: "routing", Epoch: 1, Salt: "fixed", Unit: "targetingKey",
		Threshold: threshold, CanaryBuild: "canary",
	}, map[string]*model.Flag{"routing": routingFlag(model.Rule{Variation: "canary"}, nil)})
}

// TestMonotoneRampPrefix proves a ratio change cannot move an exposed unit out of
// the canary prefix: the effective threshold is floored by the durable maximum,
// so a decrease holds and an increase only ever adds units.
//
// Every cohort is read after the compatibility window of the previous cohort has
// lapsed. A unit whose binding survives is served by the release that precedes
// the change, so a cohort taken while the store is still populated reports that
// superseded decision and says nothing about the floor.
func TestMonotoneRampPrefix(t *testing.T) {
	c := newCluster(t, withConfig(func(cfg *gogw.Config) { cfg.SessionCompatibilitySeconds = 1 }))

	const population = 48
	subjects := make([]string, 0, population)
	for index := range population {
		subjects = append(subjects, fmt.Sprintf("ramp-%02d", index))
	}
	cohort := func() map[string]bool {
		canary := map[string]bool{}
		for _, subject := range subjects {
			response := c.request(t, 0, http.MethodGet, "/orders", subject, "tenant", nil)
			require.Equal(t, http.StatusOK, response.StatusCode)
			body(t, response)
			canary[subject] = response.Header.Get("X-Actual-Build") == "canary"
		}
		return canary
	}
	lapse := func() {
		await(t, "the compatibility window of the previous cohort", func() bool {
			return c.members[0].gateway.Diagnostics().Sessions == 0
		})
	}

	c.activate(t, rampRelease(1, 6000))
	assert.Equal(t, 6000, c.members[0].gateway.Diagnostics().RampThreshold)
	first := cohort()
	require.NotEmpty(t, first)

	// A release that proposes a lower threshold must not shrink the prefix: the
	// persisted maximum holds it.
	lapse()
	c.activate(t, rampRelease(2, 3000))
	assert.Equal(t, 6000, c.members[0].gateway.Diagnostics().RampThreshold)
	second := cohort()
	assert.Equal(t, first, second)

	// A higher threshold extends the prefix and never removes a unit from it.
	lapse()
	c.activate(t, rampRelease(3, 9000))
	assert.Equal(t, 9000, c.members[0].gateway.Diagnostics().RampThreshold)
	third := cohort()
	grown := 0
	for subject, was := range first {
		if was {
			assert.True(t, third[subject], "the unit %s left the canary prefix", subject)
		}
		if third[subject] {
			grown++
		}
	}
	assert.Greater(t, grown, len(first)-grown)

	// The floor is durable as well: another lower threshold cannot pull the
	// prefix back either.
	lapse()
	c.activate(t, rampRelease(4, 1000))
	assert.Equal(t, 9000, c.members[0].gateway.Diagnostics().RampThreshold)
	lapse()
	fourth := cohort()
	assert.Equal(t, third, fourth)
}

// TestSessionBindingCompatibilityWindow covers the binding of one authenticated
// unit to a build across a release change: the unit keeps its build for the
// compatibility window of the retired release, and the old release is only kept
// alive for exactly that long.
func TestSessionBindingCompatibilityWindow(t *testing.T) {
	c := newCluster(t, withConfig(func(cfg *gogw.Config) { cfg.SessionCompatibilitySeconds = 3 }))
	c.activate(t, release(1, nil, nil))

	response := c.request(t, 0, http.MethodGet, "/orders", "canary-user", "tenant", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
	assert.Equal(t, "1", response.Header.Get("X-Actual-Hop"))
	body(t, response)
	bound := c.members[0].gateway.Diagnostics().Sessions
	assert.Equal(t, 1, bound)

	// The new release sends every unit to the stable build. A unit that is already
	// exposed keeps the build it was exposed to until the window closes.
	c.activate(t, release(2, nil, map[string]*model.Flag{"routing": routingFlag(model.Rule{Variation: "stable"}, nil)}))
	response = c.request(t, 0, http.MethodGet, "/orders", "canary-user", "tenant", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
	assert.Equal(t, "1", response.Header.Get("X-Actual-Hop"))
	body(t, response)
	assert.Positive(t, c.members[0].gateway.Diagnostics().RetiredViews)

	// The retired release stays usable for exactly the compatibility window: an
	// instance that hosts it still accepts the straggler it is bound to. The ticket
	// names the retired publication, so what is being tested is the release the
	// receiver holds and not the newest one it also holds.
	ticket := c.finalTicketOn(t, c.members[0], c.members[0].current.key, c.members[1], c.previous, http.MethodGet, "/orders")
	response = c.finalRequest(t, 1, c.members[0].current.pair, http.MethodGet, "/orders", ticket)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	body(t, response)

	// Once the window is over the unit is re-evaluated on the current release and
	// the retired one stops being served. The ticket is minted again on every poll,
	// because an expired ticket would be refused before the release is ever
	// consulted and would prove nothing about the window.
	var refusal string
	await(t, "the end of the compatibility window", func() bool {
		response := c.request(t, 0, http.MethodGet, "/orders", "canary-user", "tenant", nil)
		served := response.Header.Get("X-Actual-Build")
		_ = body(t, response)
		if served != "stable" {
			return false
		}
		retired := c.finalTicketOn(t, c.members[0], c.members[0].current.key, c.members[1], c.previous, http.MethodGet, "/orders")
		response = c.finalRequest(t, 1, c.members[0].current.pair, http.MethodGet, "/orders", retired)
		refusal = body(t, response)
		return response.StatusCode == http.StatusServiceUnavailable
	})
	assert.Equal(t, "NO_RUNTIME_VIEW\n", refusal)
}

// TestReleaseSwapKeepsInFlightStream proves a release change never terminates a
// response that is already in flight, and that closing the client side is still
// propagated upstream afterwards.
func TestReleaseSwapKeepsInFlightStream(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	stream := c.stream(t, 0, "/sse", "user-1")
	require.Equal(t, "stable", event(t, stream))

	c.activate(t, release(2, nil, nil))
	assert.Equal(t, uint64(2), c.members[0].gateway.Diagnostics().Generation)
	assert.Equal(t, 1, c.members[0].gateway.Diagnostics().Streams)

	// The swap left the running stream alone.
	select {
	case build := <-c.canceled:
		t.Fatalf("the release change terminated a running stream: %s", build)
	case <-time.After(time.Second):
	}

	require.NoError(t, stream.Body.Close())
	select {
	case build := <-c.canceled:
		assert.Equal(t, "stable", build)
	case <-time.After(awaitTimeout):
		t.Fatal("the closed stream was not canceled upstream")
	}
	await(t, "the reclaimed stream", func() bool {
		return c.members[0].gateway.Diagnostics().Streams == 0
	})
}

// TestRetryIsolationAndUnknownWrites covers the retry contract: a read may be
// retried once, and only onto another candidate of the same build, while a write
// whose outcome is unknown is never repeated.
func TestRetryIsolationAndUnknownWrites(t *testing.T) {
	// Both candidates of the stable build fail under the gateway's feet: the local
	// application drops the connection and the peer gateway is gone. A retry that
	// stayed on the same candidate would succeed, which is exactly what must not
	// happen.
	c := newCluster(t, withBuilds("stable", "stable", "canary"))
	c.activate(t, release(1, nil, nil))
	c.flaky[0].Store(true)
	c.members[1].server.Close()

	response := c.request(t, 0, http.MethodGet, "/flaky", "user-1", "", nil)
	assert.Equal(t, http.StatusBadGateway, response.StatusCode)
	assert.Equal(t, "UPSTREAM_FAILED\n", body(t, response))
	report := c.members[0].gateway.Diagnostics()
	assert.Equal(t, 2, report.Isolated["stable"])
	assert.Zero(t, report.Isolated["canary"])
	assert.Zero(t, report.Rejected["build_mismatch"])
	// The canary instance serves a build this unit was never allocated to, so a
	// fallback to it would have produced a successful response above.
	assert.Zero(t, counter(report, "execution", "served"))

	// The isolation window is bounded: once it elapses the candidate that dropped
	// the connection is re-admitted and takes traffic again.
	await(t, "the recovery of the isolated candidate", func() bool {
		response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK && response.Header.Get("X-Actual-Instance") == "stable-0"
	})
}

// TestUnknownWriteIsNotReplayed proves a write whose acknowledgement was lost is
// reported as failed instead of being repeated, which is the only safe answer
// when the gateway cannot know whether the effect was applied.
func TestUnknownWriteIsNotReplayed(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	response := c.request(t, 0, http.MethodPost, "/ambiguous", "user-1", "", nil)
	assert.Equal(t, http.StatusBadGateway, response.StatusCode)
	assert.Equal(t, "UPSTREAM_FAILED\n", body(t, response))
	assert.Equal(t, int64(1), c.writes.Load())

	// The next write is served normally once the failing candidate is re-admitted,
	// and it is still the same write count: one attempt per request.
	await(t, "the recovery of the stable build", func() bool {
		response := c.request(t, 0, http.MethodPost, "/orders", "user-1", "", nil)
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
	assert.Equal(t, int64(2), c.writes.Load())
}

// TestNoCrossBuildFallback proves a unit allocated to a build that has no
// eligible candidate is refused instead of being moved to another build.
func TestNoCrossBuildFallback(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	// The canary instance is withdrawn for the next membership revision: the
	// release still contains the canary build, so this is a membership change and
	// not a policy one.
	c.updateMembership(t, onlyMembers("stable-0"))
	response := c.request(t, 0, http.MethodGet, "/orders", "canary-user", "tenant", nil)
	assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
	assert.Equal(t, "NO_ELIGIBLE_ENDPOINT\n", body(t, response))
	assert.Positive(t, counter(c.members[0].gateway.Diagnostics(), "execution", "NO_ELIGIBLE_ENDPOINT"))

	// A draining candidate is rejected with the reason that names it, and the
	// allocation still does not fall back.
	c.updateMembership(t, drainingMembers("canary-1"))
	report := c.members[0].gateway.Diagnostics()
	assert.Equal(t, 1, report.Rejected["draining"])
	assert.Equal(t, 1, report.Members)
	response = c.request(t, 0, http.MethodGet, "/orders", "canary-user", "tenant", nil)
	assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
	assert.Equal(t, "NO_ELIGIBLE_ENDPOINT\n", body(t, response))

	// An instance the control plane reports as unready is rejected as well, and a
	// healthy membership in the same release is what makes the unit servable
	// again.
	c.updateMembership(t, notReadyMembers("canary-1"))
	assert.Equal(t, 1, c.members[0].gateway.Diagnostics().Rejected["not_ready"])
	c.updateMembership(t)
	response = c.request(t, 0, http.MethodGet, "/orders", "canary-user", "tenant", nil)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
}

// TestStreamingRequestAndResponse proves a request body and a response body are
// streamed through the gateway rather than buffered or truncated.
func TestStreamingRequestAndResponse(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	payload := strings.Repeat("the quick brown fox ", 1<<16)
	response := c.requestBody(t, 0, http.MethodPost, "/upload", "user-1", "", strings.NewReader(payload), nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "local", response.Header.Get("X-Actual-Hop"))
	assert.Equal(t, payload, body(t, response))

	select {
	case build := <-c.upload:
		assert.Equal(t, "stable", build)
	case <-time.After(awaitTimeout):
		t.Fatal("the application never received the streamed body")
	}

	// The same request forwarded to a peer streams as well.
	response = c.requestBody(t, 0, http.MethodPost, "/upload", "canary-user", "", strings.NewReader(payload), nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "1", response.Header.Get("X-Actual-Hop"))
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
	assert.Equal(t, payload, body(t, response))
	select {
	case build := <-c.upload:
		assert.Equal(t, "canary", build)
	case <-time.After(awaitTimeout):
		t.Fatal("the peer never received the streamed body")
	}
}

// TestCapacityAndRetentionBounds proves the gateway's own resources stay bounded:
// the binding store cannot grow past its configured capacity, and a retired
// release is reclaimed instead of pinning connections for the life of the
// process.
func TestCapacityAndRetentionBounds(t *testing.T) {
	c := newCluster(t, withConfig(func(cfg *gogw.Config) {
		cfg.MaxTrackedSessions = 8
		cfg.MaxRetainedViews = 1
		cfg.SessionCompatibilitySeconds = 60
	}))
	c.activate(t, release(1, nil, nil))

	for index := range 32 {
		response := c.request(t, 0, http.MethodGet, "/orders", fmt.Sprintf("crowd-%02d", index), "tenant", nil)
		require.Equal(t, http.StatusOK, response.StatusCode)
		body(t, response)
	}
	assert.LessOrEqual(t, c.members[0].gateway.Diagnostics().Sessions, 8)

	// A second and a third release: the retained views are reclaimed down to the
	// configured bound by the maintenance sweep, so the bound is reached within a
	// sweep rather than at the instant of the swap.
	c.activate(t, release(2, nil, nil))
	c.activate(t, release(3, nil, nil))
	await(t, "the reclamation of the retained views", func() bool {
		return c.members[0].gateway.Diagnostics().RetiredViews <= 1
	})
	assert.Zero(t, c.members[0].gateway.Diagnostics().InFlight)

	// The instance still serves the current release after the reclamation, so the
	// bound did not take the instance out of service.
	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "tenant", nil)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, uint64(3), c.members[0].gateway.Diagnostics().Generation)
	body(t, response)
	assert.True(t, c.members[0].gateway.Ready())
}

// TestConcurrentTrafficAcrossReleaseSwap runs the traffic of many units while a
// release is being swapped, under the race detector: every request must be served
// by exactly one admitted release, and none may fail because of the swap.
func TestConcurrentTrafficAcrossReleaseSwap(t *testing.T) {
	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	const workers, requests = 8, 12
	units := make([]string, 0, workers)
	for index := range workers {
		unit := fmt.Sprintf("concurrent-%02d", index)
		units = append(units, unit)
		// Warm the binding so the swap has to keep a stable build for a unit that
		// was already exposed.
		response := c.request(t, 0, http.MethodGet, "/orders", unit, "tenant", nil)
		require.Equal(t, http.StatusOK, response.StatusCode)
		body(t, response)
	}
	// The requests are built here, not in the workers: a helper that fails must
	// fail the test goroutine.
	pending := make([]*http.Request, 0, workers*requests)
	for index, unit := range units {
		for range requests {
			pending = append(pending, c.newRequest(t, index%len(c.members), http.MethodGet, "/orders", unit, "tenant", nil, nil))
		}
	}

	var wg sync.WaitGroup
	failures := make(chan string, len(pending))
	for index, req := range pending {
		wg.Go(func() {
			response, err := c.public.Do(req)
			if err != nil {
				failures <- err.Error()
				return
			}
			build := response.Header.Get("X-Actual-Build")
			raw, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				failures <- readErr.Error()
				return
			}
			if response.StatusCode != http.StatusOK || (build != "stable" && build != "canary") {
				failures <- fmt.Sprintf("request %d: status %d build %q body %q", index, response.StatusCode, build, raw)
			}
		})
	}

	// The swap happens while the traffic is running.
	second := c.activate(t, release(2, nil, nil))
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Errorf("a request failed across the release change: %s", failure)
	}

	report := c.members[0].gateway.Diagnostics()
	assert.Equal(t, uint64(2), report.Generation)
	assert.Equal(t, second.hash, report.BundleHash)
	assert.Positive(t, counter(report, "execution", "served"))
}
