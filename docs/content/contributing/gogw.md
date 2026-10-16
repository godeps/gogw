---
title: "Developing the Grayling Gateway Fork"
description: "Run and verify the gogw Grayling integration with a protocol mock, and maintain the Traefik compatibility boundary."
---

# Developing the Grayling Gateway Fork

Use the mock Grayling server to test this fork's co-deployed HTTP gateway before connecting a production control plane.
The integration uses the Grayling Go SDK pinned to commit `805a6969c25ec0fb18a01be1ae8ca7db255518c1`.
Build with Go 1.27.2 or later, as required by that SDK.

!!! warning "Development protocol adapter"

    The mock signs a complete `gogw.Bundle` resource and activates it after an instance reports Prepare.
    This payload is the fork's versioned contract for the resource kinds the pinned SDK leaves open, not a production Grayling discovery schema; see [Versioned Payload Extension](#versioned-payload-extension).
    Prepared endpoint flags in this mock do not prove deployment authorization, leases, or release quorum.
    Do not use the mock as a production registry or approval service.

## Run the Acceptance Tests

From the repository root, run:

```bash
make test-gogw
make test-gogw-process
```

The focused tests create a temporary certificate authority, unique gateway certificates, a WSS mock control plane, and loopback applications for the stable and canary builds.
They verify registration and lease renewal, snapshot plus delta convergence, reconnection and stale-cursor recovery, the Prepare, Activate and Abort state machine with persisted generation, revocation epochs and active-stream cancellation, session binding, request-level view atomicity, ramp monotonicity, build-local retry isolation, application failure and recovery, drain and shutdown convergence, HTTP/2 stream rejection and grace, capacity bounds, and bounded-cardinality diagnostics.
They also verify local and remote execution, user and tenant targeting, stable percentage expansion, request binding, signature trust, rollback rejection, snapshot expiration, and cold-start behavior.

The process test builds and starts real Traefik-based gogw binaries using the file provider.
It verifies file-provider reload while the control plane is offline, service-builder injection, a single HTTPS listener accepting ordinary and authenticated gateway requests, HTTP/2 requests, cross-build forwarding, encoded paths, forged ticket rejection, SSE cancellation, streaming request bodies, and SIGTERM draining with an active SSE stream.
No Docker or external registry is needed for these tests.

`make build-gogw` produces `dist/gogw` and `dist/gogw-mock` without rebuilding dashboard assets.
Use the existing `make binary` release workflow when you need regenerated dashboard assets.

## Configure gogw

Set `GOGW_CONFIG` to a JSON file before starting the binary.
Leave it unset to retain ordinary Traefik behavior.
Keep tokens and private keys in files with permissions restricted to the gateway process.

```json
{
  "service": "checkout",
  "scope": {
    "WorkspaceID": "demo",
    "EnvironmentID": "test",
    "ServiceKey": "checkout"
  },
  "instance": "stable-1",
  "boot": "unique-process-boot-id",
  "build": "stable",
  "localURL": "http://127.0.0.1:8081",
  "healthPath": "/health",
  "graylingURL": "wss://control.example.invalid:9443",
  "tokenFile": "/run/secrets/agent-token",
  "stateFile": "/var/lib/gogw/runtime.pb",
  "advertiseAddress": "10.0.0.11",
  "advertisePort": 8443,
  "certFile": "/run/secrets/gateway.crt",
  "keyFile": "/run/secrets/gateway.key",
  "caFile": "/run/secrets/ca.crt",
  "policyKeyID": "mock",
  "policyPublicKey": "HEX_ENCODED_ED25519_PUBLIC_KEY",
  "identitySecretFile": "/run/secrets/identity-secret",
  "identityIssuer": "application-auth",
  "trustedProxies": ["10.0.0.0/8"],
  "preparedTTLSeconds": 120,
  "drainGraceSeconds": 30,
  "certificateOverlapSeconds": 300,
  "sessionCompatibilitySeconds": 120,
  "maxTrackedSessions": 100000,
  "maxRetainedViews": 2
}
```

`localURL` must use an explicit loopback IP and HTTP.
`advertiseAddress` and `advertisePort` are the address this instance advertises to its peers; it must be an address the other gateways can reach, not a loopback address.
Remote gateway endpoints use HTTPS with CA, server-name, and certificate-digest verification.
Use a unique Ed25519 certificate and private key per gateway identity.
The configured certificate must match the one served by the Traefik listener.
The mock's signing-key trust window is bounded by the configured gateway certificate's validity period.
A production key-rotation adapter needs independently managed trust windows: replace `policyKeyID` and `policyPublicKey` with `policyKeys`, a list of `keyId`, `publicKey`, `notBeforeUnixMs` and `notAfterUnixMs` entries.
Each entry carries its own window, so two signing keys can be trusted at once while a rotation overlaps, and a zero window falls back to the gateway certificate's validity period.
An entry without a `keyId`, or two entries with the same one, is refused at startup.

The bounds in the example are the ones a rollout is easiest to reason about.
`preparedTTLSeconds` (default 300) bounds how long a staged acceptance stays usable, `drainGraceSeconds` (default 120) is the deadline for streams that outlive a drain, `certificateOverlapSeconds` (default 300) is how long a retiring certificate digest stays acceptable, `sessionCompatibilitySeconds` (default 300) is how long a unit keeps the build it was already exposed to, and `maxTrackedSessions` (default 65536) and `maxRetainedViews` (default 4) bound the pinning a rollout can accumulate.
`healthPath` defaults to `/health` and the rest to the values above whenever a field is absent or not positive.
Keep `maxRetainedViews` small: it is what stops a retired release from holding connections for the life of the process.

`stateFile` holds the atomically replaced signed resources, the monotonic release generation, the accepted watermarks, the revocation epoch and the durable ramp floors.
Use a separate state file for each gateway process and preserve it across restarts.
Every mutation is persisted before it is acted on, so a crash cannot lose a revocation epoch, a monotone generation or an accepted watermark.
A cold start restores the release this instance had activated, and only that one: an accepted but never activated release does not begin serving because the process restarted.
Readiness still requires a live control-plane session, so a restored release alone does not make the instance a candidate.
A corrupt state file causes startup to fail; do not delete it to bypass rollback protection.

The application must answer `healthPath` with a status below 400.
The gateway probes it once per second with a two-second timeout and does not follow redirects, so a redirect is a health verdict rather than a hop.
Health is fail-closed: an unprobed, slow or failing application makes the instance ineligible, unready and unable to start new business requests.
An unhealthy application of one instance never removes the other instances of the deployment from service.

## Configure Traefik Routing

Use an ordinary router with the fork-owned service suffix `@gogw`:

```yaml
http:
  routers:
    checkout:
      entryPoints: [websecure]
      rule: "Host(`checkout.example.invalid`)"
      service: checkout@gogw
      tls: {}

tls:
  certificates:
    - certFile: /run/secrets/gateway.crt
      keyFile: /run/secrets/gateway.key
  options:
    default:
      clientAuth:
        caFiles: [/run/secrets/ca.crt]
        clientAuthType: VerifyClientCertIfGiven
```

The listener accepts ordinary clients without a certificate.
Any request presenting a client certificate enters the internal gateway path and also requires a valid final forwarding ticket.
An internal marker with invalid credentials returns 403 rather than falling back to ordinary authentication.
Use a gateway-specific client CA; do not mix general application client certificates into this identity domain.

Apply this TLS policy consistently to the shared listener.
Do not add routing middleware that strips internal credentials or changes the host/path after the ticket is signed.
The final handler signs the path and query it passes to the proxy.
Semicolon query separators are rejected because the reused Traefik proxy rewrites them.
WebSocket upgrades and gRPC requests are rejected with 501 in this adapter.

`/__gogw/ready` returns 204 when this instance may receive business traffic and 503 with the body `NOT_READY` otherwise.
It returns no internal identities or release details, so the reason is deliberately not in the response.
Read the reason from `/__gogw/diagnostics` instead, which is served only to a peer that presents a valid final forwarding ticket, and from the `readyReason` field of that document.
A gateway that is draining answers new work with 503 and the body `DRAINING`, which is a different operator problem from `NOT_READY`: the first is a deployment decision and the second is a local or control-plane condition.
Shutdown hooks withdraw readiness before Traefik begins draining listeners.
Configure Traefik's entrypoint lifecycle grace timeout to bound long-lived request shutdown.
The mock does not coordinate external load-balancer removal or a container supervisor.

## Authenticate Business Requests

The development adapter accepts HS256 JWTs using the bytes from `identitySecretFile`, which must contain at least 32 bytes.
A token must contain an expiration, a nonempty subject, the configured issuer, and the service key as its audience.
Optional signed `tenant` and `tier` claims become evaluation attributes.
The backend still receives the original business Authorization header and remains responsible for authorization.
Replace this adapter with your approved business authentication mechanism before production use.

Client-supplied `X-Gogw-*` identity headers are removed.
The gateway injects the authenticated subject and tenant only after verification.
It also sets `X-Gogw-Hop`, which counts the gateway boundaries the request already crossed: `0` when the gateway of this process dispatched the request and `1` when it arrived on the internal surface under a verified final ticket.
The value is a count rather than a flag, so an application can assert the at-most-one-hop invariant itself instead of trusting that no gateway forwarded it further.
The client IP comes from the direct peer unless `trustedProxies` contains that peer's network.
When configured, forwarded addresses are read from right to left until the first untrusted address.
A forged X-Forwarded-For header from an untrusted peer cannot select the routing identity.

## Register with the Control Plane

The adapter opens one WSS session and keeps it for the life of the process.
It registers the configured instance and boot identity, adopts the scope and the lease the control plane answers with, and renews that lease on the cadence the control plane advertises.
A renewal that the control plane answers with a different epoch than the held one, or with a lease that is already expired, ends the session and is never treated as a renewal.
A fenced answer from the control plane withdraws eligibility until a later registration is accepted, which is what makes a replaced boot stop serving instead of serving twice.

The session then subscribes to the service-scoped Revocation, Bundle and Discovery resources in that order, so safety state is applied before the release it belongs to.
A reconnect re-subscribes the same subscription slots instead of opening new ones, and each subscription resumes from a cursor derived from the persisted watermark, so a snapshot is applied only when it is newer than what was already accepted.
An interrupted stream therefore converges to the same state as a cold start, and a re-delivered artifact is idempotent rather than applied twice.

Readiness reports are separate from the transport heartbeat.
A gateway whose application is unhealthy stays connected while reporting itself not ready, so a byte that never reaches the application is distinguishable from a peer that went away.

## Understand View Activation and Forwarding

The adapter validates the Bundle resource against its signature, scope, expiry, schema, policy revision, release generation, endpoints, and local certificate/build/boot identity.
It compiles the Grayling evaluator and constructs endpoint proxy handlers before reporting Prepare.
Prepare is reported with the exact release identity, generation and expiry that were accepted, and the acceptance is persisted before the report is sent, so a restart does not have to be prepared again.

Activate must match the prepared generation and bundle digest, and it re-checks the release identity against the live control plane before the view is persisted and switched; the prepared evidence is never a serving right on its own.
Generation is monotone per instance: an Activate or Bundle that would move it backwards is refused and reported as a rejection rather than applied.
A duplicate Activate is idempotent, an Activate for a release this instance never prepared is refused, and Abort disarms the staged acceptance without revoking the release: a release that is already active stays in service, and a further activation remains the control plane's decision.
Activation is reported to the control plane only after the switch, and the report carries the policy and discovery revisions actually in service rather than the ones that were requested.

Each request captures one view, and that reference is held for the whole request: the evaluator selects a logical build, then Traefik's WRR chooses a prepared, ready, non-draining member within that build.
Each remote member handler signs a final ticket for that exact instance and boot.
The target validates the mTLS certificate, signature, issuer/target boot, build, bundle, generation, method, authority, path, query, expiry, final flag, and hop count.
It then dispatches only to its loopback application.

A unit that was already exposed to one logical build keeps that build across release changes for the configured compatibility window, and the superseded view stays available for the stragglers that captured it.
Ramp thresholds are monotone per ramp coordinate: the durable floor can only rise, so a lowered ratio cannot pull an already-canary unit back to the default build.
Remote selection is capped by the bounded session store and by the retained-view bound; a session over the bound is reclaimed rather than admitted.

No target means 503; the gateway does not select a different build as a fallback.
Both expiries fail closed and stop every new business request, remote or local, and the refusal body names the artifact that went stale: `POLICY_EXPIRED` for an expired release policy, `DISCOVERY_EXPIRED` for a membership that stopped being republished.
A request that is already in flight keeps the handler it captured, so an expiry ends the admission of new work rather than cutting a response mid-stream.
A republished membership restores service without a new release, which is what makes the expiry a validity window rather than a revocation.
Existing SSE requests retain their captured handlers through ordinary view changes or stream completion.
The adapter owns separate transport pools per view and retires idle pools after the last captured stream releases them.
A retry never leaves the build that was selected, is attempted only for a method that is idempotent and a request that can be rewound, and never repeats a write whose result is unknown.
Repeated transport failures isolate the failing candidate instead of failing the build, and the candidate rejoins once it answers again.
Business exactly-once processing is outside this protocol.

A lost control-plane connection does not force a valid view out of service.
The SDK reconnects with bounded jittered backoff; cached policy and discovery expiry still apply.
A permanent Agent authentication or protocol failure stops the component and withdraws readiness.
A Revoke is persisted as a monotone epoch, releases the revoked release, cancels the active streams it was serving, and refuses a lower epoch, so a reconnect or a restart cannot resurrect a revoked release.
A DrainRequested withdraws readiness immediately and gives existing streams the configured grace period before the deadline closes them.
HTTP/2 streams that arrive while the instance is draining are refused with 503 instead of being admitted, so a draining instance converges to zero instead of chasing new work.

## Observe a Gateway

`/__gogw/diagnostics` is served only on the internal path, so a peer must present a valid final forwarding ticket to read it; an ordinary client cannot.
It returns a JSON document with the instance and boot identity, the control-plane session state, the lease, the readiness and eligibility verdicts together with their reasons, the staged and active release identities, the policy and discovery expiry, the membership size, the retained views, the tracked sessions, the in-flight requests and streams, the revocation epoch, the certificate digests a membership artifact must advertise, and the counters.
It never contains a token, a principal, an application address or a request header.

The counters distinguish three phases, because they answer three different questions:

- `allocation` counts a routing decision: which build a request was assigned to, and on which basis.
- `execution` counts an attempt, including the attempts that never reached an application.
- `exposure` counts what actually reached a build: a unit newly bound to a build, and a response that was delivered.

Only `exposure` is evidence that a unit was served by a build, so an experiment must not read `allocation` as an exposure count.
Every label comes from a fixed vocabulary, `build` and `label` are replaced by `overflow` when a value is not a bounded identifier, and the counter map is capped, so the cardinality cannot grow with traffic or with a hostile control plane.
The meters are diagnostic rather than exported series: this adapter does not register them with a metrics backend.

## Run the Standalone Mock

Provide an Ed25519 signing seed as hexadecimal text, a token file, TLS files, and a release JSON file:

```bash
dist/gogw-mock \
  -address 127.0.0.1:9443 \
  -cert /run/mock/server.crt \
  -key /run/mock/server.key \
  -signing-key /run/mock/signing-seed.hex \
  -token-file /run/mock/agent-token \
  -release /run/mock/release.json \
  -workspace demo -environment test -service checkout
```

`-release` is required and carries a `mock.ReleaseFile`: one `release`, the `members` overrides a real control plane would observe for itself, and an optional `revocation`.
The `release` document follows the extended Bundle contract of `pkg/gogw/protocol.go`, which binds the payload hash to the resource key; use its `Bundle`, `BuildDescriptor` and `Ramp` structs as the development payload schema.
Include a native Grayling policy snapshot with string variations mapping to logical build IDs.
Endpoint URLs advertise gateway listeners, not application loopback ports.
Populate a unique certificate digest, instance ID, boot ID, readiness, prepared state, and expiry for each endpoint.
All gateways must accept the same signed bundle before cross-build forwarding succeeds.

Send SIGHUP after replacing the release file to publish an update.
A reload is refused unless the release generation and the revocation epoch have both advanced, so a dropped reload cannot silently leave a run on the old view.
Increment the policy revision and the discovery revision for a changed whole view.
Keep flag keys, salt, randomization unit, and experiment epoch fixed when testing percentage expansion.
The mock republishes membership once per second, so an acceptance run observes a registration without waiting for a production refresh period.

## Versioned Payload Extension

The pinned SDK freezes the session, command and signed-resource envelope, but leaves the payload of the Discovery, Bundle and Revocation resource kinds to the control plane.
Those three payloads are a fork-owned, versioned extension, and `pkg/gogw/protocol.go` is their contract:

- Every document carries an explicit `schema` number and the gateway verifies it; the only value it accepts today is `1`.
- Unknown members are rejected, so a control plane cannot smuggle a field the gateway would silently ignore.
- Every document is bounded in size, member count and identifier length, and a document that exceeds a bound is refused rather than truncated.
- A document the gateway cannot fully verify is refused; partial acceptance is not a supported state.

A control plane that does not serve these exact shapes cannot negotiate with this gateway, and this contract is a statement about this fork only.
It is not a claim that any existing Grayling deployment serves these payloads, and the versioned extension is the place to add a field a future protocol revision introduces.

Two values the adapter needs are not part of the frozen envelope and travel out of band:

- The certificate digest a control plane must advertise for an instance. The gateway compares every presented peer certificate against the digests in the approved membership artifact, and `/__gogw/diagnostics` republishes the digests a membership artifact must carry for this instance, including the retiring digest and its overlap deadline during a rotation.
- The durable ramp floor and the revocation epoch, which are local state rather than control-plane fields. They are persisted so a restart cannot lower a threshold or resurrect a revoked release.

A production control plane must publish the certificate digests that match `/__gogw/diagnostics`, and an operator can verify one against the other before approving membership.
Verify that match during rollout; a mismatched digest is refused at the transport boundary and shows up as a rejected internal request rather than as a routing failure.

## Maintain the Upstream Boundary

The fork adds explicit builder injection to `pkg/server/service/managerfactory.go`, Agent setup to `cmd/traefik/traefik.go`, and pre-drain callbacks to `pkg/server/server.go`.
The extension methods, Agent adapter, protocol mock, tests, and focused build targets live in added files.
The dynamic configuration schema, provider implementations, CRDs, and generated files are unchanged.

Keep Traefik's module path and import layout.
Pin Grayling by a committed version and avoid a production `replace` directive to a neighboring workspace.
Review dependency upgrades required by the SDK separately from gateway behavior.
Use golangci-lint v2.14.0 or later for Go 1.27.2 export data.
The fork permits patch-level Go directives and disables only the `modernize/embedlit` suggestion to avoid rewriting unchanged upstream literals.

For each official upgrade:

1. Record the previous official baseline and target commit.
2. Merge the target into a temporary upgrade branch.
3. Review the builder, proxy rewrite, transport, TLS, WRR, and shutdown boundaries.
4. Run the existing Traefik checks, `make test-gogw`, and `make test-gogw-process`.
5. Verify ordinary Traefik behavior with `GOGW_CONFIG` unset.
6. Repeat the production network, discovery, release, capacity, and streaming acceptance before shipping.

A clean textual merge does not prove behavioral compatibility.
The protocol mock proves the gateway execution path and the adapter's own state machine; it is not a production control plane.
Registry quorum, approval workflow, production revocation distribution, certificate issuance, capacity limits of a real deployment and the behavior of a real Grayling server are outside what these tests can demonstrate.
`docs/acceptance/gogw-completion/STATUS.md` records which requirement of the integration is proven by which test, and which limits remain.
