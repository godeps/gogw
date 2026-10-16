---
title: "Developing the Grayling Gateway Fork"
description: "Run and verify the gogw Grayling integration with a protocol mock, and maintain the Traefik compatibility boundary."
---

# Developing the Grayling Gateway Fork

Use the mock Grayling server to test this fork's co-deployed HTTP gateway before connecting a production control plane.
The integration uses the Grayling Go SDK pinned to commit `805a6969c25ec0fb18a01be1ae8ca7db255518c1`.
Build with Go 1.27.2 or later, as required by that SDK.

!!! warning "Development protocol adapter"

    The mock signs a complete `gogw.Bundle` resource and activates it after an instance reports Prepared.
    This payload is a fork-specific development contract, not a production Grayling discovery schema.
    Prepared endpoint flags in this mock do not prove deployment authorization, leases, or release quorum.
    Do not use the mock as a production registry or approval service.

## Run the Acceptance Tests

From the repository root, run:

```bash
make test-gogw
make test-gogw-process
```

The focused tests create a temporary certificate authority, unique gateway certificates, a WSS mock control plane, and loopback applications for the stable and canary builds.
They verify local and remote execution, user and tenant targeting, stable percentage expansion, request binding, signature trust, rollback rejection, snapshot expiration, cold-start behavior, application health, SSE cancellation, and request-level draining.

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
  "certFile": "/run/secrets/gateway.crt",
  "keyFile": "/run/secrets/gateway.key",
  "caFile": "/run/secrets/ca.crt",
  "policyKeyID": "mock",
  "policyPublicKey": "HEX_ENCODED_ED25519_PUBLIC_KEY",
  "identitySecretFile": "/run/secrets/identity-secret",
  "identityIssuer": "application-auth"
}
```

`localURL` must use an explicit loopback IP and HTTP.
Remote gateway endpoints use HTTPS with CA, server-name, and certificate-digest verification.
Use a unique Ed25519 certificate and private key per gateway identity.
The configured certificate must match the one served by the Traefik listener.
The mock's signing-key trust window is bounded by the configured gateway certificate's validity period.
A production key-rotation adapter needs independently managed trust windows.

`stateFile` holds an atomically replaced, signed bundle and its monotonic watermark.
Use a separate state file for each gateway process and preserve it across restarts.
A cold start preserves the verified watermark but waits for fresh preparation and activation before becoming ready.
A corrupt state file causes startup to fail; do not delete it to bypass rollback protection.

The application must return a 2xx response to `healthPath`.
The gateway probes it at startup and once per second with a one-second timeout.
An unhealthy application blocks new business requests and readiness.

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

`/__gogw/ready` returns 204 when the application is healthy and an unexpired view is active, otherwise 503.
It returns no internal identities or release details.
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
The client IP comes from the direct peer unless `trustedProxies` contains that peer's network.
When configured, forwarded addresses are read from right to left until the first untrusted address.
A forged X-Forwarded-For header from an untrusted peer cannot select the routing identity.

## Understand View Activation and Forwarding

The SDK subscribes to a signed Bundle resource scoped to the configured service.
The adapter validates its signature, scope, expiry, schema, policy revision, release generation, endpoints, and local certificate/build/boot identity.
It compiles the Grayling evaluator and constructs endpoint proxy handlers before reporting Prepared.
An Activate message must match the prepared generation and bundle digest before the view is persisted and switched.
Applied reports the actual policy and discovery revisions after that switch.

Each request captures one view.
The evaluator selects a logical build, then Traefik's WRR chooses a prepared, ready, non-draining member within that build.
Each remote member handler signs a final ticket for that exact instance and boot.
The target validates the mTLS certificate, signature, issuer/target boot, build, bundle, generation, method, authority, path, query, expiry, final flag, and hop count.
It then dispatches only to its loopback application.

No target means 503; the gateway does not select a different build as a fallback.
Discovery expiration stops remote selection, while valid local execution can continue.
Policy expiration stops all new business execution.
Existing SSE requests retain their captured handlers through ordinary view changes or stream completion.
The adapter owns separate transport pools per view and retires idle pools after the last captured stream releases them.
It does not automatically replay writes, even when clients provide an idempotency-key header.
Business exactly-once processing is outside this protocol.

A lost control-plane connection does not force a valid view out of service.
The SDK reconnects with bounded jittered backoff; cached policy and discovery expiry still apply.
A permanent Agent authentication/protocol failure stops the component and withdraws readiness.
Mock Revoke and DrainRequested stop new requests; persisted revocation epochs and selective active-stream cancellation require the production lifecycle adapter.

## Run the Standalone Mock

Provide an Ed25519 signing seed as hexadecimal text, a token file, TLS files, and a Bundle JSON file:

```bash
dist/gogw-mock \
  -address 127.0.0.1:9443 \
  -cert /run/mock/server.crt \
  -key /run/mock/server.key \
  -signing-key /run/mock/signing-seed.hex \
  -token-file /run/mock/agent-token \
  -bundle /run/mock/bundle.json \
  -workspace demo -environment test -service checkout
```

Use the `Bundle` and `Endpoint` structs in `pkg/gogw/config.go` as the development payload schema.
Include a native Grayling policy snapshot with string variations mapping to logical build IDs.
Endpoint URLs advertise gateway listeners, not application loopback ports.
Populate a unique certificate digest, instance ID, boot ID, readiness, prepared state, and expiry for each endpoint.
All gateways must accept the same signed bundle before cross-build forwarding succeeds.

Send SIGHUP after replacing the mock's Bundle file to publish an update.
Increment the policy revision, discovery revision, and release generation for a changed whole view.
Keep flag keys, salt, randomization unit, and experiment epoch fixed when testing percentage expansion.
The provided acceptance tests construct these fixtures automatically without embedding production credentials.

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
The protocol mock proves the gateway execution path; it does not close the full production issue's registry, quorum, revocation, deployment, or capacity acceptance requirements.
