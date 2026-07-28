# Undertow proxy-parser request-smuggling boundary

Source: hourly offensive-security scan, 2026-06-11. Primary entries: GitHub advisories [GHSA-3gv6-g396-9v4r](https://github.com/advisories/GHSA-3gv6-g396-9v4r) / CVE-2026-28367, [GHSA-8v4x-mgvp-p658](https://github.com/advisories/GHSA-8v4x-mgvp-p658) / CVE-2026-28368, and [GHSA-vqqj-9cmv-hx43](https://github.com/advisories/GHSA-vqqj-9cmv-hx43) / CVE-2026-28369 for Undertow request-smuggling parser differentials.

This is durable for operators because it gives a reusable edge-stack test pattern: **the upstream proxy and Undertow disagree about where headers end, what counts as a header name, or whether leading whitespace is valid, so one HTTP byte stream becomes two different request interpretations**.

## Why it matters for assessments

Many Java application estates place Undertow behind a load balancer, CDN, reverse proxy, WAF, API gateway, or service mesh ingress. The authorization and routing decision often happens at the first hop, while the application server makes the final request interpretation. The Undertow advisories highlight three differential classes worth checking in any approved request-smuggling review:

- header-block terminator confusion, including non-standard `\r\r\r` handling;
- header-name parsing differences between Undertow and the proxy;
- first-header lines that begin with one or more spaces and are normalized by Undertow even though the form is invalid.

The target is not generic malformed-request fuzzing. The useful operator workflow is to prove a **proxy-to-origin parser split** with harmless canaries, then show whether that split can affect routing, authentication context, cache keys, or request queue boundaries.

## What to map first

1. Confirm written authorization for HTTP request-smuggling testing. These probes can desynchronize shared infrastructure if run carelessly.
2. Identify the front door and the origin stack:
   - CDN, WAF, load balancer, reverse proxy, ingress controller, service mesh, or Apache Traffic Server / Google Cloud Classic Application Load Balancer where applicable;
   - Undertow-backed services, such as WildFly, JBoss EAP, Quarkus deployments using Undertow, or embedded Undertow applications.
3. Collect safe baseline responses for a disposable route such as `/`, `/health`, `/robots.txt`, or a lab-only canary endpoint.
4. Use a dedicated test host or tenant whenever possible. Avoid production endpoints with shared connection pools unless the rules of engagement explicitly allow smuggling validation.
5. Keep payloads non-destructive: no credential reuse, no admin paths, no hidden data fetches, and no cross-user request targeting.

## Safe validation boundary

Use single-connection probes against lab or explicitly scoped targets. Prefer a purpose-built request-smuggling harness that can show front-end and back-end response boundaries without spraying traffic.

Minimal raw-socket shape for a lab canary:

```python
#!/usr/bin/env python3
import socket
import ssl

host = "app.example.test"
port = 443
payload = (
    b"GET /canary-a HTTP/1.1\r\n"
    b"Host: app.example.test\r\n"
    b"User-Agent: skillz-smuggle-canary\r\n"
    # Replace this line only in an authorized lab to test one parser differential at a time.
    b"X-Canary: baseline\r\n"
    b"\r\n"
    b"GET /canary-b HTTP/1.1\r\n"
    b"Host: app.example.test\r\n"
    b"Connection: close\r\n\r\n"
)

ctx = ssl.create_default_context()
with socket.create_connection((host, port), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname=host) as s:
        s.sendall(payload)
        print(s.recv(8192).decode("latin1", errors="replace"))
```

For Undertow-specific lab checks, mutate only one boundary at a time and record whether the proxy and origin disagree:

- a header block ending with the advisory-highlighted `\r\r\r` sequence;
- a crafted header name that the proxy rejects, forwards, rewrites, or interprets differently from Undertow;
- a first header line that begins with spaces before the header name.

Do not include a weaponized desync payload in public reports. If the program requires proof beyond a parser split, coordinate a private replay with the triage team using canary-only paths and a test account.

## Evidence to capture

Strong evidence shows all of the following:

- exact proxy/origin topology that was in scope, including product/version when the customer can provide it;
- the raw request bytes, escaped safely in a file attachment or hex dump;
- baseline response on a normal request;
- differential response when the single malformed boundary is introduced;
- whether the effect is limited to rejection/normalization or reaches a second request, alternate route, cache key, auth decision, or queue desync;
- timestamps, connection reuse behavior, and correlation IDs for the tester-owned canary requests.

Keep evidence scoped to canary paths. Do not demonstrate access to another user request, protected production data, internal admin panels, or secrets.

## Reporting heuristics

- Lead with the boundary: **front-end proxy and Undertow parse the same HTTP stream differently**.
- Name the differential class, not just "request smuggling": terminator confusion, header-name confusion, or leading-whitespace normalization.
- Include the smallest harmless impact observed: cache poisoning possibility, route confusion, auth-gate bypass precondition, or confirmed queued-request desync.
- Separate confirmed impact from plausible impact. A parser mismatch without desync is still useful evidence, but it is not the same as account takeover or data exposure.
- Recommend a private reproduction window if the next proof step could disturb shared infrastructure.

## Notes on skipped adjacent items

Updated-feed Keycloak token-revocation and WebAuthn policy-bypass advisories from the same scan were already represented in state as processed identity-boundary items and did not require a new page this hour. Generic availability-only and local-crash entries remained processed without publication unless they exposed a reusable operator boundary.

## July 28 Rust HTTP parser and identity-header update

A later unreviewed GitHub wave adds Rust parser variants and a proxy identity-canonicalization check:

- [GHSA-frmw-v2hf-gvj9](https://github.com/advisories/GHSA-frmw-v2hf-gvj9): Rouille forwards bare-LF header values into an upstream request;
- [GHSA-fgf8-ph7p-m275](https://github.com/advisories/GHSA-fgf8-ph7p-m275): Rouille forwards `Transfer-Encoding` after `tiny_http` has already de-chunked the body;
- [GHSA-5hc2-r3jq-vc45](https://github.com/advisories/GHSA-5hc2-r3jq-vc45): `tiny_http` treats any `Transfer-Encoding` value as chunked and discards `Content-Length`;
- [GHSA-5wm6-g4fr-88x8](https://github.com/advisories/GHSA-5wm6-g4fr-88x8) and [GHSA-998j-f97v-vpgr](https://github.com/advisories/GHSA-998j-f97v-vpgr): CR/LF acceptance crosses into request or response header serialization;
- [GHSA-f2m2-cc3f-h4j2](https://github.com/advisories/GHSA-f2m2-cc3f-h4j2): OpenShift `oauth-proxy` removes dash-form identity headers but may leave underscore aliases that WSGI or PHP later canonicalizes to the same application variable.

Treat these GitHub entries as leads until the exact source, affected build, deployment topology, and observed parser behavior are confirmed. The durable method is broader than any one library: compare the bytes and normalized fields at every hop, including transformations performed before a proxy reserializes the request.

### Two-hop parser fixture

Build a local chain with the candidate Rouille or `tiny_http` component in front of a mock origin that records raw bytes and parsed request boundaries. Run one mutation per fresh connection:

1. duplicate `Content-Length` / `Transfer-Encoding` controls;
2. a non-`chunked` transfer coding with a short inert body;
3. a chunked body that the first hop decodes before forwarding;
4. an inert request header containing a bare LF canary;
5. a response-header value derived from a harmless query or cookie marker containing encoded CR/LF;
6. the same fixtures against a patched or strict-parser negative control.

Record four artifacts: bytes sent to hop one, hop-one parsed fields/body, bytes reserialized toward hop two, and hop-two request/response boundaries. A useful positive result is not merely a 400/500 response. Show that the same input becomes a different message count, body length, header set, route, or cacheable response at the next hop.

Do not aim smuggling probes at shared production connection pools. Use canary routes, one connection per fixture, no victim traffic, and no protected endpoints. Do not open response-splitting output in a browser if doing so could trigger active content; preserve raw bytes instead.

### Dash-versus-underscore identity matrix

For an identity-aware reverse proxy, seed a mock upstream that reports only the normalized identity variable it receives. Use a disposable low-privilege user and fake identity values:

| Incoming client field | Proxy output to upstream | Expected result |
| --- | --- | --- |
| no identity header | proxy-generated authenticated identity only | accept baseline |
| `X-Forwarded-User: canary` | client value removed/replaced | authenticated identity only |
| `X_Forwarded_User: canary` | client alias removed before framework normalization | authenticated identity only |
| both forms with different canaries | all client forms removed | one proxy-generated value |
| case and repeated-header variants | canonicalized and removed | one proxy-generated value |

Capture raw ingress headers, proxy egress headers, the framework server-variable map, and the application-visible principal. The bounded finding is **client-supplied alias survives the trusted proxy -> upstream canonicalization merges it with the protected identity key -> application observes the canary principal**. Do not impersonate a real administrator or access another user's data; a fake principal echoed by a local upstream is sufficient.

Report parser and identity findings separately. An underscore alias is header canonicalization/identity confusion, not HTTP request smuggling unless it also changes message boundaries. Likewise, CR/LF acceptance is an injection primitive until a second parser or serializer demonstrates a security-relevant split.
