---
title: Quarkus path-policy, Prebid outbound-request, and Req multipart boundaries
---

# Quarkus path-policy, Prebid outbound-request, and Req multipart boundaries

Three July 29 reviewed advisories expose reusable web-testing surfaces: an authorization layer and downstream router resolving the same path differently, adapter fields becoming outbound authorities, and multipart metadata becoming wire-level headers or form structure.

Sources:

- [GHSA-qcxp-gm7m-4j5v / CVE-2026-50559](https://github.com/advisories/GHSA-qcxp-gm7m-4j5v): Quarkus HTTP path-policy normalization mismatch;
- [GHSA-4p3g-4hcj-wpvx / CVE-2026-54735](https://github.com/advisories/GHSA-4p3g-4hcj-wpvx): Prebid Server bidder-adapter request forgery; and
- [GHSA-px9f-whj3-246m / CVE-2026-49756](https://github.com/advisories/GHSA-px9f-whj3-246m): Elixir Req multipart header and parameter injection.

!!! warning "Authorized validation only"
    Use disposable applications, synthetic protected routes/files, owned HTTP recorders, and marker-only multipart backends. Do not request metadata or internal production services, access real protected resources, upload executable content, or send malformed requests through shared proxies and backend pools.

## Operator map

| Input | First policy view | Downstream view | Safe positive evidence |
| --- | --- | --- | --- |
| encoded Quarkus path | partial decoding plus path-policy matching | matrix stripping, routing, or static-file decoding | unauthenticated access to one synthetic marker route/file |
| Prebid bidder parameter | adapter parameter validation | outbound URL construction and HTTP client | owned callback receives a unique request marker |
| Req part `name`, `filename`, or `content_type` | application-level scalar or basename | multipart header/body serializer | local recorder sees an extra marker header or part |

The reportable edge is the disagreement between representations. Do not infer data access from a callback, execution from a generated request, or a universal Quarkus bypass from a path that only reaches a static handler.

## Quarkus path-policy normalization matrix

The advisory says `AbstractPathMatchingHttpSecurityPolicy` used Vert.x `normalizedPath()`, which decodes unreserved characters but leaves reserved delimiters encoded. Policy matching then looked for literal semicolons, while later handlers could decode `%3B`, `%2F`, `%5C`, or a second encoding layer. The affected Maven artifact is `io.quarkus:quarkus-vertx-http`; first patched versions vary by branch: 3.20.6.2, 3.27.4.1, 3.33.2.1, 3.36.3, and 3.37.0.

### Bounded fixture

1. Build a disposable Quarkus app with:
   - one public route;
   - one REST route protected only by `quarkus.http.auth.permission` path rules;
   - one equivalent route protected by annotation-based security; and
   - one protected static marker file with a filename/path chosen to expose slash-versus-character decoding.
2. Send each request both authenticated and anonymous. Record the raw request target, security-policy path, selected policy, router/static-handler path, selected resource, and response marker.
3. Exercise literal and encoded controls separately: `;`, `%3B`, `%3b`, `%2F`, `%2f`, `%5C`, `%5c`, `%252F`, unreserved-character encoding, encoded dot segments, and a null-byte canary that must fail closed.
4. Keep REST and static-resource rows separate. The source says encoded slash/backslash vectors apply to static handlers, while Quarkus REST routing shares `normalizedPath()` and should not resolve those rows to the protected REST endpoint.
5. Repeat on the relevant fixed branch and verify that policy matching and downstream resolution use one canonical path.

A valid result is **anonymous raw target not matched by the protected policy -> downstream handler resolves the target to the synthetic protected route or file**. Include the source's negative controls: unreserved encodings normalize consistently, encoded dot segments are removed, and `%2F/%5C` should not be reported as REST-route bypasses without independent evidence.

## Prebid bidder adapter to outbound authority

Prebid Server versions before v4.4.0 included bidder adapters that accepted user-supplied parameters and interpolated them into outbound request URLs. Package presence alone is insufficient: identify the enabled adapter, accepted request field, URL template, and whether the response is reflected or only influences an outbound side effect.

### Two-listener destination matrix

1. Run the assessed Prebid build in a disposable environment with only the candidate adapters enabled and no production bidder credentials.
2. Use owned listeners A and B. A represents the expected bidder origin; B is an unapproved destination and records only method, authority, path, and a unique synthetic marker.
3. Start with a valid bid request that reaches A. Vary one adapter parameter at a time across absolute-URL, scheme-relative, userinfo, encoded delimiter, redirect, alternate port, hostname case/trailing-dot, and controlled DNS-answer rows.
4. Record the parameter, adapter-selected URL, redirect chain, final socket destination, Host/authority, and whether any response bytes return to the caller.
5. Repeat on v4.4.0. Confirm that destination validation occurs after canonicalization and at every redirect or DNS-resolution step relevant to the deployment.

The bounded finding is **bid-request adapter field -> final outbound request reaches owned listener B outside the configured bidder authority**. A callback proves destination control, not access to host data. Never target cloud metadata, loopback services you do not own, RFC1918 applications, or corporate/VPN endpoints.

## Req multipart metadata to wire grammar

Req `>=0.5.3,<0.6.0` concatenated multipart `name`, `filename`, and `content_type` into per-part headers without quote, CR, or LF neutralization. Affected upload proxies and re-uploaders may derive `filename` from `Path.basename/1`, and POSIX filenames can contain CR/LF. Req 0.6.0 is the first patched version.

### Local serializer differential

1. Run a local HTTP recorder that stores the exact request body as bytes and parses the same body with the backend parser used by the assessed integration.
2. Send a baseline form with one synthetic text part and one benign file part.
3. Vary `name`, `filename`, and `content_type` independently with quote, CR, LF, CRLF, backslash, non-ASCII, and boundary-looking marker strings. Use fixed non-secret body text.
4. Compare:
   - the caller's intended part list;
   - Req's emitted raw bytes;
   - recorder-parsed headers and fields; and
   - application/backend field precedence when duplicate marker names exist.
5. Include a `%File.Stream{}` row whose disposable basename contains harmless CR/LF markers; this proves whether implicit filename derivation reaches the same serializer.
6. Repeat on Req 0.6.0 and confirm that quote, CR, and LF are encoded and cannot create a second header or part.

Report **attacker-influenceable multipart metadata -> serializer emits additional header/field structure -> local backend observes marker absent from the intended form model**. Do not call it general HTTP request smuggling unless the malformed multipart also changes HTTP message boundaries at a real two-hop parser boundary.

## Evidence and reporting

Preserve:

- exact package versions, deployment mode, enabled adapter/handler, and configuration;
- raw request targets and multipart bytes, not normalized screenshots alone;
- every representation at the policy, router, adapter, serializer, and backend boundary;
- authenticated/anonymous, expected/unapproved destination, and affected/fixed decision tables;
- synthetic marker identity and fixed-version rejection; and
- a narrow impact statement tied to the reached route, final destination, or parsed marker.

Keep the three classes distinct: **path-policy canonicalization mismatch**, **adapter-selected outbound authority**, and **multipart scalar-to-wire-grammar injection**.