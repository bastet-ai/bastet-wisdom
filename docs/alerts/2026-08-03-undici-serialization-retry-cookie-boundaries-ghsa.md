---
title: undici request serialization, retry framing, and cookie-attribute boundaries
---

# undici request serialization, retry framing, and cookie-attribute boundaries

Source: reviewed GitHub Security Advisories published August 3, 2026. These records expose three distinct HTTP-client trust boundaries: a duck-typed body property bypassing header validation, retry state becoming detached from downstream framing metadata, and structured cookie fields being reparsed as raw attributes.

Primary sources:

- [GHSA-m8rv-5g2x-5cg5 / CVE-2026-15157](https://github.com/advisories/GHSA-m8rv-5g2x-5cg5): blob-like `.type` CRLF injection;
- [GHSA-8xcm-r25x-g524 / CVE-2026-16728](https://github.com/advisories/GHSA-8xcm-r25x-g524): retry-interceptor response framing mismatch; and
- [GHSA-v3r7-h72x-cjcm / CVE-2026-16729](https://github.com/advisories/GHSA-v3r7-h72x-cjcm): cookie `domain` and `unparsed` attribute injection.

Affected lines are undici before 6.28.0, 7.x before 7.29.0, and 8.x before 8.9.0. Confirm the exact API path: native `Blob` and `fetch()` do not satisfy the blob-like advisory's stated preconditions, retry desynchronization requires `interceptors.retry()` plus downstream forwarding, and cookie injection requires attacker influence over `setCookie()`'s structured fields.

!!! warning "Raw-byte local harnesses only"
    Use an isolated Node process, owned raw HTTP listeners, fake cookies, synthetic response bodies, and one connection at a time. Never target a shared proxy, inject real authorization/session headers, desynchronize user traffic, or forward malformed framing beyond the lab.

## Boundary map

| Surface | Trusted representation | Later sink | Bounded positive |
| --- | --- | --- | --- |
| blob-like request body | object passes blob-like shape checks | `.type` is serialized as `Content-Type` without the ordinary value validator | raw listener observes an extra inert canary header boundary |
| retry interceptor | first upstream response exposes length/range metadata | resumed body is forwarded with stale first-response framing | downstream recorder receives header length different from delivered synthetic bytes |
| cookie serializer | caller supplies structured `domain` or `unparsed` data | semicolons are interpreted as additional cookie attributes | parser records an attribute not represented by the intended structured field |

## 1. Record blob shape and raw request bytes

1. Exercise `request()`, `stream()`, `pipeline()`, and `dispatch()` only where the application actually exposes them. Keep `fetch()` and native `Blob` as negative controls.
2. Build a hand-rolled blob-like object or use the application's real adapter. Give it a fixed synthetic body, valid `size`, stream method, and ordinary media type; record which duck-typing predicate accepts it.
3. Change only `.type` to contain a CRLF-delimited inert header such as `X-Skillz-Canary: <random>`. Do not include a second request, `Content-Length`, `Transfer-Encoding`, authentication, or routing headers.
4. Capture the complete request bytes at an owned one-shot listener and close the connection. Compare an explicit `content-type` header, native `Blob`, `fetch()`, malformed non-blob objects, and fixed releases.

Report **untrusted adapter field -> blob-like branch -> raw HTTP/1 serializer emits a second canary header**. Do not call it request smuggling unless a separately approved two-hop parser differential proves a second request reaches another message slot.

## 2. Bind retry output to final framing

Use an owned upstream that emits deterministic synthetic bytes and a downstream recorder that never serves another user. Enable `interceptors.retry()` explicitly.

1. Baseline a complete `200` response and a standards-consistent partial response.
2. Reproduce the advisory's state transition with a first `206` carrying a controlled `Content-Range`, a deliberately mismatched `Content-Length`, and an early close, followed by the exact range response requested by the client.
3. Record every upstream request/range, first and final response headers, retry state, bytes delivered to the application, headers exposed to the application, and bytes/headers the mock gateway would serialize downstream.
4. Compare retry disabled, no downstream header forwarding, connection close after the response, consistent range metadata, and fixed releases.

The bounded positive is **malformed owned upstream partial response -> retry resumes synthetic body -> application receives body length N with stale exposed `Content-Length` M -> isolated downstream recorder preserves the mismatch**. This proves a response-framing primitive, not cross-user impact. Do not pipeline a victim request or test production intermediaries.

## 3. Keep cookie fields structured through serialization

Call `setCookie()` directly or through the application's reachable wrapper using a fake cookie name/value. Parse the serialized result with an independent cookie parser and record the resulting attribute multimap.

| Field | Baseline | Inert boundary case |
| --- | --- | --- |
| `domain` | owned hostname | hostname followed by `; SameSite=None` |
| `unparsed` entry | `X-Canary=value` | `X-Canary=value; HttpOnly` |
| explicit flags | structured `httpOnly`, `secure`, and `sameSite` | duplicate/conflicting raw forms |

Do not place these cookies in a real browser session. The positive is **one structured caller field -> serializer emits multiple attributes -> independent parser observes an extra attribute not authorized by the structured model**. Prove the target application lets an untrusted tenant or request field reach `domain` or `unparsed`; undici alone does not establish that reachability.

## Reporting checklist

- [ ] Exact undici version, API, interceptor, adapter, and downstream-forwarding preconditions are recorded.
- [ ] Native `Blob`, `fetch()`, retry-disabled, and structured-cookie controls are included.
- [ ] Request and response evidence is raw-byte or parser-recorder output from owned one-shot listeners.
- [ ] Canaries contain no credentials, real cookies, internal URLs, or executable request fragments.
- [ ] Fixed 6.28.0, 7.29.0, or 8.9.0 behavior is replayed.
- [ ] Header injection, response framing, and cookie-attribute injection are reported as separate primitives.