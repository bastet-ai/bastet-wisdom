---
title: Nuxt route-rule and SSR payload-cache authority boundaries
---

# Nuxt route-rule and SSR payload-cache authority boundaries

Two reviewed Nuxt advisories expose the same durable testing rule: authorization must be evaluated on the exact normalized route and for the current request, not inherited from a mismatched route-rule key or a prior user's shared payload-cache entry.

Primary sources:

- shared SSR payload cache disclosure: [GHSA-wm8w-6qjm-cv43](https://github.com/advisories/GHSA-wm8w-6qjm-cv43), affecting Nuxt `4.4.0` through `4.5.0` and fixed in `4.5.1`; and
- mixed-case route-rule bypass: [GHSA-hxvh-4h3w-prp9](https://github.com/advisories/GHSA-hxvh-4h3w-prp9), affecting Nuxt `4.4.7` through `4.5.0` and `3.21.7` through `3.21.9`, fixed in `4.5.1` and `3.21.10` respectively.

!!! warning "Two-user synthetic fixtures only"
    Use a local disposable Nuxt application, two fake users or tenants, random non-secret markers, and patched data-return sinks. Never request production payloads, collect cookies or bearer tokens, test another customer's route, or seed real profile, billing, token, or tenant data into SSR state.

## 1. Inventory the full route-to-payload surface

For each page protected by middleware or a page guard, record:

- source filename and configured route-rule key;
- router case-sensitivity setting;
- requested raw path, normalized path, and matched page;
- `cache`, `swr`, or `isr` route-rule state;
- whether runtime payload extraction exposes `/<page>/_payload.json`;
- middleware and page-guard decisions for the HTML request and payload request separately;
- payload cache namespace and effective key dimensions; and
- the identity or tenant that generated the cached value.

Do not assume the HTML response and extracted payload use the same authorization or cache path. Test them as distinct resources.

## 2. Test symmetric route normalization

The route-rule regression lowercased lookup paths while leaving mixed-case compiled keys unchanged. Vue Router could still resolve the page case-insensitively, but Nuxt could omit the rule and its `appMiddleware` gate.

Create synthetic pages and rules covering lowercase, PascalCase, camelCase, wildcard, and nested route keys. Exercise exact-case and case-variant requests while recording both router and route-rule matcher output:

| Route-rule key | Request variants | Required invariant |
| --- | --- | --- |
| `/admin` | `/admin`, `/Admin`, `/ADMIN` | either all variants resolve and receive the same rule, or disallowed variants do not route |
| `/Admin/dashboard` | exact, lower, upper, mixed | key and lookup use the same normalization policy |
| `/Dashboard/**` | nested exact and case variants | wildcard expansion cannot drop `appMiddleware` |
| page-derived mixed-case key | direct navigation and payload URL | derived rule remains attached to the page selected by the router |

Patch the protected handler to return only `AUTH-CANARY-<uuid>` after recording the middleware decision. A bounded positive is **router resolves the protected page -> route-rule matcher omits the mixed-case key -> auth middleware does not run -> no-op protected handler is reached**. Do not expose account data or perform a privileged action.

Include `router.options.sensitive: true` as a control. When case-sensitive routing is intentional, both key compilation and lookup must preserve case and nonmatching variants must fail at routing rather than silently losing policy.

## 3. Test cache identity and authorization order

For the payload-cache issue, create one cached protected page whose `useAsyncData` or `useFetch` result contains only a random marker derived from the current synthetic user. Use user A to warm the page, then request both the HTML route and `/<page>/_payload.json` as:

1. user A;
2. unauthenticated client;
3. user B in the same tenant;
4. user B in a different tenant; and
5. user A after logout or permission revocation.

Capture cookie/header presence as booleans or hashes, never raw credentials. Record route middleware and page-guard invocation counts, cache lookup timing, cache key, hit/miss, marker origin, response status, and marker hash.

A bounded positive is **user A warms protected cached route -> later payload request returns A's marker from a path-only runtime cache before current-request middleware or guards run**. The HTML response remaining protected is an important differential, not a negative result.

Repeat across `cache`, `swr`, and `isr`, and include:

- uncached route control;
- public cached route control containing only globally public data;
- route with explicit `cache.varies` dimensions;
- payload request with no prior HTML navigation;
- cold and warm server processes; and
- affected-versus-fixed Nuxt versions.

The secure outcome is current-request authorization before payload return. For private state, either avoid shared runtime payload caching or bind every cache entry to all identity and tenant dimensions that affect the result.

## 4. Chain the two boundaries without retrieving data

A useful regression fixture combines a mixed-case protected route with payload extraction:

1. configure a mixed-case page and `appMiddleware` rule;
2. warm its cache with user A's random marker;
3. request exact-case and case-variant HTML and payload paths as no-user and user B;
4. record router match, rule match, middleware execution, cache lookup, and response-marker hash; and
5. deny any serializer output other than the known marker.

This distinguishes two independent failures:

- **policy attachment failure**: the router selects a page but normalization causes its route rule to disappear; and
- **policy replay failure**: a cached payload is returned without re-running authorization for the current request.

Do not collapse them into a generic “auth bypass.” Report which transition failed and whether the proof reached a protected handler, a foreign marker, or both.

## Evidence template

```text
Nuxt version and deployment mode:
Router case-sensitivity:
Configured route-rule key:
Raw / normalized / matched path:
HTML or _payload.json request:
cache / swr / isr configuration:
Current synthetic principal and tenant:
Route middleware / page guard invocation:
Cache namespace, redacted key, hit or miss:
Marker creator and returned marker hash:
Affected-versus-fixed result:
Strongest bounded claim:
Excluded data-access or action claims:
```

Keep response bodies to random markers. A cache hit, route match, or skipped hook alone is not proof of cross-user disclosure; bind the current principal, marker creator, cache decision, and returned marker in one trace.
