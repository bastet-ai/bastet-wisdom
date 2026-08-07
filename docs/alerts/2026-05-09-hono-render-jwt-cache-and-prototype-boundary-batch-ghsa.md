# Hono render, JWT, cache, and prototype-boundary batch

**Signal:** The **2026-05-09 01:15 UTC** scan added web-framework advisories where text-rendering, JWT claim validation, cache variation, and template object mutation crossed trust boundaries.

## Advisory cluster

- **Hono JSX SSR CSS declaration injection** — [GHSA-qp7p-654g-cw7p](https://github.com/advisories/GHSA-qp7p-654g-cw7p): `hono <4.12.18` failed to safely encode style-object values during JSX server-side rendering, allowing attacker-controlled style values to inject additional CSS declarations. Patch to **4.12.18+**.
- **Hono JWT NumericDate claim validation weakness** — [GHSA-hm8q-7f3q-5f36](https://github.com/advisories/GHSA-hm8q-7f3q-5f36): `hono <4.12.18` accepted improperly validated `exp`, `nbf`, or `iat` claim types in `verify()`. Patch to **4.12.18+** and reject non-integer NumericDate values before authorization decisions.
- **Hono cache middleware ignores authorization variation** — [GHSA-p77w-8qqv-26rm](https://github.com/advisories/GHSA-p77w-8qqv-26rm): `hono <4.12.18` cache middleware did not honor `Vary: Authorization` / `Vary: Cookie`, risking cross-user cache leakage. Patch to **4.12.18+**.
- **Velocity.js prototype pollution via `#set` path assignment** — [GHSA-j658-c2gf-x6pq](https://github.com/advisories/GHSA-j658-c2gf-x6pq): `velocityjs <=2.1.5` allowed path assignment into prototype-bearing keys; no patched version was listed at scan time.

## Why this matters

Framework helpers are security boundaries. A renderer that treats CSS values as inert text, a JWT verifier that accepts the wrong claim type, a cache that ignores identity-bearing headers, or a template setter that can write `__proto__` all turn convenience APIs into privilege-bleed paths.

## Triage

1. Patch Hono to **4.12.18+** anywhere JSX SSR, JWT verification, or cache middleware is enabled.
2. Search for SSR paths that pass user-controlled values into style objects; add tests for `;`, comment, URL, and escaped-newline injection in style values.
3. Add JWT tests that reject string, float, object, array, `NaN`, negative, and extremely large `exp` / `nbf` / `iat` values before claims reach authorization logic.
4. Disable caching on authenticated routes until the cache key includes the authenticated principal or the middleware honors `Authorization`, `Cookie`, and application-specific tenant/session headers.
5. Treat Velocity templates and data paths as untrusted code-adjacent input; block `__proto__`, `prototype`, `constructor`, and dotted/bracket forms that resolve to prototype objects.

## Durable controls

- Renderers must encode at the grammar boundary being emitted: HTML text, attributes, URLs, JavaScript, and CSS each need distinct encoders.
- Cache policy should default to private/no-store for authenticated responses unless an explicit identity-safe key is configured.
- JWT validation should enforce RFC data types before semantic checks; do not coerce claim values.
- Template path setters need a denylist plus positive path grammar, object creation with null prototypes, and regression tests for prototype pollution payloads.

## August 7 follow-up: SSR memo lifetime and dynamic hop-by-hop headers

Hono 4.12.34 fixes two more helper boundaries:

- [`GHSA-f23p-vx2j-j53r`](https://github.com/advisories/GHSA-f23p-vx2j-j53r) / CVE-2026-71850 affects `hono >=3.8.0,<4.12.34`. Server-side `memo()` retained rendered output across requests when props compared equal, even when the component read current-user data from `createContext()`/`useContext()`, `useRequestContext()`, or `getContext()`.
- [`GHSA-79qm-7rj5-m7r9`](https://github.com/advisories/GHSA-79qm-7rj5-m7r9) / CVE-2026-71849 affects `hono >=4.7.0,<4.12.34`. `hono/proxy` removed standard hop-by-hop response headers but failed to remove extension fields named by the origin's `Connection` header.

### Replay `memo()` as a two-principal warm-instance test

Reachability requires all of these conditions: server-side JSX, a component wrapped in `memo()`, request-specific data read from ambient context rather than props, comparator-equal props, and two requests handled by the same warm process or isolate.

Use two disposable users with unique, non-secret markers. Prime the component with user A and request the same route as user B, then reverse the order and repeat against the same instance. Capture:

```text
request order | process/instance ID | explicit props | ambient principal marker | rendered marker
A -> B        | warm-1              | equal          | B                        | must be B
B -> A        | warm-1              | equal          | A                        | must be A
```

Add three controls: an unwrapped component, request-specific values passed as props, and Hono 4.12.34+. The upstream fix removes server-side result reuse while preserving DOM-renderer memo metadata. A reliable finding needs deterministic marker crossover on an affected build and clean isolation on the fixed control; one stale response without instance affinity is not enough.

Never place real CSRF tokens, account data, or session values in the fixture. Report **cross-request SSR output reuse** first, then describe disclosure impact only for the application fields independently shown to occupy that component.

### Derive the proxy removal set from `Connection`

An intermediary must remove both the well-known hop-by-hop fields and every field named by `Connection`. Test against an owned mock origin with harmless response metadata:

```http
Connection: X-Skillz-Hop
X-Skillz-Hop: canary-only
X-Skillz-End-To-End: keep-me
```

Record the origin response and the final client response. The affected helper forwards `X-Skillz-Hop`; the fixed helper removes it while retaining `X-Skillz-End-To-End`. Vary header case, optional whitespace, and multiple comma-separated tokens, but do not put credentials or operational internal metadata in the canary.

Treat this as a transport-policy primitive, not automatic cache poisoning or authorization bypass. Escalation requires a concrete downstream consumer that trusts the leaked extension field. The strongest report includes raw origin-to-proxy and proxy-to-client header sets plus an affected-versus-fixed comparison.
