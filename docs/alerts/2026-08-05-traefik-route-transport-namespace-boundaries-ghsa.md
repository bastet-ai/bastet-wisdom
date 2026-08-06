---
title: Traefik route, transport, and namespace authority boundaries
---

# Traefik route, transport, and namespace authority boundaries

Ten reviewed Traefik advisories expose a broader controller and reverse-proxy testing rule: authorization must remain bound to the same route, namespace, identity header, transport fact, and normalized path through every rewrite, cache, resolver, and backend handoff.

Primary sources:

- [GHSA-42cj-m3vj-89wv](https://github.com/advisories/GHSA-42cj-m3vj-89wv): `IngressRouteTCP` service references could select a file-provider `TCPServersTransport` from a namespace excluded by `crossProviderNamespaces`; affected Traefik `3.6.0` through `3.6.22` and `3.7.0` through `3.7.6`, fixed in `3.6.23` and `3.7.7`.
- [GHSA-qq9q-x9w4-chhj](https://github.com/advisories/GHSA-qq9q-x9w4-chhj): Gateway API `HTTPRoute` backend-filter `extensionRef` resolution used the backend Service namespace rather than the route namespace; affected Traefik `3.7.0` through `3.7.6`, fixed in `3.7.7`.
- [GHSA-x677-9fxg-v5c5](https://github.com/advisories/GHSA-x677-9fxg-v5c5) and [GHSA-3q9r-p662-5j8m](https://github.com/advisories/GHSA-3q9r-p662-5j8m): auth middleware could preserve underscore aliases of trusted identity headers or derive forwarded port from an unsanitized request; fixed in `2.11.51`, `3.6.22`, and `3.7.6`.
- [GHSA-cxjq-mrr5-89rv](https://github.com/advisories/GHSA-cxjq-mrr5-89rv) and [GHSA-8rxv-jg7p-wvg3](https://github.com/advisories/GHSA-8rxv-jg7p-wvg3): `ReplacePathRegex` and Ingress NGINX `rewrite-target` could create traversal only after route selection; fixed in `2.11.52`/`3.6.23`/`3.7.7` and `3.7.8`, respectively.
- [GHSA-6p8f-p8j2-rqmv](https://github.com/advisories/GHSA-6p8f-p8j2-rqmv): two Gateway API routes sharing a backend Service and port could share the wrong backend-filter context; fixed in `3.7.6`.
- [GHSA-62fc-8686-hfmq](https://github.com/advisories/GHSA-62fc-8686-hfmq): `allowCrossNamespace=false` did not cover `TraefikService` backend references; fixed in `2.11.54`, `3.6.25`, and `3.7.10`.
- [GHSA-fgjj-px3w-67xx](https://github.com/advisories/GHSA-fgjj-px3w-67xx): delimiter-based Gateway API route identities could collide across namespace/name tuples and overwrite another route; fixed in `3.6.25` and `3.7.10`.
- [GHSA-6765-c87h-8mrf](https://github.com/advisories/GHSA-6765-c87h-8mrf): BasicAuth singleflight keys did not unambiguously bind password and stored-secret fields; fixed in `3.6.25` and `3.7.10`.

!!! warning "Disposable clusters and canary identities only"
    Use a local throwaway cluster, synthetic namespaces, fake client certificates, inert identity headers, no-op backends, and patched controller/config recorders. Never reference production TLS material, SPIFFE identities, middlewares, Services, Secrets, or routes; never send traffic with a real authenticated identity; and never mutate shared cluster resources.

## 1. Build a principal-object-reference map

Create three namespaces:

- `route-a`: controlled by a low-privileged synthetic route author;
- `backend-b`: containing one no-op Service and one harmless identity-header middleware; and
- `platform-c`: representing operator-owned file-provider transports.

Record, for every object reference:

| Field | Record |
| --- | --- |
| authoring principal | namespace and RBAC verbs on the route object |
| source object | API group, kind, namespace, and name |
| reference field | provider suffix, `BackendRef`, filter, or transport selector |
| explicit grant | `ReferenceGrant` source kind/namespace and target kind/namespace |
| policy allowlist | `crossProviderNamespaces` and provider enablement |
| resolver input | namespace actually passed to lookup |
| resolved object | provider, kind, namespace, name, and synthetic content hash |
| runtime effect | selected transport, backend, headers, mTLS identity, or PROXY mode |

Do not infer authorization from a successful route alone. Bind the route author, exact reference, grant, resolver namespace, resolved object, and runtime configuration in one trace.

## 2. Test CRD HTTP/TCP provider parity

Configure one inert file-provider HTTP transport and one inert file-provider TCP transport. Allow cross-provider references only from one canary namespace, leaving `route-a` outside the allowlist.

Create matched `IngressRoute` and `IngressRouteTCP` fixtures in `route-a` whose service transport fields structurally reference the corresponding file-provider objects. Patch dynamic-configuration publication or backend dialing so the controller records the selected transport but does not connect.

Exercise:

1. same-provider, same-namespace baseline;
2. allowed-namespace cross-provider reference;
3. denied-namespace HTTP cross-provider reference;
4. denied-namespace TCP cross-provider reference; and
5. missing, malformed, and explicit provider suffix controls.

The invariant is **the same provider/namespace policy decision for equivalent HTTP and TCP references**. A bounded positive is **denied namespace authors `IngressRouteTCP` -> controller accepts `name@file` -> configuration recorder shows the operator-owned TCP transport selected**.

Use only fake transport attributes. A selected client-certificate hash, SPIFFE canary ID, or PROXY-protocol mode is sufficient; do not make a TLS connection or impersonate an operational workload.

## 3. Test Gateway API namespace provenance

Create an `HTTPRoute` in `route-a` with a `BackendRef` to the no-op Service in `backend-b`. Add the minimum `ReferenceGrant` needed for that Service only. Place same-named but differently marked middleware objects in both namespaces.

Attach an `ExtensionRef` filter to the backend reference and instrument Traefik's object lookup. Compare:

- local Service plus local middleware;
- cross-namespace Service with no middleware grant;
- cross-namespace Service with a same-named middleware in both namespaces;
- explicit grant variants where the API permits them; and
- affected `3.7.6` versus fixed `3.7.7`.

The critical question is which object's namespace supplies authority. A Service `ReferenceGrant` must not become an implicit grant to a middleware in the Service namespace. A bounded positive is **route author has permission to reference Service B -> middleware lookup substitutes backend namespace B for route namespace A -> configuration recorder observes B's canary middleware without an independent authorization path**.

For identity-header impact, use `X-Canary-Principal: ROUTE-BOUNDARY-<uuid>` and a no-op backend that stores only the header name and hash. Do not use headers recognized by a production SSO, forward-auth, or authorization system.

## 4. Diff raw, routed, rewritten, and backend paths

Route authorization can be correct for the incoming path and wrong for the path produced by middleware. Build two public canary routes and one denied canary route on the same no-op backend. Exercise `ReplacePathRegex` and Ingress NGINX `rewrite-target` rules that capture user-controlled suffixes both with and without a mandatory `/` separator.

Record four values for every request:

```text
raw request target -> router match path -> post-rewrite path -> backend-normalized path
```

Use a patched backend dispatcher that records the final route ID and returns a marker without serving content. Include ordinary segment names containing `..`, encoded separators, repeated slashes, and a traversal-producing capture, plus clean negative controls. The invariant is **a rewrite must not produce a path whose canonical form would have selected a different authorization policy**.

A bounded positive is **public router selected on the pre-rewrite path -> middleware creates a dot-segment path -> mock backend normalizer resolves the denied route ID**. Do not request a real admin endpoint, retrieve protected content, or test a shared ingress.

## 5. Test identity-header alias closure and forwarded-fact provenance

For BasicAuth, DigestAuth, and ForwardAuth, configure inert trusted headers such as `X-Canary-Principal`. Send paired dash and underscore spellings and have the backend record only header names, ordering, and hashed canary values. Compare how Traefik, the wire adapter, and a CGI/WSGI-style mock canonicalizer treat:

- `X-Canary-Principal` versus `X_Canary_Principal`;
- attacker input versus auth-service response headers;
- authenticated and rejected requests; and
- affected and fixed versions.

Then test `trustForwardHeader: false` over plain HTTP with inconsistent `X-Forwarded-Proto` and explicit port inputs. Patch the auth connector to record the actual connection TLS state plus the forwarded proto/port tuple and return a fixed denial. Every forwarded fact must derive from the sanitized request and actual transport, not a sibling field on the original request.

Do not use a production identity header or real credentials. Report identity spoofing only if a detached mock authorization sink consumes the attacker marker; otherwise report alias survival or forwarded-fact inconsistency.

## 6. Bind backend-filter context to the authoring route

Create two accepted `HTTPRoute` objects that target the same synthetic Service and port but carry different inert `backendRef` filters. Use marker-only header modifiers and, where needed, a narrowly scoped `ReferenceGrant`. Capture the generated child-service identity and filter chain for both route reconciliation orders.

The invariant is **route A's request always receives route A's filter context**, even when both routes deduplicate to the same backend connection target. Test:

1. same backend and same filters;
2. same backend and different filters;
3. same backend name in different namespaces;
4. delete/recreate and reversed creation order; and
5. affected `3.7.5` versus fixed `3.7.6`.

A bounded positive is a route-A request reaching the no-op backend with route B's marker. This proves context bleed; it does not prove credential disclosure unless a synthetic authorization recorder separately changes its decision.

## 7. Audit every cross-namespace backend kind

Extend the namespace matrix beyond Middleware, TLSOption, and ServersTransport to every backend abstraction, including `TraefikService`. With `allowCrossNamespace=false`, give the synthetic author rights only in `route-a`, place same-named weighted/mirroring services in `route-a` and `backend-b`, and patch service resolution and dialing.

Test local names, explicit namespace/provider syntax, malformed suffixes, and every route family that can select the object. A policy is incomplete if one resolver reaches a foreign `TraefikService` while equivalent foreign references are denied. Prove only the resolved object hash and denied dial target; do not expose another tenant's backend.

## 8. Look for non-injective derived identities and cache keys

List every field concatenated into router, service, middleware, and authentication-work key material. Generate distinct tuples whose serialized forms collide, especially where `-`, empty fields, normalization, or raw concatenation erase boundaries.

Two useful fixtures are:

```text
(namespace=team, route=a-app) != (namespace=team-a, route=app)
(password=P, secret=H) != (password=P||H, secret="")
```

For Gateway routes, attach colliding synthetic names to the same disposable Gateway and equivalent canary match, then record configuration-map insertions. Stop at showing that the later route's canary backend replaces the earlier route's key; never relay user traffic.

For BasicAuth, patch password verification to return deterministic canary booleans and synchronize two requests so no password hashes or usable credentials are required. Record `(username, password-id, secret-id) -> singleflight key -> result owner -> propagated identity`. The result must remain bound to the complete tuple, not merely a collision-prone derived key.

## 9. Separate configuration reachability from downstream impact

Report the strongest proven transition:

1. reference parsed;
2. reference accepted by policy;
3. foreign transport or middleware resolved;
4. dynamic configuration published;
5. canary request receives the foreign transport/header behavior; or
6. downstream no-op authorization recorder changes its decision.

Do not call object resolution an authentication bypass unless the synthetic downstream decision actually changes. Likewise, transport selection can establish privileged identity reuse risk without presenting a client certificate to a real backend.

## Evidence template

```text
Traefik version and enabled providers:
Synthetic route-author RBAC:
Route kind / namespace / name:
Backend and extension/transport reference:
ReferenceGrant matrix:
crossProviderNamespaces value:
Expected resolver namespace:
Observed resolver namespace:
Resolved provider / kind / object hash:
Published configuration hash:
Raw / routed / rewritten / backend-normalized path:
Incoming and forwarded header-name sets:
Actual TLS state / forwarded proto / forwarded port:
Derived router, service, or singleflight key:
Result owner and propagated canary identity:
No-op backend or denied dial result:
Affected-versus-fixed result:
Strongest bounded claim:
Excluded identity, Secret, and traffic effects:
```

Preserve controller logs, normalized object references, and an affected-versus-fixed decision table. Keep kubeconfigs, bearer tokens, certificate bodies, Secret values, and real namespace names out of wiki and report artifacts.