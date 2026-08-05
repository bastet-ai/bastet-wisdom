---
title: Traefik route, transport, and namespace authority boundaries
---

# Traefik route, transport, and namespace authority boundaries

Two reviewed Traefik advisories expose a reusable Kubernetes controller-testing rule: a grant for one object or namespace must not silently authorize a different referenced resource, and provider allowlists must be enforced identically across HTTP and TCP route families.

Primary sources:

- [GHSA-42cj-m3vj-89wv](https://github.com/advisories/GHSA-42cj-m3vj-89wv): `IngressRouteTCP` service references could select a file-provider `TCPServersTransport` from a namespace excluded by `crossProviderNamespaces`; affected Traefik `3.6.0` through `3.6.22` and `3.7.0` through `3.7.6`, fixed in `3.6.23` and `3.7.7`.
- [GHSA-qq9q-x9w4-chhj](https://github.com/advisories/GHSA-qq9q-x9w4-chhj): Gateway API `HTTPRoute` backend-filter `extensionRef` resolution used the backend Service namespace rather than the route namespace; affected Traefik `3.7.0` through `3.7.6`, fixed in `3.7.7`.

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

## 4. Separate configuration reachability from downstream impact

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
No-op backend or denied dial result:
Affected-versus-fixed result:
Strongest bounded claim:
Excluded identity, Secret, and traffic effects:
```

Preserve controller logs, normalized object references, and an affected-versus-fixed decision table. Keep kubeconfigs, bearer tokens, certificate bodies, Secret values, and real namespace names out of wiki and report artifacts.