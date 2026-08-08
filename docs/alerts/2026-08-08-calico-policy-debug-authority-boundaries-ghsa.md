---
title: Calico tier and debug-listener authority boundaries
---

# Calico tier and debug-listener authority boundaries

Two Calico records expose reusable Kubernetes control-plane checks: a bulk API verb can skip tier-specific authorization, and an opt-in debug listener can expose privileged process state to network-reachable pods. Pair them with the existing [Calico policy-to-backend path differential](2026-07-30-url-policy-tenant-oauth-boundaries-ghsa.md#calico-policy-to-backend-path-differential) when the same assessment includes Dikastes.

Sources:

- tier-scoped `DeleteCollection` authorization: [GHSA-38w4-qxg9-xg36 / CVE-2026-41187](https://github.com/advisories/GHSA-38w4-qxg9-xg36) and [Tigera bulletin TTA-2026-006](https://www.tigera.io/security-bulletins/tta-2026-006); and
- shared pprof debug-listener exposure: [GHSA-h3h4-j2qv-pv4j / CVE-2026-41186](https://github.com/advisories/GHSA-h3h4-j2qv-pv4j) and [Tigera bulletin TTA-2026-004](https://www.tigera.io/security-bulletins/tta-2026-004).

The GitHub entries were unreviewed mirrors at scan time. The shared debug server is disabled by default according to the record. Establish feature state, component/version, listener reachability, policy object, and caller RBAC before attempting validation.

!!! warning "Disposable cluster and synthetic objects only"
    Use an isolated cluster, two synthetic namespaces/tiers, inert HTTP marker routes, deny-only Kubernetes API wrappers, and redacted debug-route evidence. Never bulk-delete policies, retrieve heap or goroutine bodies, collect tokens, contact production workloads, or weaken a shared cluster's network policy.

## 1. Build one policy-to-sink trace

Capture the complete authority tuple:

```text
caller pod or Kubernetes principal
-> API verb/resource selector or debug route
-> apiserver routing, request-scoped object set, or listener binding
-> Calico tier authorization or debug authentication decision
-> mutation target set or process-state handler
-> denied mutation/body sink
```

Pair every candidate with an allowed control, a denied control, and the fixed build. A policy object, HTTP status, RBAC permission, or open port alone does not establish a boundary bypass.

## 2. Compare single-object delete with `DeleteCollection`

Use two synthetic policy tiers, `owned-a` and `restricted-b`, populated only with inert marker policies. Create a lab principal whose RBAC includes the relevant collection verb but whose Calico tier authority is limited to `owned-a`. Replace the storage/mutation layer with a deny-only recorder, or intercept immediately before persistence.

Build a matrix across:

- `get`, `list`, single `delete`, and `deletecollection`;
- namespaced and global policy resources;
- staged and active variants;
- explicit label/field selectors, empty selectors, and no selector;
- one-tier and cross-tier result sets; and
- narrow `deletecollection` versus wildcard Kubernetes RBAC.

Capture the authenticated principal, Kubernetes verb/resource, selector, request-scoped object set, each object's tier, `AuthorizeTierOperation` invocation/result, and denied deletion set. Do not issue a live `kubectl delete --all` command.

A bounded positive is **single delete of `restricted-b` is denied -> equivalent `DeleteCollection` omits tier authorization -> denied recorder includes `restricted-b` objects**. Merely holding wildcard RBAC is a precondition, not proof that Calico's separate tier boundary was bypassed. Verify that the fixed build authorizes every selected object or rejects the collection atomically.

## 3. Treat pprof paths as privileged process-state capabilities

First prove that the shared debug server is explicitly enabled and whether kube-controllers or Goldmane binds it beyond loopback. From one disposable pod with no mounted service-account token, make header-only or body-denied requests to known pprof route names. Configure the client or a local proxy to discard response bodies and cap response bytes.

Record component, pod IP, listener address/port, network path, authentication challenge, status, `Content-Type`, `Content-Length` if present, and whether the body sink was blocked. Compare loopback, a same-namespace pod, a different synthetic namespace, and a NetworkPolicy-denied control.

A bounded positive is **opt-in component binds the debug listener to a pod-reachable non-loopback address -> an unauthenticated remote pod receives a successful pprof route response while body capture remains denied**. Do not request heap, goroutine, command-line, CPU-profile, or trace content. Route reachability establishes the unsafe process-state capability without collecting sensitive state.

## Reporting checklist

- [ ] Feature flags, component versions, topology, and affected/fixed builds are explicit.
- [ ] Single-object and collection verbs are tested against the same synthetic tier policy.
- [ ] Mutation is stopped before persistence and the exact selected object set is recorded.
- [ ] Debug listener proof uses status/headers only; no process-state body is retained.
- [ ] No production policy, workload, credential, heap, or goroutine data appears in evidence.