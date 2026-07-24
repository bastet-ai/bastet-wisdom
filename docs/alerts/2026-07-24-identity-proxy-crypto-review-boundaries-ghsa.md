---
title: Identity, proxy, crypto, and reviewed-artifact boundaries from July 24 GHSA updates
---

# Identity, proxy, crypto, and reviewed-artifact boundaries from July 24 GHSA updates

This late advisory wave yields durable checks for identity keys compared under database collation, object authorization split across two identifiers, Kubernetes proxy paths normalized after RBAC, cryptographic randomness selected by runtime, HTTP clients escaping configured transports or base paths, and reviewed container metadata changing before approval.

Sources: [GHSA-cmwh-g2h8-c222](https://github.com/advisories/GHSA-cmwh-g2h8-c222), [GHSA-rm67-g9ch-vxff](https://github.com/advisories/GHSA-rm67-g9ch-vxff), [GHSA-h4hf-v6w5-897x](https://github.com/advisories/GHSA-h4hf-v6w5-897x), [GHSA-c534-2w9c-x7fm](https://github.com/advisories/GHSA-c534-2w9c-x7fm), [GHSA-vh45-f885-3848](https://github.com/advisories/GHSA-vh45-f885-3848), [GHSA-qqc3-94qv-7fw3](https://github.com/advisories/GHSA-qqc3-94qv-7fw3), [GHSA-f45q-w629-wr25](https://github.com/advisories/GHSA-f45q-w629-wr25), and [GHSA-47w6-gwp4-w6vc](https://github.com/advisories/GHSA-47w6-gwp4-w6vc).

!!! warning "Authorized validation only"
    Use disposable DNS zones/users, lab Kubernetes namespaces, deterministic fake randomness, owned HTTP listeners, fake credentials, and inert container images. Never alter production DNS, read cluster Secrets, predict or use real private keys, capture live bearer credentials, or swap an artifact that could execute on a real compute node.

## Boundary matrix

| Component | Boundary | Replayable operator proof |
| --- | --- | --- |
| Poweradmin OIDC | `sub` is stored/looked up under accent- and case-insensitive MySQL collation instead of byte identity | With a fake IdP and two canary users, issue distinct subjects that collide only under the configured collation. Record IdP subject bytes, provider ID, local user ID, and session mapping. Fixed releases include 4.2.5/4.3.4. |
| Poweradmin record edit | permission is checked against caller-supplied zone ID while the update targets a separately supplied record ID | Create attacker/victim lab zones and harmless TXT markers. Attempt to pair the owned zone ID with the other zone's marker record ID, then restore it. Fixed releases include 3.9.11/4.2.5/4.3.4. |
| Poweradmin user API | API `user_edit_others` omits the web UI's superuser-target and separate password-edit checks | Use a non-superuser manager and a disposable target. Compare UI/API field decisions and stop at a reversible profile marker where possible; do not take over a real administrator. |
| Kite Kubernetes proxy | RBAC checks original pod/service route fields, then decoded traversal is normalized into another Kubernetes API path | Use a namespace-scoped user, a canary pod, and a second namespace containing only a non-secret marker resource. Capture original route, decoded/joined upstream path, service-account scope, and marker response. Version 0.14.1 is the fixed control. |
| `sm-crypto` SM2 | Node.js misses the browser-only CSPRNG branch, so default key and signing nonce generation derives from `Math.random()` plus wall clock | In fresh isolated processes, pin fake `Math.random` and time before import and compare generated public/private test keys. Demonstrate repeatability only; never recover or sign with a real user's key. |
| Hubuum Rust client | some methods bypass `with_transport`; built-in redirects retain bearer auth across same-origin paths outside the configured base prefix | Supply a recording custom transport and an owned local server. Exercise login, token validation, discovery, probes, export/search, and one same-origin redirect to a sibling canary path using fake credentials. Version 0.6.1 is the fixed control. |
| vantage6 algorithm review | a developer can edit another developer's pending algorithm metadata, including image/tag, before approval | Use two developer accounts and two inert images that print only distinct version markers. Capture owner, reviewer, image digest/tag, edit event, and digest actually approved; never submit an executable workload to a production node. |

## Validation sequence

1. **Model identifiers as tuples.** For identity and object tests, record issuer/provider plus exact subject bytes, or parent zone/namespace plus child record/resource ID. Change only one tuple element at a time.
2. **Preserve raw and normalized forms.** For Kite, capture the route as sent, one decode, canonical join result, authorization resource, and final upstream resource. Never infer cluster-wide access solely from a path-normalization trace.
3. **Instrument rather than escalate.** For crypto, control all entropy inputs in a one-shot harness. For HTTP clients, log which transport handled each method and where fake auth arrived. For reviewed artifacts, use inert image digests and stop before scheduling work.
4. **Run fixed controls.** Compare Poweradmin's fixed binary/collation handling, Kite 0.14.1, Hubuum 0.6.1, and the patched crypto implementation. For vantage6, document advisory status because the initial record stated no patch/workaround.

## Reporting notes

Report the narrow transition proven: **external subject bytes -> database collation -> wrong local identity**, **authorized parent ID plus unrelated child ID -> cross-parent mutation**, **authorized proxy route -> normalized upstream API path**, **runtime fallback RNG -> repeatable synthetic key material**, **configured transport/base prefix -> direct or redirected request carrying fake credentials**, or **pending reviewed image -> another developer changes digest/tag -> approval applies to changed artifact**.

Do not claim cluster compromise from a non-secret marker, private-key recovery from deterministic lab inputs, or node code execution from a metadata-only vantage6 result. Include exact versions, roles, feature flags, raw/canonical representations, patched decisions, and cleanup.