---
title: Kubernetes admission webhook outbound and token-mint authority checks
---

# Kubernetes admission webhook outbound and token-mint authority checks

A July 31 Bank-Vaults advisory exposes a reusable Kubernetes confused-deputy pattern: a low-privilege object supplies an outbound service address, an admission webhook resolves secrets with its own network position, and an adjacent annotation selects a ServiceAccount token that the webhook can mint. The durable operator lesson is to trace tenant-controlled admission metadata all the way through controller credentials and the final outbound request.

Source: [GHSA-r2v3-8gwf-7ghm / CVE-2026-54725](https://github.com/advisories/GHSA-r2v3-8gwf-7ghm) covers `vault-secrets-webhook` through 1.22.2. The [upstream fix](https://github.com/bank-vaults/vault-secrets-webhook/commit/76db45976fee0f54cafd94dffa425e6b542f65a0) marks object-supplied Vault addresses, validates them before connection or token minting, adds an address allowlist, and gates object-controlled TLS verification behavior. Version 1.23.1 is the first patched release identified by the advisory.

!!! warning "Recorder-only validation"
    Use a disposable cluster or an in-process fake client. Point the webhook only at an owned local recorder and use synthetic ServiceAccounts with no workload, Kubernetes, cloud, or Vault privileges. Never target metadata services or internal applications, request a real privileged ServiceAccount token, retain bearer material, or replay a token against Vault.

## Boundary map

```text
namespaced object writer
  -> ConfigMap or Secret annotations
  -> mutating admission webhook
       -> controller-authority TokenRequest
       -> webhook-network outbound request
  -> caller-selected Vault authority
```

The reported trigger requires both an admitted ConfigMap or Secret containing a `vault:` value and a caller-controlled `vault-addr`. The token-forwarding edge additionally depends on the `vault-serviceaccount` annotation and the webhook's `serviceaccounts/token:create` authority.

Treat these as separate claims:

| Edge | Required proof | Not sufficient |
| --- | --- | --- |
| metadata control | low-privilege principal can create or update a watched object with relevant annotations | manifest accepted by a client-side schema |
| admission reachability | that operation invokes the webhook for the resource and namespace | webhook installed elsewhere in the cluster |
| outbound confused deputy | owned recorder receives a request from the webhook execution context | a URL parser accepts the value |
| token mint authority | a fake client records a `TokenRequest` for the selected synthetic ServiceAccount | ClusterRole text alone |
| token forwarding | owned recorder receives an inert sentinel in the expected Vault login field | assuming every outbound request contains a token |

## Prerequisites

- explicit authorization for the Kubernetes cluster and webhook deployment;
- exact webhook and Helm chart version;
- disposable namespace and synthetic ServiceAccount with no RoleBinding, ClusterRoleBinding, Vault role, cloud identity, or workload;
- audit logs or an API-client reactor that records `serviceaccounts/token` requests;
- owned HTTPS recorder with a test certificate; and
- fixed-version control using 1.23.1 or later.

Inventory the admission boundary before sending a canary:

```bash
kubectl get mutatingwebhookconfigurations
kubectl auth can-i create configmaps -n "$LAB_NS" --as "$LAB_USER"
kubectl auth can-i create serviceaccounts/token -n "$LAB_NS" --as "$LAB_USER"
kubectl auth can-i create serviceaccounts/token -n "$LAB_NS" \
  --as "system:serviceaccount:$WEBHOOK_NS:$WEBHOOK_SA"
```

Capture the selected webhook rules, namespace and object selectors, failure policy, service identity, and whether the caller can directly create a token. A meaningful confused-deputy result normally shows the object writer cannot perform the privileged operation directly.

## Phase 1: outbound admission canary

Start with no token-selection annotation. Use a ConfigMap containing one inert `vault:` reference and set `vault-addr` to an owned recorder. The recorder should return a harmless Vault-shaped error or synthetic response and log only:

- method and route;
- source workload or connection identity available in the lab;
- timestamp and correlation marker; and
- whether a request body was present.

Do not log `Authorization`, `jwt`, cookies, or other credential fields. Compare four controls:

| Object address | Trigger value | Expected secure result |
| --- | --- | --- |
| operator-configured test Vault | inert `vault:` marker | normal configured behavior |
| object-supplied owned recorder | inert `vault:` marker | rejected unless explicitly allowlisted |
| object-supplied malformed URL | inert `vault:` marker | rejected before any connection |
| object-supplied owned recorder | ordinary non-`vault:` value | no Vault resolution request |

A positive on a vulnerable release is the owned recorder receiving the correlated request during admission. Do not substitute loopback, RFC1918, link-local, cloud metadata, or production service destinations; they add risk without improving proof of caller-selected authority.

## Phase 2: token-mint edge with an in-process fake

Prove token selection without minting a real JWT. In a local Go test or disposable webhook process:

1. replace the Kubernetes client with a fake reactor for the `serviceaccounts/token` subresource;
2. have the reactor return a fixed inert value such as `SKILLZ-SYNTHETIC-JWT`, not a signed token;
3. configure `vault-addr` to an `httptest.Server` or equivalent owned recorder;
4. submit a synthetic object selecting an unprivileged marker ServiceAccount; and
5. record the requested namespace/name and whether the sentinel reaches the expected Vault login field.

The evidence should contain only the literal sentinel or a boolean presence marker. This isolates three facts: the object selected a ServiceAccount, webhook authority reached the TokenRequest API, and the resulting value crossed into an outbound request. It does not claim access to Vault secrets or Kubernetes APIs.

## Phase 3: fixed-version ordering and policy differential

Repeat the identical fixture against the vulnerable and fixed releases. The upstream patch makes ordering part of the security contract: an object-supplied address must be validated before connection or ServiceAccount token minting.

| Case | Vulnerable observation | Secure 1.23.1+ observation |
| --- | --- | --- |
| non-allowlisted owned address | recorder may receive request | configuration rejection; no socket and no TokenRequest |
| exact allowlisted Vault authority | request proceeds according to operator policy | request may proceed |
| userinfo-bearing lookalike | parser-dependent behavior | rejected |
| object asks to skip TLS verification | caller may weaken transport verification | ignored/rejected unless operator explicitly permits it |

Record both sink counters. A fixed build that blocks the HTTP request but still mints a token has not preserved the intended validation-before-token ordering.

## Broader discovery workflow

Apply the pattern to other admission controllers and operators:

1. enumerate user-editable annotations, labels, CR fields, Secret references, image URLs, callback URLs, and service-account selectors;
2. map every controller API permission and outbound credential source;
3. locate URL construction, TLS override, redirect, DNS, and token-mint code paths;
4. test whether validation occurs before all privileged side effects;
5. test alternate admitted kinds and update paths, not just the primary Pod path; and
6. preserve a caller-to-sink decision table with vulnerable and fixed controls.

Prioritize fields that combine a caller-selected authority with controller-held credentials. URL control alone proves SSRF-like routing; credential disclosure requires separate evidence that a synthetic credential was attached to that exact final authority.

## Evidence and reporting

Preserve:

- webhook/chart version and admission rule coverage;
- caller and webhook identities with `kubectl auth can-i` results;
- synthetic object kind, namespace, and annotation names;
- normalized destination and owned-recorder correlation marker;
- fake TokenRequest namespace and ServiceAccount name;
- no-socket and no-token-mint fixed-version controls; and
- cleanup of test objects, recorder logs, and fixtures.

A precise title is: **“ConfigMap annotation makes the admission webhook contact a caller-selected owned endpoint before policy validation.”** If the fake-client phase is also proven, report the token-mint and forwarding boundary as a separate edge. Do not claim cluster-wide token theft, Vault compromise, cloud compromise, or secret access from RBAC inspection or an outbound callback alone.
