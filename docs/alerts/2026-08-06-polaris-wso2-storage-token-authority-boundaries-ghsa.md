---
title: Polaris storage-location and WSO2 token-authority boundaries
---

# Polaris storage-location and WSO2 token-authority boundaries

Three August 6 records expose the same reusable failure across data catalogs and identity platforms: a caller is approved for one logical namespace, but a later storage reader or API router uses broader ambient authority.

Source records:

- Apache Polaris registration-time storage-location validation: [GHSA-62q9-5g2h-5gxp / CVE-2026-64640](https://github.com/advisories/GHSA-62q9-5g2h-5gxp) and the [Apache announcement](https://lists.apache.org/thread/scd8p9wy8b9j3om5wohbotpfycnmmjl4);
- WSO2 JWT algorithm-policy bypass: [GHSA-j7vh-5w8q-4m4x / CVE-2026-5430](https://github.com/advisories/GHSA-j7vh-5w8q-4m4x) and [WSO2-2026-5328](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2026/WSO2-2026-5328); and
- WSO2 low-privilege token use against product-level Admin REST APIs: [GHSA-88j3-cjwq-qqvv / CVE-2026-1728](https://github.com/advisories/GHSA-88j3-cjwq-qqvv) and [WSO2-2026-5077](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2026/WSO2-2026-5077).

The GitHub entries were unreviewed mirrors when this page was written. Use the linked Apache and WSO2 records as primary references, and confirm exact deployed versions and configuration before testing or reporting.

!!! warning "Synthetic objects and denied sinks only"
    Use disposable catalogs, fake S3-compatible objects, throwaway signing keys, synthetic users, and patched storage/token/API sinks. Never read production objects, reuse real tokens, invoke mutating admin methods, or test algorithm confusion against an operational identity service.

## 1. Map logical permission to final authority

Build one trace that answers:

```text
caller identity and role
-> requested catalog / table / API
-> policy decision
-> user-controlled metadata or token fields
-> credential or verifier selected
-> final object key or API handler
-> response fields / mutation sink
```

A table-registration privilege is not object-read authority. A valid low-privilege token is not authorization for every route that accepts its format. A JWT parser accepting an algorithm is not proof that deployment policy permits that algorithm.

## 2. Test catalog registration before storage reads

The Polaris record is configuration-dependent. The demonstrated server-side read requires:

- an authenticated principal allowed to register a table or view;
- S3 credential vending;
- a caller-selected Iceberg metadata file; and
- catalog credentials that can read a synthetic object outside the catalog's allowed storage locations.

Create two disposable prefixes in an owned S3-compatible fixture:

```text
allowed/catalog-a/table-metadata.json
outside/catalog-a/canary-metadata.json
```

Both objects should contain non-sensitive random markers. Instrument or patch the object client so it records bucket, key, credential identity, and operation before returning a fixed synthetic response. Do not grant access to any real bucket.

Run a registration matrix:

1. metadata file inside the allowed prefix with only in-prefix references;
2. metadata file outside the allowed prefix;
3. in-prefix metadata containing an external data or metadata reference;
4. another catalog's synthetic prefix;
5. encoded, normalized, and equivalent object-key forms; and
6. a principal that can inspect but not register.

Capture the order of operations:

```text
raw registration location
-> normalized storage location
-> catalog allow-location decision
-> credential vending / object-reader selection
-> object GET recorder
-> metadata semantic validation
```

A bounded positive is **registration privilege accepted -> catalog credential selected -> denied GET recorder receives the outside-prefix canary key before location validation**. If an in-prefix metadata document merely stores an external reference and no reader follows it, report a persisted-reference boundary only; do not claim external-object disclosure.

## 3. Separate JWT cryptographic acceptance from algorithm policy

For WSO2 JWT validation, build a disposable deployment or an offline harness around the exact verifier used by the affected product. Generate a throwaway key set and synthetic claims that grant only a harmless canary identity.

Create a decision table across:

- the configured and expected algorithm;
- another algorithm supported by the underlying JWT library but not configured;
- `alg=none` as a negative control;
- wrong key, wrong issuer, wrong audience, expired token, and malformed signature controls; and
- single-tenant versus multi-tenant routing if the deployment supports both.

Record:

```text
JWT header alg
-> deployment algorithm allow-list
-> key and verifier selected
-> signature result
-> issuer/audience/tenant checks
-> synthetic principal
-> patched session/API sink
```

The strong proof is **unsupported-by-policy algorithm -> cryptographic verifier accepts the canary token -> patched authenticated route receives the synthetic principal**. An error-message difference or library support alone is insufficient. Never mint administrative claims or reuse operational signing material.

## 4. Diff token scope across route families

The second WSO2 record states that a token issued to a low-privilege user could reach product-level Admin REST APIs. Test authorization independently of authentication.

Use two disposable users:

- `canary-user`, assigned the minimum role needed to obtain a token; and
- `canary-admin`, used only for a positive control.

Inventory one read-only or patched no-op endpoint from each relevant family:

```text
self-service API
ordinary product API
organization / tenant API
product-level Admin REST API
```

For each route, compare no token, malformed token, low-privilege token, wrong-tenant token, expired token, and canary-admin token. Patch every create, update, delete, role, and configuration handler to return a marker without changing state.

Capture token subject, issuer, audience, scopes/roles, tenant or organization, matched route, authentication middleware, authorization middleware, and final handler. A bounded positive is **low-privilege token authenticates -> route-family authorization is omitted or mis-scoped -> patched Admin REST handler receives the canary request**.

Do not infer full account takeover from one readable route. Report the exact handler and authority it would exercise, and distinguish method-level authorization from route-level acceptance.

## 5. Reporting boundaries

Include:

- exact product build, deployment mode, and affected feature configuration;
- synthetic principal, catalog, prefix, object, and route identifiers;
- positive and negative controls;
- the credential/verifier/route authority selected at the final sink;
- whether evidence proves a read attempt, stored external reference, accepted principal, or admin-handler reachability; and
- primary-source status and any unresolved affected-version uncertainty.

Avoid claims of object disclosure without a final reader, JWT bypass without an authenticated sink, or administrative takeover without a specific authorized handler. The durable finding is the authority mismatch: **logical permission for one namespace or role reaches broader storage credentials, verifier policy, or route authority**.
