---
title: Lemur certificate-management authority boundaries
---

# Lemur certificate-management authority boundaries

An August 18 advisory wave against Netflix's Lemur CA-management system exposes one reusable operator pattern: a named certificate-management feature can silently become revocation, private-key-read, sub-CA-mint, rotation-hijack, or outbound-connect authority when the final sink authorizes against the wrong object (the Lemur database row instead of the CA-side certificate identity) or skips an ownership/allowlist check that only exists on one code path.

Primary records (all against `main` of https://github.com/Netflix/lemur unless noted):

- Any user can revoke an arbitrary certificate at the CA by uploading a duplicate row and revoking that row: [GHSA-pxmc-2ffp-8j67 / CVE-2026-71417](https://github.com/advisories/GHSA-pxmc-2ffp-8j67);
- Missing authorization on `POST /certificates/<id>/export` whenever the chosen plugin advertises `requires_key = False`: [GHSA-4h97-p9wq-chqj / CVE-2026-71322](https://github.com/advisories/GHSA-4h97-p9wq-chqj);
- Sub-CA creation never checks `AuthorityPermission` on the parent when `ADMIN_ONLY_AUTHORITY_CREATION=False`: [GHSA-g7p5-89mh-248h / CVE-2026-71317](https://github.com/advisories/GHSA-g7p5-89mh-248h);
- Unchecked `replaces[]` silences notifications and hijacks auto-rotation for certificates the caller has no role on: [GHSA-cfh6-pv5c-38jv / CVE-2026-71308](https://github.com/advisories/GHSA-cfh6-pv5c-38jv);
- Destination read endpoints return cleartext SFTP password / private-key-passphrase options to any authenticated user (write endpoints are admin-gated, read endpoints are not): [GHSA-6c8m-q6g9-vrw3 / CVE-2026-71307](https://github.com/advisories/GHSA-6c8m-q6g9-vrw3);
- ACME authority `acme_url` allowlist validated only at creation, so the update path can repoint an authority at an internal endpoint (incomplete fix for GHSA-v2wp-frmc-5q3v): [GHSA-v5rc-cpwc-cfpr / CVE-2026-71303](https://github.com/advisories/GHSA-v5rc-cpwc-cfpr);
- Certificate-revocation-check SSRF guard bypassable via redirect and DNS rebinding (incomplete fix for GHSA-54vg-pfh7-jq95): [GHSA-f3qq-49m6-rw8f / CVE-2026-70667](https://github.com/advisories/GHSA-f3qq-49m6-rw8f); and
- ACME-client SSRF: allowlist enforced only at authority creation, and the ACME server controls the URLs the client then follows: [GHSA-xpmj-wjcp-6pww / CVE-2026-70666](https://github.com/advisories/GHSA-xpmj-wjcp-6pww).

These entries were unreviewed when scanned and target `main` in most cases. Confirm the exact Lemur release, the enabled issuer/destination plugins, the `ADMIN_ONLY_AUTHORITY_CREATION` and `ACME_DIRECTORY_HOST_ALLOWLIST` settings, and the authenticated role before reporting. Do not reframe the sub-CA or rotation findings as unauthenticated remote compromise; they require an authenticated non-read-only principal and, for sub-CA minting, the documented `ADMIN_ONLY_AUTHORITY_CREATION=False` setting.

!!! warning "Disposable authorities, owned peers, and denied sinks only"
    Use a temporary Lemur data root, synthetic certificates, disposable authorities/roles, owned no-content ACME and CRL/OCSP peers, and patched revocation/rotation/connect/writer sinks. Never revoke a real CA certificate, read a real private key, mint a sub-CA against a real root, deploy a substitute certificate onto a live endpoint, or point an authority at a real internal/IMDS service.

## Boundary map

| Surface | Caller-controlled authority | Final sink | Bounded positive |
| --- | --- | --- | --- |
| Certificate revoke | `PUT /certificates/<id>/revoke` row id, plus `POST /certificates/upload` body/authority/external_id | CA-side revocation of the certificate identity | duplicate row revokes the real CA certificate, not just the row |
| Certificate export | chosen export plugin (`requires_key` flag) | `plugin.export(body, chain, private_key, options)` | a non-owner reaches the private-key read on a `requires_key=False` plugin |
| Sub-CA mint | `POST /authorities` `type=subca` + `parent` id/name | `create_authority` loads `parent.authority_certificate.private_key` and signs | a user with no role on the parent mints an intermediate chained to it |
| Rotation hijack | `replaces[]` / `replacements` on create/upload | `Certificate.replaces` listener sets `victim.notify=False`, rotation deploys `replaced[0]` | a no-role user's certificate is scheduled onto a victim endpoint and the victim's expiry alerts are silenced |
| Destination credential read | `GET /destinations` / `GET /destinations/<id>` | `DestinationOutputSchema` serializes every `options` value verbatim | a low-priv or read-only principal returns a cleartext SFTP `password` / `privateKeyPass` option |
| ACME authority repoint | `PUT /authorities/<id>` `options.acme_url` | ACME client fetches the server-controlled directory/URL on next issuance | an authority member repoints `acme_url` past the create-time allowlist |
| Revocation-check SSRF | uploaded certificate CRL/OCSP extension URL | `_validate_revocation_url` guard, then CRL fetch that follows redirects / re-resolves DNS | the guarded certificate still makes Lemur reach an owned internal peer via redirect or rebinding |

## 1. Build one route-to-sink trace per management feature

Start from documented Lemur API traffic and source or instrumented builds. For each certificate-management operation capture:

```text
authenticated principal and role
-> route selection
-> object/authority/destination resolution (row vs CA identity)
-> operation-specific authorization (creator, CertificatePermission, AuthorityPermission, admin_permission)
-> canonical revocation, key-read, mint, rotation, option-read, or network-connect sink
```

Do not infer authority from UI visibility. Test create, upload, revoke, export, replace, update-authority, and verify independently because they use different helper functions and often gate on different permission primitives.

## 2. Resolve revocation against the CA-side identity, not the row

Create a disposable Lemur root and a synthetic CA whose revocation call is a denied recorder. Give an attacker role `StrictRolePermission` on one certificate but no `CertificatePermission` on a second target certificate. Read the target's public `body`, `authority.id`, and `external_id` via `GET /certificates/<id>`, upload a duplicate row, and call `PUT /certificates/<id>/revoke` on that duplicate.

A bounded positive is **no-role-on-target user -> duplicate-row upload -> revoke path -> denied CA-side revocation recorder fires for the target certificate identity**. Because there is no uniqueness constraint on `body`, `serial`, or `external_id`, record whether the duplicate's creator-bypass skips `CertificatePermission`. Do not revoke a real CA certificate; file the finding on the row-vs-identity mismatch plus the missing uniqueness constraint.

## 3. Gate export on plugin capability, not on a single code path

Instantiate a certificate owned by a different user. Select an export plugin that advertises `requires_key = False` and call `POST /certificates/<id>/export`. Because the ownership/`CertificatePermission` check is nested inside `if plugin.requires_key:`, the check is skipped for such plugins.

A bounded positive is **non-owner -> `requires_key=False` plugin -> denied private-key/`export` recorder**. Also record that a `key_view` audit event is written on every call regardless of whether the key was actually read. Confirm at least one default-enabled plugin in the target build exposes `requires_key=False` before claiming a real-world path.

## 4. Test sub-CA minting against parent-authority roles

With `ADMIN_ONLY_AUTHORITY_CREATION=False`, create a user that holds no role on a chosen internal root authority but belongs to one role. Call `POST /api/1/authorities` with `type=subca` and that root as `parent`.

A bounded positive is **no-role-on-parent user -> sub-CA create -> denied `create_authority`/sign recorder that would load `parent.authority_certificate.private_key`**. Preserve the `ADMIN_ONLY_AUTHORITY_CREATION=False` precondition in the report; do not mint against a real root and do not present it as default-config exploitation where the flag is `True`.

## 5. Trace `replaces[]` to rotation deployment and notification state

On create or upload, supply a `replaces[]` referencing a certificate the caller has no role on. Instrument the `Certificate.replaces` SQLAlchemy append listener and the periodic `certificate_rotate` Celery task.

A bounded positive is **no-role user -> `replaces[]` on a victim cert -> victim `notify` set to `False` and rotation selects the attacker's certificate as the replacement** at a denied deployment sink. Do not deploy a substitute onto a live endpoint or Kubernetes secret; file the finding on the missing ownership check on `replaces[]` and the resulting rotation/notify state change.

## 6. Diff read vs write authorization on destination endpoints

Give a low-privilege (or read-only) principal a session and call `GET /api/1/destinations` and `GET /api/1/destinations/<id>`. Compare against the sibling `POST`/`PUT`/`DELETE` handlers, which are gated by `@admin_permission.require`.

A bounded positive is **non-admin principal -> destination read -> response body containing a cleartext `password` or `privateKeyPass` option** for the built-in SFTP destination. Capture only the option keys and a synthetic value you placed in a disposable destination; do not read or report real stored credentials.

## 7. Re-validate ACME URLs on every path that writes them

Confirm the target build has the create-time `_validate_acme_url()` allowlist. Then, as a member of an authority's role, call `PUT /api/1/authorities/<id>` with a modified `options.acme_url` and observe whether the allowlist is re-applied. For the revocation-check bypass, upload a certificate with attacker-controlled CRL/OCSP URLs that redirect to, or DNS-rebind to, an owned internal peer.

A bounded positive is either **authority member -> `PUT /authorities/<id>` -> stored `acme_url` outside the allowlist** or **guarded certificate -> CRL/OCSP fetch -> owned denied internal peer reached via redirect or re-resolution**. Use owned no-content peers and mocked ACME responses; never point `acme_url` or a revocation URL at a real IMDS, RFC1918, or production endpoint.

## Evidence and reporting checklist

- [ ] Exact Lemur release/build, enabled issuer and destination plugins, `ADMIN_ONLY_AUTHORITY_CREATION`, and `ACME_DIRECTORY_HOST_ALLOWLIST` are recorded.
- [ ] Each chain names the authenticated role and the specific permission primitive that was expected but not checked.
- [ ] Revocation evidence joins the row id to the CA-side certificate identity.
- [ ] Export evidence proves a `requires_key=False` plugin is present in the target build.
- [ ] Sub-CA evidence preserves the `ADMIN_ONLY_AUTHORITY_CREATION=False` precondition.
- [ ] Rotation evidence shows the `notify`/`replaced` state change without a live deployment.
- [ ] Destination evidence shows only option keys and a synthetic value, not real secrets.
- [ ] ACME and revocation-check SSRF evidence uses owned peers and stops at a denied connect.
- [ ] Every chain edge is reported separately unless one lab trace proves the entire sequence.
