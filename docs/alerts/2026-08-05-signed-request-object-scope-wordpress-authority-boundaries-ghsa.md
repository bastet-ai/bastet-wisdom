---
title: Signed-request, object-scope, and WordPress authority boundaries
---

# Signed-request, object-scope, and WordPress authority boundaries

Seven August 5 records expose three reusable attack paths: a valid signature can authorize different semantics than the signer intended, a role check can remain detached from the target object, and a publicly obtainable nonce can be mistaken for permission to spend application-wide authority.

Primary project and vendor sources:

- OpenStack Swift S3API copy-source and native control-header issues [OSSA-2026-030](https://security.openstack.org/ossa/OSSA-2026-030.html), covering [CVE-2026-71191](https://nvd.nist.gov/vuln/detail/CVE-2026-71191) and [CVE-2026-71192](https://nvd.nist.gov/vuln/detail/CVE-2026-71192);
- OpenStack Neutron cross-project subnet onboarding [OSSA-2026-032](https://security.openstack.org/ossa/OSSA-2026-032.html) and [CVE-2026-55707](https://nvd.nist.gov/vuln/detail/CVE-2026-55707);
- Kadence Memberships legacy reset-link construction [CVE-2026-9273](https://nvd.nist.gov/vuln/detail/CVE-2026-9273) and the [4.0.0-to-4.0.1 source diff](https://plugins.trac.wordpress.org/changeset?new=3549742%40restrict-content%2Ftags%2F4.0.1&old=3529319%40restrict-content%2Ftags%2F4.0.0);
- Cost Calculator Builder export authorization [CVE-2026-7753](https://nvd.nist.gov/vuln/detail/CVE-2026-7753) and its [source correction](https://plugins.trac.wordpress.org/changeset?new=3531960%40cost-calculator-builder%2Ftrunk&old=3528688%40cost-calculator-builder%2Ftrunk);
- Dokan customer-route target authorization [CVE-2026-8761](https://nvd.nist.gov/vuln/detail/CVE-2026-8761) and the [5.0.2-to-5.0.3 source diff](https://plugins.trac.wordpress.org/changeset?new=3541712%40dokan-lite%2Ftags%2F5.0.3&old=3535602%40dokan-lite%2Ftags%2F5.0.2); and
- Smart Popup permission-map, nonce, and role-selection chain [CVE-2026-18322](https://nvd.nist.gov/vuln/detail/CVE-2026-18322) and its [role-validation source diff](https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&new=3629986%40popup-by-supsystic%2Ftrunk%2Fmodules%2Fsubscribe%2Fmodels%2Fsubscribe.php&old=3628131%40popup-by-supsystic%2Ftrunk%2Fmodules%2Fsubscribe%2Fmodels%2Fsubscribe.php&sfp_email=&sfph_mail=).

The adjacent GitHub Advisory API entries were unreviewed mirrors when this page was written. Use them as discovery seeds, then confirm the product revision and behavior against the linked primary sources. Do not infer additional affected versions from this page.

!!! warning "Synthetic objects, no-op sinks, and disposable accounts only"
    Run these checks only in an owned lab or explicitly authorized customer environment. Use random object bodies, fake provider secrets, disposable users, a local mail sink, and patched mutation handlers. Never read another tenant's real objects, export production credentials, change a real administrator password, create a privileged production account, or alter operational network routing.

## 1. Bind signed fields to the semantics actually executed

Swift's S3 compatibility layer is a useful general fixture for testing signature-to-operation binding. Instrument the S3API authorization decision, normalized request headers, downstream Swift request, source-object authorization, and final copy/read sink separately.

Create two synthetic projects with random bucket, container, and object names:

- project A owns a source object containing only `SRC-<uuid>`;
- project B owns an empty destination bucket; and
- neither project grants the other read access.

Test both configuration branches because they cross different boundaries:

| S3API mode | Authorized artifact | Mutation to test | Required secure result |
| --- | --- | --- | --- |
| default `s3_acl=false` | presigned PUT URL for B's destination | add or change unsigned `X-Amz-Copy-Source` semantics | reject, or require the semantic header to be signature-covered and source-authorized |
| non-default `s3_acl=true` | signed PUT for B's destination | inject Swift-native `X-Copy-From` and `X-Copy-From-Account` controls | strip/reject native controls before downstream dispatch |

Include negative and positive controls: an unmodified destination PUT, a correctly signed copy from B's own source, an unknown header that has no copy semantics, and a copy whose source does not exist. Preserve the canonical request, signed-header list, normalized header map, S3-to-Swift translation, source principal, and no-op copy decision.

A bounded positive is **valid destination authorization -> attacker-added or attacker-selected copy semantics survive normalization -> source authorization is skipped or evaluated as the signer/destination context -> patched sink identifies A's synthetic source object**. Stop before returning the object body. A valid signature alone is not evidence of source-object access, and a copy error is not evidence of disclosure.

Generalize the matrix to every signed-request integration under test: presigned uploads, cloud-storage gateways, webhook signatures, payment callbacks, and CDN origin requests. Inventory fields that affect the final operation but are absent from the MAC/signature input, plus framework-native headers that the compatibility layer should never forward.

## 2. Re-resolve authorization against the target object

The Neutron and Dokan records share the same failure shape: middleware establishes that the caller has *some* valid role, but the handler does not bind that role to the object selected later.

Build two-principal fixtures and patch mutations to append-only event recorders:

| Product surface | Caller fixture | Foreign target | No-op sink to instrument |
| --- | --- | --- | --- |
| Neutron subnetpool onboarding | ordinary member of project B | synthetic subnet on A's shared network | subnet onboarding/state transition and resulting address-scope route plan |
| Dokan `/dokan/v1/customers/{id}` family | vendor/seller B | disposable administrator A | customer read projection, update, password setter, and delete handler |

For each route, capture the caller project/user, route-level permission, resolved target ID, target owner/role, object-level policy result, and whether the sink was reached. Exercise list, read, create/onboard, update, and delete siblings; alternate route namespaces frequently copy an upstream controller while replacing its stronger capability check.

The strongest bounded evidence is:

- **project B role accepted -> A-owned subnet resolves -> no-op onboarding sink records the foreign subnet ID**; or
- **vendor B role accepted -> administrator A resolves -> no-op password/update/delete sink records A's ID**.

Do not onboard the subnet, change routing, return customer fields, set a password, or delete an account. Demonstrate the intended same-owner operation as a positive control and an unrelated admin-only route as a negative control. Report an object-authorization bypass only when the foreign object reaches a sink that the same-owner control proves is functional.

## 3. Treat nonces as request-integrity inputs, not capabilities

The WordPress records show why nonce availability and authorization must be measured independently. Map each token's issuance audience, action binding, lifetime, and every handler that accepts it.

Use subscriber, vendor, and administrator fixtures plus a local mail recorder. Build this matrix:

| Token source | Handler or sink | Authorization decision that must remain independent |
| --- | --- | --- |
| public login shortcode | legacy lost-password handler | reset request may be public, but callback origin must be server-controlled |
| subscriber-accessible `wp-admin` header | calculator export AJAX action | capability to export all calculator configuration |
| subscription confirmation email | public popup save action | capability to change popup/subscription configuration |
| same confirmation flow | user creation and requested role | server-side allowlist for account creation and assignable role |

Patch mail generation, export serialization, option persistence, and user creation. Use only random fake provider fields such as `FAKE-STRIPE-<uuid>` and an owned callback hostname.

### Reset-link origin binding

Submit an owned-account reset request while varying the redirect/callback input across same-origin, relative, owned cross-origin, protocol-relative, encoded, and backslash-normalized forms. The mail recorder should retain only the parsed scheme/host/path and a hash of the reset key. A bounded positive is **publicly obtainable nonce -> attacker-selected host survives into the generated reset URL -> mail sink records that host with the canary account's key hash**. Do not click, capture, or replay a real reset key, and do not request resets for other users.

### Export and configuration authority

A token exposed to subscribers proves only that the request came from a page/session that could obtain that token. It does not grant export or configuration rights. Demonstrate **low-role token accepted -> missing capability decision -> no-op serializer or option-write sink reached**. For exports, record only synthetic field names and value hashes; never serialize live API keys, webhook secrets, customer records, or payment configuration.

### Role-selection chains

For account-creation flows, enumerate candidate role values from the lab's configured role map, but replace `wp_insert_user` and role assignment with a recorder. A meaningful chain requires all edges: **public token acquired -> configuration save accepted without privilege -> attacker-selected role persists in the no-op store -> confirmation path reaches the patched user/role sink**. Do not create an account. Distinguish the permission-map collision, token exposure, missing save authorization, and missing role allowlist in the report so each precondition is independently reproducible.

## 4. Audit copied and alternate route families

When a plugin or compatibility layer wraps an upstream API, diff these controls rather than trusting route names:

1. authentication middleware;
2. route-level capability callback;
3. object resolver and ownership predicate;
4. accepted field/schema allowlist;
5. nonce or signature input construction;
6. downstream principal/credential context; and
7. final read, write, copy, export, or role-assignment sink.

Replay the same decision table against versioned routes, legacy handlers, AJAX and REST twins, public confirmation endpoints, and compatibility namespaces. The core question is not whether the request was authenticated or signed; it is whether the exact caller, exact target, exact semantics, and exact sink were bound by one enforceable authorization decision.

## Reporting boundaries

- Do not report cross-tenant Swift disclosure unless the foreign synthetic source reaches the patched copy/read sink; never retrieve another tenant's content.
- Do not claim routing impact from route acceptance alone. Record the denied final mutation and a synthetic route-plan differential.
- A WordPress nonce is not an authorization bypass by itself. Show the missing capability/object/role decision and reached no-op sink.
- A reset email sent to an owned inbox is not account takeover unless its key-bearing URL uses the attacker-selected authority; stop before key replay.
- Record exact product revisions, configuration branches, route namespaces, and primary-source evidence. Label the GitHub mirrors as unreviewed discovery records.
