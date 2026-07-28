---
title: MCP exposure and WordPress identity, object, and restore-state boundaries
---

# MCP exposure and WordPress identity, object, and restore-state boundaries

A July 28 GitHub advisory wave yields durable checks for five related trust failures: a cloud-control MCP listener exposed without a caller identity, OTP proof reused for a different account selector, password reset without account ownership, customer and integration objects addressed outside their owner scope, and publicly stored restore secrets accepted as authority for filesystem operations. Two adjacent WordPress records add useful route-side-effect and multi-request taint workflows.

Sources:

- [GHSA-fw7c-j2q8-f24m / CVE-2026-9680: Alibaba Cloud RDS OpenAPI MCP server exposure](https://github.com/advisories/GHSA-fw7c-j2q8-f24m)
- [Alibaba Cloud RDS OpenAPI MCP server repository](https://github.com/aliyun/alibabacloud-rds-openapi-mcp-server)
- [GHSA-6h5p-ffrw-w4fc / CVE-2026-15014: SMS Alert OTP proof reuse](https://github.com/advisories/GHSA-6h5p-ffrw-w4fc)
- [GHSA-h3v6-mwr7-vpq3 / CVE-2026-14545: TrueBooker password-reset ownership](https://github.com/advisories/GHSA-h3v6-mwr7-vpq3)
- [WPScan record for CVE-2026-14545](https://wpscan.com/vulnerability/c97d9841-2bd7-438b-a719-7943d671c754/)
- [GHSA-xch7-4rqw-9w56 / CVE-2026-14926: FluentCart subscription ownership](https://github.com/advisories/GHSA-xch7-4rqw-9w56)
- [GHSA-r4fx-q4j5-7gqg / CVE-2026-16587: Advanced Form Integration OAuth-token overwrite](https://github.com/advisories/GHSA-r4fx-q4j5-7gqg)
- [GHSA-8mj8-7gxm-p63p / CVE-2026-14490: Demi restore-state directory deletion](https://github.com/advisories/GHSA-8mj8-7gxm-p63p)
- [GHSA-4p37-mx5p-f6gr / CVE-2026-15012: Demi restore-state directory copy](https://github.com/advisories/GHSA-4p37-mx5p-f6gr)
- [GHSA-jc98-p7c8-r93j / CVE-2026-14924: Tablesome unauthenticated post writes](https://github.com/advisories/GHSA-jc98-p7c8-r93j)
- [GHSA-fw4m-pvcf-9q9c / CVE-2026-14516: Bookly two-request SQL taint chain](https://github.com/advisories/GHSA-fw4m-pvcf-9q9c)
- [GHSA-h976-4r88-23hx / CVE-2026-6251: Chaty query before nonce verification](https://github.com/advisories/GHSA-h976-4r88-23hx)

The GitHub records were unreviewed when this page was written. Confirm the exact package or plugin slug, affected version, enabled feature, route, and fixed-build behavior before reporting. The current RDS MCP repository defaults HTTP transports to `127.0.0.1`, requires a nonblank API key for non-loopback binding, and separately gates write-capable tool groups; treat those as controls to test, not proof about every previously published artifact.

!!! warning "Authorized, marker-only validation"
    Use disposable MCP credentials with no cloud permissions, isolated WordPress sites, synthetic low-role accounts, fake subscriptions and OAuth tokens, and temporary filesystem roots. Never invoke live RDS tools, collect cloud metadata, take over real accounts, change real payment methods, overwrite production integration credentials, delete application directories, or read customer posts, invoices, backups, or form submissions.

## Build one boundary matrix

| Surface | Attacker-controlled representation | Authority that must be server-derived | Safe positive proof |
| --- | --- | --- | --- |
| Network MCP | listener address, transport, request headers | authenticated caller plus enabled tool policy | inert `tools/list` or local canary tool only |
| OTP login | session verification flag and submitted phone | verified phone bound to one login transaction | synthetic subscriber A cannot select subscriber B |
| Password reset | account ID, email, username, or phone | single-use reset proof bound to one account | A's proof cannot change B's canary password |
| Subscription API | subscription identifier | authenticated customer's ownership of that subscription | A cannot change B's synthetic marker |
| Integration settings | callback parameters and replacement tokens | administrator capability plus integration instance | fake token remains unchanged for low-role user |
| Restore worker | public key/token files and signed state fields | server-private operation state plus confined root | marker-only outside-root request is rejected |
| AJAX/REST write | post/page identifier and content | authenticated capability plus object ownership | anonymous request cannot create or replace a marker post |
| Deferred query | first-request state and second-request trigger | typed, parameterized data at the eventual query sink | query structure remains constant in an instrumented lab |

For every row, capture anonymous, expected-role, low-role, malformed-proof, cross-owner, and fixed-build controls. Stop at the first harmless marker that proves the boundary.

## Cloud-control MCP: separate reachability, identity, and tool authority

CVE-2026-9680 describes an MCP endpoint listening on all interfaces by default and allowing remote callers to invoke tools. The useful operator workflow is not merely finding an open port: prove each edge from network reachability to MCP protocol access to the authority of the exposed tool set.

### Listener and protocol decision table

1. Use a disposable host with fake Alibaba Cloud environment values and no route to real cloud APIs.
2. Record the installed package version, resolved entry point, `SERVER_TRANSPORT`, `SERVER_HOST`, `SERVER_PORT`, `API_KEY`, `MCP_TOOLSETS`, and write-tool setting. Redact any token value.
3. Observe the actual bound address with the operating system rather than trusting startup text.
4. From loopback and one explicitly allowed lab peer, test the SSE and streamable-HTTP paths with missing, malformed, wrong-scheme, wrong-value, and valid fake bearer headers.
5. Request only MCP initialization and `tools/list`. Do not invoke an RDS read or write tool.
6. If invocation evidence is required, register or intercept one inert canary tool that increments a local counter and has no cloud client behind it.
7. Repeat with a non-loopback host and no API key. A safe current control should refuse startup; it should not silently expose a listener.
8. Repeat with a fake API key and a read-only tool group, then with the default group while write tools remain disabled.

Capture four distinct decisions:

```text
socket reachable -> MCP handshake accepted -> caller authenticated -> requested tool enabled
```

A positive historical result is **non-loopback listener + anonymous MCP handshake + inert tool call reaches its counter**. Do not infer cloud impact from `tools/list`; separately document which credentials were loaded and which tool would have been authorized, without using either against a live account.

Current-source controls worth using as negative fixtures include:

- loopback default `127.0.0.1`;
- startup refusal when a non-loopback address has no nonblank API key;
- exact bearer-authentication scheme parsing and constant-time key comparison;
- explicit enablement before write-capable tool groups are exposed remotely;
- disabled request-header credentials unless intentionally configured.

## Identity proofs: bind the proof to the selected principal

### OTP verification cannot be a session-wide Boolean

The SMS Alert record says a successful OTP sets a session flag, while a later registration request independently supplies `billing_phone`. If the flag is not bound to the verified phone and transaction, proof for attacker-controlled phone A can authorize login as account B.

1. Create synthetic subscribers A and B with distinct owned phone canaries; do not use an administrator target.
2. Start fresh sessions for each matrix row and complete OTP verification only for A.
3. Submit the normal continuation with A's phone, B's phone, an unknown phone, an omitted phone, and duplicated phone fields.
4. Record the verified subject, submitted selector, resolved WordPress user ID, and session user ID.
5. Replay after logout, expiry, a second OTP transaction, and a failed OTP attempt to test proof lifecycle.
6. Repeat on the fixed build and require the server to reject any selector other than the verified subject.

The decisive evidence is **OTP for A accepted -> same transaction selects B -> resulting session resolves to synthetic B**. Redact cookies and OTP values, invalidate both sessions, and do not demonstrate the administrator case.

### Password-reset proof needs the same binding

The TrueBooker record describes a front-end reset handler that accepts an account selector without proving ownership. Use a two-account matrix rather than resetting any privileged account:

1. Request a reset only for disposable subscriber A through an owned mailbox or instrumentation sink.
2. Preserve a hash or transaction ID in evidence, never the raw reset value.
3. Keep the proof fixed while changing account fields to A, B, nonexistent, omitted, duplicated, and case-normalized variants.
4. Attempt only a unique lab password on synthetic B and verify the result through a direct B login.
5. Test single use, expiry, prior password-change invalidation, and fixed-build controls.

Report **which proof was issued for which canonical user and which different user row changed**. A success message or email alone is insufficient.

## Object and integration ownership

### Subscription child actions

The FluentCart record says several payment-method endpoints accept a subscription ID without checking that it belongs to the requesting customer.

1. Create customers A and B with separate synthetic subscriptions and fake payment fixtures.
2. Authenticate as A and exercise each relevant method with A-owned, B-owned, random, and omitted IDs.
3. Prefer a mocked “change payment method” marker that cannot charge or contact a provider.
4. If cancellation must be tested, use a reversible local status on B's disposable subscription and restore it immediately.
5. Capture customer ID, subscription ID, ownership result, action, and final marker state.

The proof is **A's valid session + B's subscription identifier -> server mutates or rebinds B's synthetic object**. Do not use production payment providers or customer identifiers.

### Low-role integration-token substitution

The Advanced Form Integration record says code on `admin_init` accepts replacement MailUp OAuth values from any authenticated user who can reach a profile page. This is an authority mix-up between “logged into wp-admin” and “allowed to configure a site-wide integration.”

1. Configure a fake integration endpoint and inert token pair that can access no service.
2. Snapshot the option value as a hash and authenticate as a subscriber.
3. Submit omitted, malformed, attacker-controlled fake, and duplicate token fields through the reachable profile/admin path.
4. Trigger one synthetic form submission to the mocked integration and record which fake account receives the canary.
5. Restore the original fake option and repeat as administrator and on the fixed build.

A strong result is **subscriber request updates the canonical site-wide integration option -> later canary delivery follows the substituted fake token**. An echoed field or transient request value is not enough.

## Restore-state chains: possession of public state is not operator authority

The two Demi records form one reusable chain:

```text
administrator starts restore
  -> key and step token appear in a web-accessible uploads subdirectory
  -> unauthenticated handler accepts possession of those files as authority
  -> caller-controlled signed state selects copy/delete paths
  -> filesystem operation escapes its intended restore root
```

The active-restore precondition matters. Test disclosure, signature acceptance, path selection, and filesystem effect separately.

### Disposable canary workflow

1. Run the affected plugin in an isolated container with a temporary WordPress tree and a second temporary sibling directory.
2. Disable script execution in uploads. Populate both roots only with unique text markers.
3. Start a restore using a lab administrator and record the exact lifetime and HTTP visibility of `.restore_key` and `.restore_step_token`; do not place the values in the report.
4. From an anonymous session, test missing, random, expired, and captured lab-only state against a no-op or instrumented restore step.
5. Decode the state structure locally and identify fields that select operation, source, and destination. Do not publish a reusable forged envelope.
6. For the copy case, request movement of one synthetic marker between disposable roots and prove the final canonical paths and hashes.
7. For the delete case, instrument the deletion function or target an empty canary directory containing no application file. Stop after that directory alone is removed.
8. Repeat after restore completion, token rotation, logout, and on the fixed version.

The evidence must show every edge: **publicly retrievable lab secret -> accepted by unauthenticated route -> signed state controls a path -> canonical path is outside the intended restore root -> marker-only operation occurs**. Do not call this path traversal if only the state file is exposed, and do not call it unauthenticated if a valid administrator session is still required at the operation step.

## Adjacent route and query checks

### Tablesome unauthenticated post replacement

The Tablesome record says one AJAX action lacks authentication, capability, and nonce checks and can create published posts or overwrite existing content.

- Seed one unpublished synthetic post with a random marker.
- Send anonymous create and update requests for that marker only.
- Verify canonical author, status, post type, ID, and content through the database or owning lab account.
- Test random and foreign marker IDs without enumerating ranges.
- Stop after an inert text change; never inject script, shortcode, embed, or executable content.

The reportable boundary is **anonymous handler invocation -> canonical post row created or changed without capability enforcement**.

### Multi-request taint and checks after side effects

Bookly reportedly stores attacker-controlled `staff_ids` in one unauthenticated booking-session request and consumes it in a later render request at a query sink. Chaty reportedly executes its query before checking a nonce. Both are reminders to model time and order:

1. Instrument the database layer against a scratch schema; do not extract WordPress data.
2. Give each request a correlation ID and record where untrusted values are stored, transformed, and consumed.
3. For Bookly, compare clean-first/clean-second, tainted-first/clean-second, clean-first/tainted-second, and tainted-both sequences.
4. For Chaty, compare query count and query structure for missing, invalid, and valid nonce values.
5. Use harmless syntax markers or mocked query assertions rather than delay payloads or data extraction.
6. Require the fixed control to parameterize the eventual sink and perform authorization/nonce checks before any query side effect.

A rejected HTTP response does not prove safety if the database query already ran. Conversely, first-request state alone does not prove SQL injection unless the later sink changes query structure.

## Reporting checklist

Include:

- exact artifact/plugin slug, version, feature flags, route, transport, method, and authentication state;
- the complete trust chain, including stored state and later requests;
- canonical user, phone, customer, subscription, integration, post, and filesystem ownership;
- actual bind address, MCP handshake result, caller-auth result, and enabled tool set as separate facts;
- public-state lifetime, token rotation, lexical paths, canonical paths, and marker hashes;
- negative controls for malformed proof, cross-owner IDs, expired state, fixed builds, and reordered requests;
- marker-only results with cookies, OTPs, reset values, API keys, OAuth tokens, and restore secrets redacted;
- a bounded impact statement that separates reachability, authentication bypass, object authorization, state disclosure, filesystem effect, query execution, and code execution.

Do not collapse these findings into “RCE” or “account takeover” unless the reproduced edges support that exact claim. Anonymous MCP listing is not a cloud action; an OTP flag is not exploitable until it selects a different principal; a public restore key is not a filesystem escape until the signed operation crosses the canonical root; and a rejected request may still be vulnerable when its side effect happens first.
