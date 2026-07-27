---
title: WordPress identity, token, route, and file-write boundaries from July 27 GHSA updates
---

# WordPress identity, token, route, and file-write boundaries from July 27 GHSA updates

A July 27 GitHub advisory wave yields six reusable WordPress operator checks: webhook proof that always succeeds, bootstrap routes that trust a named account, client-selected registration roles, portable download tokens, REST permission callbacks that are present but not invoked, and request handlers protected by an empty default key. Two adjacent records add useful cross-product controls for project-object IDOR and administrator-selected redirect URLs.

Sources:

- [GHSA-p6m4-vx92-q2pc / CVE-2026-13597: WeChat login webhook proof and code disclosure](https://github.com/advisories/GHSA-p6m4-vx92-q2pc)
- [WPScan record for CVE-2026-13597](https://wpscan.com/vulnerability/5e856219-ece5-4d79-8375-fc0cbdc37d6c)
- [GHSA-4ph4-5rpm-wrw9 / CVE-2026-12255: MainWP Child registration identity](https://github.com/advisories/GHSA-4ph4-5rpm-wrw9)
- [WPScan record for CVE-2026-12255](https://wpscan.com/vulnerability/6ecd37bf-f48a-4f7f-8a93-e7f0475371af)
- [GHSA-2qr9-rw6c-j2jw / CVE-2026-12394: MemberGlut client-selected role](https://github.com/advisories/GHSA-2qr9-rw6c-j2jw)
- [WPScan record for CVE-2026-12394](https://wpscan.com/vulnerability/6b126a3e-30d5-4bed-ba47-33e589ec2852)
- [GHSA-4m9m-6fj5-4v23 / CVE-2026-14235: Download Manager portable tokens](https://github.com/advisories/GHSA-4m9m-6fj5-4v23)
- [WPScan record for CVE-2026-14235](https://wpscan.com/vulnerability/9634b51c-59a1-45f6-8b09-421d6bfd0204)
- [GHSA-5h5h-jh94-gqhv / CVE-2026-9830: BookingPress REST permission callback](https://github.com/advisories/GHSA-5h5h-jh94-gqhv)
- [WPScan record for CVE-2026-9830](https://wpscan.com/vulnerability/5fded411-52fd-4dc5-9a23-b77fcd9cfed2)
- [GHSA-93f6-w8m2-gcpx / CVE-2026-14289: FacturaONE empty-key file-write boundary](https://github.com/advisories/GHSA-93f6-w8m2-gcpx)
- [WPScan record for CVE-2026-14289](https://wpscan.com/vulnerability/f08365f6-57d2-475a-82c8-c4d27286569e)
- [GHSA-p3jw-q4jg-x8w9 / CVE-2026-66412: Leantime milestone IDOR](https://github.com/advisories/GHSA-p3jw-q4jg-x8w9)
- [Primary Leantime advisory GHSA-wv69-xr82-phr6](https://github.com/Leantime/leantime/security/advisories/GHSA-wv69-xr82-phr6)
- [Leantime authorization fix](https://github.com/Leantime/leantime/commit/68898eeb914882a21797523f2782914795bc67ae)
- [GHSA-66xh-mw5m-g493 / CVE-2026-14236: checkout return URL host validation](https://github.com/advisories/GHSA-66xh-mw5m-g493)
- [WPScan record for CVE-2026-14236](https://wpscan.com/vulnerability/b53cc13d-c59e-4c11-aa71-fa1c38c2a34d)

The GitHub records are unreviewed. Confirm the exact plugin slug, version, route, and fixed-build behavior from the linked primary record before reporting. A package name alone is not reachability evidence.

!!! warning "Authorized validation only"
    Use disposable WordPress sites, synthetic users, fake webhook identities, marker-only packages, non-executable text files, fake payment sessions, and two-project Leantime fixtures. Never log in as a real administrator, download protected customer files, alter real bookings, upload executable content, reuse payment links, or enumerate another tenant's objects.

## Build a boundary matrix first

Record the complete decision path rather than labeling every result “missing authorization.”

| Surface | Attacker-controlled input | Authority the server should derive | Safe proof |
| --- | --- | --- | --- |
| Identity webhook | signature fields, username, event body | verified provider event bound to one login transaction | disposable subscriber session only |
| Site registration | named login or account identifier | authenticated controller and explicit account binding | synthetic low-role account session |
| Front-end signup | submitted role/capability field | server-owned registration policy | role readback on a disposable account |
| Protected download | temporary key | session, package grant, use count, expiry | marker text package |
| REST namespace | route and object identifiers | invoked permission callback plus object scope | synthetic booking marker |
| Integration handler | request key and output filename | non-empty configured secret plus confined artifact path | `.txt` marker in a lab upload directory |
| Project object | integer milestone ID | project membership for the parent object | two-project marker title |
| Checkout return | success/cancel URL | server-owned or allowlisted origin | owned landing origins only |

For each row, capture anonymous, low-role, expected-role, malformed-proof, and fixed-build controls. Stop after the minimum marker that proves the crossed boundary.

## Login webhook: separate event authenticity from code secrecy

The WeChat-login record describes a chain, not one isolated check: the webhook signature decision always succeeds, the response exposes the generated login code, and an unauthenticated AJAX route redeems that code. Test each edge separately.

### Marker-only replay

1. Install the affected plugin version on a disposable site with one synthetic **subscriber** account; do not create an administrator target.
2. Capture one legitimate owned-account webhook exchange and identify the fields consumed by signature verification, code generation, and redemption.
3. Replay the same request with a corrupted signature, missing signature, changed body, and changed synthetic username.
4. Record the signature-verification result and whether a login code appears in the response. Redact the code from retained evidence and invalidate it after the run.
5. Redeem only a code generated for the disposable subscriber and verify the resulting account ID and role through a harmless profile endpoint.
6. Add negative controls for a random code, a previously redeemed code, and an expired transaction.
7. Repeat on the fixed version when available.

The decisive evidence is **invalid provider proof accepted -> server generates and discloses a login credential -> unauthenticated redemption yields the named disposable account**. Do not escalate the synthetic user or demonstrate the administrator case.

Generalize this workflow to OAuth callbacks, chat-bot webhooks, magic links, QR login, device pairing, and SSO bridges. A cryptographic check that executes but returns success on malformed input is an authentication bypass, while code disclosure and unbound redemption are separate impact multipliers.

## Bootstrap and registration routes: bind identity and role server-side

Two records expose related account-creation mistakes:

- MainWP Child reportedly accepts a site-registration request naming an existing account when password authentication is disabled, then creates a session without proving the requester controls that account.
- MemberGlut reportedly accepts a front-end registration role chosen by the client, including privileged roles.

### Identity and role matrix

1. Create a disposable administrator only for lab setup plus separate subscriber and editor canaries.
2. For the bootstrap route, test nonexistent, subscriber, editor, and disabled-password account names while varying controller proof independently.
3. Capture whether the route creates a new relationship, updates an existing relationship, or mints a WordPress session.
4. Stop if an unauthenticated request obtains the disposable subscriber session; do not target the administrator fixture.
5. For front-end signup, intercept the normal request and inventory role-like fields in form, JSON, nested metadata, and duplicate parameters.
6. Submit omitted, expected subscriber, unknown, editor, and administrator-looking values, but configure the lab to map every unexpected privileged request to a harmless canary role if instrumentation permits.
7. Read back the created user's canonical capabilities. UI labels alone are insufficient.
8. Repeat with fixed builds and confirm that identity comes from authenticated controller state and role comes from server policy.

Report **which client field influenced which canonical account/capability row**. Do not claim full site compromise from a reflected role label or a session that is not accepted by privileged routes.

## Portable download tokens: test the full bearer lifecycle

The Download Manager record says a temporary key is not bound to the requesting session, does not expire promptly, and remains reusable. Treat session binding, resource binding, expiry, and use count as independent dimensions.

### Two-session token matrix

1. Publish a protected package containing only a unique text marker.
2. Obtain one key as disposable user A and record its issue time, package ID, and grant context without storing the raw key in the report.
3. Replay it in A's original session, a fresh browser with no cookies, user B's session, and after A logs out.
4. Replay it against a second marker package to test resource binding.
5. Perform a small, fixed number of repeats and bounded time checks to test single-use and expiry behavior.
6. Change or revoke the package grant and repeat once.
7. Compare the affected and fixed versions using a decision table.

A positive result is **key issued under A's grant -> copied to an unrelated session -> protected marker returned repeatedly or after expected revocation/expiry**. Do not brute-force keys or retrieve real packages.

## REST permission callbacks: test invocation, not declaration

The BookingPress record says routes declare a permission callback but fail to invoke it, leaving a namespace anonymously reachable for booking reads and writes. Static presence of a callback is therefore not proof of enforcement.

### Namespace route/role matrix

1. Seed two synthetic customers and bookings with unique non-sensitive markers.
2. Enumerate registered routes, HTTP methods, callback names, and object identifiers from the lab instance or source tree.
3. Instrument the permission callback with a counter or log marker that records invocation without exposing secrets.
4. Exercise each route as anonymous, customer A, customer B, staff, and administrator.
5. Start with list/status operations; if a write is reachable, modify one reversible marker on A's disposable booking only.
6. Verify the result through the owning synthetic account and restore the marker.
7. Repeat on the fixed version and preserve both the callback counter and final authorization decision.

The proof is **route matched -> handler executed while permission callback invocation count remained zero (or its result was ignored) -> synthetic object crossed the expected role/owner boundary**. Avoid reading customer fields or changing another user's real appointment.

## Empty integration keys and web-accessible file writes

The FacturaONE record describes an unauthenticated handler whose key is empty in the default unconfigured state and which can write an arbitrary file into a web-accessible directory. Separate three claims: default-state authentication, filename/path control, and executable interpretation by the web server.

### Non-executable write proof

1. Use a disposable WordPress container with the plugin installed but unconfigured and with script execution disabled in the target upload directory.
2. Record the stored/default key state and send omitted, empty, random, and configured fake-key controls.
3. Request creation of only a uniquely named `.txt` marker through the handler; do not send PHP, shell syntax, polyglots, or server configuration files.
4. Record the resolved filesystem path and fetch the marker over HTTP if the route exposes it.
5. Test basename, nested relative path, absolute-looking path, duplicate separator, and encoded-separator names only against a temporary confined root; stop on the first outside-root indication.
6. Configure a non-empty fake key and repeat the authentication matrix.
7. Compare with the fixed version.

A safe positive result is **default empty key -> unauthenticated handler accepted -> inert marker written to a web-addressable location**. This proves a dangerous file-write boundary without uploading or executing code. Claim RCE only if the affected deployment's interpreter mapping is independently established; do not demonstrate execution.

## Adjacent controls: parent-scope IDOR and return-origin trust

### Leantime milestone IDs

The Leantime record says `tickets.getMilestone` accepts integer milestone IDs without checking that the requester belongs to the milestone's project.

1. Create projects A and B, assign user A only to project A, and seed one marker milestone per project.
2. Call the JSON-RPC method with missing, random, A-owned, and B-owned IDs as user A.
3. Capture the authenticated user, requested milestone, parent project, membership result, and response marker.
4. Stop after B's synthetic title or ID is returned; do not enumerate ranges or collect descriptions/timelines.
5. Repeat against the linked authorization fix.

The evidence is **valid low-role session + foreign milestone ID -> child object returned without parent-project membership**. Integer predictability strengthens discoverability but is not required to prove missing parent scope.

### Checkout return URLs

The checkout record says a request-supplied URL controls Stripe success and cancel destinations without host validation. Test parser and flow binding without involving real payments.

1. Use Stripe test mode and two owned HTTPS origins: approved and canary-external.
2. Capture normal success/cancel parameters and identify whether the application, Stripe session, or browser performs the final redirect.
3. Test absolute URLs, scheme-relative URLs, userinfo, mixed case, trailing dot, encoded host separators, and backslash forms.
4. Record the submitted value, server-normalized value, payment-provider value, and final browser destination.
5. Do not complete a charge; use a test cancellation or mocked provider callback.

A valid result is **unauthenticated request fixes an external return origin into a checkout session -> browser reaches the owned external canary after the expected flow step**. Distinguish an open redirect from token leakage or payment-state confusion; do not claim those impacts unless sensitive material actually crosses origins in the lab.

## Reporting checklist

Include:

- exact plugin/product slug, version, configuration state, route, method, and authentication mode;
- the complete proof chain and the first attacker-controlled representation mistaken for authority;
- user IDs, canonical roles/capabilities, package and object ownership, callback invocation counters, and resolved file paths;
- negative controls for invalid proofs, unrelated sessions, foreign resources, configured keys, and patched versions;
- marker-only evidence with raw tokens, cookies, payment identifiers, and webhook secrets redacted;
- a bounded impact statement that separates authentication bypass, authorization drift, token portability, file write, redirect, and execution.

Do not combine independent weaknesses into an exploit chain unless every edge is reproduced. A missing callback does not prove every namespace method is dangerous; a web-accessible text write does not itself prove code execution; a portable token does not imply token guessing; and a return URL does not imply payment or credential theft.