---
title: ASUSTOR privileged IPC and WordPress object-authority boundaries
---

# ASUSTOR privileged IPC and WordPress object-authority boundaries

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-08-04. These were unreviewed database records at scan time; confirm exact product versions, routes, feature configuration, and corrected behavior from upstream before reporting.

This wave yields five durable operator checks:

1. a standard user's ability to recover a shared IPC key is not authority to issue filesystem operations as `SYSTEM`;
2. a public WordPress route must not spend a plugin's stored Dropbox authority without caller authorization;
3. upload safety must bind validated content, retained filename/extension, destination, and executable handling as one decision;
4. a download token must authorize the exact log object later selected; and
5. access to one subscription, RSVP, or template parameter must not authorize a different object used by the mutation sink.

Primary sources:

- ASUSTOR Backup Plan/EZSync privileged IPC [GHSA-2p27-7hcf-mpp3 / CVE-2026-18759](https://github.com/advisories/GHSA-2p27-7hcf-mpp3) and [ASUSTOR advisory AS-2026-007](https://www.asustor.com/security/security_advisory_detail?id=70);
- Easy Integration for Dropbox [GHSA-g948-x7cf-x6p5 / CVE-2026-15958](https://github.com/advisories/GHSA-g948-x7cf-x6p5);
- Improve SEO upload validation [GHSA-62v2-7mcm-qpm4 / CVE-2026-16618](https://github.com/advisories/GHSA-62v2-7mcm-qpm4);
- REST API Log token/object binding [GHSA-5v73-chf6-5qjj / CVE-2026-16547](https://github.com/advisories/GHSA-5v73-chf6-5qjj);
- Paid Membership Subscriptions object ownership [GHSA-8hc5-48cx-v7wp / CVE-2026-14848](https://github.com/advisories/GHSA-8hc5-48cx-v7wp), Brizy selector mismatch [GHSA-w3xr-4xq6-f7jx / CVE-2026-16070](https://github.com/advisories/GHSA-w3xr-4xq6-f7jx), and Wired Impact Volunteer Management RSVP ownership [GHSA-32f3-4hg9-xrh4 / CVE-2026-16546](https://github.com/advisories/GHSA-32f3-4hg9-xrh4); and
- Clearfy Cache alternate admin dispatcher [GHSA-rxcc-hfjf-j3mp / CVE-2026-16295](https://github.com/advisories/GHSA-rxcc-hfjf-j3mp).

!!! warning "Disposable identities, canary objects, and patched sinks only"
    Use isolated Windows VMs, disposable WordPress sites, fake Dropbox accounts, synthetic files, and two-user object fixtures. Never forge requests against an operational privileged service, read or overwrite host files, access a real Dropbox account, upload executable code, download live API logs, change paid memberships, remove real RSVPs, or retain administrative nonces.

## Boundary matrix

| Surface | Weak proof or selector | Authority that must be derived server-side | Bounded positive |
| --- | --- | --- | --- |
| ASUSTOR file IPC | encrypted request produced with a user-readable shared key | authenticated client identity, allowed operation, and canonical destination root | patched service recorder accepts a canary request from an ordinary lab user and resolves outside the approved temp root |
| Dropbox AJAX | public action plus path/object parameters | authenticated capability and configured-account object policy | anonymous request reaches a fake-provider recorder carrying the plugin's inert stored token |
| Improve SEO upload | accepted content type plus original filename | content, extension, destination, and non-executable serving policy | benign image-like bytes retain a dangerous-looking extension under a public executable mapping |
| REST API Log download | one valid token plus caller-selected log ID | token bound to one log entry and authorized principal | token for synthetic entry A selects marker-only entry B in a patched reader |
| Subscription/RSVP/template mutation | access to object or selector A | ownership and capability checked on exact sink object B | user A changes only a harmless marker on user B's synthetic object |
| Clearfy alternate dispatcher | authenticated access to a secondary route family | same capability policy as canonical admin page | subscriber reaches a marker-only admin view that canonical routing denies |

## 1. Separate IPC message authenticity from client and path authority

The ASUSTOR record concerns Backup Plan through 2.0.7.10171 and EZSync through 1.1.1.3113 on Windows. Their background service runs as `NT AUTHORITY\SYSTEM`. The file-based IPC uses AES, but the key file is readable by standard users and recoverable through DPAPI in that user's context. The service reportedly does not authenticate the requesting process, and its destination-path validation relies on an insufficient substring check. The critical chain is therefore **recoverable shared key -> forgeable message -> no client identity -> path escape -> privileged file sink**. Encryption by itself authenticates none of the missing policy decisions.

### Recorder-first lab workflow

1. Install the affected client in a disposable Windows VM with one administrator used only for setup and one ordinary local canary user. Create a random approved temp root, a sibling-prefix directory, and a second random outside directory.
2. Record the IPC location, service identity, ACLs on the IPC and key files, DPAPI scope, message operation, raw destination representation, normalization stages, canonical target, and final file API. Do not copy the key into report evidence.
3. Confirm separately whether the ordinary user can read the protected key material and invoke the same DPAPI recovery path. Preserve only ACL output and a one-way fingerprint of generated lab key material.
4. Patch or interpose the service's file-read and file-write sinks. The recorder must log the canonical target and then return a fixed canary result without opening, creating, truncating, or replacing that target.
5. Replay a normal in-root operation and inert path selectors covering dot segments, mixed separators, absolute syntax, sibling prefixes, replaceable parent components, final-component symlinks, and nonexistent targets. Do not target system directories, startup paths, credentials, or application configuration.
6. Compare an invalid key, valid key from the expected client, valid key from the ordinary user harness, malformed operation, allowed root, outside root, affected versions, and corrected versions.

The bounded positive is **ordinary lab user recovers only the disposable IPC key -> constructs a syntactically valid canary request -> `SYSTEM` service accepts it without client identity -> destination canonicalizes outside the random approved root -> patched file sink is reached -> fixed behavior rejects before the sink**. Do not perform an actual outside-root read/write or claim privilege escalation from key readability alone.

## 2. Detect public routes spending stored provider authority

Easy Integration for Dropbox before 2.2.0 reportedly registers several file-management AJAX actions for unauthenticated callers without authorization checks. The important authority is not the visitor's request; it is the plugin's stored Dropbox connection, which can list, download, or upload across the connected account.

1. Connect the affected plugin only to a throwaway provider account containing two folders and random text markers. Prefer a local fake Dropbox API that records requests and accepts only an inert fake bearer value.
2. Inventory every `wp_ajax_*` and `wp_ajax_nopriv_*` registration, callback, capability check, nonce check, selected provider account, path canonicalization, and provider method.
3. Exercise anonymous, subscriber, expected administrator, missing-proof, random-proof, and replayed-proof controls. Start with list metadata from the fake provider; do not retrieve file bodies.
4. For upload/download/delete/move methods, patch the provider client so it records the intended operation and object and refuses all mutation or content return.
5. Vary own synthetic folder, sibling folder, absolute/root selector, normalized equivalent, duplicate parameters, and a nonexistent object. Repeat on the fixed build.

A reportable result is **anonymous WordPress route -> no capability decision -> plugin attaches its stored fake provider credential -> recorder receives a list/read/write operation for a canary object**. Route reachability, an exposed administrator email, or an error response alone does not prove provider authority was spent.

## 3. Bind upload validation to the final served filename and handler

Improve SEO through 2.0.11 reportedly checks file content type but writes the upload with the caller-supplied extension into a public directory. Test the complete tuple rather than treating MIME validation as an isolated control.

1. Use a disposable site whose upload directory is mapped to a harmless static recorder, not a PHP interpreter.
2. Submit benign GIF-like or plain marker bytes under safe and dangerous-looking extensions. Do not upload PHP, script, polyglot, shell, or server-configuration content.
3. Record browser filename, multipart content type, detector-derived type, retained basename/extension, canonical destination, web URL, response headers, and the handler that the test web server would choose.
4. Compare extension case, trailing dots/spaces, multiple extensions, normalization-equivalent names, omitted names, mismatched declared/detected types, and a fixed build.
5. If handler impact must be shown, use a test-server routing recorder that returns `would-map-to-php` without invoking an interpreter.

The safe positive is **unauthenticated benign bytes pass content-only validation -> attacker-controlled dangerous-looking extension is retained -> file lands under a public path -> routing recorder selects an executable handler -> fixed build rejects or renames outside executable mappings**. A successful upload with a server-generated extension is not code execution.

## 4. Swap a capability token across synthetic objects

REST API Log before 1.7.1 reportedly accepts a download token without binding it to the selected log entry or checking caller capability. This is a two-selector test: prove access to A, then change only the object selector to B.

1. Seed entries A and B with marker-only request/response text. Never enable logging for credentials, cookies, authorization headers, customer content, or production API traffic.
2. Obtain A's token through the normal authorized UI. Hash it in retained evidence and use it only inside the disposable site.
3. Replay the download with token A and object A, object B, nonexistent object, another user's object if the plugin tracks ownership, omitted/duplicate IDs, random token, expired token, and fixed-build controls.
4. Patch the final log reader/exporter to record token subject, selected ID, canonical database object, acting principal, and authorization result, then return a fixed marker instead of a log body.

The bounded positive is **valid token for synthetic A -> caller changes only log ID -> patched reader selects synthetic B without capability or token-object binding**. Do not collect a real log merely because the route permits it.

## 5. Recompute authorization on the exact mutation object

Three records share one test shape:

- Paid Membership Subscriptions before 3.0.8 lets a subscriber select another member's subscription during change checkout;
- Brizy before 2.8.19 reportedly validates a request parameter different from the template object whose type metadata is updated; and
- Wired Impact Volunteer Management before 2.8.2 reportedly removes an RSVP without proving it belongs to the requester.

Build a two-user, two-object matrix. User A owns object A; user B owns object B. Preserve parent IDs, child IDs, request parameters checked by authorization code, object loaded by the sink, canonical owner, and before/after marker state.

1. Capture one normal same-owner mutation and replay it with only the sink selector changed to B.
2. Test valid parent/foreign child, foreign parent/valid child, mismatched checked and written template IDs, duplicate parameters, nonexistent IDs, stale objects, anonymous, subscriber/contributor as applicable, expected role, and fixed build.
3. Change only reversible markers: a non-billable synthetic plan label/status, harmless template-type canary, or disposable RSVP. Patch mail, payment, publication, cache, and webhook side effects to no-op counters.
4. Verify final state through user B's expected view or a privileged lab recorder, then restore the fixture.

The positive is **user A holds valid workflow proof -> authorization checks A or an unrelated selector -> sink loads B -> B's marker changes -> fixed build rejects before mutation**. Keep membership ownership, billing/payment impact, content publication, and RSVP deletion as separate claims.

## 6. Compare canonical and alternate admin dispatchers

Clearfy Cache before 2.4.3 reportedly lets subscribers render admin-only settings through an alternate dispatch path while the canonical page correctly denies access. Treat this as route-family authorization drift, not proof that every surfaced nonce permits a mutation.

Create one marker-only settings page with no secrets or real integration values. Compare canonical URL, alternate dispatcher, direct callback invocation where the framework permits it, missing/duplicate page selectors, subscriber, administrator, logged-out caller, and fixed build. Record route normalization, callback identity, capability checks, rendered sections, and whether mutating handlers independently re-check capability.

A bounded positive is **same subscriber and page selector -> canonical admin route denies -> alternate dispatcher reaches marker-only privileged renderer -> fixed build applies the canonical capability check**. If a nonce appears, retain only its action name and a hash; do not replay it against state-changing actions unless a separately authorized canary test proves those handlers also omit capability checks.

## Reporting checklist

- [ ] ASUSTOR evidence separates key readability, DPAPI recovery, client identity, path confinement, and privileged file-sink reachability.
- [ ] Provider evidence uses a fake account/token and proves the exact method/object received by a recorder.
- [ ] Upload evidence records detected type, retained extension, canonical destination, and handler mapping without executable content.
- [ ] Token evidence proves A-to-B selector substitution using marker-only log entries.
- [ ] Object evidence identifies the parameter checked and the canonical object mutated for each role.
- [ ] Alternate-route evidence distinguishes privileged page rendering from authority to execute a state-changing action.
- [ ] No host files, live logs, production cloud objects, executable uploads, paid memberships, real RSVPs, secrets, or raw nonces appear in evidence.
