---
title: Koollab LMS and WordPress identity, workflow, and callback boundaries
---

# Koollab LMS and WordPress identity, workflow, and callback boundaries

A July 29 advisory wave yields reusable application-testing workflows across an LMS and several WordPress extensions. The durable pattern is to test whether **object identifiers, SCORM state, second-factor proof, upload metadata, cloud fetch selectors, callback authenticity, and PHP callback names remain bound to the principal, object, and operation the server originally approved**.

Sources:

- [Singapore CSA alert AL-2026-094: Koollab LMS advisory cluster](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-094)
- [GHSA-2g2j-fq65-5w72 / CVE-2026-63238: Koollab user-UUID 2FA bypass](https://github.com/advisories/GHSA-2g2j-fq65-5w72)
- [GHSA-8j44-5653-q846 / CVE-2026-63237: Koollab client-selected TOTP seed](https://github.com/advisories/GHSA-8j44-5653-q846)
- [GHSA-q46f-qpmx-9862 / CVE-2026-63236: public SCORM state access](https://github.com/advisories/GHSA-q46f-qpmx-9862)
- [GHSA-qqq4-m483-fm7p / CVE-2026-63242: learner-controlled lesson completion](https://github.com/advisories/GHSA-qqq4-m483-fm7p)
- [GHSA-9ch9-66pf-cjcf / CVE-2026-63240: quiz-answer disclosure](https://github.com/advisories/GHSA-9ch9-66pf-cjcf)
- [GHSA-pv86-vg4j-hq7j](https://github.com/advisories/GHSA-pv86-vg4j-hq7j), [GHSA-x5f8-9c9r-5w63](https://github.com/advisories/GHSA-x5f8-9c9r-5w63), and [GHSA-4q7v-f574-m5cv](https://github.com/advisories/GHSA-4q7v-f574-m5cv): Koollab SQL-to-deserialization chains
- [GHSA-8g2m-jvpm-fx9f](https://github.com/advisories/GHSA-8g2m-jvpm-fx9f), [GHSA-7j7j-vvxx-737q](https://github.com/advisories/GHSA-7j7j-vvxx-737q), and [GHSA-7q3f-f53f-7cpq](https://github.com/advisories/GHSA-7q3f-f53f-7cpq): Koollab SQL-oracle surfaces
- [GHSA-m7jm-8gh3-3rp4 / CVE-2026-63227: Koollab SCORM upload](https://github.com/advisories/GHSA-m7jm-8gh3-3rp4)
- [GHSA-hqv9-x7qp-69hr / CVE-2026-14224: Easy Appointments cross-booking update](https://github.com/advisories/GHSA-hqv9-x7qp-69hr)
- [GHSA-6xgh-57mv-pxm7 / CVE-2026-14300: miniOrange email-code account confusion](https://github.com/advisories/GHSA-6xgh-57mv-pxm7)
- [GHSA-gpf8-hm73-g5qv / CVE-2026-13690: UsersWP second-factor provider confusion](https://github.com/advisories/GHSA-gpf8-hm73-g5qv)
- [GHSA-fj8r-hgww-qgmw / CVE-2026-11974: WP Media Folder Addon incomplete cloud-handler fix](https://github.com/advisories/GHSA-fj8r-hgww-qgmw)
- [GHSA-fvvp-v9c4-343h / CVE-2026-13423: Streamit public PHP callback dispatch](https://github.com/advisories/GHSA-fvvp-v9c4-343h)
- [GHSA-hmc6-h7gx-qx8g / CVE-2026-13692: PayU CommercePro unsigned order modification](https://github.com/advisories/GHSA-hmc6-h7gx-qx8g)
- [GHSA-6f8f-g768-8537 / CVE-2026-9720: Facturación Electrónica Costa Rica settings CSRF](https://github.com/advisories/GHSA-6f8f-g768-8537)

These GitHub records were unreviewed when this page was written. Confirm the exact product, affected version, feature state, route, and fixed behavior before reporting. The Koollab primary alert is concise and does not publish endpoint-level request schemas; treat the GitHub descriptions as leads and derive request shapes only from an authorized lab or customer-provided traffic.

!!! warning "Authorized validation only"
    Use disposable LMS tenants and WordPress sites, synthetic users/courses/appointments/orders, Stripe or gateway test mode, owned callbacks, fake cloud credentials, and inert marker files. Never extract a production database, reuse real JWTs or OTPs, upload a webshell, read local secrets, query internal services, modify customer bookings or orders, call dangerous PHP functions, or send CSRF links to real administrators.

## Build a decision matrix before replay

| Surface | Client-controlled value | Server authority that must remain bound | Safe proof |
| --- | --- | --- | --- |
| LMS 2FA | user UUID, TOTP seed, one-time code | authenticated first-factor transaction, enrolled secret, target account | two synthetic users and a no-session identity endpoint |
| SCORM state | user/course/lesson IDs and completion fields | current learner, assigned course, server-derived progress transition | marker lesson and before/after state |
| Assessment result | course/status selector | current learner and assessment lifecycle | synthetic wrong-answer fixture |
| SQL/deserialization chain | endpoint fields and serialized intermediate value | parameterized query plus typed server-owned state | seeded canary row and instrumented deserializer/file sink |
| SCORM archive | package entries, MIME, extension, extraction paths | designer role, allowed package type, non-executable destination | inert manifest and static marker only |
| Booking update | appointment ID and customer fields | current user owns the target appointment | two-user booking markers |
| Email/2FA proof | email, account ID, provider, code | proof issued for the same account and method | synthetic code/account matrix |
| Cloud handler | object/file selector and URL | configured provider, approved object namespace and destination | owned HTTP callback and synthetic local file |
| PHP dispatcher | function name and argument array | server-side callback allowlist and capability | instrumented harmless callback counter |
| Payment callback | order ID, totals, shipping, metadata, signature | verified provider message bound to one order and merchant | two test orders and mocked signatures |
| Global settings | CSRF token/nonce and configuration fields | administrator capability plus action-bound nonce | reversible text-only option marker |

A status code is not enough. Capture the canonical principal, target object, state transition, and sink reached. Keep object authorization, proof validation, persistent mutation, file placement, and later execution as separate conclusions.

## Koollab: split identity proof from account selection

The two 2FA records describe complementary failures: one validation route accepts a user UUID without primary credentials, while another permits the client to supply the seed used to validate a TOTP. Test them as proof-binding failures rather than trying to take over an administrator.

1. Create users A and B in a disposable tenant. Give both harmless learner roles; enroll distinct TOTP secrets and preserve only secret hashes in evidence.
2. Record a normal login for A through first factor, challenge issuance, second factor, session creation, and a status-only identity endpoint. Note every transaction, account, and challenge identifier.
3. Replay the second-factor request with no first-factor transaction, a random transaction, A's transaction plus B's UUID, and B's transaction plus A's UUID.
4. If the request accepts a seed field, compare omitted, random, A-enrolled, B-enrolled, and client-generated canary seeds. Never test a real user's enrolled secret.
5. Instrument session issuance or use a disposable learner session. A no-op cookie counter or `/me` response containing only the synthetic username is sufficient.
6. Repeat against the corrected build. It should derive the target account from the authenticated login transaction and validate only against the server-held enrolled secret.

A bounded positive is **untrusted account selector or seed -> second-factor validator accepts a canary code without the matching first-factor transaction/enrollment -> synthetic account session sink is reached**. Report whether primary credentials were absent, known, or valid for a different account.

## Koollab: test SCORM identity, integrity, and lifecycle separately

SCORM APIs often accept rich client state, but the server still owns learner identity, assignment scope, legal transitions, and assessment authority.

1. Create learners A and B, courses X and Y, one assigned and one unassigned lesson per learner, and a quiz with synthetic questions.
2. Seed unique non-sensitive markers in display name, lesson position, cached state, score, and completion status.
3. For read routes, vary learner ID, course ID, lesson ID, and enrollment ID one at a time across own, other-user, unassigned, nonexistent, malformed, and cross-course controls.
4. For the SCORM commit route, submit only a reversible completion marker. Compare ordinary progress, direct `completed`, regressive transitions, impossible score/completion pairs, and completion before content launch.
5. For assessment status, answer the synthetic quiz incorrectly and inspect only the current learner's normal response. Determine whether the response reveals expected answers before completion, then compare fixed behavior.
6. Restore all progress markers after testing.

Strong evidence is a decision table such as **learner A's session + learner B's object ID -> B marker returned**, or **learner A + assigned lesson not launched -> client-selected completed state persists**. Never collect real training history, scores, names, or assessment answers.

## Koollab: validate SQL-to-deserialization chains edge by edge

The advisory cluster names pre-authentication and post-authentication SQL oracles plus three authenticated flows where SQL-controlled data reaches `unserialize()` and eventually a web-accessible write. Do not reproduce that chain with a webshell.

1. Seed a table dedicated to the lab with one random row and no production-shaped data. Use a database account and schema that contain no user credentials or real JWTs.
2. For each candidate route, identify authorization state, parameter type, query construction, result field, deserialization call, file-write call, canonical destination, and public URL mapping.
3. Start with quote, type, sort, and numeric-boundary controls that can reveal query-shape divergence without extracting data. If an oracle must be confirmed, prove only the seeded row or a boolean expression over a constant.
4. Replace `unserialize()` with an instrumented decoder or use a class-free scalar fixture. Record whether the selected database value reaches the decoder; do not supply a gadget chain.
5. Replace file writes and web handlers with no-op counters or permit only a fixed `.txt` marker under a disposable directory. Record the canonical path and static response.
6. Repeat each edge on the fixed build. Parameterization should remove the SQL control; strict typed decoding should reject unexpected state; the file sink should choose a non-executable server-owned destination.

Report the strongest proven edge only: SQL expression control, seeded-row read, decoder reachability, marker-file write, web reachability, or instrumented handler selection. Do not label a changed text file as RCE and do not publish serialized payloads or shell content.

For SCORM archive upload, apply the same decomposition: designer authorization -> logical archive validation -> entry canonicalization -> extraction root -> persisted suffix -> public mapping -> handler selection. Use a normal manifest plus inert text markers and a no-op handler counter; never include PHP or another executable type.

## WordPress: bind nonces and proofs to the selected object

### Easy Appointments cross-booking updates

The advisory says an authenticated user can obtain a shared nonce from their own appointment edit form, then submit another appointment's ID to overwrite customer metadata.

1. Create users A and B and one appointment for each. Use marker-only names, emails under an owned test domain, phone values, and descriptions.
2. Record where A obtains the nonce and which action it names. Hash rather than retain the raw nonce.
3. Submit A's normal update, then vary only the appointment ID to B's booking while keeping A's valid nonce and session.
4. Confirm mutation from an owner/admin view, restore B's marker, and compare nonexistent and fixed-build controls.

The finding is **A-owned form yields valid nonce -> handler accepts B's appointment ID -> B's synthetic customer marker changes without an ownership check**. The nonce is valid; the defect is object authorization.

### miniOrange and UsersWP proof confusion

For miniOrange, the optional Profile Completion email-verification flow reportedly lets a code issued for one controlled email be replayed against a different account. For UsersWP, a caller who already knows valid primary credentials can reportedly choose an authentication provider that bypasses the intended second factor.

Use two disposable non-privileged accounts. Build a table over account selected at proof issuance, email or provider submitted at verification, first-factor transaction, one-time code, and resulting session identity. Codes must be single-use, short-lived, transaction-bound, method-bound, and account-bound. For UsersWP, preserve the important precondition that primary credentials are already known; do not overstate the result as pre-authentication takeover.

A harmless `/me` identity response or instrumented cookie setter is enough. Never target an administrator or retain raw codes, passwords, cookies, recovery data, or enrolled secrets.

## WordPress: isolate cloud fetch, callback dispatch, and payment authenticity

### WP Media Folder Addon incomplete handler coverage

The record describes two public AJAX cloud-storage handlers left vulnerable after a fix covered only a sibling handler. Test **every route family** that consumes a cloud object selector or URL.

- Configure only fake cloud credentials and a local mock provider.
- Seed one synthetic object and one local canary file under a disposable lab directory.
- Compare relative, absolute, URL, encoded, redirecting, and wrong-provider selectors.
- For outbound behavior, use only an owned callback and an owned redirector that terminates at another owned listener.
- For local-file behavior, stop after the synthetic canary. Never request WordPress config, keys, logs, home directories, metadata services, or internal applications.
- Repeat all sibling handlers on the fixed build; a single corrected route does not prove full coverage.

Record initial selector, decoded value, provider chosen, redirect chain, canonical local path, final authority, and marker returned.

### Streamit public PHP callback dispatch

The Streamit record says a public AJAX route accepts a PHP function name and argument array. Do not call account, filesystem, process, plugin-install, mail, network, or configuration functions.

In a disposable source-instrumented site, replace the dispatcher with a recorder and register one uniquely named no-op canary callback. Exercise omitted, unknown, canary, internal-method, case, namespace, and argument-shape controls. Capture route reachability, authentication/capability decisions, selected function, normalized arguments, and counter increments. A positive result is **anonymous request -> untrusted callback selector -> canary function dispatch with attacker-shaped arguments**. Use static call-graph evidence for dangerous built-ins; never invoke them.

### PayU CommercePro order binding

The record says order modifications are accepted without verifying the gateway signature. Use gateway test mode or a complete local mock and two synthetic orders with no fulfillment:

1. capture a correctly signed test callback for order A;
2. replay it with a missing, random, stale, or wrong-merchant signature;
3. vary order ID, total, shipping, and one harmless metadata marker independently;
4. test A's authentic callback against order B;
5. record whether the exact order fields persist, then restore or delete both orders.

The bounded finding is **unsigned or invalidly signed callback -> attacker-selected order -> synthetic total/shipping/metadata mutation**. Do not complete payment, trigger fulfillment, reduce a real total, or touch a customer order.

### Facturación Electrónica Costa Rica global settings CSRF

The record describes a settings handler with missing nonce validation. In a disposable site containing only fake tokens, compare direct administrator requests with missing, random, wrong-action, stale, and valid nonces. Mutate only a reversible text marker or test-environment flag, record before/after option hashes, then restore. Never deliver a cross-site page to a real administrator or replace production fiscal/API credentials.

## Reporting checklist

Include:

- exact product/plugin slug, affected and fixed version, feature/configuration state, route/action, role, and tenant;
- principal, first-factor transaction, challenge, proof method, target account, and resulting synthetic identity;
- current learner, requested learner/course/lesson, assignment state, lifecycle state, and persisted marker;
- query parameter, seeded-row oracle, decoder counter, canonical file destination, public mapping, and handler counter as separate edges;
- nonce provenance, appointment/order ownership, selected callback, cloud provider/authority, signature result, and changed field;
- negative controls for missing, malformed, wrong-account, wrong-object, wrong-method, replayed, stale, and fixed-build inputs; and
- redaction of passwords, OTP seeds/codes, cookies, JWTs, cloud/API credentials, payment fields, customer data, callback authorities, and filesystem paths.

Do not infer account takeover from code acceptance without a session sink, RCE from SQL control or a marker write, SSRF from URL parsing without an owned callback, or payment completion from a reversible order-field mutation.