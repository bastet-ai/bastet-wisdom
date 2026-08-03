# Vue interpolation and multifunction-printer object-boundary checks

Source: hourly offensive-security scan of the GitHub Security Advisory feed on 2026-08-03. The records were unreviewed when this page was written; confirm the exact product, market, firmware, route, role, and fixed behavior before reporting.

This wave yields two durable operator patterns: HTML escaping can leave a second template language active, and multifunction-printer workflows can authorize the UI session without authorizing the image, address-book, document-filing, or residual-cache object selected afterward.

Sources:

- [GHSA-hc5p-7rj2-94g3 / CVE-2026-69075: FlowIntel Vue interpolation injection](https://github.com/advisories/GHSA-hc5p-7rj2-94g3)
- [FlowIntel interpolation-escaping fix](https://github.com/flowintel/flowintel/commit/b0e99aa6d2708730bc422ebb6dc0c14d732389fa)
- [GHSA-wrg8-43fx-27hh / CVE-2026-60011: Sharp and Toshiba Tec stored-image authorization](https://github.com/advisories/GHSA-wrg8-43fx-27hh)
- [GHSA-hj84-h226-g524 / CVE-2026-63563: disabled-by-default MFP authentication](https://github.com/advisories/GHSA-hj84-h226-g524)
- [GHSA-8p37-6xc9-pcg2 / CVE-2026-63545: uncleared print cache](https://github.com/advisories/GHSA-8p37-6xc9-pcg2)
- [Sharp product advisory 2026-004](https://global.sharp/corporate/info/product-security/advisory-list/2026-004)
- [JVN product matrix JVNVU#98759887](https://jvn.jp/en/vu/JVNVU98759887)

!!! warning "Authorized validation only"
    Use a disposable FlowIntel instance and owned MFP lab hardware containing synthetic cases, users, address-book entries, image jobs, and documents. Never test a shared office printer, retrieve real print or scan content, enumerate contacts, retain session material, or execute browser payloads that read data, perform actions, navigate, or make network requests.

## Build the representation matrix first

| Boundary | First accepted representation | Later interpreter or selector | Safe positive |
| --- | --- | --- | --- |
| FlowIntel text field | HTML-escaped case, ticket, profile, organization, or role text | Vue `[[ ... ]]` compilation | inert expression changes one detached DOM marker |
| MFP image access | anonymous or authenticated web session | stored image/job identifier | image recorder selects user B's synthetic image under user A or no session |
| MFP initial state | shipped/default configuration | address-book and Document Filing route family | synthetic route is usable before authentication is enabled |
| MFP print lifecycle | completed job for user A | cache object later visible to user B | B's session reaches A's canary job ID in a no-content recorder |

Preserve raw input, HTML-escaped output, post-escape template tokens, canonical principal, canonical object ID, route family, device market, firmware, configuration state, and fixed control separately. A route returning `200`, a visible identifier, or a literal `[[...]]` string is not enough.

## FlowIntel: test escaping and template compilation as separate stages

The advisory describes values that are HTML-escaped and then placed into DOM nodes Vue compiles with custom `[[ ... ]]` delimiters. HTML escaping can neutralize markup while preserving interpolation syntax. The reusable review question is therefore not merely “is this output escaped?” but **which interpreters still process the escaped bytes, and in what order?**

### Inert interpolation harness

1. Deploy the affected FlowIntel revision with no production data or integrations. Create users A and B, one case, one recurring case, synthetic ticket identifiers, and disposable organization/role/profile fields.
2. Replace each candidate field with a unique plain-text control, an HTML-shaped inert marker, a literal `[[marker]]`, and an arithmetic-only interpolation such as a generated pair of small integers. Do not use script tags, event attributes, browser APIs, property traversal, function constructors, network requests, or session access.
3. Capture four stages independently: stored bytes, server-rendered HTML, DOM before Vue compilation, and DOM after Vue compilation. Use a detached browser profile with outbound networking blocked.
4. Test each affected render context separately: case and recurring-case pages, reports, profiles, navigation, organization names, and role names. Record the writer role and viewer role for every result.
5. Add missing closing delimiter, encoded brackets, nested text, HTML entities, and an ordinary escaped-tag control. Change one representation at a time.
6. Repeat against the fixing commit. Require the dedicated escape path to break interpolation delimiters before Vue compilation while preserving the intended literal text.

The bounded positive is **low-role field write -> HTML encoding preserves Vue delimiters -> normal privileged-view render compiles an inert arithmetic expression -> detached DOM differs from the literal control**. This proves a second-interpreter injection boundary. Do not claim session theft or arbitrary action unless a separately authorized, harmless JavaScript sink is demonstrated; the arithmetic-only result is normally sufficient to validate the bug class.

Generalize this workflow to Angular expressions, server-side template delimiters, Markdown directives, BBCode, shortcode engines, and client-side hydration. Build a complete interpreter pipeline rather than approving content after the first encoder succeeds.

## MFPs: bind every document operation to the authenticated job owner

The Sharp/Toshiba records expose three related but distinct checks:

1. certain stored image data can be requested without the required object authorization;
2. some market variants ship with user authentication disabled, leaving address-book editing and Document Filing functions available in the initial state; and
3. print data can remain in an internal cache and become accessible to a later user.

Do not collapse these into one “printer auth bypass.” Default configuration, route authentication, per-object authorization, and lifecycle cleanup are independent controls.

### Owned-device route and object matrix

1. Confirm the exact model, market, firmware, enabled applications, and current authentication configuration from an owned lab device. Export no configuration and change no production device.
2. Seed only synthetic objects: address entries `A-CANARY` and `B-CANARY`, one single-page image per user, and document-filing jobs whose visible content is a random non-sensitive marker.
3. Capture normal requests through the vendor UI. Do not brute-force hidden routes. Record method, route family, session state, user/job/document identifiers, and response content type.
4. Exercise anonymous, user A, user B, expired-session, malformed-object, nonexistent-object, and expected-administrator controls against A/A, B/B, A/B, and B/A object pairs.
5. Interpose a response or storage recorder where the lab permits it. Prefer evidence that the unauthorized request selects a foreign canary ID without returning image bytes. If instrumentation is unavailable, use a one-pixel synthetic marker image and retain only its precomputed hash.
6. Reboot or reset only according to the vendor's lab procedure, then compare shipped/default, authentication-enabled, and fixed-firmware states. Record whether address-book and Document Filing routes demand authentication before any object operation.
7. For cache lifecycle testing, complete A's canary print, log A out, sign in as B, and inspect only the documented history/reprint/cache UI. Stop when A's job ID reaches the recorder; do not print or export it.
8. Repeat after the expected job cleanup, logout, retention expiry, and fixed-firmware transitions. Distinguish persistent filing features from unintended residual cache.

Bounded positives are:

- **anonymous session -> caller-selected canary image ID -> image-delivery recorder**;
- **initial configuration -> address-book or Document Filing mutation recorder before authentication**; or
- **user A completes synthetic print -> user B session -> A's residual job reaches a no-content recorder**.

A banner, model fingerprint, default-disabled toggle, job-list entry, or route status alone does not prove image disclosure or cross-user access. Report the exact object and sink decision, and preserve whether the issue is configuration-dependent.

## Reporting checklist

- [ ] Exact FlowIntel revision or MFP model, market, firmware, and feature configuration are recorded.
- [ ] Writer/viewer or user/job owner pairs use synthetic identities and content.
- [ ] Stored bytes, first encoder, second interpreter, and final DOM are shown separately for FlowIntel.
- [ ] Authentication, route access, object authorization, and cache cleanup are shown as separate MFP decisions.
- [ ] Every object crossover includes own-object, foreign-object, nonexistent-object, anonymous, expired-session, and fixed controls.
- [ ] Browser networking is blocked and printer evidence contains no real cases, contacts, images, documents, or credentials.
- [ ] Impact stops at the first inert DOM or no-content object recorder rather than performing a privileged browser action or returning document bytes.
