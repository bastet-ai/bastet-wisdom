# Angular hydration TransferState cache-poisoning boundary validation

Source: hourly offensive-security scan, 2026-06-15. Primary entry: GitHub advisory [GHSA-rgjc-h3x7-9mwg / CVE-2026-54267](https://github.com/advisories/GHSA-rgjc-h3x7-9mwg), with upstream references to the Angular advisory [GHSA-rgjc-h3x7-9mwg](https://github.com/angular/angular/security/advisories/GHSA-rgjc-h3x7-9mwg), the Angular pull request [#69064](https://github.com/angular/angular/pull/69064), and commit [`6bde84fa8e6a5770b54040fbbc9bf10d5d0386fa`](https://github.com/angular/angular/commit/6bde84fa8e6a5770b54040fbbc9bf10d5d0386fa).

This is durable for operators because it exposes a reusable browser trust boundary: predictable SSR hydration state identifiers can let attacker-controlled markup win a `document.getElementById()` race and feed forged JSON into Angular's client-side `TransferState` / HTTP transfer cache.

## What changed

| Advisory | Package | Boundary | Operator value |
| --- | --- | --- | --- |
| GHSA-rgjc-h3x7-9mwg / CVE-2026-54267 | `@angular/core` | Server-rendered hydration state is recovered from a predictable DOM id such as `ng-state`; user-controlled elements with the same id can clobber the real state container before client bootstrap | Test SSR Angular apps for user-controlled `id` attributes, CMS HTML, or rich-content slots that can poison cached API responses during hydration. |

Affected ranges listed by the advisory include `@angular/core` 20.x before 20.3.25, 21.x before 21.2.17, 22.x before 22.0.1, and older lines with no patched version listed.

## Operator triage

1. **Confirm SSR plus hydration.** This workflow applies when the app uses Angular SSR and client hydration, commonly via `provideClientHydration()`. A client-only Angular SPA without serialized transfer state is not the same target.
2. **Find the state id.** Look for a JSON script element such as `<script type="application/json" id="ng-state">`. If a custom `APP_ID` is present, the state id may change to an app-specific `*-state` value.
3. **Map attacker-controlled markup before bootstrap.** Prioritize profile/CMS/rich-text/product-description/comment fields that render before Angular reads transfer state. Simple reflected text after hydration is lower signal.
4. **Target cacheable API responses, not secrets.** The proof should poison a synthetic endpoint response or lab-only API value. Do not attempt to read or forge live user secrets, tokens, payments, or private records.
5. **Require a render sink for impact.** Cache poisoning is strongest when the forged response crosses into UI trust: unsafe HTML rendering, role/config display, redirect targets, feature flags, or privileged UI decisions.

## Safe validation workflow

### Goal

Prove whether attacker-controlled DOM can replace Angular's hydration state container and cause the client to consume forged transfer-cache data.

### Preconditions

- Written authorization for the target app or a faithful lab reproduction.
- Evidence that Angular SSR hydration and transfer-state caching are enabled.
- A user-controlled markup or attribute path that can render an element before the legitimate state script is parsed or before client bootstrap reads it.
- A harmless API response key and canary payload agreed with the application owner.

### Steps

1. **Baseline the hydration state.** Capture the SSR HTML around the transfer-state script and record the exact id, script type, and representative cache keys. Redact real response bodies.
2. **Identify clobberable render points.** Search templates and rendered pages for dynamic ids such as `[id]="..."`, CMS-provided HTML attributes, markdown/rich-text HTML passthrough, or user profile fields rendered near the top of the document.
3. **Create an inert clobber element.** In the approved field, render an element with the transfer-state id and text content that is valid JSON for a disposable cache key. Keep the payload visibly synthetic, for example a `skillz_hydration_canary` string.
4. **Load a fresh SSR page.** Use a clean browser profile or disable cache. Record whether `document.getElementById('<state-id>')` resolves to the attacker-controlled element before Angular bootstrap completes.
5. **Observe transfer-cache behavior.** Trigger the client path that reads the selected API endpoint through Angular `HttpClient`. The proof is sufficient if the UI consumes the forged canary response without issuing the genuine backend request for that endpoint.
6. **Run negative controls.** Remove the clobber element, change the id, or move the element after bootstrap and confirm the real API response returns.

### Evidence to collect

- Angular package version and SSR/hydration configuration evidence.
- Redacted SSR HTML showing the legitimate transfer-state id.
- The exact synthetic clobber element and JSON canary used.
- Browser/network evidence showing cache hit versus backend request behavior.
- UI or console evidence showing only the canary value, not sensitive data.
- Negative-control evidence showing the issue disappears when the id cannot clobber the state container.

## Reporting heuristics

- Lead with the crossed boundary: **user-controlled markup/id attribute to Angular hydration state cache**.
- Separate clobberability from impact. A duplicate id is the primitive; the report needs to show what cached response or UI decision can be influenced.
- Keep claims narrow to Angular SSR hydration and `TransferState` / HTTP transfer cache behavior. Do not describe it as a generic Angular XSS unless the forged response reaches an executable sink.
- Include ordering details. The exploit depends on the attacker-controlled element being reachable by `getElementById()` when Angular reads the state.
- Use canary endpoints, canary roles, or synthetic config values. Never forge real privileges, production session details, or payment/account data.

## August 3 follow-up: raw-content serialization and transfer-cache key ambiguity

Two later Angular advisories extend this page from DOM-id clobbering to two adjacent SSR representation boundaries:

- [GHSA-vpx6-8pjr-4g3v / CVE-2026-69149](https://github.com/advisories/GHSA-vpx6-8pjr-4g3v) describes fallback raw-content elements such as `iframe`, `noembed`, `noframes`, and `noscript` whose dynamically bound text was not escaped when Angular's server-side DOM was serialized. A closing-tag sequence can therefore leave the intended text node and be reparsed as HTML by the browser.
- [GHSA-jhpw-976m-542j / CVE-2026-68945](https://github.com/advisories/GHSA-jhpw-976m-542j) describes ambiguous `HttpTransferCache` key material. A scalar parameter containing a comma and a repeated parameter whose values are joined with commas can serialize identically even though the backend treats them differently.

The listed corrected releases are `@angular/platform-server` 20.3.27, 21.2.19, and 22.0.7 for the raw-content issue, and `@angular/common` 20.3.27, 21.2.19, and 22.0.2 for the cache-key issue. Confirm the exact affected range in the advisory before testing another release line.

### Fallback raw-content serialization matrix

Use a disposable SSR application whose bound value is a synthetic marker. Block browser networking and do not use executable event handlers or scripts.

1. Render the same dynamic text inside an ordinary text element and each applicable fallback raw-content element.
2. Test plain text, a harmless closing-tag-shaped marker, encoded delimiters, mixed case, and a missing-closing-delimiter control. Change one representation at a time.
3. Capture the template value, server-side DOM text node, serialized response bytes, and browser-parsed DOM as four separate artifacts.
4. Use an inert sibling element such as `<span data-skillz-canary>` after the closing-tag marker. The bounded positive is that the sibling becomes a real DOM node only in the affected SSR serialization path.
5. Repeat on the fixed package and in a client-only render. The fixed SSR output should preserve the entire value as text, and the client-only control establishes that the issue is the server serializer rather than the template binding itself.

Do not report a literal marker in response source as XSS. Show the parser transition: **bound text -> unescaped SSR serialization -> browser reparses a harmless sibling marker outside the raw-content element**. Stop before script execution, navigation, cookie access, or privileged UI action.

### `HttpTransferCache` collision harness

The useful proof is a semantic collision, not merely two equal debug strings.

1. In a local Angular SSR fixture, create a synthetic endpoint that distinguishes a scalar comma value from repeated values and returns different non-sensitive markers.
2. Issue request A with one parameter value containing a comma and request B with two repeated values. Keep method, URL, headers, credentials mode, and every unrelated option identical.
3. Instrument the cache-key builder and backend transport. Record the structured parameter multimap, generated key, insertion order, backend request count, and response marker consumed by each caller.
4. Reverse A/B order, vary empty values and comma placement, and repeat equivalent checks for every header or option collection included in the key. Include unambiguous ordinary-value controls.
5. Require the affected build to show equal key material plus response reuse across semantically distinct requests in one SSR render. Repeat on the fixed build and require distinct keys and two backend calls.

Use only canary responses. Never place sessions, authorization headers, customer records, or role/payment data in the fixture. Report **structured request A and B -> identical transfer-cache key -> B consumes A's synthetic response**; do not infer cross-user leakage unless the application independently shares the cache across users or renders and that scope is safely proven.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger research, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. No CISA, PortSwigger, Trail of Bits, ProjectDiscovery, or Disclosed update added a new higher-signal operator workflow in this run. This page promotes the newly published Angular advisory because it turns a framework-specific hydration bug into a reusable SSR cache-poisoning and DOM-clobbering validation pattern.
