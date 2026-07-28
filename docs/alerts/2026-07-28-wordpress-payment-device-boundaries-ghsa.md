---
title: WordPress nonce, payment-response, and device filesystem boundaries from July 28 updates
---

# WordPress nonce, payment-response, and device filesystem boundaries from July 28 updates

A July 28 advisory wave yields four durable operator checks: a low-role WordPress nonce disclosing connection material later accepted by a public administrator-login route, a frontend nonce treated as authorization for persistent WooCommerce options, a successful payment response replayed across ticket orders, and unauthenticated virtual-filesystem access on SICK InspectorP6xx devices.

Sources:

- [GHSA-8fxc-wrxg-769w / CVE-2026-14328: Eazy Plugin Manager privilege escalation](https://github.com/advisories/GHSA-8fxc-wrxg-769w)
- [Eazy Plugin Manager 4.4.1 AJAX option handler](https://plugins.svn.wordpress.org/plugins-on-steroids/tags/4.4.1/plugins-on-steroids.php)
- [Eazy Plugin Manager 4.4.1 REST handlers](https://plugins.svn.wordpress.org/plugins-on-steroids/tags/4.4.1/libs/class.rest_api.php)
- [GHSA-qmvq-mp3j-6pvv / CVE-2026-13440: StoreGrowth stored popup markup](https://github.com/advisories/GHSA-qmvq-mp3j-6pvv)
- [GHSA-3368-w437-2p8j / CVE-2026-13110: StoreGrowth category-message write](https://github.com/advisories/GHSA-3368-w437-2p8j)
- [GHSA-xrhw-gwf7-m34v / CVE-2026-15411: StoreGrowth popup-option write](https://github.com/advisories/GHSA-xrhw-gwf7-m34v)
- [StoreGrowth 2.1.0 frontend nonce publication](https://plugins.svn.wordpress.org/storegrowth-sales-booster/tags/2.1.0/modules/bogo/includes/EnqueueScript.php)
- [StoreGrowth 2.1.0 popup AJAX handlers](https://plugins.svn.wordpress.org/storegrowth-sales-booster/tags/2.1.0/modules/sales-pop/includes/Ajax.php)
- [StoreGrowth 2.1.0 category-message AJAX handlers](https://plugins.svn.wordpress.org/storegrowth-sales-booster/tags/2.1.0/modules/bogo/includes/Ajax.php)
- [GHSA-f83j-v8r3-vfhv / CVE-2026-18029: pretix GiroCheckout payment-response replay](https://github.com/advisories/GHSA-f83j-v8r3-vfhv)
- [pretix security release 2026.6.1](https://pretix.eu/about/en/blog/20260728-release-2026-6-1/)
- [GHSA-2gm5-4hq3-g753: pretix quick-setup object authorization](https://github.com/advisories/GHSA-2gm5-4hq3-g753)
- [GHSA-5x3h-wq76-mxqx / CVE-2026-11841: SICK AppEngine Fileaccess exposure](https://github.com/advisories/GHSA-5x3h-wq76-mxqx)
- [SICK CSAF sca-2026-0010](https://www.sick.com/.well-known/csaf/white/2026/sca-2026-0010.json)

The GitHub records were unreviewed when this page was written. The primary pretix release uses **CVE-2026-57532** for the quick-setup issue, while the initial GitHub record used **CVE-2026-18028** for substantially the same description. Preserve that discrepancy in evidence rather than treating the identifiers as interchangeable. Confirm the exact product slug, version, route, configuration, and fixed behavior before reporting.

!!! warning "Authorized validation only"
    Use disposable WordPress sites, synthetic users, fake connection values, test-mode ticket orders, mocked payment responses, and owned SICK lab devices with vendor-approved canary storage. Never mint or retain a production administrator session, alter a real store, reuse live payment confirmations, obtain unpaid real tickets, read device passwords, change production vision parameters, or place Lua code on a device.

## Build a boundary matrix first

| Surface | First attacker-controlled representation | Authority the server should derive | Safe proof |
| --- | --- | --- | --- |
| WordPress remote management | subscriber-visible nonce and option name | capability plus server-held connection secret | fake option values and a canary user |
| WooCommerce frontend AJAX | nonce published to anonymous visitors | authenticated role and explicit capability | reversible text-only option marker |
| Ticket payment callback | successful status response | provider transaction bound to one order and amount | two mocked orders in test mode |
| Event quick setup | event ID and request timing | current user's organizer/event permissions | one reversible synthetic product marker |
| Device virtual filesystem | remote path selector | authenticated session and approved virtual root | pre-seeded non-sensitive canary file |

For every surface, preserve anonymous, low-role, expected-role, malformed-proof, wrong-object, and fixed-build controls. Stop at the first harmless marker that proves the crossed boundary.

## Eazy Plugin Manager: compose nonce scope, option scope, and login scope

The advisory describes a three-edge chain in versions through 4.4.1 when the remote-connection feature has populated its connection options:

1. admin-area assets expose a `pos` nonce to every logged-in admin-area user;
2. an AJAX handler verifies that nonce but accepts an arbitrary option name and returns `get_option()` data without a capability check; and
3. the public `epm/v1/admin/login` route authenticates using values from those options, then creates a session for the site's administrative email account.

The source confirms the important distinctions: the nonce proves only that WordPress issued a nonce to a logged-in user, the option selector determines which server state is disclosed, and the public route performs its own connection-key calculation before setting cookies. Do not collapse these into “nonce bypass.”

### Marker-only lab workflow

1. Install 4.4.1 on a disposable site. Create an administrator for setup and a separate subscriber canary.
2. Populate the plugin's remote-connection state with **fake** site and connection values. Record whether the feature is configured; the chain should fail closed when those values are absent.
3. Sign in as the subscriber and confirm whether plugin assets place the `pos` nonce on an admin-area page reachable to that role.
4. Call the option handler with a harmless custom option first. Compare an expected public option, the fake connection options, a nonexistent name, and an unrelated sensitive-looking name whose value is only a synthetic marker.
5. Record nonce acceptance and returned option name/type independently. Do not retrieve real salts, API keys, mail credentials, or user data.
6. Reproduce the route's authentication calculation offline using only the fake connection values. Retain a hash of the test input tuple, not the raw values.
7. In an instrumented lab, replace the administrative-email target with a disposable canary user or intercept `wp_set_auth_cookie()` with a counter. Send the valid fake proof and malformed, reordered, stale, and random controls.
8. If an end-to-end cookie check is required, use only the canary account and a harmless identity endpoint, then immediately invalidate the session.
9. Repeat on the fixed build and verify capability enforcement, constrained option names, and rejection at the public login route.

A bounded positive result is **subscriber receives nonce -> arbitrary-option handler returns configured fake connection state -> derived proof reaches public login handler -> canary cookie setter executes**. Do not demonstrate takeover of a real administrator. Report each edge separately if the full chain is not reproduced.

## StoreGrowth: a public nonce is not an authorization decision

StoreGrowth 2.1.0 creates `ajd_protected` and publishes it in the frontend `bogo_save_url` object. The same token is accepted by AJAX handlers registered through `wp_ajax_nopriv_*`. Source review shows `create_popup()` writes `spsg_popup_products`, while `bogo_category_msg_create()` mutates category-message settings. The associated XSS record adds a rendering question, but persistent option control and browser execution remain separate claims.

### Anonymous option-write matrix

1. Install 2.1.0 in a disposable WooCommerce site with no customer data and script execution instrumented to a harmless counter.
2. Fetch a normal public storefront page with no cookies and record whether `bogo_save_url.ajd_nonce` is present.
3. Exercise the relevant AJAX action with missing, random, stale, logged-out, public-page, subscriber, and administrator-issued nonce values.
4. Write only a unique plain-text marker into a disposable popup or category-message fixture. Read it back through the plugin UI or option API, then restore the original value.
5. Repeat with a second anonymous browser to determine whether the nonce is session-bound or simply reusable by any visitor during its validity window.
6. For the stored-markup claim, use a harmless element carrying a unique `data-*` attribute. Record storage, rendered context, sanitizer output, and DOM appearance separately; do not use script, event-handler, external-resource, or navigation payloads.
7. Confirm whether the fixed version rejects anonymous requests before any option write and whether rendering encodes the marker.

The decisive authorization evidence is **anonymous public page yields nonce -> `wp_ajax_nopriv_*` accepts it -> persistent synthetic option changes without a capability decision**. The decisive rendering evidence additionally requires **stored marker reaches the intended frontend sink after the application's normal render path**. Do not call a changed database option XSS by itself.

Generalize this check to any WordPress plugin that localizes nonces into public JavaScript and then registers mutating `nopriv` handlers. Inventory the handler's capability checks and server-owned object scope; nonce verification alone is CSRF resistance, not proof that the caller may perform the action.

## pretix: bind provider responses to one payment object

The primary pretix release says `pretix-girosolution` before 1.0.1 accepted a successful GiroCheckout status response from one payment for a different payment. That is a transaction-binding failure: authenticity of a provider response is insufficient when the response is not bound to the local order, payment ID, amount, currency, merchant context, and lifecycle state.

### Two-order replay harness

1. Use a disposable pretix organizer, the affected enterprise plugin, and a mocked or provider-approved test-mode GiroCheckout endpoint.
2. Create orders A and B with distinct marker products and amounts. Do not issue scannable real-event tickets.
3. Complete A through the mock and capture the normalized status fields consumed by pretix. Redact provider credentials and replace identifiers with stable hashes in retained evidence.
4. Replay A's response at B's callback/status transition while varying one field at a time: local payment ID, provider transaction ID, order, amount, currency, merchant account, and response timestamp.
5. Record the state transition for both orders and whether a ticket artifact is generated. Configure generated artifacts as invalid lab markers that cannot pass a production scanner.
6. Add duplicate delivery to A, out-of-order pending/success events, expired responses, and an already-refunded order as negative controls.
7. Repeat against `pretix-girosolution` 1.0.1 and confirm that A's authentic response cannot change B.

A valid result is **authentic success for synthetic payment A -> replay against B -> B becomes paid or receives a lab ticket without its own provider transaction**. Do not complete a live charge, transfer a real ticket, or test another organizer.

## pretix quick setup: test temporal and parent-object authorization together

The quick-setup issue is narrow but reusable: the primary source requires a user with limited permissions in the same organizer, an event that is still completely unconfigured, and a well-timed request. Treat organizer membership, event permission, event setup state, and timing as independent preconditions.

1. Create two organizers and three synthetic events: one unconfigured target, one configured control, and one event in another organizer.
2. Give user A read-only access where required and no configuration permission. Keep a separate expected-role operator.
3. Capture the normal quick-setup request and replay it with omitted, own-event, read-only target, configured target, and foreign-organizer event IDs.
4. Add a synchronization barrier in the lab so the request can be sent before, during, and after the legitimate setup transition.
5. Request only one reversible marker product or quota. Do not connect a real Stripe account or change bank-transfer details.
6. Verify final state through the owning operator, restore the marker, and compare fixed pretix releases 2026.6.1, 2026.5.4, or 2026.4.6.

Report the exact permission, parent organizer, target event state, and timing window. A static endpoint response without an unauthorized persisted marker is not enough.

## SICK InspectorP6xx: confine virtual-filesystem validation to canaries

SICK's CSAF identifies remote access to unintended internal virtual-filesystem paths through the SOPAS `FileSystemAccess` method. It lists InspectorP61x and P62x firmware below 5.4.0 as affected and 5.4.0 as fixed. InspectorP63x, P64x, and P65x are listed as affected across all firmware versions in that advisory. The record covers query and modification of internal storage, configuration files, and application directories; the adjacent GitHub description mentions customer-defined passwords and possible Lua execution, but those higher-impact claims must not be tested on production devices.

### Read/write boundary workflow

1. Confirm written authorization, exact Inspector model/SKU, firmware, network path, and whether SOPAS FileSystemAccess is reachable. Package presence or a web banner is not enough.
2. Use an isolated owned device. Through supported local tooling, pre-seed one non-sensitive canary in a vendor-approved application-data location and hash its contents.
3. From the remote test segment, compare unauthenticated, malformed-session, low-role, and expected authenticated requests for an allowed canary path, a nonexistent path, and one known internal path represented only by a fake lab marker.
4. Stop if the canary is returned without authentication. Do not request device parameter files, passwords, certificates, logs, customer images, or arbitrary system paths.
5. If write validation is explicitly approved, modify only a disposable canary file and verify its hash. Do not alter configuration, startup state, inspection jobs, firmware, or application code.
6. Do not upload Lua. If execution reachability matters, use static route/source evidence or an instrumented vendor lab where the application loader is replaced by a no-op counter.
7. Repeat on P61x/P62x firmware 5.4.0. For P63x/P64x/P65x, report the vendor's all-version affected status and do not infer a fixed build.

A safe positive result is **network-reachable FileSystemAccess -> no authenticated identity -> pre-seeded virtual-filesystem canary read or marker-only write outside the intended public root**. Separate unauthenticated read, write, configuration impact, application loading, and code execution in the final report.

## Reporting checklist

Include:

- exact product/plugin slug, version or firmware, configuration state, route/action, method, and authentication context;
- each chain edge as a decision table rather than one inflated impact label;
- nonce provenance, capability result, selected option, object owner, payment/order binding, and resolved virtual path;
- affected and fixed controls, including feature-disabled and unconfigured states;
- hashes or redacted identifiers for fake connection values, payment responses, cookies, and canary files;
- the pretix quick-setup CVE identifier discrepancy and the source attached to each identifier;
- a bounded impact statement that distinguishes option disclosure, session creation, persistent write, DOM rendering, payment replay, event mutation, filesystem read/write, and execution.

Do not infer administrator takeover from option disclosure alone, XSS from stored markup alone, free tickets from a callback that did not change order state, or device code execution from filesystem reachability alone.