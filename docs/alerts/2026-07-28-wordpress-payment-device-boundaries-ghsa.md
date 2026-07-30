---
title: WordPress role, nonce, payment-response, and device filesystem boundaries from late-July updates
---

# WordPress role, nonce, payment-response, and device filesystem boundaries from late-July updates

A late-July advisory wave yields eight durable operator checks: a low-role WordPress nonce disclosing connection material later accepted by a public administrator-login route, a frontend nonce treated as authorization for persistent WooCommerce options, an author-owned custom post exposing a role-assignment nonce and client-selected canonical role, contributor access accepted for site-wide event-payment settings, a successful payment response replayed across ticket orders, a public payment form whose hidden amount becomes the gateway amount, author-controlled post metadata reinterpreted as SQL during a later duplicate action, and unauthenticated virtual-filesystem access on SICK InspectorP6xx devices.

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
- [GHSA-fgx3-jj2q-3c9j / CVE-2026-12144: Wholesale for WooCommerce role assignment](https://github.com/advisories/GHSA-fgx3-jj2q-3c9j)
- [Wholesale for WooCommerce 2.0.5 request-role handler](https://plugins.svn.wordpress.org/woo-wholesale-pricing/tags/2.0.5/inc/class-wwp-wholesale-requests.php)
- [Wholesale for WooCommerce corrected request-role handler](https://plugins.svn.wordpress.org/woo-wholesale-pricing/trunk/inc/class-wwp-wholesale-requests.php)
- [GHSA-6p3r-44rr-gcj5 / CVE-2026-17166: Event Booking Manager site-wide payment settings](https://github.com/advisories/GHSA-6p3r-44rr-gcj5)
- [Event Booking Manager 5.3.7 payment-settings handler](https://plugins.svn.wordpress.org/mage-eventpress/tags/5.3.7/admin/settings/global/admin_setting_panel.php)
- [Event Booking Manager corrected payment-settings handler](https://plugins.svn.wordpress.org/mage-eventpress/trunk/admin/settings/global/admin_setting_panel.php)
- [GHSA-4hpv-v74p-q5cg / CVE-2026-1982: Persian Elementor ZarinPal amount manipulation](https://github.com/advisories/GHSA-4hpv-v74p-q5cg)
- [Persian Elementor 2.8.1 ZarinPal form](https://plugins.svn.wordpress.org/persian-elementor/tags/2.8.1/widget/zarinpal/zarinpal-button.php)
- [Persian Elementor 2.8.1 ZarinPal request and verification handler](https://plugins.svn.wordpress.org/persian-elementor/tags/2.8.1/widget/zarinpal/zarinpal-ajax.php)
- [Persian Elementor revision 3613858](https://plugins.trac.wordpress.org/changeset/3613858/persian-elementor)
- [GHSA-mjmr-35x5-p5hh / CVE-2026-16092: Improved Save Button second-order SQL injection](https://github.com/advisories/GHSA-mjmr-35x5-p5hh)
- [Improved Save Button 1.2.1 duplicate action](https://plugins.svn.wordpress.org/improved-save-button/tags/1.2.1/actions/class-lb-save-and-then-action-duplicate.php)

The GitHub records were unreviewed when this page was written. The primary pretix release uses **CVE-2026-57532** for the quick-setup issue, while the initial GitHub record used **CVE-2026-18028** for substantially the same description. Preserve that discrepancy in evidence rather than treating the identifiers as interchangeable. Confirm the exact product slug, version, route, configuration, and fixed behavior before reporting.

!!! warning "Authorized validation only"
    Use disposable WordPress sites, synthetic users and roles, fake connection values, reversible payment-setting markers, test-mode ticket orders, mocked payment responses, local SQL recorders, and owned SICK lab devices with vendor-approved canary storage. Never mint or retain a production administrator session, promote a real account, alter a real store, send a payment to a live gateway, reuse live payment confirmations, extract database data, obtain unpaid real tickets, read device passwords, change production vision parameters, or place Lua code on a device.

## Build a boundary matrix first

| Surface | First attacker-controlled representation | Authority the server should derive | Safe proof |
| --- | --- | --- | --- |
| WordPress remote management | subscriber-visible nonce and option name | capability plus server-held connection secret | fake option values and a canary user |
| WooCommerce frontend AJAX | nonce published to anonymous visitors | authenticated role and explicit capability | reversible text-only option marker |
| Wholesale-request approval | request post, nonce, status, and role slug | request ownership plus role-promotion capability and server allowlist | synthetic author and non-privileged canary role |
| Event payment settings | authenticated AJAX action and settings fields | `manage_options` plus action-bound nonce | reversible confirmation-page/status markers |
| Ticket payment callback | successful status response | provider transaction bound to one order and amount | two mocked orders in test mode |
| ZarinPal payment request | public hidden `amount` field | server-stored widget price and selected product/quantity | local gateway recorder plus synthetic amount |
| Duplicate-post metadata | author-controlled `meta_key` stored first and interpolated later | parameterized metadata copy preserving exact value | query recorder and inert delimiter-shaped marker |
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

## Wholesale for WooCommerce: compose post ownership, nonce visibility, and role selection

The 2.0.5 source registers `wwp_requests` with the ordinary `post` capability model. Its `save_requests_meta()` handler verifies `request_user_role_nonce`, but does not require `manage_options` or `promote_users`; it sanitizes the submitted `user_role_set` as text and passes that value to `WP_User::add_role()`. The advisory's important precondition is that an author who owns a wholesale-request post can reach its edit screen and nonce. This is not a nonce bypass: the valid nonce is available because the custom post type grants the wrong principal access, and the later handler mistakes a client-selected role slug for policy.

The corrected source provides three independent rejection controls worth testing: it maps the custom post type's edit/publish/delete capabilities to `manage_options`, checks `manage_options` in the save handler, and allowlists `user_role_set` against registered wholesale-role taxonomy slugs before calling `add_role()`.

### Marker-only role-assignment workflow

1. Install 2.0.5 on a disposable WordPress site. Create a synthetic author and a harmless custom canary role with no administrative capabilities. Keep the setup administrator in a separate browser.
2. Create a wholesale request through the normal registration flow for the author. Confirm the resulting request post's `_user_id`, author/owner, status, and edit-screen reachability without collecting another user's request.
3. As the author, record whether the request edit screen renders `request_user_role_nonce`. Preserve only nonce provenance and a hash; do not retain the raw value.
4. Capture the ordinary save request. Replay omitted, random, stale, valid-own-request, valid-foreign-request, and fixed-build nonce controls while varying `user_status` and `user_role_set` independently.
5. First request only the harmless canary role. Read back the target user's canonical roles and capabilities, then restore the original role. Do not request `administrator` or any role that can install plugins, edit users, access secrets, or execute code.
6. Instrument `WP_User::add_role()` if stronger sink evidence is needed. A call counter plus the submitted canary slug proves role-selector reachability without granting privilege.
7. Repeat on the corrected build and verify all three controls separately: the author cannot edit the request post, the handler rejects callers without `manage_options`, and an unexpected role slug is replaced or rejected before the role sink.

A bounded positive result is **author owns request post -> edit screen yields valid nonce -> save handler accepts client-selected canary role -> canonical role state or instrumented `add_role()` sink changes without promotion authority**. Report the post-ownership and nonce preconditions; do not generalize this to anonymous or subscriber access.

This pattern generalizes to plugins that use custom post types as approval queues. Test the post type's mapped capabilities, nonce visibility, target-user binding, submitted role/capability allowlist, and sink-level promotion check as separate edges.

## Event Booking Manager: distinguish content editing from site-wide payment authority

Event Booking Manager 5.3.7 registers the authenticated `mep_save_payment_settings_modal` AJAX action. Its handler accepts callers with either `manage_options` **or** `edit_posts`, has no action nonce check, and updates the global `payment_setting_sec` option. That option controls WooCommerce payment enablement, checkout redirects, login and billing requirements, confirmation-page selection, and ticket-confirming order statuses. A contributor's ability to edit content is therefore being reused as authority over every event's payment workflow.

The corrected source adds `check_ajax_referer( 'mep_save_payment_settings', 'nonce' )` and narrows the capability decision to `manage_options`. Treat both controls independently: a nonce fixes request provenance/CSRF exposure, while the capability check decides whether the authenticated principal may change global payment state.

### Reversible global-setting matrix

1. Install 5.3.7 in a disposable WooCommerce/Event Booking Manager lab with no live gateways, customers, orders, or tickets. Snapshot `payment_setting_sec` and create a synthetic contributor plus an expected administrator.
2. Capture the normal `mep_save_payment_settings_modal` request. Exercise anonymous, subscriber, contributor, editor, and administrator identities with omitted, random, and valid action-nonce variants.
3. Change only benign values: a disposable confirmation-page ID and a synthetic, non-production order-status marker. Avoid enabling gateways, changing checkout authentication, or selecting statuses used by real orders.
4. Read the option back through an administrator-side lab harness, record the acting user and before/after hashes, then restore the snapshot immediately.
5. Test omitted fields as well as supplied fields because the affected handler assigns defaults to absent values; one partial request may change more global keys than it names.
6. Repeat on the corrected build. Confirm that a valid nonce from a low-role context still fails `manage_options`, and that an administrator request without the action-bound nonce fails before `update_option()`.

The decisive evidence is **`edit_posts`-only principal -> authenticated AJAX action -> global `payment_setting_sec` canary changes without `manage_options`**. A `200` or JSON success response without persisted option evidence is insufficient. Report cross-event/global scope separately from checkout, ticket, or revenue impact; do not process an order to inflate the claim.

## Persian Elementor: bind a public payment request to server-owned price state

Persian Elementor 2.8.1 renders the configured ZarinPal total into a hidden `amount` input. The public `zarinpal_payment_request` AJAX handler verifies the frontend nonce, then derives its transaction amount from that submitted field. It stores the same amount in transient transaction state, passes it to the payment-request helper, and later uses the stored value for provider verification. The nonce therefore proves request provenance but does not bind the submitted amount to the widget's configured price.

The durable check is broader than one gateway: whenever a storefront renders amount, currency, product, discount, quantity, or merchant fields into the browser, determine whether the server reconstructs the payable tuple from authoritative catalog/order state before both **payment creation** and **payment verification**.

### Local gateway-recorder workflow

1. Install 2.8.1 on a disposable WordPress/Elementor site. Configure one ZarinPal widget with a synthetic product and amount; use a fake merchant identifier and prevent outbound DNS/network access.
2. Capture the public form and record the displayed total, hidden amount, nonce provenance, callback URL, and product description. Use only the normal anonymous page context.
3. Replace the ZarinPal request helper with a local recorder that accepts no payments and returns a fixed canary authority. Instrument transient writes as well. Do not redirect to or contact the real provider.
4. Replay the request with the expected amount, a different positive canary amount, zero, negative, fractional, oversized, omitted, and duplicate amount fields. Keep the values non-monetary inside the recorder.
5. For each case, record the raw submitted representation, integer/conversion result, transient amount, helper amount, and response state. Vary product/description fields separately so amount binding is not confused with descriptive metadata.
6. Invoke the callback path only through a stub verification helper. Confirm whether it verifies the attacker-selected stored amount rather than independently recovering the configured widget price.
7. Repeat against the corrected revision and require the server to derive the expected amount from server-owned widget/product state before the request helper and to bind callback verification to that same transaction tuple.

A bounded positive result is **public form exposes reusable request proof -> modified hidden amount -> local request recorder receives the modified amount -> transaction state and stub verification preserve it without a server-side price lookup**. This proves amount authority drift; it does not prove that a live payment completed, goods were delivered, or a specific monetary loss occurred.

Preserve unit conversions explicitly. The affected handler divides the submitted value before its helper restores the provider-facing unit, so evidence should show browser value, normalized internal value, and recorder value rather than assuming all three numbers use the same currency unit.

## Improved Save Button: replay stored metadata through a later SQL sink

Improved Save Button 1.2.1 illustrates a second-order SQL injection boundary. The duplicate action first reads `meta_key` and `meta_value` rows for an editable source post. It escapes the values but interpolates each metadata key into a hand-built `INSERT ... SELECT` statement joined with `UNION ALL`, then passes the assembled string to `$wpdb->query()`. The attacker's first action stores a metadata key through an otherwise ordinary post-edit path; interpretation occurs later when an authorized **Save and Duplicate** operation copies that stored row.

This differs from direct request-to-query injection. Map four moments independently: **write principal -> stored bytes -> later trigger principal -> constructed SQL grammar**. A scanner that mutates only the duplicate request may miss the actual controllable input.

### Recorder-only second-order harness

1. Install 1.2.1 in a disposable WordPress database containing only synthetic posts and metadata. Create an author-owned source post and a separate clean control post.
2. Confirm which supported custom-field, REST, XML-RPC, importer, or plugin path lets that author create a metadata key on their own post. Preserve the exact capability and API used; do not assume every WordPress role can set arbitrary keys.
3. Store an inert delimiter-shaped canary key containing a quote marker and unique token, plus a plain control key. The marker must not contain a second SQL statement, comment sequence, data-extraction expression, timing function, or destructive verb.
4. Replace or wrap `$wpdb->query()` in the lab so the duplicate action records the final SQL string and returns without executing it. Trigger **Save and Duplicate** through the normal UI as the same author and, separately, as an expected editor.
5. Compare the stored key bytes, values returned by the first metadata query, final recorded SQL, and tokenized SQL parse. The key should remain one bound data value; if the marker changes quote/token boundaries in the recorded grammar, the sink is reachable.
6. Exercise controls for a plain key, delimiter-shaped metadata **value**, protected-key prefix, metadata belonging to another author, a post the caller cannot duplicate, and no metadata. This separates key handling, value escaping, object authorization, and trigger reachability.
7. Repeat on a corrected build or locally parameterized implementation. Require metadata copying through WordPress APIs or bound placeholders, with both key and value remaining data in the parser output.

The safe positive result is **authorized author stores inert metadata key on own post -> later duplicate action reads it -> recorder shows the key crossing a SQL token boundary**. Do not execute the malformed query against even a lab database merely to prove disclosure. Query construction plus a parser diff and the fixed control provide stronger, less destructive evidence.

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
- nonce provenance, capability result, selected option or role, request-post owner, target user, global-setting scope, payment/order binding, and resolved virtual path;
- browser, normalized, stored, and gateway-recorder amount representations for payment-integrity checks;
- first-stage metadata write authority, exact inert key hash, later duplicate trigger identity, and recorded SQL token-boundary diff for second-order checks;
- affected and fixed controls, including feature-disabled and unconfigured states;
- hashes or redacted identifiers for fake connection values, payment responses, cookies, and canary files;
- the pretix quick-setup CVE identifier discrepancy and the source attached to each identifier;
- a bounded impact statement that distinguishes option disclosure, session creation, persistent write, DOM rendering, payment replay, event mutation, filesystem read/write, and execution.

Do not infer administrator takeover from option disclosure or a harmless canary-role assignment alone, store compromise from a reversible global setting alone, XSS from stored markup alone, completed underpayment from a local gateway recorder, database disclosure from a SQL grammar diff, free tickets from a callback that did not change order state, or device code execution from filesystem reachability alone.