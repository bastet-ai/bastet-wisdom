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
- [GHSA-5mvv-43fh-86fq / CVE-2026-13178: Eventin client-selected paid order status](https://github.com/advisories/GHSA-5mvv-43fh-86fq)
- [GHSA-vx7q-rhxw-6x3x / CVE-2026-13143: WP Travel unverified PayPal IPN](https://github.com/advisories/GHSA-vx7q-rhxw-6x3x)
- [GHSA-v6g6-7m7c-3mx6 / CVE-2026-15250: Appointment Booking client-selected approval status](https://github.com/advisories/GHSA-v6g6-7m7c-3mx6)
- [GHSA-9fxw-6x9j-x2gr / CVE-2026-12687: ProfileGrid privileged-group registration](https://github.com/advisories/GHSA-9fxw-6x9j-x2gr)
- [GHSA-5cfw-whc5-jqgh / CVE-2026-14356: FleekDash registration-to-account-update chain](https://github.com/advisories/GHSA-5cfw-whc5-jqgh)
- [GHSA-vm2x-vwh2-372v / CVE-2026-15255: RegistrationMagic OTP identity mismatch](https://github.com/advisories/GHSA-vm2x-vwh2-372v)
- [GHSA-49jm-q6q7-76gc / CVE-2026-11870: WP Ghost untrusted client-IP headers](https://github.com/advisories/GHSA-49jm-q6q7-76gc)
- [GHSA-qwc9-q2f8-q72q / CVE-2026-8457: WooCommerce Social Login Apple-token verification](https://github.com/advisories/GHSA-qwc9-q2f8-q72q)
- [GHSA-mxw9-rxrv-85f3 / CVE-2026-18352: User Access Manager attachment/path selector mismatch](https://github.com/advisories/GHSA-mxw9-rxrv-85f3)
- [GHSA-2cff-wc4f-2m48 / CVE-2026-13339: CubeWP SVG file-path handling](https://github.com/advisories/GHSA-2cff-wc4f-2m48)

The GitHub records were unreviewed when this page was written. The primary pretix release uses **CVE-2026-57532** for the quick-setup issue, while the initial GitHub record used **CVE-2026-18028** for substantially the same description. Preserve that discrepancy in evidence rather than treating the identifiers as interchangeable. Confirm the exact product slug, version, route, configuration, and fixed behavior before reporting.

!!! warning "Authorized validation only"
    Use disposable WordPress sites, synthetic users and roles, fake connection values, reversible payment-setting markers, test-mode ticket orders, mocked payment responses, local SQL recorders, and owned SICK lab devices with vendor-approved canary storage. Never mint or retain a production administrator session, promote a real account, alter a real store, send a payment to a live gateway, reuse live payment confirmations, extract database data, obtain unpaid real tickets or bookings, read form submissions or customer records, read device passwords, change production vision parameters, or place Lua code on a device.

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
| Apple social login | public route proof plus decoded token email | verified Apple signature and claims bound to the configured client | invalid-signature synthetic token plus no-op session recorder |
| Protected attachment download | public attachment ID plus caller-selected file path | one canonical attachment object authorizing the exact file opened | two synthetic attachments and a read-path recorder |
| CubeWP SVG helper | public nonce and caller-selected icon URL/path | server-selected media object confined to an approved SVG root | sibling SVG-text canary and patched read recorder |

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

## July 30 follow-up: bind public workflow state to server authority

The next WordPress advisory wave adds three related workflow checks. Eventin before 4.1.16 accepts a client-selected order status while creating an order; Appointment Booking Plugin before 5.6.8 lets the public booking funnel set an approval-status field; and WP Travel before 11.8.1 accepts a PayPal Instant Payment Notification without completing the provider post-back verification handshake. In each case, a browser or callback supplies a state label that the application later treats as an authoritative business transition.

### State-transition recorder

1. Use a disposable site with fake events, trips, appointments, customers, prices, and payment-provider credentials. Disconnect outbound networking.
2. Capture one normal request for each affected flow. Record the public fields separately from server-owned catalog, booking, order, and payment state.
3. Replace gateway verification, ticket issuance, email, webhook, and fulfillment sinks with local counters. No real booking or deliverable should be created.
4. For Eventin and Appointment Booking, vary status/approval fields through omitted, expected-pending, alternate valid, unknown, duplicate, and case-changed representations. Preserve the raw request and canonical persisted state.
5. For WP Travel, use a local PayPal recorder. Send missing, malformed, duplicated, and synthetic-success IPNs; record whether the plugin performs a post-back verification and binds receiver, merchant, amount, currency, booking ID, transaction ID, and lifecycle state before mutation.
6. Exercise replay, wrong-booking, wrong-user, stale, already-paid, and already-cancelled controls. Repeat on fixed builds.

The safe positive is **anonymous input supplies status or callback claim -> no server-owned transition/verification decision occurs -> synthetic order or booking reaches a paid/approved marker state**. Do not contact PayPal, reserve inventory, issue a ticket, or describe the result as financial loss without a separately authorized end-to-end proof.

## July 30 follow-up: separate registration eligibility from role and target identity

ProfileGrid before 5.9.9.8 reportedly lets an anonymous registration select a privileged group whose configured role may be administrator. FleekDash V2 through 2.6.2.2 reportedly exposes a registration route that creates a subscriber and returns a REST nonce even when normal registration is disabled, after which an account-update path can overwrite another user's email and password. RegistrationMagic before 6.0.9.4 reportedly accepts an OTP cookie without binding it to the identity whose submission is requested.

These are three different authorization edges:

| Edge | Caller proof | Missing server binding | Canary-only evidence |
| --- | --- | --- | --- |
| ProfileGrid registration | anonymous form/nonce | public-eligible group and server-chosen non-privileged role | harmless canary group and role |
| FleekDash bootstrap | newly created subscriber and returned nonce | registration policy, target user, and account-update authority | instrumented update sink targeting a second canary |
| RegistrationMagic retrieval | OTP cookie | OTP subject, requested identity, form, and submission owner | two synthetic identities and marker-only submissions |

### Two-identity lab matrix

1. Create canary users A and B, a public group, and a harmless restricted group mapped only to a custom role with no administrative capabilities. If the affected logic requires an administrator-mapped group, instrument `set_role()`/`add_role()` and stop at a call counter rather than creating that mapping.
2. For ProfileGrid, compare omitted group, public group, restricted group, nonexistent group, duplicate group parameters, and fixed-build behavior. Record the server-selected canonical role without granting privilege.
3. For FleekDash, test registration with site registration enabled and disabled. Hash any returned nonce, then replay the account-update request against self, B, a nonexistent ID, and an instrumented administrator target. The update sink must remain no-op for foreign targets.
4. For RegistrationMagic, issue separate short-lived OTPs for A and B. Cross the A cookie with B's identity, form, and submission identifiers one field at a time. Return only synthetic marker IDs, never submission bodies.
5. Invalidate all canary sessions and OTPs after testing. Repeat every matrix on a corrected release.

Report **anonymous group selection**, **self-provisioned nonce**, **foreign account-update sink reachability**, and **cross-identity OTP acceptance** separately. Do not create an administrator, change a real email/password, or read personal form data.

## July 30 follow-up: test client-IP provenance as a proxy chain

WP Ghost before 7.0.05 reportedly trusts client-IP HTTP headers without proving that they came from an approved reverse proxy. That can affect its own brute-force controls and match a hardcoded allowlisted range. This is a hop-by-hop identity issue, not merely “IP spoofing.”

1. Reproduce the deployed edge chain in a lab: direct client, approved proxy, WordPress origin, and the plugin. Give each hop a distinct synthetic address.
2. Record which headers each proxy strips, appends, or overwrites and which address the plugin finally chooses.
3. Test direct requests with `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, duplicate headers, comma lists, quoted forms, whitespace, IPv4-mapped IPv6, and malformed values. Use only canary addresses.
4. Exercise one harmless plugin decision behind counters: allowlist match and brute-force-attempt bucket. Do not submit password guesses or target WordPress core authentication.
5. Require the fixed control to trust forwarding headers only when the immediate peer is an explicitly configured proxy and to choose the client hop through one documented canonicalization rule.

A bounded positive is **untrusted direct peer supplies forwarding header -> plugin selects attacker-controlled canary address -> allowlist or rate-bucket decision changes**. Do not infer bypass of a WAF, upstream proxy, WordPress core login control, or another security plugin.

## July 31 follow-up: authentication proofs, workflow authority, and artifact exposure

The July 31 unreviewed feed adds six durable WordPress checks. Sources: [Realtyna authenticated upload GHSA-2982-9p75-vfp8](https://github.com/advisories/GHSA-2982-9p75-vfp8), [Realtyna static-credential upload GHSA-cfr3-ggcx-jjf3](https://github.com/advisories/GHSA-cfr3-ggcx-jjf3), [FlxWoo payment-state GHSA-j2wf-m8xp-xm7q](https://github.com/advisories/GHSA-j2wf-m8xp-xm7q), [ShopMonitor trusted-source GHSA-g4w8-444w-x9q8](https://github.com/advisories/GHSA-g4w8-444w-x9q8), [miniOrange 2FA GHSA-24j9-5c5r-9c88](https://github.com/advisories/GHSA-24j9-5c5r-9c88), [Demi backup GHSA-q89r-49r9-5hmx](https://github.com/advisories/GHSA-q89r-49r9-5hmx), and [Kirki stored-deserialization GHSA-rpvq-6gf9-58vg](https://github.com/advisories/GHSA-rpvq-6gf9-58vg). Confirm the exact plugin slug, version, reachable function, and corrected behavior before reporting.

### Static plugin proof must not become installation-wide authority

Realtyna illustrates two paths into the same file sink: subscriber-reachable key retrieval plus a weakly gated import route, and a public I/O endpoint whose API values are reportedly seeded identically across installations. In a disposable site, replace the upload/move sink with a recorder and use a benign GIF-like marker carrying a non-executable extension.

1. Compare anonymous, subscriber, and administrator contexts for key retrieval, REST import, and public I/O route families.
2. Test generated per-installation fake credentials against static migration-seeded fake credentials. Never publish or replay the vendor defaults.
3. Record authentication proof acceptance separately from extension/content validation and final public-path selection.
4. Stop when the recorder receives the benign marker and proposed canonical path. Do not upload PHP, probe a real media library, or request execution.

The safe positive is **public or low-role caller -> reusable installation-independent proof or insufficient route authorization -> file recorder accepts attacker-selected bytes/path**. “Upload returned 200” is insufficient, and code execution remains unproven without a separately authorized executable sink—which this workflow deliberately avoids.

### Bind 2FA to the server-held subject secret

Create users A and B with disposable passwords and TOTP seeds. Intercept the final session-creation sink. For B's login, cross server-held seed B with a caller-supplied seed or provisioning value controlled by A, then submit an OTP generated only from A's value. Exercise missing, malformed, expired, replayed, wrong-user, and fixed-build controls.

The proof is **B's valid first factor -> OTP checked against attacker-supplied material rather than B's enrolled server secret -> no-op session sink for B increments**. Do not target an administrator, preserve QR/provisioning URIs, or create a live privileged session.

### Bind payment and email-routing transitions to server authority

- **FlxWoo:** replace the payment provider with a local recorder and fulfillment with a counter. Submit paid, unpaid, unknown, wrong-order, replayed, and malformed checkout-session states. The counter must move only after server-to-provider verification binds payment status, merchant, amount, currency, order, and transaction ID.
- **ShopMonitor:** reproduce direct client, approved proxy, and origin hops. Supply forwarding/trusted-source headers only with canary addresses and replace email delivery with a recorder. Trigger password reset only for a disposable user. A positive requires an untrusted direct request to satisfy source trust and change the recorder destination; do not deliver mail or take over an account.

### Treat backups and stored objects as two-stage boundaries

- **Demi backup exposure:** create a synthetic backup containing only a unique marker, record its generated URL, then test anonymous access during and after export. Compare predictable-name guesses, directory listing disabled, expired/removed artifact, and fixed-build controls. Stop at the marker; never download a real database, hashes, configuration, or media.
- **Kirki stored deserialization:** store an inert serialized object whose permitted test class only increments a recorder when instantiated. Capture write principal, stored bytes, later administrator-review trigger, allowed-class decision, and recorder event separately. Use no magic method that executes commands, reads files, makes network requests, or mutates application state.

These are compound chains. Public artifact naming does not prove sensitive content unless the synthetic marker is returned; attacker-controlled storage does not prove object injection until the later deserializer instantiates the inert class.

## July 31 follow-up: transaction proofs and unauthenticated REST mutation

Three adjacent plugin records add reusable object-proof and route-authorization checks:

- [Fluent Forms GHSA-gx6f-fm4p-x72r / CVE-2026-17567](https://github.com/advisories/GHSA-gx6f-fm4p-x72r) says payment receipt lookup accepts a bounded, guessable transaction hash derived from observable submission/form/time context;
- [MailerPress GHSA-gjcp-gv56-hccw / CVE-2026-18437](https://github.com/advisories/GHSA-gjcp-gv56-hccw) says `mailerpress/v1/contact` permits unauthenticated contact updates through 1.5.0; and
- [MailPress GHSA-vfgx-g9m5-wfgv / CVE-2026-18436](https://github.com/advisories/GHSA-vfgx-g9m5-wfgv) says the campaign revision-restore route was registered without a permission callback through 1.5.0.

The GitHub records were unreviewed at scan time. Confirm the exact plugin slug—the records use both **MailerPress** and **MailPress**—version, route registration, identifier construction, and corrected behavior before reporting.

### Fluent Forms: measure proof entropy without collecting receipts

Use a disposable site containing only two synthetic forms, submissions, transactions, and payment receipts. Replace receipt rendering with a recorder that returns the matched canary transaction ID and no customer fields.

1. Create transactions A and B with distinct marker amounts/statuses and record the server-side inputs used to construct their public transaction proofs.
2. Capture A's legitimate receipt URL. Change submission ID, form ID, transaction timestamp component, and proof one field at a time.
3. Reconstruct the candidate space only for B's synthetic tuple. Rate the local function or recorder, not a network endpoint, and record candidate count, alphabet, entropy assumptions, and first match.
4. Exercise random, expired, wrong-form, wrong-submission, wrong-time-window, cross-session, and fixed-build controls.
5. Stop when B's canary transaction ID reaches the recorder. Do not render or retain names, email addresses, billing addresses, order items, payment methods, or any production receipt.

The bounded positive is **anonymous caller plus observable synthetic object context -> practical search over transaction proof -> foreign canary transaction reaches the receipt-selection sink**. Do not call the proof predictable solely because it is short; demonstrate the effective candidate space under the application's actual construction and validation rules.

### MailerPress/MailPress: inventory permission callbacks and object binding

Create two contacts and two campaigns owned by a disposable administrator. Campaign A should have two plain-text revisions; campaign B is the foreign-object control. Intercept contact writes and campaign content writes with reversible recorders where possible.

| Route | Anonymous | Low role | Expected manager | Required secure decision |
| --- | --- | --- | --- | --- |
| `mailerpress/v1/contact` | reject | reject unless explicitly delegated | update in-scope canary | authenticate, check capability, bind contact ID and writable fields |
| campaign restore-revision route | reject | reject unless explicitly delegated | restore revision belonging to campaign | authenticate, check campaign capability, bind revision to parent campaign |

1. Enumerate the WordPress REST route definitions and capture `permission_callback`, accepted methods, argument schema, and handler names. Source evidence is useful, but retain a request-to-sink control as well.
2. For contact update, test omitted ID, own canary, foreign canary, nonexistent ID, duplicate ID, and immutable-looking fields. Change only a reversible marker field; never use a real subscriber record or email address.
3. For revision restore, cross campaign A with A's revision, campaign A with B's revision, campaign B with A's revision, nonexistent IDs, and an already-current revision. Instrument the content assignment sink or use plain-text markers only.
4. Record authentication, capability decision, canonical object lookup, parent-child binding, before/after marker hashes, and response independently.
5. Restore all canaries and repeat on a corrected build.

The safe positives are **anonymous REST request -> contact write recorder accepts a foreign canary ID** and **anonymous REST request -> revision restore changes a synthetic campaign without a capability decision**. A route visible in the REST index or a missing callback in source is not by itself proof of mutation. A valid revision must also belong to the selected campaign; otherwise report parent-child authorization drift separately.

## August 1 follow-up: plan roles, attachment paths, and structural markup allowlists

Three WordPress plugin records add reusable composition checks:

- [Subscriptions for WooCommerce GHSA-x6w6-m8vc-m6cp / CVE-2026-15414](https://github.com/advisories/GHSA-x6w6-m8vc-m6cp), with the [2.0.0 plan save handler](https://plugins.svn.wordpress.org/subscriptions-for-woocommerce/tags/2.0.0/includes/membership/class-wps-membership-plan-cpt.php);
- [Bit Integrations GHSA-j262-2rh9-xjv4 / CVE-2026-15006](https://github.com/advisories/GHSA-j262-2rh9-xjv4), with the [2.9.0 mail attachment handler](https://plugins.svn.wordpress.org/bit-integrations/tags/2.9.0/backend/Actions/Mail/MailController.php) and [Contact Form 7 trigger](https://plugins.svn.wordpress.org/bit-integrations/tags/2.9.0/backend/Triggers/CF7/CF7Controller.php); and
- [SendPulse Email Marketing Newsletter GHSA-5jrx-957p-3f93 / CVE-2026-13362](https://github.com/advisories/GHSA-5jrx-957p-3f93), with the [2.2.5 form-meta writer](https://plugins.svn.wordpress.org/sendpulse-email-marketing-newsletter/tags/2.2.5/inc/class-senpulse-newsletter-forms.php) and [shortcode renderer](https://plugins.svn.wordpress.org/sendpulse-email-marketing-newsletter/tags/2.2.5/inc/class-senpulse-newsletter-shortcodes.php).

The records were unreviewed at scan time. Confirm the exact free/Pro plugin combination, configured integration flow, custom-post capability mapping, reachable render path, and corrected behavior before reporting.

### Compose content capabilities with delayed role assignment

Subscriptions for WooCommerce 2.0.0 registers `wps_membership_plan` with the ordinary `post` capability model. Its plan save handler accepts a valid plan nonce plus `edit_post`, sanitizes `_wps_plan_user_role` as a key, verifies only that the slug names a registered role, and stores it. The advisory says the Pro companion later reads that meta and applies the role during membership lifecycle events. A disabled role selector in the browser is not a server policy, and “registered role” is not a safe privilege allowlist.

1. Use a disposable site with the exact affected free/Pro combination, a synthetic contributor, and a harmless custom role with no administrative capabilities. Replace the Pro role-application sink with a recorder when possible.
2. Determine whether the contributor can create or edit a membership-plan post and obtain the plan nonce. Preserve nonce provenance and a hash, not the token.
3. Capture an ordinary plan save, then vary only `_wps_plan_user_role`: omitted, harmless custom role, nonexistent slug, expected membership role, and a privileged-looking slug sent only to a recorder that rejects before mutation.
4. Trigger each configured purchase, subscription, auto-enrolment, expiry, and removal lifecycle path using synthetic users and products. Record plan ID, canonical stored slug, lifecycle event, target canary user, and the argument reaching `add_role()` or its equivalent.
5. Repeat on the corrected build. Require a plan-management capability separate from generic content editing and a server-side allowlist containing only purpose-built membership roles.

The bounded positive is **content-editing principal -> editable plan plus valid nonce -> caller-selected harmless role persists -> later membership event reaches the role-assignment recorder without promotion authority**. Do not request `administrator`, grant capabilities, buy a real product, or create a privileged session. Report edit-screen reachability, persistence, and delayed role application as separate edges.

### Trace public form fields into mail attachment paths

Bit Integrations 2.9.0 merges Contact Form 7 posted data with uploaded-file values, then executes configured flows. Its mail action treats the configured attachment selector as a key into that field map; `processAttachment()` accepts each readable path and forwards it to `wp_mail()` without a visible allowed-root check. This is a configured chain: anonymous form submission alone is not enough unless an attacker-controlled field is selected as the mail attachment input and survives into the action.

1. Build a disposable WordPress/Contact Form 7/Bit Integrations site with one public canary form and a mail flow whose transport is replaced by an attachment-path recorder. Disable real email delivery.
2. Seed a normal uploaded-file canary inside the expected temporary upload root and a second plain-text canary in a disposable sibling directory. No WordPress configuration, keys, user data, logs, or host files should exist in the lab.
3. Record the configured attachment field name. Submit expected upload metadata, a plain field containing the sibling canary path, relative and absolute benign path forms, a nonexistent path, a directory, a symlink to an in-root canary, and a symlink to the sibling canary. Change one representation at a time.
4. Intercept `wp_mail()` before it opens or sends attachments. Capture only the canonical paths proposed by the plugin and return a synthetic success response; do not attach, copy, or email the sibling file.
5. Establish controls with no matching flow, a flow whose attachment selector names only the real upload field, authenticated-only form access, unreadable canaries, and the corrected plugin.

A safe positive is **anonymous synthetic submission -> configured attachment field -> readable sibling-canary path reaches the mail attachment recorder outside the approved upload root**. A public form, readable local path, or mail-flow configuration by itself is insufficient. Do not use traversal to read content; path selection plus canonical-root evidence proves the boundary.

### Validate the whole markup tree, not one approved child

SendPulse 2.2.5 stores raw `_sp_form_code` for users who can edit a `sendpulse_form`. The shortcode renderer parses that string, verifies that the DOM contains exactly one `script` whose host and attributes are allowed, then returns the **entire original string** unchanged. The structural mismatch is durable: a validator approves one descendant while the renderer trusts the complete container, including sibling elements it did not validate.

1. Use a disposable site, synthetic contributor, test form post, and a page containing only the test shortcode. Block outbound requests and replace browser script/event/navigation sinks with counters.
2. First store one inert script element whose `src` uses an approved host but is prevented from loading. Confirm that the validator's positive branch returns the original markup.
3. Add harmless sibling markup carrying a unique `data-*` marker before and after the approved script. Do not use event handlers, external resources, forms, navigation, CSS, or executable JavaScript.
4. Record the raw stored string, DOM tree seen by the validator, selected script count/host/attributes, returned output bytes, final page DOM, and marker presence.
5. Exercise controls with zero scripts, two scripts, a non-approved host, a disallowed script attribute, sibling text only, malformed nesting, contributor versus expected manager, and the corrected build.

The safe positive is **low-role author stores container markup -> validator approves its one allowed script descendant -> renderer returns unvalidated sibling markup unchanged -> inert sibling marker appears in the shortcode DOM**. This proves policy-scope drift, not script execution. Claim stored XSS only when an independently authorized harmless browser counter demonstrates an executable sink; do not load SendPulse or any attacker-controlled host during validation.

## August 1 follow-up: test file confinement in every root-lifecycle state

[FormGent GHSA-68f5-7j6g-q5r2 / CVE-2026-3141](https://github.com/advisories/GHSA-68f5-7j6g-q5r2) adds a filesystem-validation edge that is easy to miss when a test fixture creates its upload directory too early. In versions through 1.9.2, the public `responses/attachments` route family includes a delete handler that base64-decodes a caller-supplied file token, appends it beneath the WordPress uploads path, resolves the result with `realpath()`, and compares it with `realpath()` of the intended `uploads/formgent` root. The [1.9.2 controller](https://plugins.svn.wordpress.org/formgent/tags/1.9.2/app/Http/Controllers/AttachmentController.php) builds that comparison even when the intended root does not exist. The advisory reports that this default post-install state weakens the containment check and permits traversal outside the FormGent directory. The [1.10.0 controller](https://plugins.svn.wordpress.org/formgent/tags/1.10.0/app/Http/Controllers/AttachmentController.php) instead validates a structured file token and resolves an existing upload path through a dedicated helper.

This is two independent boundaries: **may the caller invoke deletion**, and **is the resolved existing target inside the intended root for every root state**. A happy-path test performed only after the first FormGent upload may exercise a different branch from a fresh installation.

### Disposable sibling-canary matrix

1. Use a disposable WordPress site and snapshot it immediately after installing FormGent 1.9.2. Do not submit a form or upload an attachment before capturing the **root absent** fixture.
2. Create only harmless marker files in disposable directories: one beneath the intended FormGent root for the **root present** fixture and one sibling canary beneath the lab uploads directory. Do not place canaries at `wp-config.php`, plugin/theme paths, media owned by another user, logs, backups, or operating-system paths.
3. Confirm route registration, method, authentication middleware or permission callback, and normalized request parameters from source and a normal request. Record anonymous, subscriber, expected form submitter, and administrator decisions independently; route visibility alone is not proof that deletion reaches the sink.
4. Replace `wp_delete_file()` with a recorder if possible. Feed it a normal in-root token, a nonexistent target, an encoded sibling-canary traversal, repeated separators, dot segments, mixed separator forms relevant to the host, and malformed base64. The recorder should retain only the proposed canonical path and whether it is inside the expected root.
5. Run the same matrix with the FormGent root absent, present, replaced by a file, and represented through a symlink to another disposable directory. Recreate the snapshot between cases so one upload does not silently change the root lifecycle state.
6. If sink-level proof is explicitly required, permit deletion only of the disposable sibling canary, verify its pre/post hash and absence, then restore the fixture. Stop after one marker. Never delete application configuration or use a missing configuration file to trigger WordPress reinstallation.
7. Repeat on 1.10.0. Require malformed or unsigned tokens, traversal-shaped relative paths, symlink escapes, and targets outside the canonical upload root to fail before the delete sink in every lifecycle state.

The bounded positive is **anonymous delete request -> caller-selected token resolves to the disposable sibling canary while the FormGent root is absent -> delete recorder accepts that outside-root path**. An optional marker-only deletion can confirm impact in the lab, but site takeover is not necessary and must not be attempted. Report root state, token representation, canonical target, route authorization, and sink decision separately.

Generalize this check to any upload, cache, extraction, or workspace helper that calls `realpath()` on both a candidate and an intended base. Build explicit fixtures for absent, empty, populated, symlinked, moved, and permission-denied roots; reject on any failed canonicalization before comparing paths.

## August 1 follow-up: bind identity proofs to one subject and one browser flow

The August 1 WordPress wave adds several authentication failures that look different at the route level but share one durable question: **which server-held subject and initiating browser flow does this proof authorize?** Relevant records were unreviewed at scan time:

- [Single Sign On For TNG unauthenticated password reset GHSA-75h6-5h53-j8cq](https://github.com/advisories/GHSA-75h6-5h53-j8cq)
- [User Profile Builder post-registration login binding GHSA-p782-jwj4-rqqc](https://github.com/advisories/GHSA-p782-jwj4-rqqc)
- [Authora one-time-code disclosure GHSA-qh94-hqp6-76h4](https://github.com/advisories/GHSA-qh94-hqp6-76h4)
- [Login & Register Forms reset-counter binding GHSA-79h9-6m37-f387](https://github.com/advisories/GHSA-79h9-6m37-f387)
- [Chat On Desk OTP-state enforcement GHSA-ggm5-8542-75h6](https://github.com/advisories/GHSA-ggm5-8542-75h6)
- [Builderall OAuth `state` session binding GHSA-q7qm-9x83-phwf](https://github.com/advisories/GHSA-q7qm-9x83-phwf)
- [DynamicKit reset-link authority selection GHSA-wrwc-chj8-j397](https://github.com/advisories/GHSA-wrwc-chj8-j397)
- [YOP Poll forwarding-header vote-limit bypass GHSA-jqjg-6w6p-5mh7](https://github.com/advisories/GHSA-jqjg-6w6p-5mh7)

Confirm the exact plugin slug, affected version, feature configuration, route, and fixed behavior. A WordPress nonce is request provenance, not account ownership. An OTP or OAuth `state` value is useful only when the server binds it to the intended subject, purpose, initiating session, attempt budget, and expiry. A reset key can still be compromised if the requester chooses the authority placed into the emailed link.

### Two-user proof-binding matrix

1. Use a disposable site, users A and B, a local mail sink, fake mobile numbers, fake OAuth credentials, and an intercepted session-creation sink. Neither user should have administrative capabilities.
2. Record each flow as a tuple: `initiating browser`, `subject`, `purpose`, `proof`, `attempt bucket`, `redirect authority`, and `final sink`. Hash short-lived proofs in retained evidence.
3. For the TNG reset route, vary valid public nonce, email A/B, operation name, missing ownership proof, and fixed-build behavior. Intercept `reset_password()` before mutation. A public nonce must not authorize a caller-selected account reset.
4. For User Profile Builder, create user A through the affected non-default registration mode, then vary any caller-controlled identity field so the post-registration login resolver points at A, B, a nonexistent ID, and a recorder-only privileged sentinel. The newly created canonical user ID—not a request value—must select the session subject.
5. For Authora and Chat On Desk, cross A's OTP request, verification token, claimed mobile number, verification state, and reset request with B one field at a time. The issue is proven when the response exposes a usable proof or the reset/session recorder for B increments without a server-held verified state for B; do not create a live session or change a password.
6. For Login & Register Forms, keep the target fixed and vary the unauthenticated value used to key the code and attempt counter. Use a patched verifier with a tiny synthetic code space and no password mutation. Show whether changing that value resets the budget while the same target/code verification remains reachable; never brute-force a network endpoint.
7. For Builderall, start independent OAuth flows in browsers A and B against a mocked provider. Cross `state`, callback code, browser cookie, and already-connected integration state. Record only which fake token would reach the option-write recorder. Durable overwrite and first-time connection are separate cases.
8. For DynamicKit, submit only owned callback authorities and capture the local mail sink. Compare configured site origin, caller-selected origin, userinfo, explicit port, mixed case, trailing dot, encoded separators, and malformed values. Redact the reset key; the result is the authority decision, not account takeover.
9. Repeat all cases on corrected builds and require single-use proofs, one subject, one purpose, one initiating session, a server-side attempt budget, and a server-owned reset-link authority.

The bounded positives are **public request proof -> foreign-subject reset/session recorder**, **same target plus caller-resettable counter -> verification budget restarts**, **OAuth callback from browser B -> browser A's fake integration token is replaced**, or **caller URL -> valid synthetic reset key is addressed to an owned foreign authority**. Report these separately; do not collapse them into generic “authentication bypass.”

YOP Poll belongs in the same identity-provenance family but uses a network principal. Recreate direct client, approved proxy, and origin hops; test only synthetic forwarding addresses and a vote-counter recorder. A positive is **untrusted immediate peer -> caller header selects the rate-limit identity -> a second canary vote reaches the recorder**. Do not manipulate a public poll or infer that another proxy or security control is bypassed.

## August 1 follow-up: separate object ownership from business-action authority

The same wave exposes reusable role, order, ticket, and delegated-credential boundaries:

- [Pronamic Pay caller-selected user role GHSA-72h4-7f42-rjh6](https://github.com/advisories/GHSA-72h4-7f42-rjh6)
- [RealHomes Memberships unverified premium tier GHSA-mm9c-22g4-wf37](https://github.com/advisories/GHSA-mm9c-22g4-wf37)
- [Direct Payments for WooCommerce order mutation GHSA-cp6p-3j8j-57c9](https://github.com/advisories/GHSA-cp6p-3j8j-57c9)
- [Buckaroo refund authorization GHSA-63p2-7wgc-gxrq](https://github.com/advisories/GHSA-63p2-7wgc-gxrq)
- [Event Tickets order-status mutation GHSA-rpwc-gx32-cjcf](https://github.com/advisories/GHSA-rpwc-gx32-cjcf)
- [Event Tickets seating-object authorization GHSA-cfmh-2g6m-xpvm](https://github.com/advisories/GHSA-cfmh-2g6m-xpvm)
- [Fluent Support per-ticket customer reassignment GHSA-vprj-v253-jvjv](https://github.com/advisories/GHSA-vprj-v253-jvjv)
- [Pixel Tag Manager delegated conversion event GHSA-9mjw-584w-6228](https://github.com/advisories/GHSA-9mjw-584w-6228)
- [Pixelavo delegated conversion event GHSA-gm56-v4px-r8mh](https://github.com/advisories/GHSA-gm56-v4px-r8mh)

### No-op business-action harness

1. Build a two-user lab with orders A/B, tickets A/B, events A/B, one harmless custom role, and mocked payment/advertising providers. Replace refunds, fulfillment, email, role assignment, inventory writes, and external API dispatch with argument recorders.
2. For Pronamic Pay, use the ordinary Gravity Forms path and vary only the role field. Confirm form ownership and the caller's current role independently. Send a harmless role to `set_role()`; send privileged-looking slugs only to a rejecting recorder.
3. For RealHomes and Direct Payments, cross user A's request with order/membership objects owned by A and B. Vary status, tier, payment label, and proof-file metadata independently. Persist only marker states and restore them immediately.
4. For Buckaroo and Event Tickets, compare anonymous, subscriber, contributor, scoped event manager, and expected operator. A valid nonce does not replace a refund/order capability check; event-level edit access does not authorize every seating layout or attendee assignment.
5. For Fluent Support, create agents scoped to separate synthetic inboxes. Cross ticket ID, current customer, replacement customer, inbox, and agent one field at a time. Stop at a no-op reassignment recorder; never read ticket bodies.
6. For Pixel Tag Manager and Pixelavo, block outbound networking and substitute a local conversion-API recorder loaded with a fake token. Compare missing, public-page, stale, wrong-action, and expected nonces plus malformed event fields. Record whether an anonymous caller can spend the site's delegated API authority, not whether the provider accepted an event.
7. Repeat on fixed builds and require capability, object ownership, parent-child scope, writable-field allowlists, server-side payment state, and idempotency before any sink.

The safe result is a decision table showing **caller -> proof -> canonical object -> required capability -> recorder action**. A JSON success, guessed object ID, or public nonce alone is not enough. Do not issue refunds, alter real orders, grant premium service, reassign customer records, modify event inventory, or send advertising events.

## August 1 follow-up: prove chained filesystem selectors without touching host files

Two records add useful multi-stage filesystem checks:

- [Nex Forms stored-location to deletion chain GHSA-2446-gfm3-96v2](https://github.com/advisories/GHSA-2446-gfm3-96v2)
- [Support Genix ticket-attachment traversal GHSA-g8p2-p6hq-8pw4](https://github.com/advisories/GHSA-g8p2-p6hq-8pw4)

Nex Forms reportedly lets the same authenticated principal first store a caller-selected `location` value and later send the resulting record through a deletion handler that passes the stored path to `unlink()`. Support Genix reportedly applies an extension allowlist to an attachment-download selector without first proving that the canonical file belongs to the selected ticket and attachment root. HTML sanitization does not make a string safe as a path, and an extension allowlist does not provide confinement.

1. Use disposable directories containing only an in-root attachment and a sibling text canary. Patch `unlink()` and file-open/read helpers to record canonical paths without deleting or returning content.
2. For Nex Forms, capture write principal, stored raw bytes, canonicalized stored value, deletion trigger principal, and final sink argument separately. Test own record, foreign record, nonexistent record, relative sibling path, absolute sibling path, mixed separators, and symlinked canaries.
3. For Support Genix, compare valid own-ticket attachment ID, foreign-ticket attachment ID, sibling canary with an allowed extension, disallowed extension, encoded separators, duplicate path parameters, and fixed-build behavior. Stop when the recorder receives an outside-root path.
4. Require corrected builds to resolve an attachment by a server-side object ID, bind it to the selected ticket and caller, canonicalize an existing target, verify root containment, reject symlink escape, and only then open or delete it.

The bounded positives are **authorized first-stage record write -> stored synthetic path -> later delete recorder receives sibling canary** and **download route -> extension-approved but outside-root sibling path reaches read recorder**. Do not delete a file, return canary content, inspect another user's ticket, or use configuration, credential, log, backup, plugin, or operating-system paths.

## August 2 follow-up: verify token cryptography before identity lookup

[WooCommerce Social Login GHSA-qwc9-q2f8-q72q](https://github.com/advisories/GHSA-qwc9-q2f8-q72q) reports that versions through 2.8.7 decode an Apple `id_token` payload but do not verify its signature against Apple's keys or validate issuer, audience, or expiry before using the email claim to select a WordPress user. The same record says the route nonce is localized into the public login page. The durable chain is therefore **public request proof -> unverified token claims -> email-to-account lookup -> session sink**. A public nonce is expected CSRF/request-provenance material; it cannot replace cryptographic token verification or account binding.

The record was unreviewed and did not link public plugin source at scan time. Treat the route and affected-version details as a lead until reproduced against the exact commercial package. Do not infer behavior from a similarly named plugin.

### Synthetic Apple-token decision matrix

1. Use a disposable WordPress site, the exact affected package, users A and B with no administrative capabilities, fake Apple client settings, blocked outbound networking, and an intercepted `wp_set_auth_cookie()` or equivalent session sink.
2. Fetch the normal logged-out login page and record whether it publishes the route nonce. Hash the nonce in retained evidence; do not call its public availability a disclosure by itself.
3. Build only synthetic JWT-shaped fixtures. Keep B's fake lab email in the payload and vary valid structure, invalid signature, unknown key ID, wrong issuer, wrong audience, expired `exp`, future `iat`, missing email, duplicate claim keys, and malformed base64 one property at a time. Do not use a real Apple identity or signing key.
4. Patch the session sink to record the resolved canary user ID and return without setting a cookie. Record token parsing, key selection, signature decision, claim validation, email normalization, account lookup, and sink reachability independently.
5. Include random/missing nonce, expected public nonce, unknown email, A/B email crossover, existing linked account, and fixed-build controls. A corrected flow must reject before identity lookup when signature or required claims fail and must bind the token's audience to the configured Apple client.

The bounded positive is **logged-out visitor obtains ordinary route nonce -> invalid-signature synthetic token naming B -> B reaches the no-op session recorder without signature/issuer/audience/expiry acceptance evidence**. Do not mint an administrator token, set a live cookie, reuse a real Apple token, or retain a login proof.

## August 2 follow-up: bind authorization and file selection to one attachment

[User Access Manager GHSA-mxw9-rxrv-85f3](https://github.com/advisories/GHSA-mxw9-rxrv-85f3) reports a selector mismatch through 2.3.15: a caller supplies the file representation through `uamgetfile`, while a valid public `attachment_id` can leave a global post available for the access decision when URL-to-attachment resolution returns zero. The [2.3.14 redirect controller](https://plugins.svn.wordpress.org/user-access-manager/tags/2.3.14/src/Controller/Frontend/RedirectController.php) confirms the relevant shape: it converts the supplied URL into a filesystem path, resolves an attachment ID through `attachment_url_to_postid()`, checks access on the resulting `FileObject`, and then sends that object's path to the file handler. The [file handler](https://plugins.svn.wordpress.org/user-access-manager/tags/2.3.14/src/File/FileHandler.php) eventually opens an existing path for delivery.

The reusable question is whether **the object that passed authorization is the same canonical object whose bytes reach the read sink**. Never test this by requesting `wp-config.php`, credentials, backups, logs, another tenant's media, or operating-system files.

### Two-selector read-recorder workflow

1. Build a disposable site with public attachment A, restricted attachment B, and a sibling plain-text canary outside the approved upload root. Patch `fopen()`, range delivery, and accelerator-header helpers to record the proposed canonical path and return no content.
2. Capture a normal protected-download request. Vary `attachment_id`, `uamfiletype`, and `uamgetfile` independently: A/A, B/B, A/B, B/A, nonexistent object, traversal-shaped sibling canary, absolute canary path, encoded separators, duplicate parameters, and symlink aliases.
3. For every case record the raw selectors, `attachment_url_to_postid()` result, global/current post ID, `FileObject` ID and type, access decision, constructed path, canonical path, and final recorder call. Reset global query state between requests so fixture leakage is visible rather than accidental.
4. Repeat without `attachment_id`, with an invalid ID, with a private current post, and after a clean WordPress bootstrap. This determines whether the claimed fallback genuinely depends on request-populated global state.
5. Repeat on the corrected changeset/build. Require a failed URL lookup to reject, one server-resolved attachment ID to drive both access and path selection, canonical upload-root confinement, and symlink-safe open behavior.

The bounded positive is **public attachment A authorizes -> caller-selected sibling canary remains the read target -> recorder receives the outside-root path while the authorized object ID is still A**. A mismatched response, path-construction observation, or source-only fallback is insufficient without sink reachability. Stop before opening or returning the canary.

## August 2 follow-up: distinguish a public nonce from SVG file authority

[CubeWP Framework GHSA-2cff-wc4f-2m48](https://github.com/advisories/GHSA-2cff-wc4f-2m48) reports unauthenticated path traversal through 1.1.30 when a posts shortcode or widget with AJAX loading publishes the required nonce. The [1.1.30 `cubewp_get_svg_content()` source](https://plugins.svn.wordpress.org/cubewp-framework/tags/1.1.30/cube/functions/admin-functions.php) confirms a file-authority sink: it accepts an icon structure, can translate a URL beginning with the site/home URL into an `ABSPATH` path, and calls `file_get_contents()` when that path exists. The advisory establishes the claimed public route; source confirms the helper sink. Reproduce the request-to-helper edge before reporting the full chain.

### Patched SVG-read harness

1. Use a fresh CubeWP 1.1.30 lab with one public AJAX-loaded posts widget, an in-root inert SVG marker, and a sibling text canary containing SVG-like plain text. Block outbound networking and patch `file_get_contents()` plus `wp_safe_remote_get()` to argument recorders.
2. Fetch the widget anonymously and record nonce provenance, action name, icon structure, and route registration. Compare missing, random, expired, public-page, subscriber, and administrator nonce values; nonce acceptance is not file authorization.
3. Submit only canary selectors: registered attachment ID, expected local SVG URL, dot-segment sibling URL, encoded separators, URL with userinfo/port, duplicate URL fields, symlinked in-root path, symlink to the sibling canary, nonexistent path, and an owned remote callback URL handled only by the recorder.
4. Record raw URL, prefix check, URL-to-path replacement, normalized/canonical path, selected branch, and recorder argument. Do not let the helper read or render the sibling file and do not contact an internal service.
5. Repeat on the corrected changeset/build. Require a server-resolved media attachment, verified SVG type/content policy, canonical containment beneath the approved media root, symlink rejection, and an explicit outbound-fetch policy before either sink.

The bounded positive is **anonymous widget yields ordinary nonce -> caller-selected local URL survives into `cubewp_get_svg_content()` -> patched reader receives the sibling canary outside the approved media root**. This proves file-selector authority drift, not disclosure of a real secret. Treat the remote-fetch fallback as a separate SSRF surface and claim it only when an owned callback records a request after final-destination policy checks.

## August 2 follow-up: bind every proof, selector, and delegated capability to one object

The next unreviewed WordPress wave adds eighteen reusable checks. They belong here because each composes an apparently valid proof or low-role capability with a second selector the server fails to bind:

- appointment bulk scope and unauthenticated deletion: [GHSA-j5pv-734r-xv95 / CVE-2026-16540](https://github.com/advisories/GHSA-j5pv-734r-xv95);
- file-metadata update to download selection: [GHSA-2rf9-6fhx-g6mg / CVE-2026-16292](https://github.com/advisories/GHSA-2rf9-6fhx-g6mg);
- unauthenticated media-ID download: [GHSA-953r-r7wf-54g9 / CVE-2026-16285](https://github.com/advisories/GHSA-953r-r7wf-54g9);
- foreign notification and attachment deletion: [GHSA-77fq-7qxg-43vp / CVE-2026-16291](https://github.com/advisories/GHSA-77fq-7qxg-43vp) and [GHSA-vpwf-36p2-3fwr / CVE-2026-15248](https://github.com/advisories/GHSA-vpwf-36p2-3fwr);
- public account create/update with a caller role: [GHSA-vrg4-ffx9-cfhg / CVE-2026-16256](https://github.com/advisories/GHSA-vrg4-ffx9-cfhg);
- reset and social-login identity binding: [GHSA-5hm3-fq9v-vwj3 / CVE-2026-16261](https://github.com/advisories/GHSA-5hm3-fq9v-vwj3) and [GHSA-rhj3-v77h-x35q / CVE-2026-12586](https://github.com/advisories/GHSA-rhj3-v77h-x35q);
- event quick-edit object authorization and delayed object deserialization: [GHSA-5hqh-mj83-f2f6 / CVE-2026-16064](https://github.com/advisories/GHSA-5hqh-mj83-f2f6) and [GHSA-xh9j-gpmv-5c2v / CVE-2026-16062](https://github.com/advisories/GHSA-xh9j-gpmv-5c2v);
- low-role navigation configuration crossing into public rendering: [GHSA-9jvp-fc5f-j7qr / CVE-2026-15385](https://github.com/advisories/GHSA-9jvp-fc5f-j7qr) and [GHSA-m349-rc55-q5w8 / CVE-2026-11872](https://github.com/advisories/GHSA-m349-rc55-q5w8);
- frontend versus REST content-policy drift: [GHSA-4v4h-6mhp-rwxf / CVE-2026-15939](https://github.com/advisories/GHSA-4v4h-6mhp-rwxf);
- public use or disclosure of stored API authority: [GHSA-xqfh-qj3w-mr75 / CVE-2026-15241](https://github.com/advisories/GHSA-xqfh-qj3w-mr75) and [GHSA-465m-pvh5-8rh9 / CVE-2026-15236](https://github.com/advisories/GHSA-465m-pvh5-8rh9);
- OTP verification detached from the selected phone/account: [GHSA-63jw-46hv-gwp2 / CVE-2026-15206](https://github.com/advisories/GHSA-63jw-46hv-gwp2);
- board import detached from source-board authorization: [GHSA-66hj-2rxc-44vr / CVE-2026-14938](https://github.com/advisories/GHSA-66hj-2rxc-44vr); and
- unauthenticated REST mutation of consent, post, and license state: [GHSA-xw6w-vrqp-fhq4 / CVE-2026-13389](https://github.com/advisories/GHSA-xw6w-vrqp-fhq4).

Confirm the exact plugin or theme slug, edition, feature configuration, affected version, route, and corrected behavior. Several descriptions combine multiple outcomes; prove each route-to-sink edge separately rather than inheriting the record's maximum impact.

### Two-object authorization matrix

Build synthetic objects A and B under different owners: appointments, uploads, notifications, media attachments, posts, events, menus, and boards. Give a low-role user legitimate access only to A. Replace read, delete, publish, import, and metadata-write sinks with recorders where possible.

| Operation | Control selector | Crossover selector | Bounded evidence |
| --- | --- | --- | --- |
| bulk appointment read/delete | A-only filter or current requester | omitted filter, B ID, all-records flag | recorder lists B's canary ID or receives B delete, no personal data |
| file metadata/update/download | A upload and its metadata | B upload ID/path with A or public proof | B canonical ID reaches a no-content read recorder |
| notification/media delete | A object ID | B object ID | no-op delete recorder receives B after low-role authorization |
| event quick edit | editable event A | post/page B plus title/status marker | B write recorder receives a reversible marker |
| board import | authorized board A | stages/tasks from B | import recorder receives B's synthetic item IDs |
| REST restriction | front-end-denied post B | alternate REST representation of B | response recorder selects B's marker content |

Exercise anonymous, owner, low-role non-owner, expected manager, nonexistent object, wrong parent, duplicate parameter, stale nonce, and corrected-build controls. Record the canonical object used at the authorization guard and the canonical object reaching the sink. Stop at IDs, hashes, and marker fields; never return appointment personal data, private uploads, board descriptions, or attachment bytes, and never perform a destructive delete.

The decisive positive is **proof valid for caller or object A -> caller-selected object B -> B reaches a read/write/delete/import recorder without a B-specific capability and ownership decision**. A successful HTTP status, enumerable numeric ID, or route visibility alone is insufficient.

### Account creation, password reset, social login, and OTP subject matrix

Use disposable non-administrator users A and B, fake phones, invalid-signature third-party identity fixtures, a local mail sink, and patched account/session/password/role sinks.

1. For POUCO Import Users, test each public AJAX action independently. Record whether authentication, nonce, account-create/update capability, target-user binding, and a role allowlist execute before the sink. Send only a harmless custom role to the recorder; do not create an administrator.
2. For login-social, separate password reset from third-party sign-in. Cross requester, target user, reset key, provider subject, verified-signature decision, claimed email, and final session subject one field at a time. Invalid-signature or absent-proof fixtures must fail before account lookup.
3. For Lenxel WP, compare public CSRF nonce acceptance with reset-key and target-ownership decisions. A nonce can establish request provenance; it cannot authorize a caller-selected account.
4. For SMS Alert, verify A's fake phone and OTP, then switch only the later login/signup phone selector to B. Intercept session creation. The server must bind the verified phone, verification attempt, browser session, target account, purpose, and expiry as one tuple.
5. Repeat on corrected builds, expire every proof, and invalidate all canary sessions.

Safe positives are **public account route -> caller-selected harmless role reaches a no-op role sink**, **unverified reset/provider proof -> foreign-user password or session recorder**, or **OTP for phone A -> phone B selects the session subject**. Do not change passwords, send messages, mint live sessions, or use real provider identities.

### Delegated API and credential authority

AI ChatBot for WooCommerce and Gallery for Google Photos illustrate two sides of stored third-party authority: a public route may **use** the operator's credential, or it may **return** persistent OAuth material. Use fake provider credentials and mocked transports only.

1. For the chatbot, load a fake API token into a disposable site, disconnect outbound networking, and replace the provider client with a recorder. Compare anonymous, authenticated, nonce, feature-disabled, knowledge-base-disabled, and fixed-build cases. Send one inert prompt marker and return no indexed content.
2. For the gallery, seed only fake access/refresh tokens. Inventory public route families and intercept response serialization. A positive is the unauthenticated serializer selecting synthetic credential fields; do not retain or replay any real token.
3. Record separately: route authentication, nonce provenance, requested operation, canonical credential owner, provider scope, outbound argument, response fields, and billing/content sink.

Report **unauthenticated delegated API dispatch** separately from **credential disclosure** and **knowledge-base selection**. Provider acceptance, cost, linked-account compromise, and private-content access remain unproven unless separately authorized—and are unnecessary for this workflow.

### Delayed deserialization and menu rendering

Event Booking Manager's object-injection record explicitly says the affected plugin does not supply its own POP chain. Prove only the storage-to-deserializer boundary: store an inert serialized marker through a contributor-reachable event field, patch `unserialize()` or object construction to record the class name and input hash, and trigger the normal later read. Do not load a gadget, invoke magic methods, delete files, read data, or claim code execution.

For RT Mega Menu and Clever Mega Menu, distinguish configuration authorization from browser execution. Use a subscriber canary, synthetic menu item, and harmless CSS/attribute-shaped markers. Record nonce provenance, capability decision, menu-item ownership, persisted setting, render context, and detached DOM/AST result. Do not use event handlers or script payloads. A useful result is **subscriber -> menu configuration sink -> inert marker escapes its intended attribute/style node in a detached parser**; site takeover requires a separate, authorized executable-sink proof.

The adjacent generic stored/reflected XSS records, cache-flush availability issue, low-impact settings reset, and empty advisory summary were processed without publication because they add no distinct workflow beyond the existing render, role, and business-action matrices.

## August 3 follow-up: cross-check object, identity, upload, and role selectors

The next WordPress wave adds four reusable boundary families. The GitHub records were unreviewed when processed; confirm plugin slug, affected version, route registration, prerequisite role, and corrected behavior before reporting.

### Parent, owner, and publication-state authorization

- Dokan vendor product-attribute writes and bulk order-status changes: [GHSA-cjjh-8xvm-fchv / CVE-2026-16565](https://github.com/advisories/GHSA-cjjh-8xvm-fchv) and [GHSA-rgp2-2vg6-97f5 / CVE-2026-16564](https://github.com/advisories/GHSA-rgp2-2vg6-97f5);
- Academy LMS lesson enrollment and publication state: [GHSA-9988-37r6-j7j6 / CVE-2026-16563](https://github.com/advisories/GHSA-9988-37r6-j7j6);
- Classified Listing cross-owner post content and revenue totals: [GHSA-xw94-m5qr-wj9w / CVE-2026-16274](https://github.com/advisories/GHSA-xw94-m5qr-wj9w) and [GHSA-jxrw-x44m-c9mq / CVE-2026-16276](https://github.com/advisories/GHSA-jxrw-x44m-c9mq);
- Contest Gallery foreign-post deletion: [GHSA-pwq7-3xxm-qxqg / CVE-2026-16057](https://github.com/advisories/GHSA-pwq7-3xxm-qxqg);
- Tag, Category, and Taxonomy Manager private/draft post derivation: [GHSA-2fw4-4h2j-gcmv / CVE-2026-15231](https://github.com/advisories/GHSA-2fw4-4h2j-gcmv); and
- GEO my WP foreign geolocation modification/deletion: [GHSA-qgxr-8r3m-cw55 / CVE-2026-15260](https://github.com/advisories/GHSA-qgxr-8r3m-cw55).

Use two vendors/authors/students, parent objects A and B, and synthetic child objects. Give the low-role principal legitimate access only to A. Cross only one selector per request: product, order, lesson, course enrollment, publication state, post, report scope, or geolocation record. Replace update, status-change, and delete sinks with no-op recorders; return only marker text for read tests. The positive is **A-authorized principal or parent -> B selector -> B's marker reaches the read/write/delete recorder without B ownership, enrollment, publication, or capability authorization**. Never return paid lesson content, revenue, private posts, customer orders, or location data.

### Account subject and canonical role enforcement

- ChamaWP arbitrary-user reset and unauthenticated object input: [GHSA-6m7v-g5wq-gghp / CVE-2026-16300](https://github.com/advisories/GHSA-6m7v-g5wq-gghp) and [GHSA-w2rh-rmh8-jmwq / CVE-2025-15672](https://github.com/advisories/GHSA-w2rh-rmh8-jmwq);
- Import and export users and customers role/edit-policy bypass: [GHSA-xw98-5fp3-v7vg / CVE-2026-16534](https://github.com/advisories/GHSA-xw98-5fp3-v7vg);
- Simple Membership failed-user-creation identity confusion: [GHSA-7g75-5pmj-3v8p / CVE-2026-15930](https://github.com/advisories/GHSA-7g75-5pmj-3v8p); and
- SoftMarket email-verification session binding: [GHSA-6gxj-34hr-jj8j / CVE-2026-14557](https://github.com/advisories/GHSA-6gxj-34hr-jj8j).

Build users A and B with harmless custom roles and intercept password, email, role, and session sinks. Cross requester, reset/verification proof, claimed user ID, returned user-creation result, CSV row, canonical editable user, submitted role, and final session subject one field at a time. Force user creation to return each relevant `WP_Error`, falsey, zero-like, and valid canary representation. For ChamaWP deserialization, use a patched `unserialize()` recorder with an inert class-name marker only—no gadget or magic method.

Safe positives are **proof for A -> B reaches a password/session recorder**, **failed create result -> existing canary user reaches the update recorder**, or **`create_users`-only principal -> disallowed canary role/foreign-user edit reaches the role or account recorder**. Do not reset a password, change an email, assign `administrator`, set a cookie, or instantiate an object.

### Upload container, extension, and public-handler drift

- Articulate Content archive validation to a server-executable public file: [GHSA-v4q5-7cp7-m46j / CVE-2026-16060](https://github.com/advisories/GHSA-v4q5-7cp7-m46j);
- Personal QR Message and Webinfos unauthenticated file handlers: [GHSA-r4mq-7p9v-x8fv / CVE-2026-16250](https://github.com/advisories/GHSA-r4mq-7p9v-x8fv) and [GHSA-jm79-ggg6-34q9 / CVE-2026-12872](https://github.com/advisories/GHSA-jm79-ggg6-34q9); and
- SVG Support `.svgz` sanitizer drift: [GHSA-2v5f-qf73-676h / CVE-2026-13340](https://github.com/advisories/GHSA-2v5f-qf73-676h).

Use a patched write recorder and inert files only. For archive tests, include one allowed media marker plus one dangerous-looking filename containing plain text; never include PHP or executable syntax. For direct handlers, vary authentication, nonce, capability, extension, MIME, case, duplicate suffix, and destination independently. For `.svgz`, gzip the same harmless SVG marker used by the `.svg` control and compare decompression, sanitizer invocation, stored bytes, response type, and detached DOM. A positive requires the disallowed representation to reach the public-path write recorder or to bypass the sanitizer that the equivalent `.svg` invokes. File placement is not execution, and a served SVG-like file is not XSS without an independently proven browser sink.

### Query grammar items from the same wave

LogMyTrip cookie-to-query ([GHSA-q8gv-w79g-jw6j / CVE-2026-16572](https://github.com/advisories/GHSA-q8gv-w79g-jw6j)), Link Library unauthenticated query input ([GHSA-pm7r-7m99-28qp / CVE-2026-16532](https://github.com/advisories/GHSA-pm7r-7m99-28qp)), and Super Store Finder unauthenticated AJAX input ([GHSA-hr2r-68v6-qv47 / CVE-2026-12965](https://github.com/advisories/GHSA-hr2r-68v6-qv47)) fit the existing query-recorder method: send delimiter-shaped inert values, intercept the final SQL, and compare parser tokens with bound-parameter controls. Do not execute extraction, timing, stacked-statement, or destructive payloads.

The adjacent generic stored-XSS, low-impact group-membership metadata, administrator-only object injection, and brute-force/timing records were processed without separate publication because they do not add a distinct operator workflow beyond the existing render, object, deserialization, and authentication matrices.

## Reporting checklist

Include:

- exact product/plugin slug, version or firmware, configuration state, route/action, method, and authentication context;
- each chain edge as a decision table rather than one inflated impact label;
- intended-root lifecycle state, raw/decoded token, canonical target, containment result, and delete-sink decision for filesystem operations;
- nonce provenance, capability result, selected option or role, request-post owner, target user, global-setting scope, payment/order binding, and resolved virtual path;
- proof subject, initiating browser/session, attempt-bucket key, reset-link authority, immediate network peer, and chosen client identity;
- canonical order/ticket/event owner, parent object, delegated provider authority, recorder action, and idempotency state;
- canonical vendor/course/post/location owner, enrollment/publication state, account-create result, role-policy decision, and final no-op sink subject;
- upload container/member, raw extension and MIME, sanitizer invocation, canonical destination, and public-path write-recorder decision;
- token signature/key decision, issuer/audience/time claims, resolved login subject, and no-op session result;
- authorized attachment ID, path-selected attachment/file, canonical root result, and patched read-sink argument;
- browser, normalized, stored, and gateway-recorder amount representations for payment-integrity checks;
- first-stage metadata write authority, exact inert key hash, later duplicate trigger identity, and recorded SQL token-boundary diff for second-order checks;
- affected and fixed controls, including feature-disabled and unconfigured states;
- hashes or redacted identifiers for fake connection values, payment responses, cookies, and canary files;
- the pretix quick-setup CVE identifier discrepancy and the source attached to each identifier;
- a bounded impact statement that distinguishes option disclosure, session creation, persistent write, DOM rendering, payment replay, event mutation, filesystem read/write, and execution.

Do not infer administrator takeover from option disclosure or a harmless canary-role assignment alone, store compromise from a reversible global setting alone, XSS from stored markup alone, completed underpayment from a local gateway recorder, database disclosure from a SQL grammar diff, free tickets from a callback that did not change order state, or device code execution from filesystem reachability alone.