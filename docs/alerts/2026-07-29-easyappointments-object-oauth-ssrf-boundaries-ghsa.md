---
title: Easy!Appointments object, OAuth, and CalDAV boundaries
---

# Easy!Appointments object, OAuth, and CalDAV boundaries

Five July 29 advisories for Easy!Appointments 1.5.2 and earlier yield a reusable multi-tenant workflow: a search or reschedule response discloses an object capability, mutation routes trust caller-selected owner IDs, an OAuth callback consumes an unbound provider ID, and a connection-test URL becomes a server-side `REPORT` request.

Sources:

- [GHSA-4vmm-5qvc-w5p7 / CVE-2026-55651](https://github.com/advisories/GHSA-4vmm-5qvc-w5p7): customer search leaks appointment hashes used by management routes;
- [GHSA-xgr6-pqjv-3pf8 / CVE-2026-52837](https://github.com/advisories/GHSA-xgr6-pqjv-3pf8): public reschedule pages inline the full customer record;
- [GHSA-w8xc-8g92-v77h / CVE-2026-52839](https://github.com/advisories/GHSA-w8xc-8g92-v77h): appointment store/update accepts a foreign provider ID;
- [GHSA-8hm4-r66f-29wr / CVE-2026-52841](https://github.com/advisories/GHSA-8hm4-r66f-29wr): Google OAuth provider binding lacks provider ownership checks; and
- [GHSA-pm5p-7w5h-jm5q / CVE-2026-52840](https://github.com/advisories/GHSA-pm5p-7w5h-jm5q): CalDAV connection testing permits caller-selected outbound authorities.

The corresponding fixes are included in release 1.6.0. A nearby admin-authored booking-message stored-XSS advisory is not required for these object, identity, and outbound-request workflows.

!!! warning "Authorized validation only"
    Use two or three disposable providers, synthetic customers and appointments, a fake OAuth issuer, and owned HTTP recorders. Do not enumerate live booking hashes, read customer records, alter real schedules, bind production Google accounts, or probe metadata/private services.

## Boundary graph

| Source | Missing binding | Bounded proof |
| --- | --- | --- |
| `/customers/search` response | returned appointment hash to caller-visible provider/customer scope | synthetic foreign hash appears in provider B's response |
| public reschedule URL | capability hash to minimum customer projection | marker-only fields not needed by the page appear in inline state |
| appointment JSON | `id_users_provider` and appointment ID to authenticated provider | provider A creates/reassigns one canary row owned by B |
| OAuth start/callback session | selected provider ID to initiating caller's authority | fake token is stored against provider B after A initiates the flow |
| CalDAV URL | integration setting to approved scheme/final authority | `REPORT` reaches owned listener B and a synthetic response marker returns |

Treat each edge independently. A disclosed hash is not takeover until a mutation accepts it; outbound callback evidence is not internal data access; and OAuth token storage is not appointment disclosure until a lab sync proves the downstream data route.

## Capability disclosure and object mutation chain

### Three-provider matrix

1. Create providers A and B plus an admin control account. Seed one customer and one uniquely marked appointment per provider. Use fake names, addresses, notes, hashes, and calendar content.
2. As provider A, call customer/appointment search routes using only ordinary UI-supported parameters. Record whether B's customer rows, appointment objects, or appointment hashes appear.
3. Fetch only the pre-seeded B reschedule URL in the lab. Compare fields required by the UI with all fields emitted into inline JavaScript. Store field names and marker presence, not real values.
4. Exercise store and update separately:
   - create a canary appointment while selecting B's provider ID;
   - reassign A's canary appointment to B; and
   - attempt to update B's pre-existing canary appointment.
5. After every request, query through the normal UI/API as A, B, and admin. Record response status and database/UI state independently because the affected store path may commit before returning an error.
6. Use a dedicated synthetic appointment to test whether a disclosed hash reaches reschedule, update, cancel, or delete. Stop after one reversible marker transition; do not test against business appointments.
7. Repeat on 1.6.0. Search projections, capability use, and every mutation sink should enforce provider/object ownership.

Strong evidence is a phase table showing **foreign capability disclosed -> capability resolves a synthetic object -> mutation sink changes that object without matching provider authority**. If only the first edge is present, report excessive exposure without claiming takeover.

## Google OAuth provider-binding workflow

The affected OAuth start route stores a URL-selected provider ID in the session, while the callback writes the resulting Google token and sync settings to that row. Companion calendar-selection and disable-sync paths have stronger provider/role checks, creating a useful route-family authorization differential.

1. Replace Google with a local fake OAuth server that issues only inert tokens and records the redirect URI, state, code subject, and callback request.
2. As provider A, start OAuth with A's provider ID and complete the callback. This is the baseline.
3. Start the flow as A while selecting provider B's ID. Before callback, inspect only the lab session's selected-provider field and preserve the OAuth state value.
4. Complete the callback with a fake account. Record which provider row receives `google_sync`, `google_token`, and calendar selection. Redact all but fixed token prefixes.
5. Separately test administrator, provider, and secretary roles; callback replay; concurrent tabs selecting different provider IDs; and state from one session completed in another.
6. If token storage crosses providers, trigger one synthetic appointment sync and record only whether B's canary event reaches the fake calendar. Do not sync customer data or use a real Google account.
7. Repeat on 1.6.0 and compare start, callback, select-calendar, and disable-sync authorization decisions.

Report **initiating principal -> session-selected provider -> callback token write -> optional canary sync** as separate edges. This avoids overstating downstream calendar disclosure or deletion behavior.

## CalDAV URL-to-final-destination workflow

The affected connection test accepts a caller-selected `caldav_url`, constructs a Guzzle client, and sends `REPORT`. Error messages may include an upstream status and a bounded response fragment, so test both destination control and response relay.

1. Run owned listeners A and B. A is the approved fake CalDAV authority; B is an unapproved canary authority. Neither should expose sensitive endpoints.
2. As each backend role, submit A and confirm the normal request method, authority, path, authentication-header behavior, and response handling.
3. Vary one URL feature at a time: scheme, userinfo, alternate port, hostname case, trailing dot, IPv4/IPv6 form, redirect to B, and controlled DNS answer change. Do not send private, loopback, link-local, or metadata destinations unless the listener itself is the owned local fixture.
4. Record the submitted URL, parsed URL, redirect chain, resolved address, final socket authority, request method, and response bytes reflected in the JSON message.
5. Repeat on 1.6.0. Confirm validation is applied to the canonical final destination and after every redirect or DNS resolution relevant to the application.

Positive evidence is **authorized backend user supplies integration URL -> final `REPORT` reaches owned listener B outside the approved authority**. Record response relay as a second property; do not infer general port scanning or credential theft.

## Evidence and reporting

Capture version, deployment configuration, role, route, object/provider IDs, capability provenance, status-versus-committed-state, OAuth session binding, raw redirect chain, final destination, and 1.6.0 negative controls. Keep every artifact synthetic and state the narrow crossed boundary: **search projection**, **capability scope**, **provider ownership**, **OAuth callback target**, or **CalDAV authority**.
