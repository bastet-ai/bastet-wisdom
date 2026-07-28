---
title: Joomla Regular Labs code, AJAX, database, and client-IP boundaries from July 28 GHSA updates
---

# Joomla Regular Labs code, AJAX, database, and client-IP boundaries from July 28 GHSA updates

A late GitHub advisory wave for Regular Labs Joomla extensions yields four reusable operator workflows: source-tag ownership and execution-policy drift, privileged AJAX handlers whose CSRF and authorization checks diverge, database replacement routes that do not consistently require Super User authority, and IP/GeoIP conditions that trust client-spoofable forwarding headers.

Sources:

- [GHSA-p85f-w9w7-64vg / CVE-2026-64796: Sourcerer code-injection vectors](https://github.com/advisories/GHSA-p85f-w9w7-64vg)
- [NVD record for CVE-2026-64796](https://nvd.nist.gov/vuln/detail/CVE-2026-64796)
- [GHSA-335f-24jh-fw8m / CVE-2026-63265: inconsistent AJAX token and privilege checks](https://github.com/advisories/GHSA-335f-24jh-fw8m)
- [NVD record for CVE-2026-63265](https://nvd.nist.gov/vuln/detail/CVE-2026-63265)
- [GHSA-c78w-786v-53cq / CVE-2026-63685: DB Replacer authorization bypass](https://github.com/advisories/GHSA-c78w-786v-53cq)
- [NVD record for CVE-2026-63685](https://nvd.nist.gov/vuln/detail/CVE-2026-63685)
- [GHSA-9vjf-jcj2-pvfh / CVE-2026-63280: Conditions manager token and permission drift](https://github.com/advisories/GHSA-9vjf-jcj2-pvfh)
- [NVD record for CVE-2026-63280](https://nvd.nist.gov/vuln/detail/CVE-2026-63280)
- [GHSA-mr48-vrgg-4vf5 / CVE-2026-63683: Conditions manager client-IP spoofing](https://github.com/advisories/GHSA-mr48-vrgg-4vf5)
- [NVD record for CVE-2026-63683](https://nvd.nist.gov/vuln/detail/CVE-2026-63683)
- [Regular Labs product site](https://regularlabs.com/)

The GitHub entries are unreviewed, and neither the GitHub nor NVD records identify affected or fixed versions. Confirm the exact extension, edition, installed version, route, configuration, and fixed-build behavior before reporting. Do not infer reachability from the vendor name or Joomla installation alone.

!!! warning "Authorized validation only"
    Use a disposable Joomla instance, synthetic articles, low-role lab users, marker-only source snippets, temporary tables, an owned reverse proxy, and fake GeoIP values. Never execute operating-system commands, include host files, alter production content or databases, forge traffic through a shared proxy, or test another tenant's location restrictions.

## Inventory the extension boundary before testing

Capture extension manifests and effective policy instead of beginning with payloads.

```text
Joomla build:
Extension / edition / version:
Route or AJAX task:
Authentication role:
CSRF token present / valid:
Component permission:
Object or mapped-item permission:
Article creator / last modifier:
Source language / include mode:
Trusted-proxy configuration:
Observed client IP / GeoIP decision:
Result:
```

Build anonymous, low-role, expected-role, Super User, invalid-token, and fixed-build controls for every reachable route. For Sourcerer, add article-creator and last-modifier combinations. For IP rules, add direct and trusted-proxy paths; an arbitrary `X-Forwarded-For` header is not meaningful if an upstream proxy strips it.

## Sourcerer: treat both article owners and every execution form as authority inputs

The Sourcerer record distinguishes Free and Pro behavior:

- Free reportedly did not require both the article creator and the last modifier to be Super Users before executing article PHP.
- Pro reportedly applied configured CSS, JavaScript, and PHP permissions inconsistently across tags, attributes, files, and both article owners.
- PHP include attributes could reportedly escape the configured include directory.
- alternate executable script or style representations could reportedly bypass detection.

This is an ownership-transition and representation-equivalence problem, not merely “PHP in an article.”

### Two-author execution matrix

1. Create disposable Super User S and low-role author L. Seed one synthetic article containing only a marker source construct supported by the lab extension.
2. Exercise creator/last-modifier pairs `S/S`, `S/L`, `L/S`, and `L/L`. Keep the article body otherwise identical.
3. Use a no-network, no-file-write marker such as an instrumented evaluation counter or fixed text value. Do not invoke shell, database, network, or filesystem APIs.
4. Repeat independently for inline tags, source attributes, file-backed source, and any documented CSS/JavaScript/PHP modes enabled in the lab.
5. For include confinement, place one text marker inside the configured include directory and one in a temporary sibling directory. Resolve candidate paths without including or interpreting the sibling file; stop when instrumentation shows an outside-root path would be selected.
6. Test only benign representation variants: mixed case, spacing, documented aliases, nested wrappers, and extension-recognized script/style forms. Record which parser stage classifies each representation.
7. Repeat on a fixed build when one is identified.

A strong proof is **low-role ownership at either required article edge -> policy reports execution forbidden -> inert evaluation counter still increments**. For path confinement, report **source attribute -> resolved canonical path outside configured include root** separately. A lexical escape does not prove file disclosure or code execution unless the later include edge is independently reached.

## Privileged AJAX: compare token, component, object, and form authority independently

CVE-2026-63265 describes multiple Regular Labs AJAX endpoints whose checks could diverge across CSRF tokens, component/item permissions, and trusted server-generated form configuration. CVE-2026-63280 applies the same pattern to Conditions administration.

### Route and role matrix

1. Enumerate extension-owned AJAX routes from the installed lab code and normal browser traffic. Record component, task, method, expected token location, object identifier, and required permission.
2. Seed two synthetic components or mapped items, A and B. Grant low-role user A access only to A.
3. Capture one legitimate A request, then vary one dimension at a time:
   - omitted, malformed, expired, and valid CSRF token;
   - missing, A-owned, B-owned, and random object ID;
   - normal server-generated form configuration, omitted configuration, and a harmless client-modified field;
   - anonymous, user A, unrelated user B, expected manager, and Super User sessions.
4. Instrument permission and token checks with counters if source access is available. A declared helper is not evidence that the route invoked or honored it.
5. Begin with lookups that return only synthetic labels. If a mutation route is reachable, use a transaction that is rolled back or change one reversible marker owned by A; do not modify B's object.
6. Repeat the Conditions-manager tests for both component permission and mapped-item permission. Preserve the route selected, check counters, canonical object owner, and final decision.

The decisive result is **route matched -> required token or permission check missing/ignored -> foreign synthetic object lookup or marker-only mutation path reached**. Separate CSRF, horizontal object-scope drift, and vertical privilege drift; they are different findings even when one endpoint exhibits all three.

## DB Replacer: prove privileged route reachability without changing data

The DB Replacer advisory says administrator routes and replacement requests did not consistently require both Super User permission and a valid token. Because the handler can perform broad database replacement, route-level evidence is normally sufficient.

### Dry-run authorization proof

1. Install DB Replacer only in a disposable Joomla environment and create a temporary table containing a unique, non-sensitive marker row.
2. Identify the normal preview and replacement requests from Super User traffic. Record method, task, token, selected table, search term, and replacement term.
3. Add an application- or database-layer hook that logs entry into the replacement code path and rolls back before the first write.
4. Replay omitted, invalid, and valid token states as anonymous, low-role backend, manager, and Super User identities.
5. Prefer a preview/count action if it exercises the same authorization guard. If it does not, use the rollback hook and verify the temporary row hash remains unchanged.
6. Test only the temporary table; never select Joomla user, session, extension, or configuration tables.
7. Confirm the fixed build rejects unauthorized requests before query construction or replacement dispatch.

A safe positive is **non-Super-User or invalid-token request -> replacement handler counter increments for the synthetic table -> transaction remains unchanged by design**. Do not perform a destructive replacement merely to strengthen impact. State-changing capability follows from reaching the same instrumented handler only when the control flow is demonstrated.

## Conditions manager: separate proxy trust from header parsing

The client-IP advisory says IP and GeoIP conditions trusted spoofable forwarded headers. Test both where a value came from and how it was parsed.

### Direct-versus-proxy decision table

1. Configure an allow rule for one fake test IP or country and a deny rule for another. Protect only a synthetic marker page.
2. Record the server's direct peer address, Joomla-observed client address, selected forwarding header, normalized address, and final condition result.
3. Send direct requests with the forwarding header absent, containing the direct test address, and containing the alternate fake address.
4. Place an owned reverse proxy in front. Configure it to strip inbound forwarding headers and set one canonical value, then repeat the same matrix.
5. Add bounded parser controls for comma-separated chains, whitespace, IPv4-mapped IPv6, duplicate headers, and the documented proxy header name. Do not use third-party proxy services.
6. Repeat with trusted-proxy mode disabled, correctly restricted to the owned proxy, and intentionally broad in the lab.
7. Verify the fixed build derives identity from the socket peer unless that peer is an explicitly trusted proxy, then selects the correct hop from a normalized chain.

A valid bypass is **direct untrusted client supplies forwarding value -> Conditions manager adopts it -> synthetic location rule changes**. If the application is behind a trusted proxy that overwrites the header, document that negative control; header trust may be vulnerable in code but not reachable in that deployment.

## Reporting checklist

Include:

- exact Joomla build, extension name, edition, manifest version, configuration, route, and method;
- creator and last-modifier identities for source execution;
- source representation, policy decision, evaluation counter, and canonical include path;
- CSRF state, component permission, mapped-item ownership, helper invocation counters, and final AJAX decision;
- DB Replacer handler-entry evidence plus unchanged temporary-row hash;
- socket peer, proxy trust state, raw forwarding header, normalized client IP, GeoIP result, and rule decision;
- affected-versus-fixed decision tables when a fixed version can be established;
- redacted session and token evidence with no production article, database, or user data.

Bound impact precisely. A source-policy mismatch is not operating-system command execution; a resolved outside-root include path is not file disclosure until content is read; an AJAX lookup is not a mutation; handler entry under rollback is not a completed database replacement; and a spoofable client IP matters only when it changes a reachable authorization or content decision.
