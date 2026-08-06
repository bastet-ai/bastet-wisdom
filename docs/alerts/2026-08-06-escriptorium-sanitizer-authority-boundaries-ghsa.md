---
title: eScriptorium object authority and HTML sanitizer context boundaries
---

# eScriptorium object authority and HTML sanitizer context boundaries

Nine August 6 records yield two reusable operator workflows: prove the final object or network authority selected by alternate API, serializer, and WebSocket paths; and evaluate sanitized HTML in the browser context where surviving elements, attributes, and CSS grammar become active.

Source records:

- eScriptorium import SSRF: [GHSA-cpqx-fhwg-cr7g / CVE-2026-18359](https://github.com/advisories/GHSA-cpqx-fhwg-cr7g) and [work item 1230](https://gitlab.com/scripta/escriptorium/-/work_items/1230);
- OCR-model grant/revoke authorization: [GHSA-w7gw-xhpj-265q / CVE-2026-18277](https://github.com/advisories/GHSA-w7gw-xhpj-265q) and [work item 1227](https://gitlab.com/scripta/escriptorium/-/work_items/1227);
- process and annotation serializer scope: [GHSA-4mrh-554p-w3v7 / CVE-2026-18275](https://github.com/advisories/GHSA-4mrh-554p-w3v7) and [work item 1228](https://gitlab.com/scripta/escriptorium/-/work_items/1228);
- document-event WebSocket room authorization: [GHSA-vr95-3w53-6w94 / CVE-2026-18276](https://github.com/advisories/GHSA-vr95-3w53-6w94) and [work item 1229](https://gitlab.com/scripta/escriptorium/-/work_items/1229);
- globally resolved line, transcription, virtual-collection, tag, and process IDs: [GHSA-xg85-j7xm-gqc8 / CVE-2026-18258](https://github.com/advisories/GHSA-xg85-j7xm-gqc8) and [work item 1226](https://gitlab.com/scripta/escriptorium/-/work_items/1226);
- `html_sanitize_ex` CSS at-rule survival: [GHSA-g72r-5wgp-6532 / CVE-2026-68747](https://github.com/advisories/GHSA-g72r-5wgp-6532) and the [upstream advisory](https://github.com/rrrene/html_sanitize_ex/security/advisories/GHSA-87v2-pfhj-r5x7);
- `<object data>` active-resource survival: [GHSA-6g7x-33rf-28v3 / CVE-2026-66843](https://github.com/advisories/GHSA-6g7x-33rf-28v3) and the [upstream advisory](https://github.com/rrrene/html_sanitize_ex/security/advisories/GHSA-xmm9-jc22-rcgj);
- document-wide `<meta http-equiv="refresh">` behavior: [GHSA-c486-5fvq-fp3v / CVE-2026-66829](https://github.com/advisories/GHSA-c486-5fvq-fp3v) and the [upstream advisory](https://github.com/rrrene/html_sanitize_ex/security/advisories/GHSA-2c6f-3j54-xpcr); and
- form-owner reassociation plus `formaction`: [GHSA-r8xc-fmjg-37c5 / CVE-2026-66370](https://github.com/advisories/GHSA-r8xc-fmjg-37c5) and the [upstream advisory](https://github.com/rrrene/html_sanitize_ex/security/advisories/GHSA-w3f9-jjhw-wwvq).

The eScriptorium and GitHub entries are unreviewed mirrors and identify versions through 26.04.1 without a fixed release. The sanitizer mirrors identify `html_sanitize_ex` ranges before 1.5.3 or 1.5.4 and link project advisories and commits. Confirm the deployed code and current project status before reporting.

!!! warning "Synthetic tenants, owned peers, and script-disabled DOMs only"
    Use two lab users, marker-only documents/models, patched mutation and task sinks, owned no-content HTTP peers, and detached or script-disabled browser fixtures. Never access another user's real transcription, subscribe to production events, run OCR jobs, contact metadata/internal services, collect form submissions, or load active attacker content in a privileged origin.

## 1. Build one final-authority trace

For every route, record:

```text
authenticated principal and role
-> request path/method or WebSocket action
-> body/query object IDs
-> serializer/view/consumer branch
-> request-scoped queryset or global manager
-> final object, group, mutation, task, or network sink
```

Seed user A and user B with random document, part, line, transcription, collection, tag, process, OCR-model, and event markers. First prove A can use A's objects and cannot use B's through ordinary detail endpoints. Those controls distinguish object existence, route-level authentication, and final authorization.

## 2. Compare rendering-time checks with mutation handlers

The OCR-model record places an ownership check in `get_context_data()`, a path used while rendering a GET response, while create/delete POST handlers reportedly reach grant and revoke operations without the same decision.

Patch grant/revoke persistence and build a method matrix for GET, POST, malformed body, owned model, foreign model, self target, and second synthetic user target. Capture whether `get_context_data()`, form validation, object lookup, and the mutation sink ran. A bounded positive is **GET for foreign model denied -> equivalent POST skips the owner check -> patched grant/revoke sink receives the foreign model and target user IDs**. Do not change a real ACL.

Generalize this test to every sibling create/delete/action handler. A permission check in a page-rendering helper is not evidence that API mutation paths inherit it.

## 3. Trace nested IDs to the child relation

The process/annotation record describes a `many=True` related field whose queryset restriction was attached to the outer `ManyRelatedField` rather than `child_relation`; the global-ID record describes serializers resolving body-supplied primary keys through a global model manager instead of the request-scoped queryset.

For each body field that accepts one or many IDs:

1. send A-owned IDs as a positive control;
2. send one B-owned marker alone;
3. mix A and B IDs in different orders;
4. repeat through create, update, bulk, process, annotation, and delete route families; and
5. patch save/delete/task enqueue functions so no record or OCR/transcription job changes.

Record field class, outer and child querysets, validation result, resolved object owner, parent document/part, and denied final sink. A bounded positive is **A-authenticated body -> global or unscoped child lookup resolves B's marker -> serializer validates -> patched mutation/task sink receives B's object**. Do not infer broad tenant takeover from an existence oracle or validation error; prove the specific final object binding.

## 4. Bind WebSocket rooms to object visibility

The WebSocket record identifies client-supplied `object_cls` and `object_pk` reaching `group_add`. Use two synthetic documents and a patched channel-layer group recorder. Compare no session, invalid session, A joining A, A joining B, unknown classes, nonexistent IDs, mixed numeric/string IDs, and direct HTTP access to the same object.

Capture connection authentication, normalized class/ID, object lookup, visibility decision, derived group name, subscription result, and synthetic event delivery. A bounded positive is **HTTP object access denied to A -> A's join message derives B's room -> group recorder accepts the subscription -> one random B event marker reaches the test client**. Do not observe production task names or activity.

## 5. Prove import SSRF at the final peer

The import record states that `mets_uri` and `iiif_uri` accept arbitrary hosts when `IMPORT_ALLOWED_DOMAINS` defaults to `*`, without address filtering, a redirect cap, or timeout. Use an owned redirector and two owned no-content peers representing allowed and denied destinations. Do not use metadata addresses or internal production services.

Trace raw URI, parsed scheme/authority, configured domain rule, DNS answers, redirect hops, final peer tuple, timeout, parser selection, and response relay. A bounded positive is **authenticated import request -> wildcard or incomplete policy -> redirect/final connector selects the owned denied peer**. Patch the METS/IIIF parser and import persistence; network reachability is enough. Test explicit allowlists, redirects, DNS answer changes, user-info, ports, trailing dots, mixed address forms, and both parameters independently.

## 6. Test sanitizers in the final browser context

The `html_sanitize_ex` records show why tag removal alone is incomplete:

- a CSS scrubber that rewrites only `property: value` substrings can copy unmatched `@import` grammar unchanged;
- `<object data>` can retain protocol-relative, `data:`, mixed-case-scheme, or same-origin resource selectors;
- `<meta http-equiv="refresh">` can affect the whole document even when injected as a fragment; and
- an allowed `<input form="target" formaction="…">` can reassociate with a pre-existing host-page form and override its destination.

Build a detached, script-disabled fixture with an owned no-content resource recorder. Test sanitized output in at least three host contexts: no surrounding form, a synthetic form without an ID, and a synthetic form with a known ID. Patch navigation, resource fetch, form submission, and CSP application so they record intent and deny the action.

For each case, preserve raw HTML, sanitizer version/configuration, serialized output, parsed DOM, computed form owner, selected URL and scheme, stylesheet/object/navigation/submission decision, and denied sink. Include ordinary property declarations and safe links as controls. Strong bounded positives are:

- **at-rule not matched by declaration regex -> survives output -> CSS parser selects owned stylesheet URL**;
- **surviving object attribute -> browser selects owned resource URL**;
- **surviving meta element -> document-level refresh/CSP recorder activates**; or
- **surviving input attributes -> element binds to existing synthetic form -> submission recorder selects caller-controlled action**.

Do not call these XSS unless executable script in the tested origin is independently proven. Keep resource inclusion, navigation, document policy, form retargeting, and script execution as separate claims. In particular, `data:` object documents normally receive an opaque origin, and the form-retargeting path requires a host form with a predictable ID.

## Evidence and reporting boundaries

- Pair every alternate route with an owned-object and denied foreign-object control.
- Preserve serializer field, child relation, queryset, resolved owner, and final sink evidence.
- Treat WebSocket connection authentication and per-room authorization as separate decisions.
- Prove SSRF with the final owned peer, not merely URL acceptance or DNS lookup.
- Evaluate sanitizer output under the exact host-page structure that activates it.
- Report unreviewed mirrors and project advisories with distinct confidence labels.
- Do not claim data theft, cross-tenant mutation, internal-service access, credential capture, or XSS beyond the denied synthetic sink actually reached.
