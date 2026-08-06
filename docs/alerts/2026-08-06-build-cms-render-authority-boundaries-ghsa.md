---
title: Build cache, CMS, and renderer authority boundaries
---

# Build cache, CMS, and renderer authority boundaries

Twenty August 6 records expose a common testing question: does an early trust decision remain bound to the final file, peer, object, identity, method, parser state, or browser context? The reusable workflows cover Nx remote-cache extraction, AWS CLI EMR SSH wrappers, Contao job/crawler boundaries, Mermaid renderer state, Statamic identity/content routes, embedded PDF engines, HTML/Markdown normalization, and Craft CMS configuration and route authority.

Source records:

- Nx self-hosted remote-cache archive extraction: [GHSA-vp3h-ghgh-jr7g / CVE-2026-71476](https://github.com/advisories/GHSA-vp3h-ghgh-jr7g);
- AWS CLI EMR helper host-key verification: [GHSA-hqvf-45jj-mccq / CVE-2026-18654](https://github.com/advisories/GHSA-hqvf-45jj-mccq);
- Contao cross-job attachment path resolution and crawler credential forwarding: [GHSA-grm4-wm43-9jh5 / CVE-2026-55825](https://github.com/advisories/GHSA-grm4-wm43-9jh5) and [GHSA-3mr9-p497-58f6 / CVE-2026-55824](https://github.com/advisories/GHSA-3mr9-p497-58f6);
- Mermaid configuration/architecture prototype writes and sibling CSS reach: [GHSA-c4c3-pg64-4m4v / CVE-2026-71438](https://github.com/advisories/GHSA-c4c3-pg64-4m4v), [GHSA-3rrr-jr9j-h3q3 / CVE-2026-71437](https://github.com/advisories/GHSA-3rrr-jr9j-h3q3), and [GHSA-6x64-9x62-f2gx / CVE-2026-50159](https://github.com/advisories/GHSA-6x64-9x62-f2gx); and
- Statamic OAuth identity matching, restricted navigation content, frontend upload rules, Antlers method resolution, and notification-email HTML: [GHSA-93qh-5269-9wcf / CVE-2026-64665](https://github.com/advisories/GHSA-93qh-5269-9wcf), [GHSA-qh8c-7588-qfrv / CVE-2026-64662](https://github.com/advisories/GHSA-qh8c-7588-qfrv), [GHSA-qhr7-v3xp-vw9m / CVE-2026-71434](https://github.com/advisories/GHSA-qhr7-v3xp-vw9m), [GHSA-j2vp-f2pv-5rj4 / CVE-2026-64663](https://github.com/advisories/GHSA-j2vp-f2pv-5rj4), and [GHSA-vx89-p3j7-8xqc / CVE-2026-71435](https://github.com/advisories/GHSA-vx89-p3j7-8xqc);
- PDF.js script execution and the embedded `ngx-extended-pdf-viewer` fork: [GHSA-hq66-cqwq-w95j / CVE-2026-16633](https://github.com/advisories/GHSA-hq66-cqwq-w95j) and [GHSA-w9hm-4m3m-fxmm](https://github.com/advisories/GHSA-w9hm-4m3m-fxmm);
- jsoup custom raw-text-element cleaning: [GHSA-pmhh-3w7g-xqp8 / CVE-2026-71497](https://github.com/advisories/GHSA-pmhh-3w7g-xqp8);
- League CommonMark control-byte URL normalization: [GHSA-29pj-957v-52mc / CVE-2026-71478](https://github.com/advisories/GHSA-29pj-957v-52mc); and
- Craft CMS generic user saves, post-cleanse condition merging, Twig sandbox class hierarchy, and sibling global-set action authorization: [GHSA-p8x7-9vfw-p7vc](https://github.com/advisories/GHSA-p8x7-9vfw-p7vc), [GHSA-265m-7826-wjqm](https://github.com/advisories/GHSA-265m-7826-wjqm), [GHSA-f5wm-88jv-g5hx](https://github.com/advisories/GHSA-f5wm-88jv-g5hx), and [GHSA-9p7c-v5x3-rfx8 / CVE-2026-14793](https://github.com/advisories/GHSA-9p7c-v5x3-rfx8).

The Mermaid, League CommonMark, and JS-YAML resource-exhaustion records are source-tracked but not converted into availability-testing workflows. The sparse Silverstripe breadcrumb XSS record is also source-tracked rather than generalized beyond its stated sink.

!!! warning "Denied sinks and synthetic authority only"
    Use disposable workspaces, owned cache/HTTP/SSH peers, fake credentials, two-user CMS fixtures, patched file/process/configuration/script/mutation sinks, and detached browser DOMs. Never overwrite host files, intercept operational SSH, collect crawler credentials, read another user's content, delete CMS data, upload executable content, execute templates or commands, or run active document/HTML content in a privileged origin.

## 1. Build one raw-to-final authority trace

Record the complete tuple instead of stopping at input validation:

```text
principal and configured trust source
-> raw artifact, path, URL, claim, object ID, template value, or diagram
-> parser and normalization steps
-> policy decision and authority tuple
-> redirects, archive links, nested objects, or renderer transforms
-> final file, process argv, peer, object, identity, method, or DOM sink
```

Pair every negative test with a valid same-owner or in-root control. A parser error, accepted value, generated header, or rendered string is not enough: preserve the final denied sink the application attempted to reach.

## 2. Treat a remote build cache as a write authority

The Nx record applies to the built-in self-hosted HTTP cache in affected `nx` releases and separately versioned deprecated S3, GCS, Azure, shared-filesystem, and Powerpack cache packages. The default local cache and Nx Cloud use different retrieval paths and are not the stated surface.

Use an owned mock cache that serves inert tar metadata and patch extraction/copy syscalls so they record destination paths without creating files. Test:

- ordinary declared outputs;
- `../` and absolute archive names;
- Windows separators and drive-shaped names;
- symlink and hardlink entries followed by regular files;
- declared outputs resolving outside the workspace;
- a real parent replaced by an in-root symlink; and
- the extractor destination versus the later cache-to-workspace restore destination.

Capture the artifact origin, integrity/TLS decision, raw entry name/type/link target, post-decoding path, canonical destination, workspace containment result, declared-output match, and denied file syscall. A bounded positive is **owned cache artifact -> archive member escapes the cache root or restore crosses the workspace root -> denied write recorder receives the outside destination**. Destination control alone is not code execution; do not place shell, CI, package-manager, or startup files.

## 3. Audit CLI wrappers at the final SSH argv

The AWS CLI record states that affected EMR `ssh`, `socks`, `put`, and `get` helpers supplied `StrictHostKeyChecking=no` to the underlying SSH client. Validate wrapper behavior without intercepting traffic:

1. place a non-executing argv recorder named `ssh` or `scp` first in a disposable `PATH`;
2. invoke each helper against a synthetic cluster description and fake key path;
3. record the exact argv, environment, selected host, port, user, and known-hosts options; and
4. compare affected and fixed CLI releases.

A bounded positive is **helper selects the synthetic endpoint -> final argv disables host-key checking or discards the known-hosts binding**. Keep DNS spoofing, network position, credential disclosure, and session compromise as unproven preconditions unless separately established in an isolated lab. Never proxy or intercept a real EMR session.

## 4. Preserve the authorized path segment through canonicalization

The Contao attachment record authorizes one job UUID, then combines it with an attacker-controlled attachment identifier before mount-level canonicalization. Staying inside `var/job-attachments` does not preserve the authorized job directory.

Seed jobs A and B with random marker filenames. Authenticate as a user allowed to view A but not B, patch the file-open sink, and compare:

```text
A/owned.csv
A/../B/marker.csv
A/%2e%2e/B/marker.csv
A/..\B\marker.csv
A/nested/../../B/marker.csv
```

Record route decoding, authorized job UUID, raw identifier, canonical mount-relative path, first path segment, resolved job owner, and denied open. A bounded positive is **A passes access control -> identifier canonicalizes under B -> file recorder selects B's marker**. A known UUID/filename is a precondition; do not brute-force identifiers or read crawler logs.

## 5. Bind crawler credentials to every final authority

The Contao crawler record describes confidential Symfony HttpClient options surviving into the external-host client because the cleaner checked different option names. Use only fake Basic/Bearer values and owned no-content peers.

Build a matrix across same-origin links, external links, configured additional URIs, redirects, scheme/host/port changes, user-info, and mixed-case/trailing-dot authorities. Patch or mock the HTTP transport and capture:

```text
raw URL -> normalized origin -> scoped-client branch -> default options
-> generated Authorization/Cookie headers -> redirect hop -> final peer
```

A bounded positive is **external or redirected owned peer -> generated request still contains the fake credential marker**. Test generated authentication separately from literal headers; a mock that ignores client default options can create a false negative. Never place reusable credentials in the fixture or probe internal services.

## 6. Test diagram state in the embedding realm and host DOM

Mermaid exposes two distinct authority classes:

- trusted configuration APIs can deep-merge caller objects into shared state, while `architecture-beta` identifiers can reach prototype-backed parent lookups; and
- namespaced diagram CSS can still select host-page siblings through `+` or `~` combinators after nesting expansion.

Run a same-process fixture with a fresh JavaScript realm per test. Snapshot own properties and `Object.prototype`, render one inert marker diagram, inspect an unrelated plain object, then destroy the realm. Separately embed the rendered SVG in (a) an only-child wrapper and (b) a wrapper with synthetic siblings. Use harmless computed-style markers and a script-disabled DOM.

Capture raw configuration/diagram, parsed keys or group IDs, own-versus-inherited lookup, prototype diff, expanded selector, final matched nodes, and computed style. Bounded positives are **untrusted value -> unexpected inherited marker appears on an unrelated object** or **diagram-scoped rule -> final selector matches a synthetic node outside the SVG**. Do not infer remote code execution or XSS: the stated prototype values are constrained strings, and CSS reach establishes UI/style authority only.

## 7. Differential-test CMS route, identity, and interpreter authority

Use two disposable Statamic users, collections, draft entries, navigation trees, upload containers, forms, and an OAuth provider mock. Patch content deletion, asset deletion, upload persistence, mail delivery, and template method calls.

### OAuth identity proof

Return the same email under verified, unverified, and absent verification claims; then vary subject, issuer, case, and an already-linked provider identity. Record which claim proves the address, how the local account is selected, and whether binding is by `(issuer, subject)` or email alone. A bounded positive is **unverified mock identity -> existing local account selected -> session recorder receives that principal**. Do not sign in as a real administrator.

### Navigation and object scope

Compare ordinary entry detail/list/search APIs with every navigation/tree endpoint while user A requests A-visible, B-restricted, and unpublished random markers. Capture the request-scoped queryset, tree resolver, final entry lookup, serialized fields, and response decision. A positive requires the restricted synthetic marker in the final response, not merely an object-existence error.

### Frontend versus Control Panel upload rules

Submit the same benign text payload with allowed and administrator-disallowed extensions through Control Panel and public form route families. Record global allowlist, field/container rules, MIME/extension decisions, target disk, public URL generation, and denied persistence. A useful result is **Control Panel rejects the inert type -> frontend route reaches persistence under the same field policy**. Do not use PHP, HTML, script, polyglot, or executable payloads, and do not claim execution from public storage alone.

### Antlers method resolution

Identify only templates where untrusted values influence a variable, method, or resolver name. Patch the resolver and destructive methods, then compare literal names, unknown names, encoded separators, nested paths, and callable-looking values. A bounded positive is **request value -> resolver selects a non-allowlisted destructive method -> denied call recorder activates**. Never invoke delete/move operations or infer arbitrary code execution.

### Notification-email browser context

Submit harmless HTML markers and record template source, escaped output, MIME part, and detached-mail DOM. Patch links/forms/resource loads and mail delivery. Report HTML injection only when markup survives into the HTML part; keep script execution, credential capture, and mailbox-specific behavior separate and unclaimed.

## 8. Inventory the renderer actually shipped

The `ngx-extended-pdf-viewer` record is a dependency-recon warning: the package embeds a fork of PDF.js, so a `package.json` dependency scan does not reveal the vulnerable engine. Build a renderer inventory from bundled filenames, source maps, license banners, SBOM/VEX data, package tarballs, and runtime feature flags. Record both the wrapper version and embedded engine commit/version.

In a disposable origin, patch the PDF.js script evaluator and XFA rich-text insertion sink. Feed a synthetic PDF carrying only inert marker actions, then compare:

- scripting enabled and disabled;
- XFA enabled and disabled;
- wrapper defaults versus direct PDF.js defaults;
- inline-script-permitting and denying CSP fixtures; and
- affected, wrapper-patched, and upstream-patched releases.

Capture document feature, wrapper option, effective engine option, CSP decision, parsed action/rich-text node, and denied evaluator/DOM sink. A bounded positive is **untrusted PDF -> enabled engine feature -> inert marker reaches the patched script or active-DOM sink**. Do not execute JavaScript, read page state, or open a test document under a real application origin. Report wrapper and embedded-engine exposure separately; nominal dependency absence is not evidence of safety.

## 9. Diff sanitizer parse, serialization, and host reparse

The jsoup record requires a custom `Safelist` that permits raw-text elements; built-in safelists are not the stated surface. The key differential is that malformed tag-name bytes can change parser state, so text accepted under one interpretation becomes markup after serialization and browser reparsing.

Create a table-driven harness using harmless marker elements and no event handlers. For each allowed raw-text element, vary exact names, suffix control bytes, malformed closing tags, adjacent markup, character references, and chunk boundaries. Preserve:

```text
raw bytes -> jsoup token/tag identity -> safelist decision -> serialized HTML
-> script-disabled browser token/DOM identity -> denied active-node sink
```

A bounded positive is **cleaner classifies the marker as raw text -> serialized output reparses as a different active element or attribute-bearing node**. Compare custom and built-in safelists, and test CSS handling separately when `style` is allowed: jsoup does not itself make CSS safe. Do not place executable handlers, live forms, or network-loading URLs in the fixture.

## 10. Normalize URLs the way the final browser does

The League CommonMark record shows a policy check and browser disagreeing about control bytes in a URL scheme. Test only inert, non-executing scheme markers in a patched navigation fixture. Exercise literal tabs, CR/LF, leading C0 bytes, percent-encoded forms, HTML entities, Unicode whitespace, and ordinary safe/denied controls through both core Markdown destinations and extension-supplied `href`/`src` attributes.

Record raw bytes, Markdown parser branch, attribute override order, library safety verdict, emitted attribute bytes, browser-normalized scheme, and denied navigation decision. A bounded positive is **library marks the raw URL safe -> emitted bytes survive -> browser normalization selects the denied scheme marker**. Preserve inert non-link controls to distinguish a filter bypass from an executable sink; an `href` emitted on an element that cannot navigate is not XSS.

## 11. Re-check CMS authority after every transformation

The Craft records expose four related test families. Use a low-privileged Control Panel user, a second disposable administrator, synthetic global sets, and patched password/config/template/process sinks.

### Generic save versus dedicated privileged action

Submit the same harmless password marker through the dedicated password route and generic element-save route. Vary self versus another synthetic user, `Edit users` versus `Administrate users`, elevated-session state, omitted fields, and nested/alternate encodings. Capture model scenario, safe/mass-assignable attributes, resolved target user, current-password/elevated-session decision, and denied password-write sink. A positive is **dedicated route denies the marker -> generic save binds `newPassword` -> write recorder selects self or the synthetic administrator without the required proof**. Never change a usable account password.

### Cleanse before decode/merge

Send inert forbidden configuration keys as ordinary nested objects and as strings decoded or merged after the initial cleanse. Patch behavior/event attachment, object creation, and process execution. Preserve raw request type, first-cleanse result, decoded object, merge order, second validation, selected class/behavior/event, and denied sink. A positive is **outer string passes cleanse -> later decode reconstructs a forbidden key -> patched configuration sink receives it**. Stop before class instantiation or command execution.

### Sandbox class and hierarchy authority

Map every allowed class, interface, method, property, and `AllowedInSandbox` attribute to the runtime object's complete ancestry. Use inert subclasses and a patched method dispatcher to compare exact-class, interface, inherited-method, overridden-method, and project-added allowlist cases. A positive is **interface/base approval -> runtime subclass exposes an inherited non-allowlisted method -> dispatcher recorder selects it**. This proves method authority drift, not RCE; do not render a command-capable Twig template.

### Sibling action authorization

Build a route/method matrix for adjacent create, save, reorder, and delete actions. Compare administrator and non-administrator sessions while patching project-config persistence. A positive is **sibling actions enforce the admin gate -> reorder reaches persistence for the non-admin principal**. Keep display-order modification separate from content access or code execution.

## Evidence and reporting boundaries

- Distinguish cache-server control, on-path cache tampering, and local archive control.
- Preserve both extraction and restore paths; either stage can break containment.
- Report wrapper-generated SSH argv, not hypothetical interception impact.
- Keep mount confinement separate from per-job authorization.
- Capture generated client defaults and every redirect authority before claiming credential forwarding.
- Separate shared-realm prototype state, sibling CSS reach, and script execution.
- For CMS routes, pair every alternate surface with the canonical route and the same synthetic policy.
- Inventory vendored or forked renderer engines; dependency manifests alone can miss the reachable parser.
- Preserve raw bytes, library output, and final browser normalization before claiming a sanitizer or URL-policy bypass.
- For configuration and template systems, re-evaluate authority after decode, merge, subclass resolution, and generic model binding.
- State exact affected/fixed versions from the source record and verify the deployed integration before reporting.
