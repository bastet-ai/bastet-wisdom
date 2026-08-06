---
title: Build cache, CMS, and renderer authority boundaries
---

# Build cache, CMS, and renderer authority boundaries

Twelve August 6 records expose a common testing question: does an early trust decision remain bound to the final file, peer, object, identity, method, or browser context? The reusable workflows cover Nx remote-cache extraction, AWS CLI EMR SSH wrappers, Contao job/crawler boundaries, Mermaid renderer state, and Statamic identity/content routes.

Source records:

- Nx self-hosted remote-cache archive extraction: [GHSA-vp3h-ghgh-jr7g / CVE-2026-71476](https://github.com/advisories/GHSA-vp3h-ghgh-jr7g);
- AWS CLI EMR helper host-key verification: [GHSA-hqvf-45jj-mccq / CVE-2026-18654](https://github.com/advisories/GHSA-hqvf-45jj-mccq);
- Contao cross-job attachment path resolution and crawler credential forwarding: [GHSA-grm4-wm43-9jh5 / CVE-2026-55825](https://github.com/advisories/GHSA-grm4-wm43-9jh5) and [GHSA-3mr9-p497-58f6 / CVE-2026-55824](https://github.com/advisories/GHSA-3mr9-p497-58f6);
- Mermaid configuration/architecture prototype writes and sibling CSS reach: [GHSA-c4c3-pg64-4m4v / CVE-2026-71438](https://github.com/advisories/GHSA-c4c3-pg64-4m4v), [GHSA-3rrr-jr9j-h3q3 / CVE-2026-71437](https://github.com/advisories/GHSA-3rrr-jr9j-h3q3), and [GHSA-6x64-9x62-f2gx / CVE-2026-50159](https://github.com/advisories/GHSA-6x64-9x62-f2gx); and
- Statamic OAuth identity matching, restricted navigation content, frontend upload rules, Antlers method resolution, and notification-email HTML: [GHSA-93qh-5269-9wcf / CVE-2026-64665](https://github.com/advisories/GHSA-93qh-5269-9wcf), [GHSA-qh8c-7588-qfrv / CVE-2026-64662](https://github.com/advisories/GHSA-qh8c-7588-qfrv), [GHSA-qhr7-v3xp-vw9m / CVE-2026-71434](https://github.com/advisories/GHSA-qhr7-v3xp-vw9m), [GHSA-j2vp-f2pv-5rj4 / CVE-2026-64663](https://github.com/advisories/GHSA-j2vp-f2pv-5rj4), and [GHSA-vx89-p3j7-8xqc / CVE-2026-71435](https://github.com/advisories/GHSA-vx89-p3j7-8xqc).

The Mermaid resource-exhaustion records [GHSA-rhh3-jpg6-66xh](https://github.com/advisories/GHSA-rhh3-jpg6-66xh) and [GHSA-2v8p-3f2j-5mp7](https://github.com/advisories/GHSA-2v8p-3f2j-5mp7) are source-tracked but not converted into an availability-testing workflow.

!!! warning "Denied sinks and synthetic authority only"
    Use disposable workspaces, owned cache/HTTP/SSH peers, fake credentials, two-user CMS fixtures, patched file/process/mutation sinks, and detached browser DOMs. Never overwrite host files, intercept operational SSH, collect crawler credentials, read another user's content, delete CMS data, upload executable content, or run active HTML in a privileged mailbox or origin.

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

## Evidence and reporting boundaries

- Distinguish cache-server control, on-path cache tampering, and local archive control.
- Preserve both extraction and restore paths; either stage can break containment.
- Report wrapper-generated SSH argv, not hypothetical interception impact.
- Keep mount confinement separate from per-job authorization.
- Capture generated client defaults and every redirect authority before claiming credential forwarding.
- Separate shared-realm prototype state, sibling CSS reach, and script execution.
- For CMS routes, pair every alternate surface with the canonical route and the same synthetic policy.
- State exact affected/fixed versions from the source record and verify the deployed integration before reporting.
