---
title: Template, passkey, and webmail authority boundaries
---

# Template, passkey, and webmail authority boundaries

August 7 advisory records expose three durable offensive-testing themes:

- a template sandbox can approve a wrapper or lexical path while the final stream or symlink resolves to a different file authority;
- a valid WebAuthn assertion becomes a replayable bearer artifact when the server accepts client-supplied request options and fails to advance credential state; and
- a webmail application's path-like fields can reach local files, alternate data streams, UNC peers, archive operations, and response headers through several sibling handlers.

Source records:

- Smarty nested stream-resource bypass and trusted-directory symlink escape: [GHSA-rjhh-76wf-8xmw / CVE-2026-62996](https://github.com/advisories/GHSA-rjhh-76wf-8xmw) and [GHSA-f6wf-28g6-769x / CVE-2026-62992](https://github.com/advisories/GHSA-f6wf-28g6-769x);
- Craft CMS passkey assertion replay: [GHSA-wg23-69c2-gjc8](https://github.com/advisories/GHSA-wg23-69c2-gjc8); and
- TeamDavid Webbox file, path, outbound-peer, authorization, and response-construction records: [GHSA-92px-7r7f-w562 / CVE-2026-54200](https://github.com/advisories/GHSA-92px-7r7f-w562), [GHSA-9qx3-7v72-8555 / CVE-2026-54208](https://github.com/advisories/GHSA-9qx3-7v72-8555), [GHSA-9r62-vc7q-pm8j / CVE-2026-54202](https://github.com/advisories/GHSA-9r62-vc7q-pm8j), [GHSA-8rv5-p2xx-4q2w / CVE-2026-12070](https://github.com/advisories/GHSA-8rv5-p2xx-4q2w), [GHSA-ppvf-phq2-5chq / CVE-2026-54207](https://github.com/advisories/GHSA-ppvf-phq2-5chq), [GHSA-8rw4-wgvv-9v82 / CVE-2026-54205](https://github.com/advisories/GHSA-8rw4-wgvv-9v82), [GHSA-5g7h-mgc9-867w / CVE-2026-54204](https://github.com/advisories/GHSA-5g7h-mgc9-867w), [GHSA-9q86-rqgf-5jcm / CVE-2026-54206](https://github.com/advisories/GHSA-9q86-rqgf-5jcm), [GHSA-xjch-93pr-7c7c / CVE-2026-54214](https://github.com/advisories/GHSA-xjch-93pr-7c7c), [GHSA-pfmg-m2fv-v732 / CVE-2026-54199](https://github.com/advisories/GHSA-pfmg-m2fv-v732), and [GHSA-r8f9-gq2j-8hf4 / CVE-2026-54201](https://github.com/advisories/GHSA-r8f9-gq2j-8hf4).

The adjacent TeamDavid buffer-overflow, shutdown, memory-disclosure, password-obfuscation, generic XSS, and open-redirect summaries; Apache Fory and FFmpeg memory-safety records; dracut command-injection summary; and kernel/Postfix updates are source-tracked but not generalized here. Their current records either emphasize availability, need a dedicated memory-safety harness, duplicate a better boundary below, or do not provide enough primary detail for a bounded workflow.

!!! warning "Synthetic artifacts and denied sinks only"
    Use disposable template roots, fake WebAuthn credentials, two-user mail fixtures, owned no-content SMB peers, and patched file/network/mutation/header sinks. Never read host files, capture or relay NTLM material, replay a real assertion, write or delete operational files, send real messages, or test production webmail users.

## 1. Trace the final authority, not the accepted syntax

Build one evidence row for every test:

```text
principal and feature configuration
-> raw template resource, assertion body, path, directive, or header value
-> decoding, wrapper selection, canonicalization, and policy checks
-> persisted state or selected object
-> final file, peer, session, mutation, or response-header sink
```

Pair each negative case with an ordinary valid control. An accepted template, successful parser return, generated path, or `302` response is not enough: preserve the final denied sink and affected-versus-fixed behavior.

## 2. Test template sandboxes at the final file identity

### Nested resource wrappers

The Smarty stream record states that version `5.8.0` can classify a resource as the built-in `stream` type before the security check evaluates the nested PHP stream wrapper. The direct nested wrapper and the wrapper reached through `stream:` therefore take different policy paths.

Use an instrumented Smarty fixture with security enabled, all streams denied, a disposable template directory, and an outside synthetic marker file. Replace `fopen`, `file_get_contents`, and resource loading with recorders that deny the operation. Compare:

- an ordinary in-root template;
- a direct denied stream-wrapper reference;
- the same inert reference nested behind each built-in resource type;
- case, slash, and percent-encoding variants;
- nested filters with a synthetic target name; and
- affected and fixed releases when a fixed release is identified.

Capture the raw resource string, selected Smarty resource plugin, wrapper extracted for policy, security decision, nested URI passed to the loader, and denied open target. A bounded positive is **direct wrapper denied -> built-in resource accepted -> file recorder receives the synthetic outside target**. Do not open a real file or treat base64/filter selection as additional impact.

### Symlink identity after lexical confinement

The symlink record affects Smarty before `5.8.2` when an attacker can both place a symlink under a trusted directory and influence a template reference. Create a disposable trusted root and an outside canary, then patch the final open:

```text
trusted/ordinary.tpl                 -> trusted/ordinary.tpl
trusted/link-to-canary               -> outside/canary.tpl
trusted/subdir/../link-to-canary     -> outside/canary.tpl
trusted/dangling-link                -> outside/future.tpl
```

Record the configured trusted directories, lexical normalized path, native `realpath` result, symlink chain, containment decision, and denied open target. Compare affected and `5.8.2` or later. A positive requires **lexical path passes -> existing link resolves outside -> open recorder selects the outside canary**. A dangling-link result is useful only for write/create workflows; do not report it as a read unless the eventual file exists and reaches a denied read sink.

## 3. Treat WebAuthn state as a one-time server-owned tuple

The Craft record describes two coupled conditions in Craft CMS `5.10.3` and the tested `5.x` HEAD:

1. `users/login-with-passkey` accepts `PublicKeyCredentialRequestOptions` from the unauthenticated request body, allowing an old challenge to be supplied again; and
2. the updated credential source or signature counter returned by assertion validation is not persisted.

Use a disposable Craft instance, one canary user, and a software authenticator whose credential and counters are fully test-owned. Patch session creation to issue inert session markers. Capture one successful assertion, then compare:

| Test | Request options | Assertion | Stored counter/state | Expected result |
| --- | --- | --- | --- | --- |
| fresh control | server-issued | fresh | current | one inert session marker |
| exact replay | captured | captured | unchanged or advanced | denied after first use |
| old challenge + fresh assertion | captured | fresh test credential output | current | denied if challenge is server-owned and single-use |
| fresh challenge + old assertion | server-issued | captured | current | denied by challenge/signature binding |
| second browser session | captured | captured | current | denied independent of browser cookies |

Preserve the request-options source, challenge identifier, relying-party ID, credential ID, assertion counter, stored counter before/after, validator result, persistence call, and denied session sink. A bounded positive is **first canary assertion succeeds -> no credential-state update is persisted -> byte-identical body reaches a second session marker**.

Do not capture traffic from a real user, use request logs containing production assertions, or retain private authenticator material. Report challenge reuse and counter persistence as separate failed invariants even when both are required for the observed replay.

## 4. Model webmail path fields as a shared authority surface

The TeamDavid records affect Webbox through Rollout `524` and describe several sibling features that consume path-like values: archive creation/move, link storage, search roots, message job directives, attachments, and comment files. Build one route/directive matrix rather than validating each in isolation.

Use two synthetic mail users, disposable archive roots, patched filesystem operations, and an owned SMB listener configured to record only connection metadata and immediately refuse authentication. Exercise:

- ordinary same-user relative paths;
- another synthetic user's random marker path;
- parent segments, mixed separators, drive-shaped paths, and trailing-dot/space forms;
- alternate data stream syntax against synthetic files only;
- UNC-shaped paths pointing to the owned no-content peer;
- the same path through archive, search, link, include, attachment, and comment-file handlers; and
- unauthenticated, user A, user B, and administrator route states.

For every case capture:

```text
route + handler + principal
-> raw field or directive
-> decoded/canonical local path or normalized UNC authority
-> object/user scope decision
-> final file operation or outbound peer
```

### Local file and archive boundaries

Patch open, create-directory, write, move, and delete operations. Seed only random canary names. Bounded positives are:

- **user A's request -> alternate stream or normalization bypass -> denied read selects user B's synthetic access-file marker**;
- **archive path -> canonical destination leaves the archive/user root -> denied directory-create recorder activates**;
- **write handler -> outside-root synthetic destination reaches the denied write recorder**; or
- **comment-file directive -> denied delete recorder selects an out-of-root canary**.

Do not retrieve password files, private keys, messages, or server configuration. Destination selection proves file authority; it does not prove execution.

### UNC final-peer boundaries

For archive move, link storage, search root, and include directives, record the raw path, parsed host/share, authentication state, DNS result, final `(scheme, host, port)` tuple, and denied connector call. A bounded positive is **path-like input -> connector selects the owned SMB peer despite local-path policy or missing authentication**.

Stop before any authentication exchange. Do not capture challenge responses, hashes, or reusable credentials, and do not attempt relay. An outbound connection attempt is sufficient evidence of peer authority.

### Route and response-header differentials

Compare canonical protected routes with sibling log-serving and redirect-producing routes. For response construction, use harmless `X-Canary`-shaped values in a patched header writer rather than browser redirects. Preserve raw bytes, percent-decoding, line splitting, generated status/header sequence, and final header API calls.

A bounded positive is **unauthenticated route selects a synthetic log object that the canonical route denies**, or **request data survives decoding as a second header field at the patched writer**. Keep header injection, redirect selection, cache effects, and browser script execution as separate claims.

## 5. Evidence and reporting boundaries

- State the exact reachable feature, version, principal, and precondition; Smarty symlink escape requires both link placement and template influence.
- For nested wrappers, report the resource plugin and final wrapper independently.
- For filesystem checks, preserve lexical path, canonical path, symlink/stream interpretation, and final denied operation.
- For passkeys, show first-use/replay order and both in-memory and persisted credential state; a copied request body alone is not replay proof.
- For webmail, do not generalize one route's result to sibling handlers without a route-by-handler trace.
- For UNC paths, connection metadata is enough; never collect or relay authentication material.
- Separate destination control, content control, rendering, execution, and credential impact.
- Use affected-versus-fixed comparisons whenever a fixed release exists; otherwise label the result against the exact tested build and avoid implying all releases are affected.
