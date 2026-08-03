---
title: SAML, repository, SSH-channel, CMS, and publish-mode trust boundaries
---

# SAML, repository, SSH-channel, CMS, and publish-mode trust boundaries

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-08-03. The Angular and Russh records were reviewed advisories; the XML::Sig, Net::SAML2, GitPython, SiYuan, Grav, and OpenWrt records were unreviewed database entries at scan time. Confirm the exact product, revision, configuration, route, role, and fixed behavior before reporting.

This wave exposes six reusable operator patterns: cryptographic verification detached from the identity object later consumed, repository metadata crossing into Git configuration, SSH callbacks detached from channel state, publish-mode routes drifting from document policy, CMS helper arguments crossing filesystem or callable boundaries, and read-only management roles reaching shell-backed methods.

Primary sources:

- Perl XML::Sig duplicate-ID [GHSA-wqp7-2ww4-q6mf / CVE-2026-9487](https://github.com/advisories/GHSA-wqp7-2ww4-q6mf) and XPath-construction [GHSA-mhmm-7px6-jx3j / CVE-2026-9390](https://github.com/advisories/GHSA-mhmm-7px6-jx3j) records;
- Perl Net::SAML2 embedded-certificate [GHSA-p5j9-p2w8-q5rw / CVE-2026-18089](https://github.com/advisories/GHSA-p5j9-p2w8-q5rw), signed-subtree [GHSA-657v-xpf8-79x2 / CVE-2026-18092](https://github.com/advisories/GHSA-657v-xpf8-79x2), and unsigned-decrypted-assertion [GHSA-g48m-j5m7-625h / CVE-2026-18108](https://github.com/advisories/GHSA-g48m-j5m7-625h) records;
- GitPython [GHSA-9xx9-hw38-h2w9 / CVE-2026-69097](https://github.com/advisories/GHSA-9xx9-hw38-h2w9);
- Russh [GHSA-m65r-rprj-r5rg / CVE-2026-68930](https://github.com/advisories/GHSA-m65r-rprj-r5rg);
- SiYuan raw-SQL [GHSA-p2x7-4c4p-8wh6 / CVE-2026-69084](https://github.com/advisories/GHSA-p2x7-4c4p-8wh6), search SQL [GHSA-5w4j-hchp-r332 / CVE-2026-69085](https://github.com/advisories/GHSA-5w4j-hchp-r332) and [GHSA-pqpf-6vqv-6w92 / CVE-2026-69083](https://github.com/advisories/GHSA-pqpf-6vqv-6w92), attribute-view traversal [GHSA-x7jr-gvvr-p9w7 / CVE-2026-69086](https://github.com/advisories/GHSA-x7jr-gvvr-p9w7), password-gate [GHSA-g64v-qqpg-v37h / CVE-2026-68584](https://github.com/advisories/GHSA-g64v-qqpg-v37h), publish-policy [GHSA-85xq-27m5-59m9 / CVE-2026-68587](https://github.com/advisories/GHSA-85xq-27m5-59m9) and [GHSA-2mmh-4rf8-7xg6 / CVE-2026-68586](https://github.com/advisories/GHSA-2mmh-4rf8-7xg6), and metadata [GHSA-3rfw-7fxw-6jxm / CVE-2026-68585](https://github.com/advisories/GHSA-3rfw-7fxw-6jxm) records;
- Grav static-call [GHSA-vj8j-973f-r65j / CVE-2026-69088](https://github.com/advisories/GHSA-vj8j-973f-r65j), watermark traversal [GHSA-mmwh-j75q-gxp8 / CVE-2026-69089](https://github.com/advisories/GHSA-mmwh-j75q-gxp8), and form redirect [GHSA-85vc-29fc-65gw / CVE-2026-69087](https://github.com/advisories/GHSA-85vc-29fc-65gw) records; and
- OpenWrt luci-app-dockerman [GHSA-wjfh-jfr9-fxvm / CVE-2026-69096](https://github.com/advisories/GHSA-wjfh-jfr9-fxvm).

!!! warning "Generated fixtures and recorders only"
    Use locally generated SAML keys and assertions, disposable repositories, an instrumented SSH server, synthetic notebooks, a lab CMS, and an isolated OpenWrt image. Never replay a real assertion, alter a real repository's Git configuration, invoke an operational SSH command, read notebooks or host files, navigate users to external sites, or execute shell payloads as the web or root account.

## Boundary map

| Surface | First trusted fact | Detached selector or state | Bounded positive |
| --- | --- | --- | --- |
| XML::Sig / Net::SAML2 | one digest, signature, or decryption operation succeeds | duplicate ID, injected XPath, embedded key, sibling assertion, or unsigned plaintext supplies consumed identity | generated canary assertion B is consumed although only A was authenticated |
| GitPython | caller may create/clone a submodule | submodule name becomes a config section and then a directive | serialized temp `.git/config` contains an inert injected key outside the intended section |
| Russh | client has authenticated | recipient channel ID reaches `exec_request` without a successful channel open | handler recorder fires for a never-opened canary channel |
| SiYuan | anonymous/publish-reader route access | raw SQL, block ID, document ID, or attribute-view ID selects global content/storage | query or object recorder selects a forbidden synthetic notebook marker |
| Grav | page editor or form submitter controls one field | static callable, resource path, or redirect authority is interpreted later | call/file/redirect recorder receives an inert out-of-policy canary |
| luci-app-dockerman | principal has the package's read ACL | mutating RPC arguments are concatenated into a root shell command | patched `system()` recorder observes syntax-changing marker bytes |

## 1. Bind SAML verification to one canonical assertion

Build all fixtures locally with a throwaway service provider, generated IdP and attacker keys, random entity IDs, and canary users. Patch the post-verification login/session sink so it records claims and returns without creating a session.

1. Establish a valid signed assertion A and require the consumer to record `A-CANARY`.
2. Change one binding at a time: duplicate A's referenced ID on unsigned assertion B; place B before or after A; use an ID containing XPath metacharacters; sign A while placing B's `NameID`, attributes, audience, or session index earlier in document order.
3. Test trust separately. Give a response an embedded attacker certificate but configure no external trust anchor, then repeat with the generated IdP trust anchor present.
4. Test encryption separately. Encrypt an unsigned canary assertion to the lab SP's public encryption certificate and verify whether decryption success is mistaken for signature success.
5. Record the reference URI, node selected for digesting, certificate source, trust-anchor decision, decrypted node, signed subtree, and exact node used to construct the identity object.
6. Repeat on fixed builds and require duplicate-ID rejection, NCName-safe lookup without string-built XPath, an external trust anchor, signature validation after decryption, and claim extraction exclusively from the verified subtree.

The strongest bounded positive is **signature checks node A -> application consumes identity from node B -> no-op session recorder receives `B-CANARY`**. XML acceptance alone is insufficient, and no real IdP assertion, account, role, cookie, or access token should enter the harness.

## 2. Treat submodule names as Git configuration syntax

GitPython before 3.1.53 is described as insufficiently escaping submodule section names during create or clone workflows. Test serialization without allowing Git to start SSH or any helper process.

1. Create a temporary parent repository and owned local child repository. Set `HOME`, global/system Git config, hooks, credential helpers, and protocol helpers to empty disposable paths.
2. Patch `subprocess.Popen` or GitPython's command runner to log argv and abort before execution. Use a harmless injected key such as `skillz.canary=true`; do not inject `core.sshCommand`, aliases, hooks, helpers, or executable commands.
3. Supply ordinary, quoted, backslash, newline, closing-bracket, and section-shaped submodule names one at a time through the affected API.
4. Parse the resulting temporary `.git/config` with both Git's config parser and an independent line/section recorder. Determine whether the canary remained data in the intended submodule section or became a new directive/section.
5. Repeat on 3.1.53 and require round-trip identity: parsed section name equals the API input and no extra key appears.

Report **repository-controlled name -> config serializer -> unintended inert directive**. Do not run a later SSH operation; the configuration boundary proves the primitive without command execution.

## 3. Enforce the SSH channel lifecycle before callbacks

The Russh advisory requires a valid login but describes channel-scoped callbacks dispatched for recipient IDs that were never opened or confirmed. Keep authentication and channel authorization as separate claims.

1. Run the affected and fixed Russh versions with a generated host key and disposable user. Replace `exec_request` and every channel-scoped callback with a recorder that accepts only `SKILLZ-CANARY` and performs no command.
2. Baseline a normal session: authenticate, open a session channel, receive confirmation, send the canary request, and close it.
3. On a fresh connection, authenticate but send no `SSH_MSG_CHANNEL_OPEN`. Send one channel request to a randomly selected nonexistent recipient ID.
4. Add controls for a denied channel-open request, a closed former channel, an ID from another connection, repeated IDs, and wraparound-adjacent values. Send one packet per case; do not enumerate a live server's channel space.
5. Capture raw packet type and recipient ID, server channel-state table, open-policy result, callback invocation, and response packet.

A positive is **authenticated connection + no confirmed channel -> channel request -> callback recorder fires**. Do not call it authentication bypass and do not execute a shell command.

## 4. Build a SiYuan route, role, object, and query matrix

Use a disposable SiYuan instance with exactly two cleartext notebooks, one publish-allowed document, one password-protected document, one publish-disabled document, and unique random markers. Never use production notebooks or encrypted notebook material.

1. Capture legitimate UI requests for each affected route family. Test anonymous, publish `RoleReader`, ordinary authenticated, and expected-admin states; test publish authentication enabled and disabled separately.
2. Pair every route with allowed object A, forbidden object B, nonexistent object, malformed ID, and cross-notebook ID. Record only marker presence or the selected object ID, not document bodies.
3. For heading, backlink, backmention, transaction, and `getBlockInfo` routes, compare list-route filtering with direct content/metadata retrieval. A list hiding B does not authorize a direct B lookup.
4. For attribute-view paths, place a synthetic JSON canary in a sibling directory and patch the file reader to return only the canonical path. Test separators, encoded separators, dot segments, absolute forms, and symlink components independently.
5. For `searchEmbedBlock`, `searchDocs`, and asset-content search, patch the SQLite execution boundary to record SQL text, bound parameters, statement count, and read-only/read-write handle selection. Use quote, delimiter, repeated-value, and benign second-statement markers but abort before SQLite executes attacker-shaped SQL.
6. Repeat on 3.7.3. Require one canonical publish-policy check for every content-returning route, containment after path resolution, parameterized query structure, single-statement enforcement, and a read-only database handle where mutation is unnecessary.

Bounded positives are a forbidden synthetic object reaching a no-content recorder, an outside-root canary path reaching a patched reader, or caller text changing SQL grammar/statement count in the recorder. Do not retrieve notebook text or execute modifying SQL.

## 5. Separate Grav editor permission from callable, file, and redirect authority

Test three independent paths in a disposable Grav site:

- **Dynamic field calls:** patch the static-call dispatcher and use a harmless test class whose method records arguments. Compare simple allowed helpers, denied dangerous methods, and fully qualified `Class::method` forms under a page-editor account without `admin.pages_twig` or super-admin rights.
- **Watermarks:** place two generated one-pixel images inside the media root and one synthetic image in a sibling directory. Patch the image loader to return the canonical selected path, then test dot segments, URI schemes, encoded separators, and symlink components. Stop before reading any other file type.
- **Form redirects:** use an owned callback origin and a form explicitly configured to interpolate a `next` field. Compare relative paths, same-origin absolute URLs, scheme-relative URLs, userinfo, backslashes, encoded separators, and the owned foreign origin. Patch navigation during automated tests and record only the `Location` decision.

The proofs are respectively **low-role editor input reaches an out-of-policy static callable recorder**, **watermark selector resolves to the sibling canary image**, or **form field chooses an external owned authority**. Do not invoke built-in filesystem/process gadgets, read host files, or send phishing links.

## 6. Cross-check read ACLs against shell-backed OpenWrt RPC methods

The luci-app-dockerman record describes a `docker.container.ttyd_start` method exposed by a broad read ACL even though it mutates state and builds a command from request fields before calling `system()` in the `rpcd` root context.

1. Use an isolated firmware image with no WAN access, containers, credentials, or host mounts. Create a least-privileged lab user holding only the package's read ACL.
2. Enumerate methods from the local ACL and RPC definitions rather than probing appliances. Classify read, mutate, process-start, and shell-backed methods.
3. Replace `system()` with a recorder that logs the final string and returns failure. Send ordinary IDs/commands/users, then inert metacharacter-shaped markers that cannot execute because the sink is patched.
4. Record authenticated role, ACL rule, method, structured request fields, final command string, sink identity, and whether syntax boundaries changed.
5. Repeat with the corrected ACL/implementation when available. Require a mutating privilege and argv-style process creation or strict field grammar before any process starts.

Report **read-only principal -> mutating RPC -> request field changes root shell grammar in a recorder**. Never execute a marker as root or test an Internet-reachable router.

## Reporting checklist

- [ ] Advisory review status, exact package/revision, role, route, and configuration are recorded.
- [ ] SAML signature, trust, decryption, node selection, and identity consumption are shown separately.
- [ ] Repository and RPC tests stop at config or command recorders before helper/process execution.
- [ ] SSH authentication, channel-open policy, channel state, and callback dispatch are distinct evidence.
- [ ] SiYuan proofs contain only synthetic marker/object/path/query metadata and no notebook content.
- [ ] Grav callable, filesystem, and redirect findings are reported as separate primitives.
- [ ] Fixed-build and negative controls fail at the intended boundary.
