# SiYuan kernel: publish-access tiers, localhost-trust admin bypass, and attribute-view SQL/SSTI boundaries (GHSA)

Source: hourly offensive-security scan, 2026-09-04 late GitHub advisory wave (SiYuan kernel cluster). This is the largest cluster in the wave — 22 advisories across one desktop note-app kernel — and it is durable because it exposes a **repeatable trust-boundary audit axis** that the 2026-07-10 boundary page first flagged: a loopback note-app kernel that grants broad privileges on origin/localhost trust and that is missing per-route access-tier enforcement on its publish and attribute-view endpoints.

Primary entries (all linked in the source index): [GHSA-5fhr-f75j-8wr9](https://github.com/advisories/GHSA-5fhr-f75j-8wr9), [GHSA-8x84-r2ff-h8pq](https://github.com/advisories/GHSA-8x84-r2ff-h8pq), [GHSA-jv8v-xq2h-657v](https://github.com/advisories/GHSA-jv8v-xq2h-657v), [GHSA-qvq9-hq6p-v378](https://github.com/advisories/GHSA-qvq9-hq6p-v378), [GHSA-vpjw-wf5h-cgpq](https://github.com/advisories/GHSA-vpjw-wf5h-cgpq), [GHSA-67x2-mq63-v9vm](https://github.com/advisories/GHSA-67x2-mq63-v9vm), [GHSA-6mcf-g667-w3qv](https://github.com/advisories/GHSA-6mcf-g667-w3qv), [GHSA-x67c-8pwr-m8g3](https://github.com/advisories/GHSA-x67c-8pwr-m8g3), [GHSA-v7ph-r5r6-4jcj](https://github.com/advisories/GHSA-v7ph-r5r6-4jcj), [GHSA-3mp7-4rh5-jrv9](https://github.com/advisories/GHSA-3mp7-4rh5-jrv9), [GHSA-mw8r-mw84-88v2](https://github.com/advisories/GHSA-mw8r-mw84-88v2), [GHSA-q2vg-7qgx-x5fc](https://github.com/advisories/GHSA-q2vg-7qgx-x5fc), [GHSA-wgwx-479j-23vq](https://github.com/advisories/GHSA-wgwx-479j-23vq), [GHSA-7j72-f6wg-cxw6](https://github.com/advisories/GHSA-7j72-f6wg-cxw6), [GHSA-pm3w-vxp9-ccwc](https://github.com/advisories/GHSA-pm3w-vxp9-ccwc), [GHSA-36v8-mpjm-8j5r](https://github.com/advisories/GHSA-36v8-mpjm-8j5r), [GHSA-69mh-gvh4-8gp7](https://github.com/advisories/GHSA-69mh-gvh4-8gp7), [GHSA-fph3-ghq9-vw66](https://github.com/advisories/GHSA-fph3-ghq9-vw66), [GHSA-7hm9-v7vf-7g4w](https://github.com/advisories/GHSA-7hm9-v7vf-7g4w), [GHSA-vh22-h7hf-www7](https://github.com/advisories/GHSA-vh22-h7hf-www7), [GHSA-gw25-m53r-qh88](https://github.com/advisories/GHSA-gw25-m53r-qh88), and [GHSA-99rq-75j6-5j9f](https://github.com/advisories/GHSA-99rq-75j6-5j9f).

!!! warning "Authorized validation only"
    Keep proofs to a disposable SiYuan desktop or Docker kernel with synthetic notebooks and no personal workspace data. Use synthetic block IDs, marker-only workspace files, a lab `AccessAuthCode`, and denied SQLite/file sinks. Do not query real note content, read assets or sync keys, capture browser history, exfiltrate encrypted-notebook derivation material, or execute SQL beyond inert canary statements.

## Why this cluster is one audit axis

The 2026-07-10 page established that SiYuan's loopback kernel treats `chrome-extension://` origins as administrators and reaches unauthenticated render/template helpers. This wave generalizes that into a **route-by-route access-tier inventory**:

- **Publish-access tier is not enforced consistently.** A large share of the kernel's read endpoints (`getAttributeViewKey`, `getBlockAttrs`, `getFileAnnotation`, `getBlockBreadcrumb`, `getBlockInfo`, `getBacklinkDoc`, and the Graph endpoints) either omit the publish-password tier entirely, apply the wrong tier, or allow anonymous access where a password-protected tier should apply. The same route family is also reachable through WebSocket broadcast, where the publish-boundary check is bypassed.
- **Localhost-trust admin bypass.** `GHSA-3mp7-4rh5-jrv9` / CVE-2026-72809: endpoints gated by `AccessAuthCode` still grant administrator action to a caller identified only by localhost origin/loopback peer. Pair with the 2026-07-10 blanket `chrome-extension://` administrator trust.
- **Attribute-view → SQL/SSTI chain.** `GHSA-x67c-8pwr-m8g3` / CVE-2026-72807 routes second-order SSTI into arbitrary SQL via attribute-view rendering; `GHSA-fph3-ghq9-vw66` / CVE-2026-69083 and `GHSA-vh22-h7hf-www7` / CVE-2026-69084 reach unauthenticated arbitrary SQL execution (including `REGEXP` injection); `GHSA-q2vg-7qgx-x5fc` / CVE-2026-72811 adds SQL injection in backlink/mention search through an unescaped fragment.
- **Path/identifier handling.** `GHSA-7hm9-v7vf-7g4w` / CVE-2026-69086 (path traversal via unvalidated `avID` in `RenderAttribute...`) and `GHSA-gw25-m53r-qh88` (path traversal via an `/export/temp/` short-circuit branch) are filesystem-boundary legs; `GHSA-jv8v-xq2h-657v` / CVE-2026-72802 discloses absolute filesystem path and OS username; `GHSA-8x84-r2ff-h8pq` / CVE-2026-72801 is encrypted-notebook key-derivation/wrap exposure.
- **DoS / disclosure tails.** `GHSA-99rq-75j6-5j9f` (stored and reflected XSS via an SVG sanitizer gap) and the remaining cross-boundary disclosure records (`GHSA-pm3w-vxp9-ccwc`, `GHSA-36v8-mpjm-8j5r`, `GHSA-69mh-gvh4-8gp7`).

## Boundary map

| Class | Route / sink | Defect | Reusable check |
| --- | --- | --- | --- |
| Publish-tier omission | `getAttributeViewKey`, `getBlockAttrs`, `getFileAnnotation`, `getBlockBreadcrumb`, `getBlockInfo` | publish-password tier not applied; anonymous reaches protected data | For each read endpoint, compare anonymous vs. publish-password vs. full-auth tier and record which tier actually gates it. |
| Publish-tier omission (Graph) | Graph endpoints | publish-password tier omitted; anonymous graph access | Enumerate graph read routes; test anonymous reachability against a password-protected notebook. |
| Publish-boundary bypass | WebSocket broadcast | broadcast path skips publish-boundary check | Drive the same read through the broadcast channel and compare the access decision vs. the REST route. |
| Localhost-trust admin | auth-code-gated endpoints | loopback peer treated as administrator | Confirm whether the admin decision binds to `AccessAuthCode`, a peer address, or origin; a loopback/origin allow is the vulnerable pattern. |
| Second-order SSTI → SQL | attribute-view rendering | rendered template value reaches a SQL/REGEXP sink | Seed a value that survives one round-trip then reaches the SQL sink; prove the sink is reached with an inert canary query, not a real read. |
| Unauth SQL execution | `searchEm...`, backlink/mention search | unescaped user fragment into SQL | Craft an unescaped fragment that changes the query shape; stop at query-shape/parse evidence, not data exfiltration. |
| Path traversal | `RenderAttribute` `avID`, `/export/temp/` short-circuit | unvalidated identifier escapes the intended root | Use a sibling marker file outside the intended root; record whether the traversal reaches it. |
| Info disclosure | filesystem path / OS username; encrypted-notebook key material | absolute path, username, KDF/wrap material disclosed | Capture the disclosed fields as the boundary proof; do not use KDF material to decrypt real notebooks. |
| XSS | SVG sanitizer | legacy handler list blocked but newer attributes allowed before insert | Insert a harmless event marker via a newer attribute; prove the sanitizer gap, not script execution. |

## Replayable validation boundaries

### Publish-access tier inventory (the core check)

1. Stand up a disposable SiYuan kernel (Docker or desktop) with one synthetic notebook whose publish password is set, and one notebook with no publish password as the negative control.
2. For each attribute/read endpoint in the map above, issue the same request under three principals: **anonymous**, **publish-password**, and **full auth-code**. Record which tier actually gates the response.
3. A positive finding is a route that returns protected data to **anonymous** when a publish-password tier is configured, or a route whose tier is weaker than the notebook's configured protection.
4. Repeat the flagged routes through the **WebSocket broadcast** channel and record whether the broadcast path enforces the same tier as the REST route.
5. Capture the `AccessAuthCode` / peer-address / origin decision for the admin-gated endpoints: does the administrator role bind to a token, or is a loopback peer sufficient?

Report each positive as **configured publish tier -> observed tier -> route** without disclosing real note content. Keep evidence to route metadata, status differentials, and one synthetic block ID.

### Attribute-view → SQL/SSTI chain

1. In a lab notebook, create one attribute-view record whose cell value contains an inert canary template token, for example `SILYUAN-CANARY-{{ }}` or a fragment that would be a tautology in SQL.
2. Trigger the attribute-view render and capture the query string or prepared statement that the renderer builds (lab logging or a proxy between kernel and SQLite). A positive is that the user value reaches the SQL/`REGEXP` sink without parameterization.
3. Prove sink reach with a **query-shape differential only** — for instance, a fragment that turns the query into a syntax error vs. a clean value — not a real data read. Do not run `SELECT` against real notebook tables, do not use `UNION`/stacked queries to exfiltrate, and do not escape the SQLite sandbox.
4. For the second-order SSTI leg, confirm the value survives one round-trip (write → store → re-render) before it reaches the SQL sink; the two-stage persistence is the reusable part of the chain.

Report as **attribute-view cell -> unescaped template/fragment -> SQL/REGEXP sink**, naming the exact endpoint and the round-trip that carries the value.

### Path-traversal and identifier handling

1. Place one inert marker file just outside the intended workspace/asset root in the lab.
2. Drive `avID` in `RenderAttribute...` and the `/export/temp/` short-circuit branch with values that would escape the root (encoded `..`, absolute path, or a value that the short-circuit branch treats as a literal filesystem path).
3. A positive is the handler reading or writing the sibling marker file. Record the exact input that escaped and the resolved path.
4. For the filesystem-path/username disclosure and the encrypted-notebook key-material item, capture the disclosed fields as the boundary proof and **stop** — do not use the KDF/wrap material to decrypt a real notebook or turn the absolute path into a read primitive.

### XSS / SVG sanitizer gap

1. Seed a note containing an SVG payload that uses a *newer* handler attribute (one the legacy blocklist does not name).
2. Render it through the affected stored/reflected sink and record whether the attribute survives sanitization to the DOM. A positive is the attribute reaching the renderer with a harmless event marker, not executed script.
3. Do not escalate to cross-origin or storage-XSS data theft; the reusable value is the sanitizer-allowlist gap, proven with a marker.

## Durable operator value

1. **Access-tier drift is a whole-route-family bug, not a single-CVE bug.** SiYuan shipped 10+ advisories that are all "endpoint X forgot the publish-password tier." The operator workflow is a **full route × tier matrix** (every read endpoint × anonymous / publish-password / auth-code / loopback), not per-CVE patching. Any note-app, wiki, or "personal data" service with tiered access should be audited this way.
2. **Localhost/origin trust is the root enabler.** The admin bypass and the 2026-07-10 `chrome-extension://` administrator trust are the same class: a decision that grants privilege from *where* the request came from rather than *who* authenticated. Inventory every route that keys authorization on origin, peer address, or scheme instead of a token.
3. **Attribute-view / template-to-SQL is a reusable injection class.** Any UI that renders user cell values into a generated query (SQL, `REGEXP`, template) is a second-order injection surface. Test the value's full lifecycle: write → store → re-render → sink, because the dangerous leg is the round-trip, not the first request.
4. **Short-circuit branches are where path checks live or die.** The `/export/temp/` branch bypassing the normal root check is a pattern: audit *every* route that branches on request shape (query param, temp flag, alternate method) and re-apply the containment check on each branch.
5. **DoS/XSS tails are the disclosure, not the impact.** The SVG sanitizer gap and the disclosure items are what makes the cluster reportable; keep them bounded to marker proof so the page stays a durable recon/heuristic asset rather than a payload sheet.

## Safety

- **Disposable kernel only.** Synthetic notebooks, one synthetic block ID, marker files outside the intended root, a lab `AccessAuthCode`, and denied SQLite/file sinks.
- **No real data exfiltration.** No real note content, no asset/sync-key reads, no KDF-material use against real notebooks, no browser-history capture.
- **No real SQL execution.** Query-shape/parse evidence only; no `UNION`/stacked data reads, no sandbox escape.
- **No script execution.** XSS proven with a harmless event marker, not a live payload.

---

*Source: hourly offensive-security scan, 2026-09-04. All 22 SiYuan kernel advisories tracked in the [source index](../notes/source-index.md).*
