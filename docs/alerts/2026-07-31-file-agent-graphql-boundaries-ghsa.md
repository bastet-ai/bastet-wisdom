---
title: File-browser subtitle, agent file, and GraphQL recovery boundaries
---

# File-browser subtitle, agent file, and GraphQL recovery boundaries

A late July 31 advisory set yields three reusable operator checks: media helpers that bypass the file browser's normal scoped-path pipeline, agent tools whose inline mode trusts paths differently from their alternate mode, and deprecated GraphQL fields that expose internal resolver state despite an anti-enumeration response.

Primary sources:

- FileBrowser Quantum [GHSA-vvp7-h4fj-m28w / CVE-2026-54910](https://github.com/advisories/GHSA-vvp7-h4fj-m28w);
- gemini-bridge [GHSA-c5px-58j2-7fqp / CVE-2026-54785](https://github.com/advisories/GHSA-c5px-58j2-7fqp); and
- WPGraphQL [GHSA-jhh7-832h-f8hv / CVE-2026-54768](https://github.com/advisories/GHSA-jhh7-832h-f8hv).

The WPGraphQL record has inconsistent version metadata at publication time: its package range says `<= 2.6.0`, while its narrative says the deprecated field remains in later 2.x releases and lists no corrected version. Treat the exact source revision and installed schema as the authority; do not infer exposure from the package range alone.

!!! warning "Synthetic files and users only"
    Use disposable roots, random text canaries, patched file-open and outbound-model recorders, and synthetic WordPress users. Never request host credentials, keys, configuration, another user's files or profile, or send file contents to a real model provider. Stop once a recorder or canary proves the boundary.

## Boundary map

| Surface | Caller-controlled value | Expected policy | Bounded positive |
| --- | --- | --- | --- |
| FileBrowser subtitle API | `path`, `name`, and source | resolve inside the authenticated user's storage scope | a sibling canary outside the scope is selected by either parameter |
| gemini-bridge inline file tool | `directory`, `files`, mode, and query | every file remains under the selected working directory before reading or forwarding | patched reader selects an absolute, traversal, or symlink target outside the directory |
| WPGraphQL password-reset mutation | username/email and requested output fields | valid and invalid identities have indistinguishable public response shapes | deprecated `user` is object-like for a synthetic existing author and `null` for a non-user |

## 1. FileBrowser Quantum subtitle-path dual differential

The advisory describes `GET /api/media/subtitles` before commit `f3f4bbe80cb5`. The handler passed raw `path` into `GetRealPath()` without the `SanitizeUserPath()` call used by other handlers. It then joined caller-controlled `name` to the derived parent directory. These are independent selectors:

- `path` can choose an outside parent without requiring an in-scope anchor file;
- `name` can escape relative to the parent of a valid in-scope anchor; and
- the subtitle helper returns only UTF-8 text below its size limit, which constrains the read but does not restore scope.

This is more useful than a generic traversal check because it suggests a repeatable audit heuristic: enumerate media, thumbnail, subtitle, archive, preview, and metadata helpers, then compare their path-normalization sequence with the primary download handler.

### Recorder-first validation

1. Run the affected and corrected builds with one disposable source root and a non-administrator user scoped to `root/allowed`.
2. Place random UTF-8 markers at `root/allowed/movie.txt`, `root/sibling/subtitle.srt`, and a temporary host-side directory readable only in the lab. Use no real files.
3. Instrument `os.Stat`, text detection, and `os.ReadFile`, or interpose the subtitle helper, so the harness records the final canonical path and returns a sentinel before reading.
4. Establish a valid in-scope subtitle control.
5. Vary one selector at a time: dot segments in `path`; dot segments in `name`; absolute forms; percent-encoded separators; mixed slash direction on the target OS; repeated separators; Unicode lookalikes as negative controls; and symlinked parents or leaves.
6. Compare the subtitle route with the normal download route using the same logical file. Preserve the path at URL decode, user-path sanitization, source-scope resolution, join, canonicalization, and file-open stages.
7. Repeat on the corrected revision. An outside path should be rejected before any stat/read operation.

A strong finding is **the same scoped user and logical outside canary are denied by the primary file route but selected by the subtitle route**. Report the `path` and `name` branches separately. Do not retrieve `/etc/passwd`, application databases, JWT keys, SSH material, or another user's content.

## 2. gemini-bridge inline mode versus alternate-mode confinement

In gemini-bridge `>= 1.0.0, < 1.3.1`, `consult_gemini_with_files(..., mode="inline")` could read caller-selected absolute, traversal, or symlink-resolved paths outside `directory`. The advisory says the alternate `at_command` mode already applied confinement. Release `1.3.1` resolves symlinks and checks `Path.relative_to(root)` before the inline read.

The reusable test is a **mode parity matrix**. Agent and MCP tools often validate an `@file` attachment path but omit the same check when embedding bytes directly into a prompt.

### No-provider harness

1. Run the MCP server in a temporary workspace with no provider credentials and outbound network disabled.
2. Create `workspace/in-scope.txt`, `sibling/outside.txt`, and an in-workspace symlink to the sibling marker. Fill each with a different random string.
3. Patch `_read_file_for_inline`, the Gemini CLI process launcher, and any provider transport. The reader should record the canonical path and return `SKILLZ_FILE_READ_BLOCKED`; the process/transport recorder must reject every invocation.
4. Invoke the real tool-dispatch path across:

| Mode | File operand | Expected |
| --- | --- | --- |
| inline | in-scope relative file | reader selects the in-scope canary |
| inline | `../sibling/outside.txt` | rejected before reader |
| inline | absolute sibling path | rejected before reader |
| inline | in-root symlink to sibling | rejected after canonicalization |
| alternate/`at_command` | same four operands | same confinement decisions |

5. Repeat with lists containing one valid and one invalid file. Record whether the implementation rejects the whole request or silently drops only the invalid entry; partial processing can otherwise hide policy drift.
6. Compare `1.3.0` and `1.3.1`, preserving requested directory, raw file value, joined path, resolved path, policy result, reader calls, and provider/process call count.

Do not put secrets in the fixture or allow the real Gemini CLI to start. Prove **outside-root file selection** and **content forwarding** as separate edges; the patched reader is sufficient for the first, while a synthetic in-memory marker plus a mocked transport proves the second.

## 3. WPGraphQL deprecated output field defeating response obfuscation

The `sendPasswordResetEmail` resolver intentionally returns `success: true` for both existing and nonexistent identities. The advisory says internal payload state still contains a user ID on the valid branch, and deprecated schema field `SendPasswordResetEmailPayload.user` resolves that state to a `User` object. Therefore testing only the documented `success` scalar misses a response-shape oracle.

This yields a broader GraphQL review heuristic:

1. locate authentication, registration, invite, recovery, and verification mutations that promise indistinguishable responses;
2. inspect the full output type, including deprecated fields, fragments, interfaces, extensions, aliases, and nested object resolvers;
3. trace internal payload keys into every field resolver; and
4. compare valid and invalid synthetic subjects by shape, nullability, error path, timing, and side effects.

### Two-user lab matrix

Use a disposable WordPress instance with WPGraphQL, mail delivery redirected to a local sink, one synthetic author, one synthetic non-author account, and one guaranteed nonexistent identifier.

```graphql
mutation RecoveryShape($identity: String!) {
  sendPasswordResetEmail(input: { username: $identity }) {
    success
    user {
      databaseId
      name
      slug
    }
  }
}
```

Run these controls:

| Subject | Requested fields | Evidence to compare |
| --- | --- | --- |
| nonexistent identity | `success` only | status, data shape, errors, timing bucket, local mail count |
| synthetic author | `success` only | should be publicly indistinguishable except owned mail side effect |
| nonexistent identity | `success` plus deprecated `user` | `user` nullability and resolver calls |
| synthetic author | `success` plus deprecated `user` | object/null differential using only canary profile fields |
| synthetic non-author | same selection | whether exposure depends on public-author policy |

Also inspect schema introspection and generated client artifacts for deprecated fields; user interfaces may omit them while the API still serves them. Rate-limit the lab harness and use only owned mailboxes. Do not enumerate public sites, request resets for third parties, or retain reset links.

A bounded title is **“Deprecated WPGraphQL recovery payload field distinguishes a synthetic existing author from a nonexistent identity.”** Separate existence disclosure, public profile-field disclosure, and reset-mail delivery. A null/object differential does not by itself prove account takeover.

## Evidence and reporting

Preserve:

- exact package, commit, build, OS, and path-separator behavior;
- role, source root, scope, and route/mode configuration;
- raw and decoded operands plus joined and canonical paths;
- recorder events proving the selected file and proving that no real provider call occurred;
- GraphQL schema field deprecation metadata, selection set, response shape, resolver trace, and synthetic mail-sink count; and
- affected-versus-corrected controls.

Prefer narrow claims:

- **“Subtitle `path` reaches an outside-scope canary without the normal file-route sanitizer.”**
- **“Inline MCP file mode selects a symlink-resolved sibling path while alternate mode rejects it.”**
- **“Deprecated recovery output resolves internal user ID state despite a constant `success` response.”**

Do not turn sink reachability into a maximum-impact claim. Credential exposure, provider disclosure, privilege escalation, or account compromise each require additional evidence and are intentionally outside this workflow.
