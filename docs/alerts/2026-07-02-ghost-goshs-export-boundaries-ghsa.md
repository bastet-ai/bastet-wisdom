# Ghost preview-cache, goshs share/WebDAV, and export file-boundary checks

Source: hourly offensive-security scan, 2026-07-02. Primary entries: GitHub Advisory Database [GHSA-62q6-4hv4-vjrw](https://github.com/advisories/GHSA-62q6-4hv4-vjrw) / CVE-2026-53943, [GHSA-3whc-qvhv-xqjp](https://github.com/advisories/GHSA-3whc-qvhv-xqjp) / CVE-2026-50138, [GHSA-j48m-h7xq-2xpj](https://github.com/advisories/GHSA-j48m-h7xq-2xpj) / CVE-2026-50139, [GHSA-v45h-mqf4-6939](https://github.com/advisories/GHSA-v45h-mqf4-6939) / CVE-2025-48977, and [GHSA-mpmf-3w4r-qfpf](https://github.com/advisories/GHSA-mpmf-3w4r-qfpf) / CVE-2026-9804.

These advisories are durable for operators because they expose reusable boundaries across publishing platforms, temporary file shares, data-grid REST APIs, and Kubernetes VM export workflows: request headers crossing into shared cache keys, one-use share tokens enforced after transfer instead of before transfer, alternate WebDAV listeners bypassing HTTP mode flags, log-path selectors escaping intended log roots, and export symlinks reaching pod-local files. Keep proofs to lab instances, harmless markers, tiny canary files, disposable namespaces, and fake share links only.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-62q6-4hv4-vjrw](https://github.com/advisories/GHSA-62q6-4hv4-vjrw) / CVE-2026-53943 | Ghost frontend behind shared caches | unauthenticated `x-ghost-preview` requests could alter rendered frontend output that a cache then stores for later visitors | Test whether request-specific preview state is part of the cache key before claiming a Ghost/CDN deployment is isolated. |
| [GHSA-3whc-qvhv-xqjp](https://github.com/advisories/GHSA-3whc-qvhv-xqjp) / CVE-2026-50138 | `goshs <= v2.0.9` WebDAV listener | WebDAV routes ignored `--read-only`, `--upload-only`, and `--no-delete` flags enforced by the primary HTTP routes | File-share reviews need per-protocol mode matrices; do not assume HTTP route flags apply to WebDAV, SFTP, or alternate listeners. |
| [GHSA-j48m-h7xq-2xpj](https://github.com/advisories/GHSA-j48m-h7xq-2xpj) / CVE-2026-50139 | `goshs <= v2.0.9` share links | download counters were incremented after serving the file, allowing concurrent requests to redeem a single-use token more than once | Temporary-share assessments should include concurrency proofs for one-use and limited-use links using harmless canary files. |
| [GHSA-v45h-mqf4-6939](https://github.com/advisories/GHSA-v45h-mqf4-6939) / CVE-2025-48977 | Apache Ignite REST API `cmd=log` | authenticated log path input could traverse outside the expected log file boundary | Treat diagnostic log endpoints as file-read APIs; validate path canonicalization with synthetic log markers only. |
| [GHSA-mpmf-3w4r-qfpf](https://github.com/advisories/GHSA-mpmf-3w4r-qfpf) / CVE-2026-9804 | KubeVirt `virt-exportserver` VMExport directory endpoint | symlinks inside an exported PVC could point outside the mount root and disclose exporter pod-local files | VM/disk export flows need symlink and realpath controls; prove with disposable PVC content and pod-local marker files, never service-account tokens. |

## Operator triage

1. **Separate origin behavior from cache behavior.** For Ghost, first confirm the origin renders different output when `x-ghost-preview` is present, then test whether the shared cache varies on that header.
2. **Build a route/protocol capability matrix.** For `goshs`, compare primary HTTP and WebDAV ports for `GET`, `PUT`, `DELETE`, `MKCOL`, `MOVE`, `COPY`, share-token redemption, and configured mode flags.
3. **Probe consumption limits under concurrency.** Any one-shot download link, invite, reset, or export token should be tested with parallel requests before accepting the limit as enforced.
4. **Treat diagnostics and exports as filesystem APIs.** Ignite log reads and KubeVirt VM exports are not just admin conveniences; they cross from user-controlled selectors into server or pod filesystems.
5. **Keep evidence synthetic and bounded.** Use canary pages, throwaway share files, fake logs, and lab PVCs. Do not read staff sessions, real documents, customer VM files, pod service-account tokens, or production logs.

## Replayable validation boundaries

### Ghost `x-ghost-preview` shared-cache poisoning check

- Preconditions: owned Ghost lab or explicitly authorized customer test, shared caching layer in front of Ghost, no staff users browsing the test path, and a harmless public page created for the case.
- Send baseline requests for the canary page without `x-ghost-preview` and record cache headers, `Age`, `Via`, and response hash.
- Send a request with `x-ghost-preview` containing only a harmless preview marker or use the minimal header form described by the advisory; do not inject script or staff-targeting payloads.
- Re-request the same URL without the header from a separate client or cache-busted control path.
- Positive evidence: the no-header client receives preview-altered output or a marker that should have varied on `x-ghost-preview`.
- Negative controls: patched Ghost, cache bypass for preview-header requests, cache key variation on preview headers, and separate frontend/admin domains where applicable.

### `goshs` WebDAV mode-flag matrix

- Preconditions: disposable `goshs` instance, temp directory with only synthetic files, Basic Auth test credentials, WebDAV enabled, and no real engagement artifacts.
- Start separate cases for `--read-only`, `--upload-only`, and `--no-delete`.
- For each case, test the primary HTTP port and WebDAV port with harmless verbs: `GET`, `PROPFIND`, `PUT` of `skillz-webdav-canary.txt`, `DELETE` of a disposable file, and `MKCOL` for a marker directory.
- Positive evidence: the primary HTTP route denies the action while WebDAV permits the same class of action.
- Negative controls: fixed version or wrapper guard that applies mode flags to every WebDAV state-changing verb.
- Do not point the share root at home directories, source trees, reports, credential stores, or customer data.

### `goshs` one-shot share race harness

- Preconditions: disposable file share, one tiny canary file, generated one-use token, and no sensitive link contents.
- Create a `limit=1` or equivalent share token for the canary file.
- Fire two or more parallel requests for the same token and record status codes, byte counts, and server-side download counter state.
- Positive evidence: multiple clients receive the canary despite a one-use limit.
- Negative controls: fixed version that reserves the download count before serving, serial request that fails after the first redemption, and retry behavior for failed transfers.
- Stop at marker files; do not race password resets, invite links, production exports, or real customer shares.

### Ignite REST `cmd=log` path-boundary check

- Preconditions: authenticated Ignite lab user, disposable Ignite node, synthetic log directory, and a harmless canary file outside the approved log root.
- Confirm the normal `cmd=log` request can read an approved synthetic log path.
- Try traversal/canonicalization variants only against the harmless outside-root canary file; record request path, normalized path if available, status, and returned marker decision.
- Positive evidence: the log command returns the outside-root canary content.
- Negative controls: patched Apache Ignite 2.18.0 or later, canonical realpath root checks, and denial for symlink or traversal segments.
- Never request `/etc/passwd`, private keys, cloud credentials, kubeconfigs, application secrets, or production logs.

### KubeVirt VMExport symlink escape check

- Preconditions: isolated cluster, disposable namespace, throwaway VM/PVC, namespace-level test identity matching the advisory preconditions, and no real VM disks or service-account token evidence.
- Place a symlink inside the exported PVC that points only to a pod-local synthetic marker file created for the test environment.
- Request the VMExport directory endpoint for the symlink path and record whether the marker is returned.
- Positive evidence: the export endpoint follows the symlink outside the mounted PVC/export root.
- Negative controls: fixed KubeVirt build, `O_NOFOLLOW`/realpath enforcement, and denial when the resolved target leaves the export root.
- Do not target `/var/run/secrets/kubernetes.io/serviceaccount`, real pod config, tenant VM data, host paths, or cluster credentials.

## Reporting notes

- Lead with the crossed boundary: **preview header to shared cache entry**, **WebDAV route to ignored mode flag**, **share token to post-transfer counter race**, **diagnostic log path to outside-root file**, or **PVC symlink to exporter pod-local read**.
- Include affected version, deployment topology, exact route/protocol, synthetic marker label, positive/negative decision table, and fixed-version or configuration control.
- Keep the exploit narrative scoped to authorized validation. Avoid publishing staff-account takeover payloads, production cache poisoning details, sensitive file paths, or destructive file-share actions.

## July 28 goshs residual-boundary follow-up

Four later advisories show why a fixed primary route is not enough for a multi-protocol file server:

- [GHSA-rmxw-pq4x-3fvh / CVE-2026-54719](https://github.com/goshs-labs/goshs/security/advisories/GHSA-rmxw-pq4x-3fvh): the early `?bulk` ZIP path did not apply the effective per-folder `.goshs` ACL or block list used by normal file reads; fixed in v2.1.1.
- [GHSA-rjrw-mjq6-hpmm / CVE-2026-62325](https://github.com/goshs-labs/goshs/security/advisories/GHSA-rjrw-mjq6-hpmm): an empty password in `-b 'user:'` left both SFTP authentication handlers unset, causing the SSH library to enter no-client-auth mode; v2.1.3 was affected and v2.1.4 fixed this residual of CVE-2026-40884.
- [GHSA-hq33-8jgp-8qq3 / CVE-2026-64863](https://github.com/goshs-labs/goshs/security/advisories/GHSA-hq33-8jgp-8qq3): WebDAV `MOVE` remained outside the `--no-delete` branch even though moving removes the source and overwrite mode can remove the destination; fixed in v2.1.4.
- [GHSA-wg2q-39h6-66x9 / CVE-2026-66063](https://github.com/goshs-labs/goshs/security/advisories/GHSA-wg2q-39h6-66x9): multipart filename cleanup removed separators but did not reject the `..` component, allowing an upload-created marker to escape the served tree; the reviewed range is through v2.1.4 with a patched pseudo-version from commit `f3ef599e4091`.
- [GHSA-964w-f6gj-5236 / CVE-2026-66064](https://github.com/goshs-labs/goshs/security/advisories/GHSA-964w-f6gj-5236): `sendFile` opened a cleaned path but derived the block-list/ACL filename from the raw path, so a trailing slash produced an empty policy key and exposed block-listed files or `.goshs` itself; authentication on an auth-protected directory remained enforced. The reviewed ranges and patched pseudo-version match the multipart fix.

### One disposable route/protocol matrix

1. Start each affected release against a new temporary root containing `public.txt`, `protected/secret-canary.txt`, `protected/blocked-canary.txt`, and a disposable WebDAV source/destination pair. Protect only the synthetic `protected` directory with `.goshs`; keep global authentication off only for the ACL-routing fixture.
2. Compare normal `GET` with `?bulk&file=` as anonymous and authorized lab users. Record status, ZIP entry names, and canary hashes only. A positive result is a protected or block-listed synthetic entry present in the anonymous bulk archive while its normal route rejects.
3. Compare a block-listed canary and the synthetic `.goshs` policy file with and without a trailing slash. Record raw path, cleaned open path, derived policy filename, status, and marker hash. Preserve the advisory's limit: a 401 on an authentication-protected directory is a negative control, not an authentication bypass.
4. Start the SFTP listener with an intentionally empty lab password and no key file. Record configured handler presence and whether a no-password client reaches only the synthetic root. Do not enumerate or download non-canary files. A configuration that silently becomes `NoClientAuth` is the finding.
5. Under `--no-delete`, compare `DELETE`, `MOVE` to a new name, and `MOVE` with overwrite against disposable files. Preserve before/after hashes; never point the root at a real workspace. The meaningful differential is `DELETE` denied while `MOVE` removes or replaces a marker.
6. For multipart handling, target only a pre-created disposable sibling directory and a unique filename marker. Capture the raw filename, server-normalized name, final resolved path, and resulting marker hash. Do not target startup files, application code, credentials, or web roots.
7. Repeat every positive row on the stated fixed release or commit. Test legacy v1 separately because the reviewed records list no fixed v1 release; do not infer that a v2 fix protects it.

Report these as five separate boundaries: **bulk route to skipped folder ACL**, **raw-vs-clean filename to block-list/policy-file bypass**, **empty auth component to SFTP no-client-auth**, **WebDAV MOVE to delete-policy bypass**, and **multipart filename to outside-root write**. Preserve protocol, listener, flags, authentication configuration, and synthetic-file preconditions; do not collapse them into generic unauthenticated filesystem access.
