# Joomla page-builder upload and ColdFusion traversal KEV boundary checks

Source: CISA Known Exploited Vulnerabilities catalog updates released 2026-07-07 and 2026-07-10, plus CVE/NVD records for [CVE-2026-48908](https://nvd.nist.gov/vuln/detail/CVE-2026-48908), [CVE-2026-56290](https://nvd.nist.gov/vuln/detail/CVE-2026-56290), [CVE-2026-48282](https://nvd.nist.gov/vuln/detail/CVE-2026-48282), [CVE-2026-56291](https://nvd.nist.gov/vuln/detail/CVE-2026-56291), and [CVE-2026-48939](https://nvd.nist.gov/vuln/detail/CVE-2026-48939). Vendor references include [SP Page Builder](https://www.joomshaper.com/page-builder), [JoomlaCK](https://www.joomlack.fr/), [Balbooa Forms](https://www.balbooa.com/joomla-forms), [iCagenda](https://www.icagenda.com/), and [Adobe APSB26-68](https://helpx.adobe.com/security/products/coldfusion/apsb26-68.html).

This batch is durable because the KEV additions point at two reusable operator workflows: unauthenticated CMS extension upload surfaces where extension-specific media endpoints cross into executable PHP storage, and ColdFusion path handling where traversal reaches code-execution context without user interaction. Keep validation scoped to owned or explicitly authorized instances and use inert marker files only.

## What changed

| CVE | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [CVE-2026-48908](https://nvd.nist.gov/vuln/detail/CVE-2026-48908) | JoomShaper SP Page Builder extension for Joomla, versions 1.0.0 through 6.6.1 | unauthenticated upload path accepts arbitrary files that can become executable PHP | Add extension-specific unauthenticated upload probes to Joomla page-builder assessment checklists; prove with non-executable marker files unless a lab explicitly permits PHP execution. |
| [CVE-2026-56290](https://nvd.nist.gov/vuln/detail/CVE-2026-56290) | JoomlaCK Page Builder CK extension for Joomla, versions 1.0 through 3.6.0 | unauthenticated arbitrary file upload permits executable file placement and RCE | Treat page-builder extensions as independent upload surfaces, not just CMS core media managers. |
| [CVE-2026-48282](https://nvd.nist.gov/vuln/detail/CVE-2026-48282) | Adobe ColdFusion 2025.9, 2023.20, and earlier | pathname restriction failure can traverse to an execution-relevant file boundary | Validate ColdFusion-exposed file routes for decode-order, prefix, and extension-mapping drift with disposable canaries only. |
| [CVE-2026-56291](https://nvd.nist.gov/vuln/detail/CVE-2026-56291) | Balbooa Forms extension for Joomla | form-upload path accepts dangerous file types when extension policy and storage placement are not bound | Add form-builder upload endpoints to Joomla extension recon; prove with harmless marker uploads and path reachability, not shells. |
| [CVE-2026-48939](https://nvd.nist.gov/vuln/detail/CVE-2026-48939) | iCagenda extension for Joomla | calendar/event media upload handling can place dangerous file types in web-reachable storage | Treat event/calendar attachments as independent upload surfaces during Joomla assessments. |

## Joomla page-builder upload validation

1. **Fingerprint product and extension, not just CMS core.** Capture Joomla core version, extension name, extension version, exposed page-builder routes, and whether upload endpoints are reachable before authentication.
2. **Use benign multipart canaries first.** Submit a text marker and an image-like marker with a harmless extension. Record status code, response JSON, returned file path, and whether the file is reachable over HTTP.
3. **Check filename and MIME controls separately.** Exercise original filename, content type, magic bytes, extension allowlist, path normalization, and storage directory decisions. Do not upload web shells or execute code on production targets.
4. **Prove executable placement only in a lab.** If explicit lab authorization permits PHP execution testing, use a minimal inert marker such as a fixed string response and delete the file afterward. For customer or bounty targets, stop at evidence that a dangerous extension is accepted into an executable directory.
5. **Include negative controls.** Compare patched extension versions, authenticated-only endpoints, blocked extensions, and storage outside PHP-executed paths.

## Joomla form and event upload follow-up

The July 10 KEV additions expand the same boundary beyond page builders: form builders and event/calendar extensions often expose upload fields, attachment APIs, or media helpers that operators miss when they only test Joomla core's media manager.

1. **Map every extension-owned upload route.** Include public form submissions, authenticated form drafts, event image uploads, ICS/import helpers, AJAX upload controllers, and media cleanup endpoints.
2. **Separate acceptance from execution.** First prove whether a benign marker file is accepted, where the response says it was stored, and whether the path is web-reachable. Only in a disposable lab should you test executable interpretation.
3. **Exercise filename/MIME/magic-byte drift.** Use harmless GIF-like or text canaries with dangerous-looking extensions, double extensions, mixed case, trailing dots/spaces, and mismatched `Content-Type` headers.
4. **Check context binding.** Confirm whether uploads are tied to an owned form submission/event ID, whether unauthenticated users can create attachments for existing objects, and whether cleanup/delete routes can reach sibling extension directories.
5. **Stop at safe proof.** Good evidence is **extension upload field -> dangerous extension accepted -> web-reachable or executable-directory storage** with a non-executable marker. Do not upload PHP shells or mutate production events/forms beyond disposable test objects.

## ColdFusion traversal validation

1. **Inventory reachable ColdFusion routes.** Record version evidence, exposed CFML/admin paths, document roots, upload/import/download handlers, and any reverse-proxy path rewriting that may change decode order.
2. **Use marker files under authorized roots.** Place disposable canaries in lab-controlled directories and attempt traversal only toward those markers. Never read configuration, credentials, templates, logs, or customer files.
3. **Vary path canonicalization forms.** Test single/double URL encoding, mixed separators, dot segments, trailing spaces/dots, case changes, and extension mapping boundaries when they are in scope.
4. **Stop before unsafe writes or execution.** Positive evidence can be a canary read, route dispatch to a marker template in a disposable lab, or a decision table showing traversal escaping the intended directory. Do not publish payloads that overwrite CFML, deploy web shells, or trigger production code execution.
5. **Capture proxy/origin differentials.** Include raw request path, proxy-normalized path, ColdFusion-observed path if logged, response marker, and patched-version behavior.

## August 7 follow-up: bind Phoca Commander actions to one canonical file-manager root

Three unreviewed GitHub records add a reusable Joomla file-manager workflow for Phoca Commander 1.0.0 through 6.1.3:

- [GHSA-fcf9-29pq-pgc6 / CVE-2026-66493](https://github.com/advisories/GHSA-fcf9-29pq-pgc6) reports path traversal in delete, copy, and move actions;
- [GHSA-xj92-38c4-rf5r / CVE-2026-66491](https://github.com/advisories/GHSA-xj92-38c4-rf5r) reports arbitrary file selection in `getSource`; and
- [GHSA-7c99-cx95-2fcq / CVE-2026-66492](https://github.com/advisories/GHSA-7c99-cx95-2fcq) reports traversal in the upload action.

Confirm the exact extension package, route names, authentication/role precondition, configured root, affected version, and corrected behavior. Do not infer anonymous reachability from the file-path flaw alone.

### Multi-action path matrix

1. Use a disposable Joomla site with a dedicated Phoca Commander root, an in-root source and destination, and a sibling directory containing only synthetic read, write, and delete markers.
2. Capture normal `getSource`, upload, copy, move, and delete requests through the UI. Record route/action, method, principal, CSRF proof provenance, raw source/destination selectors, and the server's configured root.
3. Replace file read, upload-finalize, copy, rename, and unlink helpers with recorders that canonicalize the proposed path and deny any outside-root operation. Keep source and destination authorization decisions distinct for two-path actions.
4. For every action, compare ordinary in-root paths with dot segments, encoded separators, platform-relevant mixed separators, absolute forms, duplicate parameters, nonexistent components, and in-root symlinks pointing to the disposable sibling markers.
5. For copy and move, cross in-root/out-of-root source and destination independently. For upload, test both caller filename metadata and any explicit destination selector. For `getSource`, stop when the recorder selects the sibling marker; do not return its bytes.
6. Exercise anonymous, lowest extension-capable role, expected manager, invalid/stale CSRF proof, read-only root, feature-disabled, and fixed-build controls. Restore all markers between cases.

Safe positives are **authorized file-manager request -> sibling canary reaches the read recorder**, **upload metadata/destination -> outside-root write recorder**, or **copy/move/delete selector -> outside-root marker reaches the corresponding denied sink**. A normalized path string or successful response without final sink reachability is insufficient. Never select Joomla configuration, credentials, logs, backups, extensions, templates, customer uploads, home directories, or operating-system paths.

Require corrected behavior to resolve an existing canonical root and target, reject canonicalization failure, enforce segment-aware containment, refuse symlink escape, and re-check the final file descriptor or syscall target. For copy and move, both endpoints must satisfy policy under the same operation.

## Reporting notes

- Name the crossed boundary precisely: **unauthenticated page-builder upload to executable PHP storage**, **form-builder upload field to CMS web root**, **event attachment to executable extension storage**, **extension upload policy to CMS web root**, or **ColdFusion route pathname to outside-root execution context**.
- Evidence should include version, endpoint, auth state, request shape, allowed extension/MIME result, storage path, route reachability, and safe canary proof.
- Keep all artifacts synthetic: disposable Joomla sites, lab ColdFusion instances, marker files, owned callback/log endpoints, and redacted paths. Do not include exploit shells, real filesystem listings, credentials, or production code-execution output.
