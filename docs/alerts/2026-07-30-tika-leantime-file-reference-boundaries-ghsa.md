---
title: Tika and Leantime secondary file-reference boundaries
---

# Tika and Leantime secondary file-reference boundaries

Two July 30 records expose the same durable file-ingestion question: does an accepted dataset or import request contain a secondary filename that is later interpreted relative to the server filesystem or by a URL-capable file API?

Sources:

- [Apache Tika GHSA-vrmh-37mg-28h3](https://github.com/advisories/GHSA-vrmh-37mg-28h3): the ISA-Tab parser accepts `Study Assay File Name` references that can traverse outside the dataset directory and emit the referenced file into extracted text; and
- [Leantime GHSA-rfxf-9pcf-q3rq](https://github.com/advisories/GHSA-rfxf-9pcf-q3rq): the authenticated Blueprints import path passes caller-selected filenames to `file_get_contents()`, creating local-path and URL-wrapper interpretation boundaries.

The Tika record covers 1.8 through 3.3.1 and 4.0.0-alpha-1. Verify exact fixed releases from the upstream advisory before claiming a version is corrected.

!!! warning "Canary references only"
    Use disposable parser/import roots, one synthetic outside-root file, and owned callback URLs. Never reference environment files, keys, application source, cloud metadata, internal services, or another tenant's uploads.

## Preconditions

- Confirm the exact parser or import route is reached. Merely accepting an archive, directory, or blueprint is not enough.
- Record the service working directory, dataset/import root, path canonicalization, URL-wrapper configuration, process identity, and output channel.
- Create `inside-canary.txt` under the intended root and `outside-canary.txt` in a disposable sibling directory. Give each a random, non-secret marker.
- For URL behavior, run one owned HTTP listener that returns a harmless marker and cannot redirect to non-owned destinations.

## Tika ISA-Tab reference workflow

1. Build a minimal valid ISA-Tab dataset with ordinary investigation, study, and assay files. Establish the extracted-text baseline.
2. Change only `Study Assay File Name`: normal child name, missing name, `../` sibling reference, repeated traversal, absolute path, encoded separator if the surrounding ingestion layer decodes it, and symlink to the outside canary.
3. Instrument the raw field, decoded value, joined path, canonical path, containment decision, file-open target, and extracted output marker.
4. A bounded positive is **accepted investigation metadata -> secondary assay filename resolves outside the dataset root -> only the synthetic outside marker appears in extracted text**.
5. Compare patched and affected builds with the same fixture. Component-aware containment must be evaluated after decoding and symlink resolution.

Do not describe archive extraction traversal unless an archive entry itself writes outside the root; this issue is a secondary-reference read during parsing.

## Leantime blueprint file-selector workflow

1. Capture a normal authenticated Blueprints import request from the exact lab version. Identify the JSON-RPC method and the field that reaches `file_get_contents()` without guessing undocumented schemas.
2. Submit the inside canary, sibling canary, absolute temporary canary, and owned HTTP URL one dimension at a time. Test only URL wrappers enabled in the lab; never use process, archive-to-execution, or filter chains.
3. Record raw filename, PHP wrapper classification, normalized local path or parsed URL, open/fetch target, response marker, and import parser result.
4. Keep local read and outbound fetch claims separate. The owned listener proves server-side fetch; the random outside marker proves local opening.
5. Negative controls: unauthenticated request, unrelated low-role user if object ownership applies, disabled remote wrappers, out-of-root rejection, random nonexistent path, and corrected build.

## Evidence and reporting

Report **manifest secondary filename to outside-root parser read**, **blueprint filename to local file open**, or **blueprint filename to owned outbound fetch**. Include authentication state, exact route/parser, roots, canonical paths, wrapper configuration, marker hashes, callback logs, and fixed controls. Do not infer code execution from `file_get_contents()` or from parser output.
