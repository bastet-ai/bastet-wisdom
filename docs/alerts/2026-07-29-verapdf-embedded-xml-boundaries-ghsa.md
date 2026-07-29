---
title: veraPDF embedded-XML validation boundaries from July 29 GHSA updates
---

# veraPDF embedded-XML validation boundaries from July 29 GHSA updates

Three reviewed veraPDF advisories expose a durable file-format testing heuristic: a format described as PDF can carry secondary XML languages, and validation or metadata-extraction code may parse those embedded streams with a different security posture than the outer PDF parser.

Sources:

- [GHSA-cg9x-g3gm-h5h6 / CVE-2026-54082](https://github.com/advisories/GHSA-cg9x-g3gm-h5h6): default `DocumentBuilderFactory` use across rich-text and XFA paths;
- [GHSA-3jh7-wm29-q568 / CVE-2026-54078](https://github.com/advisories/GHSA-3jh7-wm29-q568): rich-text `/RC` or `/RV` XML parsing; and
- [GHSA-36mm-w85j-3q2j / CVE-2026-54079](https://github.com/advisories/GHSA-36mm-w85j-3q2j): XFA parsing reached by `GFPDAcroForm.getdynamicRender()` and PDF/UA-1 validation.

Affected Maven artifacts are `org.verapdf:validation-model` and `org.verapdf:validation-model-jakarta`. The aggregate advisory lists affected branches `1.17.35-1.30.1` and `1.31.1-1.31.70`, with first patched versions 1.30.2 and 1.31.71. The rich-text advisory gives a narrower lower bound of 1.25.73 for that path; preserve this source discrepancy when reporting instead of applying one lower bound to every sink.

!!! warning "Authorized validation only"
    Use locally generated PDFs, a synthetic text canary, and an owned loopback HTTP recorder in a disposable validator environment. Never target document-processing services outside scope, reference system or user files, query metadata/internal services, or place credentials and sensitive document content in evidence.

## Operator use

Apply this workflow when scope includes:

- upload, archival, accessibility, preflight, compliance, or PDF/A/PDF/UA validation services;
- background jobs that call `PDFAValidator.validate(...)` on user- or tenant-supplied documents;
- applications that inspect AcroForm rich text or call `GFPDAcroForm.getdynamicRender()`; or
- file pipelines whose extension/MIME allowlist hides secondary parsers reached after acceptance.

Package presence alone is insufficient. Establish the application route, queued job, CLI, or library call that reaches each parser path.

## Build a secondary-language map

Inventory embedded grammars before fuzzing the outer container:

| PDF carrier | Inner language | veraPDF sink | Trigger distinction | Safe evidence |
| --- | --- | --- | --- | --- |
| annotation/form `/RC` or `/RV` | XHTML/XML rich text | `DictionaryKeysHelper.getRichTextStringOrStreamEntryStringRepresentation()` | normal validation of the carrier | synthetic text marker in a local report plus owned callback |
| AcroForm `/XFA` stream | XFA/XML | `GFPDAcroForm.getdynamicRender()` | direct API call or PDF/UA-1 rule/profile reachability | owned callback and rule-execution trace |

Keep the carrier and parser edge explicit. The finding is not “all PDFs are XML”; it is **attacker-supplied PDF field -> decoded embedded XML -> default JAXP parser resolves an external entity**.

## Bounded rich-text fixture

1. In a disposable workspace, generate one minimal PDF containing an ordinary rich-text field and a unique nonce in `/RC` or `/RV`. Validate it and preserve the baseline report.
2. Create a second fixture whose embedded XML references only an owned loopback URL returning a short synthetic token such as `VERAPDF_RICH_CANARY`.
3. Run the exact application validation path. Record the PDF hash, veraPDF artifact/version, validation flavour, API/CLI entry point, callback path, and whether the returned token appears in the local validation report.
4. Compare string-backed and stream-backed rich-text entries if both are accepted by the target. Change one property per run so outer-PDF parsing failures are distinguishable from XML resolution.
5. Repeat with 1.30.2 or 1.31.71 on the corresponding release branch. The negative control should reject or leave the external reference unresolved, with no callback.

The report can distinguish **outbound entity resolution** from **in-band expansion reflected into validation output**. Do not substitute `/etc/passwd`, home-directory files, application config, or cloud credentials for the synthetic response.

## Bounded XFA fixture

The XFA edge has an extra reachability condition. The reviewed advisory states that `getdynamicRender()` is consumed by a bundled PDF/UA-1 rule, while its value is not reliably echoed into the report. Treat callback evidence and report reflection as separate outcomes.

1. Create a minimal AcroForm PDF with an XFA stream and a benign `dynamicRender` value. Compare explicit PDF/UA-1 validation, automatic flavour detection, a non-PDF/UA profile, and direct `getdynamicRender()` invocation where the application exposes it.
2. Replace only the XFA XML with a fixture referencing an owned loopback endpoint that returns `VERAPDF_XFA_CANARY`.
3. Instrument rule/property access or preserve a stack trace in the lab to prove `getdynamicRender()` was reached. Record callbacks independently; lack of report reflection is not a negative result if the owned listener was contacted.
4. Repeat with the fixed branch version and confirm the callback count remains zero.

Lead with the narrow chain: **untrusted XFA stream -> selected validation profile/rule -> XML parser -> owned outbound callback**. State whether the target auto-selects PDF/UA-1 or requires an operator-selected profile.

## Cross-format heuristic

Reuse the method for other compound formats:

1. enumerate embedded XML, HTML, SVG, archive, image, font, and script subformats;
2. map each carrier field to the library/API and feature flag that parses it;
3. test every secondary parser with synthetic local/callback canaries;
4. preserve the phase where decoding, validation, rendering, indexing, or reporting occurs; and
5. require a fixed-version negative control at the same application entry point.

This catches parser-composition bugs that extension checks and top-level MIME validation miss. Report only the demonstrated secondary-parser effect; do not infer arbitrary file disclosure, internal-service access, or code execution from a callback alone.