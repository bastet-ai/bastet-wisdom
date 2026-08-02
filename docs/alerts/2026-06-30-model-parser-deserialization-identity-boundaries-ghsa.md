# Model parser, deserialization, and identity-extractor boundary checks

Source: hourly offensive-security scan, 2026-06-30. Primary entries: GitHub Advisory Database [GHSA-j35x-w4gj-pf7w](https://github.com/advisories/GHSA-j35x-w4gj-pf7w) / CVE-2025-10996, [GHSA-8j3x-m868-cpw8](https://github.com/advisories/GHSA-8j3x-m868-cpw8) / CVE-2025-10995, [GHSA-m5gw-83w2-7749](https://github.com/advisories/GHSA-m5gw-83w2-7749) / CVE-2026-48207, [GHSA-m3v4-v5gx-7wf5](https://github.com/advisories/GHSA-m3v4-v5gx-7wf5) / CVE-2026-47117, and [GHSA-293q-567p-wmwq](https://github.com/advisories/GHSA-293q-567p-wmwq) / CVE-2026-47838.

These advisories are durable for operators because they expose repeatable trust-boundary tests: chemistry conversion services parsing untrusted SMILES or compressed molecule files, Python deserialization policies failing to cover reduce-state restoration, AI privacy-filter model names routing into `trust_remote_code=True`, and X.509 client-certificate CN parsing disagreeing with the authenticated identity actually selected.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-j35x-w4gj-pf7w](https://github.com/advisories/GHSA-j35x-w4gj-pf7w) / CVE-2025-10996 | Open Babel `OBSmilesParser::ParseSmiles` | crafted SMILES strings could write past a heap buffer when parsed through `obabel`, `OBConversion`, or language bindings before 3.2.0 | Scientific file-conversion APIs are attack surface when web apps, notebooks, LIMS, or cheminformatics pipelines accept user molecule text. Prove in a lab harness only. |
| [GHSA-8j3x-m868-cpw8](https://github.com/advisories/GHSA-8j3x-m868-cpw8) / CVE-2025-10995 | Open Babel bundled `zipstream` gzip reader | crafted gzip-compressed chemistry files reached an overlapping `memcpy` / out-of-bounds write path | Include compressed-wrapper variants in parser-boundary tests; a safe extension or declared format does not remove decompressor risk. |
| [GHSA-m5gw-83w2-7749](https://github.com/advisories/GHSA-m5gw-83w2-7749) / CVE-2026-48207 | Apache Fory PyFory `ReduceSerializer` | reduce-state restoration and global-name resolution bypassed documented `DeserializationPolicy` validation hooks when strict mode was disabled | Treat policy-based deserializers as sinks: every constructor, reducer, global lookup, and state-restore path needs canary deny/allow tests. |
| [GHSA-m3v4-v5gx-7wf5](https://github.com/advisories/GHSA-m3v4-v5gx-7wf5) / CVE-2026-47117 | OpenMed privacy-filter model loader | user-controlled `model_name` substring matching routed attacker repositories into Hugging Face loading with `trust_remote_code=True` | AI service assessments should test model-name routing, repository authority, `auto_map`, and tokenizer/model config execution boundaries with inert repos. |
| [GHSA-293q-567p-wmwq](https://github.com/advisories/GHSA-293q-567p-wmwq) / CVE-2026-47838 | Spring Security `SubjectDnX509PrincipalExtractor` | malformed X.509 certificate CN values could make the extractor read the wrong username | mTLS/client-cert deployments need identity-extractor parser-differential tests: certificate subject string parsing must match the principal mapping policy. |

Adjacent Open Babel NULL-pointer and out-of-bounds-read advisories, duplicate Open Babel records, Apache Fory generic duplicate summaries, Spring Security duplicate advisory IDs, and availability-only parser/resource issues were processed without separate promotion because they did not add a distinct workflow beyond the boundaries above.

## Replayable validation boundaries

### Open Babel untrusted chemistry parser harness

- Preconditions: isolated lab host or CI job with vulnerable and fixed Open Babel versions, ASAN/UBSAN if building from source, and disposable molecule inputs only.
- Exercise both direct SMILES input and gzip-wrapped chemistry files through the same path the target uses: `obabel`, `OBConversion`, Python/Ruby/Java bindings, upload converters, or notebook helpers.
- Positive evidence is limited to sanitizer crash logs, process exit status, parser-format decision tables, and fixed-version negative controls. Do not attempt exploit reliability, shellcode, memory disclosure, or production conversion-service crashes.
- Include wrapper cases: raw molecule text, `.smi`, declared alternate formats, gzip-compressed files, and API calls where the service auto-detects format from extension or content.
- Negative controls: Open Babel 3.2.0 or later, input size/time limits, parser isolation, and format allowlists bound to the actual conversion code path.

### PyFory policy-bypass deserialization harness

- Preconditions: disposable Python process, affected `pyfory` version, strict mode disabled only in the lab, and a custom `DeserializationPolicy` that denies an inert canary callable/class.
- Create paired serialized payloads that try the same canary through normal object paths, reduce-state restoration, and global-name/module-attribute resolution.
- Positive evidence is a policy-denied canary being resolved or invoked through a reducer path while the same policy blocks the direct path.
- Keep canaries harmless: set an in-memory flag, return a marker string, or write to a temporary lab file. Do not deserialize payloads that launch processes, read environment variables, import cloud SDKs, or touch credentials.
- Negative controls: PyFory 1.0.0 or later, strict mode enabled, reducer/global lookup tests in CI, and policy hooks covering every restoration path.

### OpenMed privacy-filter model-routing harness

- Preconditions: owned OpenMed lab below 1.5.2, a disposable Hugging Face-compatible repository under your control, inert `auto_map` code that records only a marker, and no production PHI/PII.
- Send model names that contain the privacy-filter substring in unexpected positions, such as an owned namespace/repository name with `privacy-filter` embedded, and record which dispatcher path runs.
- Positive evidence is the service loading code or tokenizer/model config from the attacker-controlled repository because substring routing selected the privacy-filter loader with `trust_remote_code=True`.
- Do not load untrusted third-party repositories, exfiltrate prompts, process patient data, or run commands on production inference workers.
- Negative controls: OpenMed 1.5.2 or later, exact model allowlists, `trust_remote_code=False` for user-selectable models, and repository-owner pinning.

### Spring Security X.509 principal parser-differential harness

- Preconditions: lab Spring Security app using X.509 client-certificate authentication, affected `spring-security-web`, disposable users, and a test CA accepted only by the lab.
- Generate certificates with CN values that include escaping, separators, repeated attributes, unusual ordering, and malformed-but-accepted subject strings.
- Build a table for each certificate: raw subject DN, parsed CN from `SubjectDnX509PrincipalExtractor`, expected username, authenticated username, and authorization result for a harmless route.
- Positive evidence is a certificate authenticating as a different disposable user than the mapping policy intends.
- Do not use real client certificates, production CAs, customer usernames, or privileged admin routes.
- Negative controls: `SubjectX500PrincipalExtractor`, fixed Spring Security versions, strict subject mapping, and explicit certificate-to-account binding tests.

## August 2 Keras HDF5 external-link file-authority follow-up

[GHSA-m8wh-29wm-52mv / CVE-2026-9335](https://github.com/advisories/GHSA-m8wh-29wm-52mv) reports that Keras through 3.14.0 can dereference HDF5 `ExternalLink` objects when untrusted `.h5`, `.weights.h5`, or `.keras` artifacts reach `KerasFileEditor` or `keras.saving.load_weights`. The record says those paths bypass the `safe_get_h5_group` and `safe_get_h5_dataset` helpers used to reject external and soft links. This is a **model artifact -> secondary local file authority** boundary, not generic pickle execution.

The record was unreviewed at scan time. Confirm the exact Keras package, backend, container format, entry point, and corrected behavior. HDF5 external links reference HDF5 objects in another file; do not claim arbitrary byte-file disclosure unless the tested parser can actually expose that format and object.

### Patched HDF5-open matrix

1. Create a disposable directory containing a normal toy weights file, a second synthetic HDF5 file with one uniquely named dataset, and an empty sibling directory. No model cache, home directory, environment file, credentials, datasets, notebooks, or production weights should be present.
2. Build inert container fixtures whose link target is: an internal hard link, internal soft link, relative external link to the synthetic sibling HDF5 file, absolute external link to the same file, nonexistent file, nonexistent object, nested external-link chain, and symlink alias. Keep every target inside the disposable fixture tree for the first pass.
3. Patch `h5py.File` and relevant HDF5 file-open callbacks to record the canonical filename and object path, then return a sentinel before reading a secondary file. Invoke both `KerasFileEditor` and the exact application path to `keras.saving.load_weights`; helper-only reachability is insufficient when the assessed service never exposes that path.
4. Record archive/container provenance, outer model path, link type, raw linked filename, normalized/canonical secondary path, selected object, helper used, open-recorder event, and whether any dataset would be copied into editor state or model weights.
5. Compare direct helper calls that reject links with the two affected entry points. Repeat on the corrected commit/build and require rejection before any secondary open.
6. Only if sink-level dereference is explicitly required, allow one read of the synthetic sibling dataset and verify only its random marker hash. Never point a link at `/etc`, home directories, cloud configuration, model caches, customer datasets, or another tenant's files.

The bounded positive is **untrusted model artifact -> external-link metadata -> secondary synthetic HDF5 path reaches the file-open recorder outside the artifact's own logical object graph**. A stronger canary-only result is the sibling dataset marker appearing in `KerasFileEditor` state or loaded toy weights. Report editor extraction and weight loading separately; do not infer code execution, arbitrary non-HDF5 reads, or remote reachability without an independently demonstrated upload/import path.

This pattern generalizes to model, archive, and scientific-data formats that support external references. Inventory nested files, URIs, link tables, sidecar tensors, schema includes, and resolver callbacks even when the primary artifact passed extension, signature, or `safe_mode` checks.

## August 2 Transformers named-chat-template file-write follow-up

[GHSA-xrqw-3rrv-vx5w / CVE-2026-9856](https://github.com/advisories/GHSA-xrqw-3rrv-vx5w) reports that `huggingface/transformers <= 5.8.0.dev0` used attacker-controlled `chat_template` dictionary keys as filenames when `PreTrainedTokenizerBase.save_pretrained()` or `ProcessorMixin.save_pretrained()` emitted named templates. A malicious Hub repository could supply the legacy list-of-dictionaries form in `tokenizer_config.json`; each `name` becomes a dictionary key and then `additional_chat_templates/<name>.jinja`. A traversal-bearing name could therefore move the write outside the requested save directory when a downstream workflow downloaded and re-saved the tokenizer or processor.

The GitHub record was unreviewed at scan time and does not list a corrected release. The linked [Transformers commit](https://github.com/huggingface/transformers/commit/eaaaf8494dd5386634ae37d1d122212fdc315be5) adds resolved-parent checks to both save paths and regression tests. Confirm the exact package build and fixed-release provenance; do not infer that loading alone writes a file, because the vulnerable edge requires the later `save_pretrained()` operation.

### Recorder-first save matrix

1. Use an offline disposable environment containing affected and corrected Transformers builds, a toy tokenizer or processor, and a temporary root with `save/` plus one randomly named sibling canary path. Do not use a real model cache, home directory, notebook tree, startup file, credentials directory, or production inference worker.
2. Construct local synthetic `chat_template` dictionaries rather than downloading an unknown repository. Include a normal name, nested separator, parent traversal, absolute-path-like name, mixed separator, dot segment, Unicode lookalike, symlinked `additional_chat_templates` directory, and a template name that merely contains two dots. Keep every template body to a random inert marker.
3. Patch `open()` or the module's file-write helper to record the raw path, normalized path, canonical parent, open mode, and marker hash, then raise before creating a file outside the temporary `save/` tree. Exercise tokenizer and processor save paths separately; a helper-only call is not evidence that an application's import/export workflow reaches the sink.
4. Establish positive and negative controls: a valid named template should resolve immediately under `save/additional_chat_templates/`; traversal-shaped names should be rejected before the write recorder; a normal single-template save should retain expected behavior.
5. If a filesystem proof is explicitly required in an isolated affected build, permit only one write to the pre-created disposable sibling canary path and verify its random marker hash. Never overwrite an existing file, target shell or Python startup files, or combine the primitive with code execution.
6. Repeat against the commit above or a release proven to contain it. Require rejection before file creation in both `PreTrainedTokenizerBase` and every reachable `ProcessorMixin` subclass; the advisory specifically notes Idefics, Florence, Gemma, Phi, and Qwen-VL families as examples.

The bounded positive is **untrusted repository metadata -> named chat-template key -> canonical output path outside the requested tokenizer/processor save root -> write recorder**. Preserve the full application chain in evidence: repository authority, revision pin, `tokenizer_config.json` representation, class selected, call site that invokes `save_pretrained()`, requested save root, canonical destination, and fixed-build result. Report path acceptance, write reachability, overwrite semantics, and any later execution sink as separate claims.

This generalizes beyond model deserialization: enumerate attacker-controlled names that become sidecar files during model, tokenizer, processor, adapter, dataset, or checkpoint export. Loading policy, `trust_remote_code`, artifact signatures, and revision pins do not replace canonical destination confinement when trusted software later materializes repository metadata as filenames.

## Reporting notes

- Lead with the exact boundary crossed: **untrusted molecule input to native parser**, **deserialization policy to reduce/global lookup**, **model-name substring to remote code loader**, **model metadata name to sidecar-file destination**, or **certificate subject string to authenticated username**.
- Include affected and fixed versions, the minimal canary input shape, expected denial or safe parse, observed result, and a fixed-version negative control.
- Keep evidence scoped and inert: sanitizer traces, temp-file markers, owned model repos, fake users, lab CAs, and synthetic molecule files only.
