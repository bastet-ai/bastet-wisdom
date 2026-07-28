---
title: Kiota code-generation and Seroval deserialization boundaries from July 24 GHSA updates
---

# Kiota code-generation and Seroval deserialization boundaries from July 24 GHSA updates

A July 24 GitHub advisory wave exposes two reusable review surfaces: OpenAPI metadata crossing into generator network, filesystem, shell, source-code, and downstream plugin-manifest sinks; and typed serialization control nodes resolving attacker-selected values from a general object table. The value is not package-version alerting. It is a set of bounded tests for developer tools and server-side deserializers that consume attacker-influenced structured input.

Sources:

- [GHSA-3hrf-2gc2-mx32 / CVE-2026-59860: Kiota C# XML doc-comment newline breakout](https://github.com/advisories/GHSA-3hrf-2gc2-mx32)
- [GHSA-7f3j-j7jj-r3vr / CVE-2026-59862: Kiota Python enum-description code generation injection](https://github.com/advisories/GHSA-7f3j-j7jj-r3vr)
- [GHSA-xg2h-5xr2-29jw / CVE-2026-59861: Kiota Ruby literal interpolation injection](https://github.com/advisories/GHSA-xg2h-5xr2-29jw)
- [GHSA-jqwh-526h-c92j / CVE-2026-59859: Kiota PHP literal interpolation injection](https://github.com/advisories/GHSA-jqwh-526h-c92j)
- [GHSA-hq9q-27g5-qwpj / CVE-2026-59865: Kiota description-supplied dependency install command](https://github.com/advisories/GHSA-hq9q-27g5-qwpj)
- [GHSA-4vv7-jj25-4gh6 / CVE-2026-59866: Kiota class/namespace file-path injection](https://github.com/advisories/GHSA-4vv7-jj25-4gh6)
- [GHSA-4rj6-vrwv-wr8m / CVE-2026-59863: Kiota workspace output-path escape](https://github.com/advisories/GHSA-4rj6-vrwv-wr8m)
- [GHSA-rg4h-fpcp-2qm8 / CVE-2026-59867: Kiota external `$ref` SSRF and file inclusion](https://github.com/advisories/GHSA-rg4h-fpcp-2qm8)
- [GHSA-4jwf-m4wg-8p66: Kiota AI plugin static-template path injection](https://github.com/advisories/GHSA-4jwf-m4wg-8p66)
- [GHSA-p5rm-jg5c-8c77: encoded Kiota static-template traversal bypasses](https://github.com/advisories/GHSA-p5rm-jg5c-8c77)
- [GHSA-mv8w-475r-vwqw / CVE-2026-59940: Seroval Promise resolver type confusion](https://github.com/advisories/GHSA-mv8w-475r-vwqw)

The same publication wave included Valibot and LZ4 crash paths, an AWS CLI local-permissions issue, ONNX and ImageMagick memory-safety records, and a SvelteKit remote-form resource-exhaustion issue. Those are not expanded because this page focuses on exact, replayable source-to-sink boundaries rather than availability-only or local-host findings.

!!! warning "Authorized validation only"
    Use disposable repositories, synthetic OpenAPI descriptions, temp output roots, owned HTTP callbacks, fake dependency commands, generated clients that never leave the lab, and inert Seroval plugins. Do not point generators at cloud metadata or production internal services, read workstation secrets, overwrite shell or CI configuration, execute downloaded packages, deploy tainted generated clients, or invoke real server tools during deserialization.

## Operator use

Use these checks when scope includes:

- SDK generation from partner, tenant, repository, marketplace, or remotely hosted OpenAPI descriptions;
- pull requests that can modify `.kiota/workspace.json`, API descriptions, lockfiles, generated-client inputs, or AI plugin metadata;
- CI jobs or IDE extensions that run `kiota generate`, `kiota info`, dependency installation, generated-code compilation, or generated tests;
- Microsoft 365 Copilot or Teams plugin packages generated from `x-ai-adaptive-card` or `x-ai-capabilities` extensions;
- applications or frameworks that call `seroval.fromJSON()` on browser-, tenant-, cache-, RPC-, or job-controlled JSON with plugins enabled.

## Build one provenance map

Do not test every string blindly. Map each attacker-reachable field to the phase and interpreter that consumes it:

| Input | Kiota or framework phase | Sensitive sink | Safe proof |
| --- | --- | --- | --- |
| OpenAPI `$ref` | description resolution | build-host HTTP request or local file read | owned callback and synthetic out-of-tree schema |
| `.kiota/workspace.json` `outputPath` | workspace regeneration | filesystem write outside repository | marker-only temp sibling directory |
| `x-ms-kiota-info` names | source layout and declarations | output path plus generated identifier/context | generated filename and non-executable marker text |
| `dependencyInstallCommand` | `kiota info` / IDE handoff | human- or IDE-triggered shell | fake command string plus dry-run argument capture |
| descriptions, defaults, wire names | language writer | comment or quoted-literal breakout | harmless declaration/counter in isolated generated source |
| `static_template.file` | plugin-manifest generation and AI-host load | out-of-package path/URI resolution | synthetic sibling card plus manifest-resolution trace |
| Seroval Promise control node | `fromJSON()` graph resolution | method invocation on plugin-produced value | inert object method that increments a local counter |

Preserve the input document hash, Kiota command and version, workspace root, generated file list, outbound callback record, emitted source/manifest snippet, and fixed-version result. The report should separate effects that happen **during generation** from those that require **building/importing generated code** or **loading a plugin package downstream**.

## Kiota external-reference network and file boundaries

Affected Kiota versions before 1.32.5 could resolve remote and local external `$ref` values without an explicit allowlist. This is valuable as a generator-side SSRF/LFI check, but the proof should stop at schema inclusion.

### Bounded fixture

1. Create a disposable workspace with one root OpenAPI document.
2. Host a second synthetic schema at an owned callback origin. Give it a unique, harmless property such as `REMOTE_SCHEMA_CANARY`.
3. Place another synthetic schema in a temp sibling directory outside the workspace. Give it `SIBLING_SCHEMA_CANARY`; do not use a system or user file.
4. Reference each schema separately through `$ref`, including one nested reference to determine whether resolution is transitive.
5. Run the same Kiota generation command used by the target workflow. Capture the callback and search only the generated temp output for the canary property.
6. Repeat with Kiota 1.32.5 or later without `--allowed-external-origins`, then with a narrowly scoped owned origin/path allowed.

A positive result is **attacker-influenced OpenAPI document -> generator resolves an unapproved URL/path -> canary schema appears in generated output**. It is SSRF or local inclusion, not code execution. Never substitute metadata endpoints, internal admin APIs, credentials, or unrelated local files.

## Kiota workspace and metadata file-write boundaries

There are two distinct sources and they should produce separate findings:

- repository-controlled `.kiota/workspace.json` `outputPath`; and
- description-controlled `x-ms-kiota-info.clientClassName` or `clientNamespaceName` used in output layout.

### Temp-root matrix

1. Put the repository under `TEMP/repo` and create `TEMP/outside` with a marker indicating that the directory is disposable.
2. For the workspace case, set one consumer's `outputPath` to a relative sibling escape and, in a separate run, an absolute path under `TEMP/outside`.
3. For the metadata case, omit `-c/--class-name` so the zero-config `x-ms-kiota-info` path is reached. Use class and namespace values containing only a path-shaped canary aimed at `TEMP/outside`.
4. Run generation under a recorder that inventories created paths. Do not choose startup files, package-manager hooks, web roots, CI configuration, or executable search paths.
5. Confirm whether generated marker source appears outside `TEMP/repo`; then repeat with 1.32.5 or later.

Report **repository config to out-of-workspace generation** separately from **OpenAPI metadata to filename/namespace generation**. The class-name advisory explicitly notes that malformed names reused at several sites break compilation; do not overstate the demonstrated file-write/build-corruption primitive as clean RCE.

## Dependency-command trust handoff

In affected Kiota versions, `x-ms-kiota-info.languagesInformation.<language>.dependencyInstallCommand` could replace Kiota's normal recommendation in `kiota info` and its JSON output. Reachability depends on a developer or IDE action that executes the recommendation.

1. Use a description whose command is an inert marker such as `printf kiota-canary > TEMP/command-seen`; do not download or install anything.
2. Run both human-readable `kiota info` and `kiota info --json` and capture the exact field provenance.
3. If an IDE extension is in scope, instrument its process-spawn boundary or replace the shell runner with an argument recorder. Do not allow the marker command to reach a real shell unless explicitly authorized in the disposable lab.
4. Show whether the description-controlled string is merely displayed, offered behind confirmation, or executed by one click/automation.
5. Repeat on 1.32.5 or later, where the description-supplied command should no longer be surfaced.

The chain is **untrusted API description -> trusted tool recommendation/JSON -> human or IDE install action -> command execution**. State the required action precisely.

## Generated-language context checks

The C#, Python, Ruby, and PHP records are a compact code-generator sink taxonomy:

| Target | Attacker-shaped source | Dangerous context | Harmless validation |
| --- | --- | --- | --- |
| C# | description or external-doc text | newline exits `///` XML comment | emit a benign constant; compile only in a sandbox |
| Python | `x-ms-enum.values[].description` | newline exits generated comment | import increments an in-memory marker counter |
| Ruby | defaults or property wire names | `#{...}`, `#$...`, or `#@...` interpolation in double quotes | interpolation returns a fixed marker string |
| PHP | descriptions, defaults, or property names | `${...}`, `$var`, or `{$...}` interpolation in double quotes | expression returns a fixed marker string |

Use one generated client per language and a harmless marker—never a shell, network call, environment read, or persistence action. Capture the exact input field, emitted source context, syntax/compiler result, and whether the marker executes at generation, compile, import, construction, serialization, or request time. Fixed baselines differ: C# at 1.32.3, Python/Ruby at 1.32.0, PHP at 1.32.4; use 1.34.0 or later for the complete cluster including later plugin-path fixes.

## AI plugin static-template confinement

`static_template.file` is not opened on the Kiota build host in the reported chain. Kiota emits it into a generated Copilot/Teams plugin manifest, and a downstream AI host may later resolve it relative to the plugin package.

1. Generate an API plugin from a synthetic description using both `x-ai-adaptive-card.file` and `x-ai-capabilities.response_semantics.static_template.file` paths.
2. Test literal parent traversal, absolute/rooted forms, URI forms, percent-encoded separators/dots, double encoding, encoded NUL/control characters, and Unicode full-width dot forms.
3. Inspect the generated manifest first. Then use only a disposable local package resolver or test host containing `package/adaptiveCards/card.json` and `sibling/card-canary.json`.
4. Record the raw field, every decoding/normalization pass, manifest value, resolved final path, and whether it remains under the package root.
5. Compare 1.32.4, 1.32.5, and 1.34.0 where feasible: the advisory sequence documents an initial confinement fix followed by percent-encoding and residual canonicalization fixes.

A valid report proves **description field -> generated manifest -> downstream normalization -> synthetic out-of-package canary selected**. Do not claim build-host file read or production AI-host disclosure unless that separate sink is actually demonstrated.

## Seroval control-node type-confusion validation

The Seroval issue is narrower than generic “JSON causes RCE.” Preconditions are:

- the application accepts attacker-controlled Seroval JSON;
- it calls `seroval.fromJSON()`;
- plugins are enabled; and
- a registered plugin can deserialize a callable, privileged, or method-bearing wrapper that the confused Promise resolver can invoke.

### Inert harness

1. Pin `seroval@1.5.2` in a local Node harness and register one test-only plugin that returns an object with resolver-shaped method names. Each method should only increment a counter and append a marker to an in-memory event list.
2. Serialize a legitimate Promise-containing graph and record the expected internal control-node/reference layout. This gives a format baseline without copying a weaponized payload.
3. Mutate only the reference target so a Promise control node points to the plugin-produced object in the general reference table.
4. Call `fromJSON()` and record whether deserialization itself invokes the marker method before application code intentionally uses the value.
5. Repeat with `seroval@1.5.3`; the expected negative control is rejection before the side effect.
6. For a downstream framework, prove the exact route or RPC body reaches this path and replace all real framework tools with inert wrappers. Package presence alone is insufficient.

Lead with **untrusted typed graph -> control-node/reference-table type confusion -> plugin-produced method invoked as a deserialization side effect**. Only call it RCE when the target application registers a concretely reachable execution-capable wrapper; otherwise report the unintended invocation primitive.

## Reporting notes

Include:

- attacker control over the repository, description, manifest field, or serialized graph;
- exact command/API and version;
- source field and all transformations;
- the phase where the side effect occurs;
- disposable path/callback/counter evidence;
- a patched negative control; and
- the extra user, IDE, compile, import, deployment, or plugin precondition.

Avoid collapsing the cluster into “malicious OpenAPI equals RCE.” External `$ref` stops at fetch/inclusion in the confirmed advisory; class-name injection provides out-of-root writes but malformed generated code may not compile; plugin template paths are realized downstream; and Seroval impact depends on registered plugins and framework reachability.

## July 26 follow-up: JSON Schema `customBasePath` to generated Python import

[GHSA-7x49-hhjc-29rg / CVE-2026-63720](https://github.com/advisories/GHSA-7x49-hhjc-29rg) reports that `datamodel-code-generator` before 0.70.0 accepts schema-controlled `customBasePath` values containing newlines and emits them into a Python `from ... import ...` statement. The [primary validation commit](https://github.com/koxudaxi/datamodel-code-generator/commit/545a96c5) adds a dotted-Python-identifier validator for scalar and nested-list values and tests both file generation and `generate_dynamic_models()`.

This is the same source-generation boundary as Kiota's language-writer findings, but with two distinct execution phases:

- CLI/file generation writes attacker-shaped Python that executes only if a later workflow imports or runs it;
- dynamic-model APIs may generate and execute the resulting module in the same application process.

### Inert generation/import differential

1. Use a disposable JSON Schema with one ordinary model and a unique `customBasePath` canary. Keep the injected line to a harmless module-level assignment such as `DMCG_CANARY = "<nonce>"`; do not use imports, calls, environment reads, shell syntax, or network access.
2. Run the exact CLI, library `generate()`, or dynamic-model API reached by the assessed workflow under a temporary output root.
3. Before importing anything, preserve the schema hash, generator version/options, emitted filename, and the generated `from` statement plus adjacent canary line.
4. For file-generation workflows, import the generated module only in a fresh disposable interpreter and read the inert variable. This separates **source emitted** from **generated source executed**.
5. For dynamic-model workflows, use an in-memory marker or instrument the module-execution boundary to establish whether execution occurs during the API call.
6. Repeat with valid scalar and list `customBasePath` controls, then with 0.70.0 or the linked validation commit. The unsafe fixture should fail before an output file exists or dynamic execution begins.

The useful proof is **attacker-controlled schema extension -> newline escapes generated import context -> inert statement appears -> only the actually reachable import/dynamic phase observes the marker**. Require evidence that the target accepts untrusted schemas and later imports or dynamically executes generated code; package presence or malformed generated text alone is not RCE.

## July 28 datamodel-code-generator source/fetch/file wave

A second `datamodel-code-generator` wave expands the `customBasePath` lesson into a full schema-ingestion matrix. Treat remote retrieval, local include resolution, source emission, and later import as different sinks.

Sources and reviewed fixed controls:

- generated Python contexts: [GHSA-j884-q54q-mmx3](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-j884-q54q-mmx3) (GraphQL Union-description CR breakout, fixed 0.60.1), [GHSA-wjv6-jcfj-mf9r](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-wjv6-jcfj-mf9r) (extras comment CR breakout, fixed 0.60.2), [GHSA-386q-5hp3-95m9](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-386q-5hp3-95m9) (`default_factory`, fixed 0.60.2), [GHSA-8m8r-38jm-f355](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-8m8r-38jm-f355) (validator fields/mode, fixed 0.60.2), [GHSA-m34r-v34r-rf9q](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-m34r-v34r-rf9q) (`x-python-type`, fixed 0.60.2), and [GHSA-5578-w22f-pfx9](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-5578-w22f-pfx9) (`x-python-import`/`customTypePath`, fixed 0.64.0);
- outbound fetches: [GHSA-rfr2-mq9m-x2qx](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-rfr2-mq9m-x2qx) (`--url`, fixed 0.61.0), [GHSA-954p-556p-r752](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-954p-556p-r752) (HTTP `$ref` fetched by default, fixed 0.61.0), [GHSA-r5vv-ff45-prp2](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-r5vv-ff45-prp2) (headers retained across cross-origin redirect, fixed 0.63.0), and [GHSA-vx7x-vcc2-c44g](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-vx7x-vcc2-c44g) (DNS validate/connect rebinding gap, fixed 0.63.0);
- local includes: [GHSA-442q-2j6p-642g](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-442q-2j6p-642g) (XSD `schemaLocation`, fixed 0.62.0) and [GHSA-8359-h9fx-j6v9](https://github.com/koxudaxi/datamodel-code-generator/security/advisories/GHSA-8359-h9fx-j6v9) (JSON Schema `file://` and relative `$ref`, fixed 0.62.0).

### Source-context fixture

1. Run each input in a disposable repository with no credentials, network tokens, package hooks, or importable production modules. Preserve the generator version, input hash, options, output tree, and emitted source diff.
2. Use one inert assignment per source field. Test CR, LF, CRLF, quote, backslash, dotted-identifier, and list-element boundaries independently in descriptions, extras comments/validators, `default_factory`, `x-python-type`, `x-python-import`, and `customTypePath`.
3. First prove only that the marker escaped its expected comment, quoted value, type annotation, decorator, or import context. Syntax errors are useful negative evidence but are not execution.
4. If the real workflow imports generated models, do so only in a fresh sandbox and observe an in-memory variable or no-op counter. Never use process launch, environment reads, callbacks, persistence, or package imports as the marker.
5. Repeat at the specific fixed version. Because fixes landed across 0.60.1, 0.60.2, and 0.64.0, testing one intermediate release can leave sibling sinks reachable.

### Fetch, redirect, and local-reference fixtures

Use two owned loopback listeners: A serves the root schema and redirects; B serves a synthetic nested schema and records only path, origin, and presence of a fake header. Exercise `--url` and remote `$ref` separately across default behavior, explicit remote-reference denial, same-origin redirects, and cross-origin redirects. A positive redirect result is that B receives the fake header after A changes host, port, or scheme; never use a live credential.

For rebinding, use a fully owned DNS/test-resolver fixture whose first lookup maps to an owned global test listener and second lookup maps to loopback. Prove validation of one address followed by connection to the other owned canary. Never query metadata, RFC1918 services, or production localhost endpoints.

For file confinement, create `TEMP/repo/schema` and `TEMP/sibling/schema-canary` under one disposable parent. Test JSON Schema relative `$ref`, `file://`, and XSD `xs:include`/`xs:import` `schemaLocation` independently, including sibling-prefix and symlink controls. Run with explicit remote references disabled as a control. The positive result is **resolved local target leaves the input/base root and its synthetic type marker reaches generated output**. Do not read system files, home files, CI config, cloud credentials, or unrelated repositories.

Report narrow edges: **schema field to generated Python context**, **schema URL/reference to owned outbound fetch**, **trusted-host header to redirected origin**, **validated DNS answer to different connection address**, or **local include to out-of-root canary**. State whether generated source was merely emitted or actually imported by the assessed workflow.

## Style Dictionary token-path prototype boundary

[GHSA-vj5c-m527-mpff / CVE-2026-54639](https://github.com/style-dictionary/style-dictionary/security/advisories/GHSA-vj5c-m527-mpff) adds a generated-design-token variant. Style Dictionary `>=4.3.0,<5.4.4` could pass a token key such as `{__proto__.canary}` through `convertTokenData(..., { output: 'object' })`; the same conversion is reached indirectly by enabled Expand and transform lifecycle paths. The advisory confirms process-global `Object.prototype` pollution, but downstream impact still depends on a separate gadget.

Use a fresh Node process per row and synthetic token arrays only. Compare direct `convertTokenData`, Expand enabled/disabled, transform lifecycle, DTCG/legacy token shapes, `__proto__`, `constructor.prototype`, nested segments, and 5.4.4. Before and after each call, inspect a unique inert property on `{}`, the returned object's own keys/prototype, and one no-op sink object. Do not use authentication, process-spawn, filesystem, template-execution, or network gadgets.

Report **untrusted token path -> object conversion/transform -> process-global prototype gains synthetic marker** separately from any downstream effect. Require evidence that a server, collaborative build API, pull-request workflow, or plugin accepts attacker-controlled tokens; repository maintainers transforming only their own trusted tokens have a different boundary. Reset the process between tests so one polluted row cannot contaminate controls.
