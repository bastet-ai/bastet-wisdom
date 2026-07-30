---
title: VaahCMS template supply-chain and browser-execution boundaries
---

# VaahCMS template supply-chain and browser-execution boundaries

A late-July VaahCMS disclosure identifies malicious obfuscated JavaScript in the Blade template used to render security OTP messages. This yields a durable operator workflow for reviewing compromised server-rendered templates: bind the finding to an exact artifact, prove the template is reachable, recover behavior without executing the original payload, and distinguish **HTML generation**, **message delivery**, **client-side script execution**, **DOM access**, and **outbound command-channel reachability**.

Sources:

- [GHSA-m2cx-9w9f-2hm7 / CVE-2026-67595](https://github.com/advisories/GHSA-m2cx-9w9f-2hm7)
- [VulnCheck advisory](https://www.vulncheck.com/advisories/vaahcms-malicious-javascript-supply-chain-via-security-otp-blade-php)
- [VaahCMS pull request 317](https://github.com/webreinvent/vaahcms/pull/317)
- [VaahCMS removal commit `8d7898f`](https://github.com/webreinvent/vaahcms/commit/8d7898f7a385a5fade1180a9b664ff158d873129)

The public records identify VaahCMS 2.0.0 through 2.3.4 and describe an obfuscated script in `Resources/views/mails/security-otp.blade.php`. The removal commit deletes the script and advances the package version to 2.3.5. The advisory attributes WebSocket command-channel logic, password-input observation, DOM collection, and page redirect/overwrite behavior to the payload. Treat those as source claims until the exact installed artifact, loader/render path, and inert behavioral harness independently establish each edge.

!!! warning "Authorized validation only"
    Analyze copied artifacts in an isolated workspace with network egress denied. Use synthetic OTPs, fake account data, inert DOM markers, and recorder-only browser APIs. Never render the original payload in a real mailbox or authenticated browser, connect to its embedded endpoint, enter credentials, collect user messages, or preserve command-and-control details in shared evidence.

## Boundary map

| Edge | Question | Bounded positive evidence |
| --- | --- | --- |
| artifact provenance | does the exact installed package contain the suspect template bytes? | archive hash plus file hash matches the copied installed artifact |
| render reachability | does a normal application path select the template? | an instrumented renderer emits a unique synthetic OTP marker and payload marker |
| generated HTML | does the script survive server-side rendering and mail composition? | captured local message source contains the inert replacement script marker |
| client interpretation | does the selected client or web preview execute scripts in that context? | an isolated no-network harness increments a script-start counter |
| DOM capability | can that context observe synthetic password/message nodes? | recorder receives only predefined canary node identifiers |
| outbound authority | would the payload attempt a command-channel connection? | a stubbed `WebSocket` constructor records a redacted authority class and call count |
| command effect | can received data reach navigation or document-replacement sinks? | fake local events increment no-op redirect/write counters |

Do not collapse these edges. Suspicious source is not proof that the file shipped in every distribution channel; generated script-bearing HTML is not browser execution; execution is not credential capture unless the target DOM is present; and a WebSocket constructor call is not proof that an external endpoint was reachable or issued commands.

## Preserve and compare exact artifacts

1. Acquire the installed VaahCMS package or deployment tree from the authorized target as a read-only copy. Record acquisition source, package/version metadata, archive hash, suspect-file hash, filesystem path, and timestamps.
2. Obtain independently trusted copies of the preceding affected version and 2.3.5 or later. Do not run package hooks or application startup code while collecting them.
3. Compare release archive, repository tag, package-manager artifact, and deployed bytes. A repository fix does not prove that every package channel contained identical vulnerable bytes.
4. Diff the suspect template and its renderer/callers. Inventory includes, Blade render calls, mail classes, queue jobs, preview routes, and test fixtures that select `security-otp`.
5. Record structural indicators only: obfuscated block location, script tag presence, browser API families, DOM-source families, navigation/document sinks, and outbound transport type. Redact literal endpoint, encoded payload, and any recovered command strings.
6. Verify that 2.3.5 removes the block from both source and built artifact. Keep hashes and line ranges so another tester can reproduce the comparison without copying the malicious code.

A strong provenance result is **authorized installed artifact -> exact template contains release-specific obfuscated script -> ordinary renderer references that template -> independently obtained 2.3.5 artifact removes the block**.

## Deobfuscate without executing the payload

Work in a disposable, offline container or VM. Prefer parsing and constant recovery over evaluation.

1. Extract only the suspect script text from a copied template. Hash the original, then create a separate working copy.
2. Parse the JavaScript into an AST with a parser configured not to execute plugins or project-local configuration. Inventory string tables, decoder functions, dynamic-property lookups, event registration, DOM selectors, transport constructors, timers, and navigation/document-write sinks.
3. Resolve simple literal concatenation, array indexing, and deterministic decoder functions in a purpose-built evaluator that accepts only strings, numbers, arrays, and pure operations. Reject property access outside an explicit allowlist.
4. Replace browser and network primitives before any behavioral test: `WebSocket`, `fetch`, `XMLHttpRequest`, `MutationObserver`, `location`, `document.write`, timers, storage, and clipboard APIs should be recorder-only stubs.
5. Replace recovered authorities and command strings with typed placeholders such as `REDACTED_WS_AUTHORITY` and `CANARY_COMMAND_1`. Do not put the originals into tickets, the wiki, terminal history, or test fixtures.
6. Produce a source-to-sink table that separates confirmed static edges from behavior observed only in the inert harness.

Do not use `eval`, import the script as a Node module, open the original HTML in a normal browser, or permit DNS/network access merely to make deobfuscation easier.

## Render-path and message-source harness

Prove that the malicious block reaches generated output without sending mail externally.

1. Clone only the necessary render path into a disposable VaahCMS/Laravel lab, or replace the mail transport with a local non-relaying recorder. Seed one fake user and a synthetic OTP that has no authentication value.
2. Replace the suspect script body in the lab copy with a harmless marker before rendering. Preserve the original only as a sealed offline evidence file.
3. Exercise the ordinary OTP generation path, direct template render, queue worker path, and any authenticated preview route separately. Record template name, variables, queue serialization, content type, and exact output hash.
4. Capture raw local message source. Confirm whether HTML encoding, minification, sanitization, multipart generation, or queue serialization changes or removes the marker.
5. Compare the affected artifact with 2.3.5. Require the fixed artifact to generate the expected OTP message without the script block.

The bounded result is **normal synthetic OTP workflow -> suspect template selected -> script marker survives into locally captured HTML**. This establishes delivery content, not execution in a recipient client.

## Client-execution and DOM-capability matrix

Most mail clients restrict active JavaScript. Test only clients, web previews, or application views that are in scope, and preserve that precondition instead of generalizing from a permissive browser fixture.

1. Create a no-network browser harness under a fresh profile. Register a restrictive request interceptor before loading any content; every unexpected scheme or authority must fail closed.
2. Replace the malicious block with an inert behavior model that invokes only recorder stubs corresponding to the statically identified API families.
3. Seed synthetic DOM fixtures: no password field, an initial canary password field, a dynamically inserted canary field, generic message text, and an unrelated-origin iframe. Use marker values that cannot be mistaken for real data.
4. Compare raw browser HTML, the relevant webmail/client rendering path, sanitized message view, print/export view, and any VaahCMS web preview. Record CSP, sandbox flags, origin, script-start counter, observer registrations, and which canary nodes are visible.
5. Feed a fixed local event into the stubbed command handler. Navigation and document-replacement APIs must only increment counters; they must not change the real page or load another URL.
6. Repeat with the fixed template and with script disabled. These are required negative controls.

Report **template-derived script executes in client context -> recorder-only model observes synthetic node or reaches a no-op sink** only for the exact client/context tested. If scripts are stripped or blocked, report the earlier artifact/render boundary and the negative client result.

## Reporting checklist

Include:

- exact VaahCMS version, package channel, deployment path, archive/file hashes, and acquisition time;
- suspect and fixed artifact provenance, including whether repository, release, and deployed bytes agree;
- template caller/render evidence and locally captured message-source hash;
- static AST-derived API/source/sink families, with embedded authorities and command strings redacted;
- browser/client name and version, render context, origin, CSP/sandbox state, and network-deny evidence;
- recorder counts for script start, observer registration, WebSocket construction, synthetic DOM access, navigation, and document replacement;
- affected-versus-2.3.5 results for every edge; and
- separate conclusions for artifact presence, render reachability, delivery, script execution, DOM visibility, outbound attempt, and command-effect sink.

The useful operator finding is not merely “obfuscated JavaScript exists.” It is a reproducible chain whose boundaries remain explicit: **specific artifact -> reachable server template -> generated HTML -> exact client execution context -> synthetic DOM capability -> recorder-only outbound/command sinks**.