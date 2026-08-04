---
title: Agent tool, browser action, and stored-query boundaries
---

# Agent tool, browser action, and stored-query boundaries

Three August 4 records expose one reusable design failure: structured data that has passed an earlier trust decision is still untrusted when a later component interprets it as a tool call, browser navigation, or query fragment.

Primary sources:

- Amazon Bedrock AgentCore harness crafted-content-block tool invocation [CVE-2026-18830](https://nvd.nist.gov/vuln/detail/CVE-2026-18830) and [AWS security bulletin AWS-2026-073](https://aws.amazon.com/security/security-bulletins/2026-073-aws);
- `@a2ui/web_core` agent-controlled `openUrl` scheme handling [CVE-2026-10032](https://nvd.nist.gov/vuln/detail/CVE-2026-10032); and
- OpenMeter stored usage-attribution SQL construction [CVE-2026-18801](https://nvd.nist.gov/vuln/detail/CVE-2026-18801).

The GitHub Advisory API records for this wave are secondary/unreviewed mirrors. Treat the behavior below as a validation seed, not proof that a deployment is affected. Confirm the named product, component, release, and primary vendor/project record before reporting. OpenMeter's record identifies `v1.0.0-beta.218` through `v1.0.0-beta.231` as affected; the source records available during this scan did not provide a reliable package range for the other two.

!!! warning "Inert recorders and disposable fixtures only"
    Use fake tools, a detached browser origin, synthetic customers/meters, and patched invocation/navigation/query sinks. Never execute a tool with side effects, run script, access browser storage, or send a query to production data.

## 1. Separate message acceptance, model output, and tool authority

The AgentCore record states that crafted content blocks could invoke configured tools without model invocation and bypass the controls expected around that model path. Build a harness with one harmless tool that accepts a random marker and only logs invocation. Instrument these edges separately:

1. conversation-message schema parsing;
2. role and content-block normalization;
3. model invocation or deliberate model bypass;
4. approval/policy evaluation;
5. tool-name and argument validation; and
6. the no-op tool dispatcher.

Compare ordinary user text, model-produced tool calls, caller-supplied tool-shaped blocks, nested/duplicate content fields, unknown block types, and replayed assistant/tool-role messages. The secure invariant is that transport provenance never grants tool authority: every invocation must be produced or accepted through the configured policy and approval path.

A bounded positive is **caller-crafted message block -> no model-output event and no approval decision -> inert tool dispatcher receives the marker**. Do not configure shell, file, network, payment, cloud, or destructive tools. Preserve the exact normalized block and decision trace, but exclude prompts, credentials, and provider tokens.

## 2. Revalidate agent-supplied URLs at the browser action

The A2UI record describes a Button `functionCall` action whose agent-controlled URL reached `window.open()` without a scheme decision. Use a local component fixture with scripts disabled and replace `window.open` with a recorder. Generate equivalent actions through direct component JSON and the normal agent-render pipeline.

Test:

- relative and same-origin HTTPS controls;
- owned cross-origin HTTPS URLs;
- protocol-relative, whitespace/control-prefixed, mixed-case, encoded, and backslash-normalized forms;
- non-navigation schemes; and
- values that change after URL parsing or framework decoding.

Record original value, decoded value, browser-parser protocol/origin, user gesture, allowlist decision, and recorder argument. A strong result is **agent action accepted -> user clicks inert button -> recorder receives a non-HTTP(S) executable-capable scheme**. Do not execute the URL or use a victim application origin. Report the parser differential and action provenance; a malicious-looking string that the final browser parser rejects is only a negative control.

## 3. Trace stored values into the later query compiler

The OpenMeter record is second-order SQL injection: customer `usageAttribution.key` or `subjectKeys` values were stored, then later concatenated into a ClickHouse `WITH map(...)` expression during meter/event queries. Seed two synthetic customers and a mock query compiler whose execution function only records SQL and bound parameters.

Vary one field at a time with quotes, delimiters, Unicode lookalikes, empty/list values, duplicate keys, and harmless syntax-marker strings. Compare create/update validation, database round-trip, API serialization, meter query, event query, and any export/aggregation path that rebuilds attribution maps.

The bounded positive is **stored attribution marker -> later query construction changes SQL tokens or structure -> recorder shows the value outside a bound parameter**. Do not run a timing, union, file, network, or data-extraction payload. Seed no sensitive rows. Capture the stored value, generated query template, parameter map, parser/token diff, and affected-versus-corrected result.

## Reporting boundaries

- A caller-shaped block is not a tool-policy bypass until the dispatcher is reached without the required model/approval event.
- An unsafe URL string is not browser execution; stop at the patched `window.open` recorder and parser decision.
- A quote in generated SQL is not injection unless it changes the parsed query structure or escapes the intended value slot.
- State exactly which source is primary and which is an unreviewed advisory mirror. Do not overstate package ranges or fixed versions absent from the primary record.