---
title: Agent control-plane, tool-policy, file, and fetch authority boundaries
---

# Agent control-plane, tool-policy, file, and fetch authority boundaries

Twelve August 6 records expose a reusable agent-platform testing pattern: an early mode, deny-list, approval, path, or URL decision is not authoritative when a later route, tool injector, alternate command handler, shell, file sink, or connector sees richer input.

Source records:

- NanoClaw `send_file` local-read boundary: [GHSA-q94p-g4rh-r9rf](https://github.com/advisories/GHSA-q94p-g4rh-r9rf) and [project issue #2760](https://github.com/nanocoai/nanoclaw/issues/2760);
- LettaBot shared-mode management routes: [GHSA-c8v3-2w4m-9q57](https://github.com/advisories/GHSA-c8v3-2w4m-9q57) and the [disclosure record](https://gist.github.com/YLChen-007/2ba2e586f3d16cb368c8dcd6ef680178);
- Hermes Agent memory-tool deny-policy bypass: [GHSA-6rr9-mpp7-j4mp](https://github.com/advisories/GHSA-6rr9-mpp7-j4mp), [project issue #46171](https://github.com/NousResearch/hermes-agent/issues/46171), and [proposed fix #46185](https://github.com/NousResearch/hermes-agent/pull/46185);
- IronClaw shell approval parser differential: [GHSA-cw23-qwr7-c655](https://github.com/advisories/GHSA-cw23-qwr7-c655), [project issue #4861](https://github.com/nearai/ironclaw/issues/4861), and [merged fix #4869](https://github.com/nearai/ironclaw/pull/4869);
- super-agent-party `extension_proxy` outbound-fetch boundary: [GHSA-m39w-xf3h-v4h2](https://github.com/advisories/GHSA-m39w-xf3h-v4h2) and the [disclosure record](https://gist.github.com/YLChen-007/2f12ffb785d975b46b73896c0fb8cb5d); and
- super-agent-party manual `get_file_content` dispatch: [GHSA-fvhg-m33v-6wqx](https://github.com/advisories/GHSA-fvhg-m33v-6wqx) and the [disclosure record](https://gist.github.com/YLChen-007/479bfabb441bd6cc5337db910b004841);
- Mercury Agent shell redirection, alternate `/bg` command, and restricted-child tool-surface records: [GHSA-ccg4-hv3q-9622](https://github.com/advisories/GHSA-ccg4-hv3q-9622), [issue #72](https://github.com/cosmicstack-labs/mercury-agent/issues/72), [GHSA-9hrj-55h5-5mr2](https://github.com/advisories/GHSA-9hrj-55h5-5mr2), [issue #73](https://github.com/cosmicstack-labs/mercury-agent/issues/73), [GHSA-7hmv-r6w5-pr73](https://github.com/advisories/GHSA-7hmv-r6w5-pr73), and [issue #74](https://github.com/cosmicstack-labs/mercury-agent/issues/74);
- CowAgent Self-Evolution MCP tool re-injection: [GHSA-wjcq-xp37-c947](https://github.com/advisories/GHSA-wjcq-xp37-c947) and [issue #2904](https://github.com/zhayujie/CowAgent/issues/2904);
- LobsterAI message-derived artifact file reads: [GHSA-7v78-v35x-cqg5](https://github.com/advisories/GHSA-7v78-v35x-cqg5) and [issue #2176](https://github.com/netease-youdao/LobsterAI/issues/2176); and
- JeecgBoot anonymous chat-attachment SSRF: [GHSA-wwv2-c3p6-cpr5](https://github.com/advisories/GHSA-wwv2-c3p6-cpr5) and [issue #9672](https://github.com/jeecgboot/JeecgBoot/issues/9672).

The GHSA entries are unreviewed mirrors. The NanoClaw, Hermes, Mercury, and LobsterAI project issues remain open in the cited records; the CowAgent and JeecgBoot issues are closed without a fixed release identified in the mirror; the IronClaw correction is merged; and the LettaBot and super-agent-party evidence is researcher-published rather than a vendor advisory. Treat all stated release ranges as validation seeds and confirm the deployed commit, route exposure, configuration, and current project status before reporting.

!!! warning "Denied sinks and synthetic data only"
    Use disposable agent instances, fake status objects, synthetic memory rows, temporary canary roots, owned no-content HTTP peers, and patched tool/file/network/process sinks. Never read host files, persist real conversation content, execute commands, probe internal services, or relay credentials or responses.

## 1. Inventory the final authority surface

Before testing payloads, capture one trace that joins configuration to the final action:

1. listener address, reverse-proxy path, and route authentication;
2. conversation/portal mode and caller identity;
3. requested toolsets plus explicit denies;
4. the final model-visible schemas and dispatcher allow-list;
5. approval classification and remembered session grants;
6. raw and canonical path or URL;
7. the final file, process, or connector sink; and
8. the returned or outbound delivery channel.

This prevents partial findings. A model-visible tool is not yet executable; a risky-looking command is not an approval bypass; and a private-looking URL is not SSRF until the final connector selects the owned canary peer.

## 2. Compare route authentication across operating modes

The LettaBot record describes `GET /api/v1/pairing/:channel` and `GET /api/v1/status` skipping API-key rejection when the effective portal mode is `shared`. Build a disposable server with synthetic agent, channel, pairing, and conversation identifiers. Keep the listener local or on an isolated lab network.

Create a route matrix across:

- no credential, invalid credential, and valid fake API key;
- default, `shared`, and per-channel/per-user modes;
- empty and populated synthetic pairing state; and
- direct listener versus the intended reverse-proxy path.

Record status, response schema or field-name hash, effective mode, and whether the authentication middleware ran. A bounded positive is **same unauthenticated request denied in the restrictive control mode but returns synthetic management metadata in shared mode**. Do not enumerate real pairing requests or conversation identifiers. Report mode-dependent route authorization, not a universal application takeover.

## 3. Recompute deny policy after every tool injection

The Hermes record states that built-in memory tools were filtered for `disabled_toolsets=['memory']`, after which provider schemas such as `fact_store` and `fact_feedback` were appended and inserted into the runtime's valid-tool set. This is a general test for plugins, MCP servers, provider tools, aliases, and dynamically discovered capabilities.

For each tool source, snapshot:

```text
requested enabled/disabled sets
-> built-in schema filter
-> provider/plugin injection
-> model-visible tool names
-> dispatcher-valid tool names
-> approval rule
-> patched handler result
```

Use a temporary memory provider whose handlers only record a random marker. Compare default policy, explicit allow, explicit deny, deny plus provider enabled, aliases, and reload/reconnect behavior. Require the explicit deny to win at both schema and dispatch time.

A strong result is **denied category absent after the first filter -> provider injects a member of that category -> patched handler receives the marker**. Stop before a real memory write. Preserve tool-name/provenance and decision traces, not prompt or conversation bodies.

The Mercury and CowAgent records add two useful variants. Mercury accepts `allowedTools` for a delegated child but supplies the full capability registry when the child actually runs, including sibling orchestration tools. CowAgent initially creates a reduced Self-Evolution review agent, then a later MCP synchronization step appends configured tools before schema generation.

Add delegated and background agents to the policy matrix. Create two inert child agents and one fake MCP tool whose handler only records a marker. Compare the declared child allow-list, construction-time tools, final model-visible schemas, dispatcher-valid names, target-object ownership, and patched handler result. A bounded positive is **restricted child/reviewer starts without a capability -> runtime registry or MCP reconciliation restores it -> denied tool recorder receives the marker**. For orchestration tools, patch halt/delete operations and record the synthetic target agent ID; do not interrupt real work.

## 4. Differential-test approval parsing against execution parsing

The IronClaw record describes risk classification splitting shell chains on some separators while `sh -c` also recognized newline. Its merged correction adds newline/CRLF and wrapper-aware regression coverage. Reuse that methodology wherever an agent remembers approval for a command tool.

Replace process creation with an argv/script recorder. Compare semantically equivalent inert markers encoded with:

- semicolon, newline, CRLF, pipe, and conditional separators;
- quoting, escaping, line continuation, and surrounding whitespace;
- direct shell `-c`, `env ... sh -c`, timing/wrapper utilities, and option values that invoke helpers; and
- ask-each-time versus remembered/session auto-approval.

For every case, record raw text, classifier tokens, risk level, approval decision, final interpreter/argv tuple, and whether the recorder would dispatch one or multiple commands. The bounded positive is **control encoding pauses -> equivalent alternate encoding inherits approval -> final parser trace contains a second command**. Never execute either command. Keep parser disagreement, approval inheritance, and command execution as separate claims.

Mercury contributes two controls that should be standard in this harness:

- **redirection semantics**: a classifier can label a command family such as `echo` as read-only while the final shell interprets output redirection as a write; and
- **alternate command surfaces**: a normal `run_command` path can invoke approval while an in-chat background-command path reaches a separate shell runner without the same check.

Use marker-only command strings and replace every spawn or shell constructor with a denied recorder. Pair each alternate route with the semantically equivalent guarded tool call. A bounded positive is **guarded route requests approval -> alternate route or redirection-bearing safe family is auto-approved -> denied recorder observes the same write- or execution-capable shell semantics**. Do not create the marker file or publish a command-bearing API body.

## 5. Bind file tools to a canonical allowed root and delivery authority

NanoClaw's record links an absolute path accepted by `send_file` to an outbox delivery path. The super-agent-party record links non-HTTP `file_url` input to local file handling through a manually executable tool. Test both the read authority and the subsequent response/delivery authority.

Create a temporary layout containing:

```text
allowed-root/document.txt
sibling-root/canary.txt
allowed-root/link-to-sibling -> ../sibling-root/canary.txt
```

Patch `open`, copy, and outbox/send functions so they only record the requested path and deny the syscall. Exercise relative paths, absolute paths, `..`, sibling-prefix names, symlinks, dangling final symlinks, encoded separators, `file:` forms, and path-like strings that are not HTTP(S) URLs.

Record input, decoded path, `realpath`/final target, allowed-root decision, tool provenance, and attempted response/outbox destination. A bounded positive is **untrusted tool/API input -> canonical target outside the temporary allowed root -> denied read/copy sink reached -> normal response or delivery path selected**. Never point the harness at home directories, credentials, project source, or production mounts.

Also test passive artifact parsing. The LobsterAI record describes assistant/tool text containing a `MEDIA:` or `file:` path being parsed in the renderer, automatically forwarded across an Electron preload/IPC bridge, and resolved by a main-process file reader when the session opens. Seed only a synthetic session message and patch `stat`/`readFile` at the main-process boundary. Record message provenance, parsed artifact path, session root, final canonical target, IPC method, and denied syscall. The strongest bounded claim is **message-derived path outside the disposable workspace -> automatic preview loader -> denied main-process reader**; a rendered artifact label alone is not file disclosure.

## 6. Distinguish URL detection from final-peer enforcement

The super-agent-party proxy record describes a private-address check that logged a warning but returned the URL to the connector. A detector without a deny transition is not an enforcement control.

Use two owned no-content peers representing allowed and denied destinations. Patch or wrap the connector to record, but not issue, the request. Exercise hostnames, literal addresses, redirects, DNS changes between validation and connect, mixed/encoded IP forms, user-info, explicit ports, and scheme changes.

Capture:

```text
raw URL -> parsed authority -> DNS answers -> policy result
-> redirect/final authority -> connector destination -> response relay decision
```

A strong result is **policy classifies the target as denied or private -> execution continues -> connector recorder receives that peer**. Do not contact metadata, loopback services, private production ranges, or arbitrary Internet hosts. If the connector is not reached, report only a validation inconsistency.

For AI chat attachments, trace one step further. The JeecgBoot record describes an anonymous `files` URL being downloaded, parsed as an allowed document type, and inserted into model context. Use an owned no-content document server and a patched parser/model-context sink. Capture route authentication, URL policy, resolved peer, redirect chain, downloaded media/extension decision, parser invocation, and whether a random marker would enter context. A bounded positive is **anonymous attachment URL passes incomplete address policy -> connector selects the owned denied peer -> synthetic document marker reaches the patched context builder**. Never request private services or let retrieved content reach a live model.

## Evidence and reporting boundaries

- Include positive and negative mode/auth controls for management routes.
- Diff requested policy against both model-visible and dispatcher-valid tool sets.
- Diff construction-time and final runtime tool surfaces for child, review, plugin, provider, and MCP injection paths.
- Prove shell parser or alternate-route disagreement with a denied spawn recorder, not command side effects.
- Prove filesystem escape with a temporary synthetic path and denied sink, not file contents.
- Bind passive artifact parsing to the final IPC/file syscall before claiming a local-file-read path.
- Prove SSRF at final peer selection using an owned fixture; a warning log alone is insufficient.
- State whether evidence comes from a vendor/project record, merged fix, open issue, researcher disclosure, or unreviewed mirror.
- Do not claim universal unauthenticated access, host compromise, secret theft, or fixed-version coverage beyond the exact tested configuration and source evidence.
