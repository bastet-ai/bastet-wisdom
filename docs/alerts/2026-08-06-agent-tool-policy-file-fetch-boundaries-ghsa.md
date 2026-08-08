---
title: Agent control-plane, tool-policy, file, and fetch authority boundaries
---

# Agent control-plane, tool-policy, file, and fetch authority boundaries

Twenty-two August 6 records, three August 7 Nanobot follow-ups, and eleven August 8 MCP-wrapper records expose a reusable agent-platform testing pattern: an early mode, deny-list, approval, path, environment, argument, or URL decision is not authoritative when a later route, capability wrapper, alternate command handler, login shell, file sink, process wrapper, or connector sees richer input.

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
- TinyAGI unauthenticated message, `prompt_file`, and response-attachment boundaries: [GHSA-w22m-c8rq-w42r](https://github.com/advisories/GHSA-w22m-c8rq-w42r), [issue #284](https://github.com/TinyAGI/tinyagi/issues/284), [GHSA-2r4w-xxv7-6r74](https://github.com/advisories/GHSA-2r4w-xxv7-6r74), [issue #283](https://github.com/TinyAGI/tinyagi/issues/283), [GHSA-69rx-5vq2-c562](https://github.com/advisories/GHSA-69rx-5vq2-c562), and [issue #282](https://github.com/TinyAGI/tinyagi/issues/282);
- NanoClaw child-agent privilege inheritance: [GHSA-grxx-9qr2-2q6v](https://github.com/advisories/GHSA-grxx-9qr2-2q6v) and [issue #2807](https://github.com/nanocoai/nanoclaw/issues/2807); and
- `openclaw-cn` wrapper approval, elevated-sender, and dangling-symlink `apply_patch` boundaries: [GHSA-p2px-f69r-9h28](https://github.com/advisories/GHSA-p2px-f69r-9h28), [issue #563](https://github.com/mf-yang/openclaw-cn/issues/563), [GHSA-f57q-9mhr-fhmm](https://github.com/advisories/GHSA-f57q-9mhr-fhmm), [issue #564](https://github.com/mf-yang/openclaw-cn/issues/564), [GHSA-2mj8-f2gc-5q5j](https://github.com/advisories/GHSA-2mj8-f2gc-5q5j), and [issues #565–566](https://github.com/mf-yang/openclaw-cn/issues/565).
- OpenChamber default-auth, command-route, and workspace-read boundaries: [GHSA-xj9x-9j3p-fff9 / CVE-2026-53975](https://github.com/advisories/GHSA-xj9x-9j3p-fff9), [GHSA-9wgq-4cmq-jhvv / CVE-2026-53976](https://github.com/advisories/GHSA-9wgq-4cmq-jhvv), and the [project correction](https://github.com/openchamber/openchamber/commit/f1b9506132faf6c564a2694c7f33b94421a49b4a); and
- LudusMCP credential-dialog description-to-command boundary: [GHSA-5ccg-4qw3-g338 / CVE-2026-19045](https://github.com/advisories/GHSA-5ccg-4qw3-g338) and [project issue #2](https://github.com/NocteDefensor/LudusMCP/issues/2); and
- LudusMCP direct CLI-wrapper and guide-path boundaries: [GHSA-grhp-mc55-jxg8 / CVE-2026-19047](https://github.com/advisories/GHSA-grhp-mc55-jxg8), [project issue #3](https://github.com/NocteDefensor/LudusMCP/issues/3), [GHSA-6j8j-xrrf-px36 / CVE-2026-19046](https://github.com/advisories/GHSA-6j8j-xrrf-px36), and [project issue #4](https://github.com/NocteDefensor/LudusMCP/issues/4).
- Nanobot shell allow-list, login-shell environment, and MCP capability-scope boundaries: [GHSA-m259-67hc-p7v5 / CVE-2026-19243](https://github.com/advisories/GHSA-m259-67hc-p7v5), [issue #4521](https://github.com/HKUDS/nanobot/issues/4521), [merged fix #4562](https://github.com/HKUDS/nanobot/pull/4562), [GHSA-hfxr-wggc-4cr6 / CVE-2026-19245](https://github.com/advisories/GHSA-hfxr-wggc-4cr6), [issue #4518](https://github.com/HKUDS/nanobot/issues/4518), [GHSA-qwp6-wxvx-2jc8 / CVE-2026-19244](https://github.com/advisories/GHSA-qwp6-wxvx-2jc8), [issue #4435](https://github.com/HKUDS/nanobot/issues/4435), and [merged fix #4436](https://github.com/HKUDS/nanobot/pull/4436).
- August 8 MCP wrapper and local journey-path records: context-engine `review-git-diff` [GHSA-fjwc-rc47-268g / CVE-2026-19266](https://github.com/advisories/GHSA-fjwc-rc47-268g), mcp-bridge-api server command/argument dispatch [GHSA-c8c4-xf97-vvc8 / CVE-2026-19263](https://github.com/advisories/GHSA-c8c4-xf97-vvc8), MCPGateway Claude usage-range handling [GHSA-8cv7-xjpc-f5hw / CVE-2026-19268](https://github.com/advisories/GHSA-8cv7-xjpc-f5hw), and mcp-ui-probe journey/usage storage [GHSA-h8jj-pqww-5m4w / CVE-2026-19270](https://github.com/advisories/GHSA-h8jj-pqww-5m4w).
- August 8 local MCP tool follow-ups: mcp-pdf-vision `load_pdf` `pdfPath`/`sessionId` handling [GHSA-jgc6-5vgc-hvqg / CVE-2026-19279](https://github.com/advisories/GHSA-jgc6-5vgc-hvqg) and slidev-builder-mcp `generateChart` `outputDir` handling [GHSA-wgq9-x672-9734 / CVE-2026-19281](https://github.com/advisories/GHSA-wgq9-x672-9734).
- August 8 MCP memory/history/manifest path follow-ups: memory-graph domain storage [GHSA-4297-h6wq-2qm5 / CVE-2026-19285](https://github.com/advisories/GHSA-4297-h6wq-2qm5) and [issue #14](https://github.com/aaronsb/memory-graph/issues/14), mindpilot-mcp history storage [GHSA-6cmv-x2ph-3gc2 / CVE-2026-19287](https://github.com/advisories/GHSA-6cmv-x2ph-3gc2) and [issue #24](https://github.com/abrinsmead/mindpilot-mcp/issues/24), and rive-mcp-server-core library manifests [GHSA-4p6x-rj5h-hg93 / CVE-2026-19288](https://github.com/advisories/GHSA-4p6x-rj5h-hg93) and [issue #2](https://github.com/astralisone/rive-mcp-server-core/issues/2); and
- August 8 project/Git wrapper follow-ups: coder-api project creation [GHSA-745r-gxf5-fh45 / CVE-2026-19284](https://github.com/advisories/GHSA-745r-gxf5-fh45) and [issue #9](https://github.com/MauricioMilano/coder-api/issues/9), plus llm_memory_mcp `auto.capture` [GHSA-rrf2-j3h9-99wg / CVE-2026-19282](https://github.com/advisories/GHSA-rrf2-j3h9-99wg) and [issue #21](https://github.com/andreahaku/llm_memory_mcp/issues/21).

The GHSA entries are unreviewed mirrors except where a source record says otherwise. The NanoClaw, TinyAGI, `openclaw-cn`, Hermes, Mercury, LobsterAI, LudusMCP, mcp-pdf-vision, slidev-builder-mcp, memory-graph, mindpilot-mcp, rive-mcp-server-core, coder-api, and llm_memory_mcp project issues remain open in the cited records; the CowAgent and JeecgBoot issues are closed without a fixed release identified in the mirror; the IronClaw and OpenChamber corrections are committed; and the LettaBot and super-agent-party evidence is researcher-published rather than a vendor advisory. Nanobot's cited corrections are merged, and the mirrors identify `0.3.0` as containing the shell and MCP fixes. The context-engine mirror names `1.9.1` and correction `e0729dcfd3a2b1682a7bff86e7174852c03419ba`; the mcp-bridge-api correction reportedly awaits acceptance, while the remaining August 8 MCP mirrors identify no corrected release. Treat all release ranges as validation seeds and confirm the deployed commit, route exposure, configuration, and current project status before reporting.

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

TinyAGI adds a capability-bearing message route. Patch the provider process constructor and compare unauthenticated and authenticated canary messages across provider adapters. Record route middleware, selected agent/provider, configured tool policy, approval mode, and final argv. The bounded positive is **unauthenticated `POST /api/message` -> normal queue and agent invocation -> provider recorder receives `--dangerously-skip-permissions` or an equivalent pre-approved mode**. Do not send a tool-seeking prompt or execute the provider; argv evidence is enough.

OpenChamber adds a default-configuration variant where the authentication middleware reportedly becomes a no-op when `UI_PASSWORD` is absent, while `/api/fs/exec` reaches a process launcher. In a disposable instance, replace process creation with a denied argv recorder and compare absent, empty, invalid, and valid synthetic password configurations. Send only an inert operation marker. Capture listener exposure, middleware branch, effective authentication state, route match, structured command/argument representation, and denied spawn. A bounded positive is **no configured password -> anonymous request passes the route gate -> process recorder receives caller-controlled execution intent**. Do not execute a command or preserve command output.

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

Nanobot adds a capability-*class* variant. In affected builds, `enabledTools` filtered `list_tools()` results but resource and prompt wrappers were registered separately. Build a fake MCP server with one inert tool, resource, and prompt; set `enabledTools: []`; and capture the model-visible schemas plus the final `read_resource`, `get_prompt`, and tool dispatch decisions. The bounded positive is **deny-all blocks the ordinary tool -> resource or prompt wrapper still appears -> patched wrapper receives the marker**. Also test a specific tool list and `*`; the merged correction allows resource/prompt registration only for the wildcard policy. Do not return real resource content or submit the prompt to a live model.

NanoClaw adds a construction-time identity variant. Patch child-agent creation and configuration persistence, then compare the parent caller's identity and policy with the child owner, workspace, tool allow-list, environment, and channel bindings. A bounded positive is **ordinary parent reaches child creation -> caller-controlled fields select a stronger child mode or inherited authority -> patched creator records the elevated configuration**. Child creation alone is not privilege escalation; preserve the exact authority delta and deny every real tool action.

## 4. Differential-test approval parsing against execution parsing

The IronClaw record describes risk classification splitting shell chains on some separators while `sh -c` also recognized newline. Its merged correction adds newline/CRLF and wrapper-aware regression coverage. Reuse that methodology wherever an agent remembers approval for a command tool.

Replace process creation with an argv/script recorder. Compare semantically equivalent inert markers encoded with:

- semicolon, newline, CRLF, pipe, and conditional separators;
- quoting, escaping, line continuation, and surrounding whitespace;
- direct shell `-c`, `env ... sh -c`, timing/wrapper utilities, and option values that invoke helpers; and
- ask-each-time versus remembered/session auto-approval.

For every case, record raw text, classifier tokens, risk level, approval decision, final interpreter/argv tuple, and whether the recorder would dispatch one or multiple commands. The bounded positive is **control encoding pauses -> equivalent alternate encoding inherits approval -> final parser trace contains a second command**. Never execute either command. Keep parser disagreement, approval inheritance, and command execution as separate claims.

Nanobot's `exec.allowPatterns` follow-up applies the same principle even without remembered approval. The affected guard used `re.search()` on the complete raw command while the sink passed that string to `bash -c`; one matching prefix could therefore authorize additional shell segments. Use a denied spawn recorder and compare one allowed marker with semantically inert chains separated by `&&`, `||`, `;`, pipe, newline, comments, quotes, escapes, and nested parentheses. Record which segments the guard recognizes and the final shell parse. A positive is **one segment matches -> a non-matching second segment survives the guard -> denied sink records both operations**. The merged fix splits top-level `&&`, `||`, `;`, and pipe operators while respecting quotes, escapes, and parentheses, so newline/comment and wrapper variants remain important independent controls rather than assumed coverage.

### Compare curated environments with the shell's reconstructed environment

A reduced `env` map is not authoritative when the process starts a login shell. The Nanobot record says affected `exec` calls defaulted to `bash -l -c` or `zsh -l -c` while forwarding `HOME`, allowing startup files to reintroduce variables that the curated environment omitted.

1. Create a temporary `HOME` containing a synthetic startup file that exports only a random canary variable.
2. Patch process creation or use a no-command shell harness that records argv and the post-startup environment without exposing host variables.
3. Compare omitted `login`, `login=false`, and `login=true` across Bash, Zsh, a non-login shell, absent startup files, and a different temporary `HOME`.
4. Capture the curated environment, shell argv, startup files consulted, and whether the canary appears after shell initialization.

The bounded positive is **canary absent from the child environment supplied by the agent -> default `-l` shell reads the temporary profile -> canary appears at the recorder**. Never inspect the real home directory, shell startup files, or process environment. Report ambient-policy reconstruction, not generic secret theft.

Mercury contributes two controls that should be standard in this harness:

- **redirection semantics**: a classifier can label a command family such as `echo` as read-only while the final shell interprets output redirection as a write; and
- **alternate command surfaces**: a normal `run_command` path can invoke approval while an in-chat background-command path reaches a separate shell runner without the same check.

Use marker-only command strings and replace every spawn or shell constructor with a denied recorder. Pair each alternate route with the semantically equivalent guarded tool call. A bounded positive is **guarded route requests approval -> alternate route or redirection-bearing safe family is auto-approved -> denied recorder observes the same write- or execution-capable shell semantics**. Do not create the marker file or publish a command-bearing API body.

The `openclaw-cn` record adds shell multiplexers such as `busybox sh -c` and `toybox sh -c`. Compare two inert payloads using the same outer executable after an `allow-always` decision. Capture the approved full command, resolved outer binary, persisted allow-list pattern, inner applet and payload, second approval decision, and denied spawn. A bounded positive is **first wrapper command approved -> trust persists only as the multiplexer path -> changed inner shell payload skips a second approval -> execution branch reaches the denied recorder**. If the tested build crashes before spawn, report only the missed approval and overbroad persisted trust.

LudusMCP adds a UI-helper boundary. The mirror identifies `get_credential_from_user` input reaching `SecretDialog.showSecretDialog`, with the `Description` field affecting command construction on the local host. Treat that as a source-review seed, not proof of remote MCP execution. Patch Electron/process/shell launch points, then vary only inert description markers across quotes, separators, line breaks, option-looking text, and ordinary prose. Record MCP caller, raw description, UI serialization, generated executable/argv or shell text, and denied sink. Report only if the description changes process grammar; displaying attacker-controlled text is not command injection by itself.

The two later LudusMCP mirrors add direct tool paths: `ludus_cli_execute` reportedly passes `command`/`args` through `executeArbitraryCommand` or `executeCommand`, while `ludus_environment_guides_search` uses `guide_name` in local path handling. Both records describe local access and open project issues, so do not present them as unauthenticated remote MCP exploitation or as fixed-release facts.

For the CLI wrapper, replace every process constructor with a denied argv recorder and compare structured argument arrays, a single shell-like string, option-looking values, separators, quoting, and line breaks. Capture the MCP transport and caller, raw tool arguments, normalization, selected wrapper, final executable/argv or shell grammar, and denied spawn. A bounded positive is **nominally structured tool input -> wrapper reparses it as shell syntax or changes executable selection -> denied process sink records a second operation**. Do not execute either marker.

For guide lookup, create `guides/owned.md` plus a sibling canary under a disposable root, then patch open/stat/read calls. Exercise plain names, nested names, `..`, absolute paths, encoded separators, sibling-prefix paths, and symlinks. Record raw and decoded `guide_name`, configured guide root, canonical target, containment decision, and denied syscall. A bounded positive is **guide identifier -> canonical sibling path -> denied read sink**, not disclosure. Never point the tool at real Ludus, workspace, home, or credential files.

### Bind elevated chat authority to stable sender identity

For chat-controlled elevated modes, compare stable sender identifiers with recipient/self fields and mutable profile metadata. Use two synthetic chat users and patch session-state persistence.

Test allow-list values against sender ID, normalized sender address, recipient address, display name, username, tag, case changes, and provider prefixes. Record the general command gate separately from the narrower elevated gate. The bounded positive is **command-authorized but non-elevated sender -> recipient or mutable metadata matches the elevated allow-list -> `/elevated` state recorder receives an enable transition**. Do not execute an elevated tool; the unauthorized state transition is sufficient.

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

TinyAGI contributes two end-to-end file-authority variants. First, an unauthenticated agent-configuration route can persist a caller-selected `prompt_file`, which prompt construction later reads and sends to the model provider. Second, provider/agent output containing a `[send_file: path]` tag can enter an outbound channel attachment queue. Use a temporary canary file, patched `readFile`/provider body recorder, and patched Telegram/Discord/WhatsApp attachment constructors. A bounded positive is **unauthenticated route or influenced model output -> outside-workspace canary path -> denied reader or attachment sink -> provider/outbound delivery authority selected**. Never let canary contents reach a live model or messaging account.

OpenChamber adds explicit read-route controls: `/api/fs/read`, `/api/fs/stat`, and `/api/fs/raw` reportedly accept `allowOutsideWorkspace=true` with an absolute path. Build only temporary workspace and sibling-canary roots. Compare the flag absent, false, true, malformed, and duplicated across relative, absolute, sibling-prefix, and symlink cases. Patch `stat` and read syscalls, and capture the raw parameter, selected root policy, canonical target, authentication state, and denied final path. A bounded positive is **anonymous or low-authority request -> override flag disables workspace confinement -> canonical sibling canary reaches the denied reader**. Never point the route at host secrets or use file-read evidence to forge a session.

For workspace mutation tools, include dangling final symlinks, not only existing symlinks and `..`. The `openclaw-cn` record describes a component walk returning success on `ENOENT` before the final `writeFile` follows an in-workspace dangling symlink to an outside target. Create only a disposable symlink and patch the final writer. Record lexical path, nearest existing ancestor, `lstat` result, symlink target, intended final location, and denied write. The positive is **direct traversal denied -> dangling in-root alias accepted -> final write recorder resolves outside the temporary root**; do not create the outside file.

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

## August 8 follow-up: trace MCP arguments to the final process or file sink

The four later mirrors add a compact review heuristic: a field that looks structured at the MCP schema is still untrusted grammar if a utility later joins it into shell text or treats an identifier as a filename. Do not infer network reachability from the package name. Record the actual transport, route registration, authentication, caller role, tool exposure, and deployment topology first.

### Git and server-command wrappers

Use disposable repositories and replace every `spawn`, `exec`, shell, Git, and wrapper constructor with a denied recorder. Exercise only inert grammar markers.

| Record | Input under test | Final authority to capture |
| --- | --- | --- |
| context-engine `review-git-diff` | `args` supplied to `execGitCommand` | executable, argv array, repository cwd, environment, and any shell reparse |
| mcp-bridge-api Servers endpoint | `command` and `args` | selected server/process, structured argv versus joined shell text, and denied spawn |
| MCPGateway usage-range endpoint | `since` passed through `getUsageByDateRange` | date parser result, generated Claude command, final argv/shell text, and denied spawn |
| mcp-pdf-vision `load_pdf` | `pdfPath` and `sessionId` | PDF utility selection, temporary/session path, executable/argv, and any shell reparse |
| slidev-builder-mcp `generateChart` | `outputDir` | chart utility arguments, canonical output root, executable/argv, and any shell reparse |
| coder-api project creation | Git `url`, `branch`, and `depth` from REST or MCP | generated clone operation, argument boundaries, destination root, and denied spawn |
| llm_memory_mcp `auto.capture` | caller-selected Git `hash` | every generated `git show` invocation, repository cwd, and denied spawn |

For each surface compare a normal scalar, structured list, option-looking value, whitespace, quotes, separators, line breaks, and duplicate/array/object representations. Include direct helper calls and the actual HTTP/MCP route because framework coercion may change the type before the wrapper sees it. Capture raw JSON, schema validation, coerced value, generated command representation, executable, argv, shell flag, cwd, environment, and recorder event.

The bounded positive is **caller-controlled field accepted as data -> wrapper changes command grammar or executable/argument boundaries -> denied process recorder observes an additional inert operation or attacker-selected executable**. A string containing metacharacters is not sufficient. Never execute Git hooks, shell commands, package helpers, or a real Claude CLI, and do not preserve repository content in evidence.

The local MCP mirrors identify affected functions but do not independently establish remote transport exposure. For mcp-pdf-vision, join both `pdfPath` and `sessionId` to the final utility and temporary-path construction. For slidev-builder-mcp, join `outputDir` to both path canonicalization and the chart-generation process call. For coder-api, compare its REST and MCP project-creation entry points against the same patched Git sink. For llm_memory_mcp, trace the revision through every `git show` helper rather than stopping at the first call. Pair direct function tests with the actual registered schema, because validation or coercion may differ. A useful result requires the denied process trace to show changed grammar; an outside-root output path without shell re-interpretation is a separate file-confinement finding.

### Journey IDs and filenames are file capabilities

For mcp-ui-probe, create a temporary journey root with `owned.json` and a sibling canary. Patch read, delete, analysis-load, and usage-stat filesystem calls. Exercise `journeyId` and `filename` through `get_journey`, `delete_journey`, `analyze_journey`, and `usage_stats` using plain IDs, nested paths, `..`, encoded separators, absolute paths, sibling-prefix paths, existing symlinks, dangling symlinks, and nonexistent controls.

Record raw and decoded input, extension/default-name handling, configured root, lexical path, canonical target, operation, and denied syscall. Require the same final-path confinement for reads, analysis, statistics, and deletes. The bounded positive is **local or authenticated journey selector -> canonical sibling canary -> denied read/delete/stat recorder**. Do not open or remove the canary, and do not describe this as remote traversal unless the tested deployment independently exposes the route to a remote caller.

### Trace one identifier across every file lifecycle operation

The memory-graph, mindpilot-mcp, and rive-mcp-server-core records expand the journey-ID heuristic beyond one read or delete helper. An identifier may be accepted during creation, retained in an object, and reused later for reads, saves, overwrites, imports, or cleanup. Review the full lifecycle, not just the route named by an advisory.

Build a disposable layout with an intended storage root and sibling canaries whose extensions match each product's generated suffix. Patch the final `open`, `readFile`, `writeFile`, `unlink`, and rename/replace calls. Then exercise:

- memory-graph domain creation, selection, memory retrieval, and save using the same domain ID;
- mindpilot-mcp history update, collection update, and delete using the same route ID; and
- rive-mcp-server-core import and manifest save using the same `libraryId`.

Compare plain IDs, nested names, `..`, absolute paths, encoded separators at the transport layer, sibling-prefix paths, Windows drive/UNC forms where supported, existing and dangling symlinks, and generated suffix edge cases. Record raw input, decoded value, appended extension, lexical and canonical target, operation, route/tool authentication, and denied syscall.

A bounded positive is **caller-controlled identifier -> generated filename canonicalizes outside the temporary root -> one or more denied lifecycle sinks receive the sibling canary path**. Report the exact proven operations separately; a write-path result does not imply read or delete authority. Never open, overwrite, or remove the canary, and do not infer remote exploitability from an MCP package or HTTP route without independently proving listener and authentication state.

## Evidence and reporting boundaries

- Include positive and negative mode/auth controls for management routes.
- Diff requested policy against both model-visible and dispatcher-valid tool sets.
- Diff construction-time and final runtime tool surfaces for child, review, plugin, provider, and MCP injection paths.
- Apply allow/deny policy to every MCP capability class, including tools, resources, and prompts.
- Prove shell parser or alternate-route disagreement with a denied spawn recorder, not command side effects.
- Preserve the MCP/HTTP schema type, framework coercion, generated argv or shell text, and final denied process sink for wrapper arguments.
- Trace stored identifiers across create, read, update, save, import, and delete operations; report only the lifecycle sinks actually reached.
- Record shell startup mode and post-startup environment separately from the environment supplied at process creation.
- Prove filesystem escape with a temporary synthetic path and denied sink, not file contents.
- Bind passive artifact parsing to the final IPC/file syscall before claiming a local-file-read path.
- Prove SSRF at final peer selection using an owned fixture; a warning log alone is insufficient.
- State whether evidence comes from a vendor/project record, merged fix, open issue, researcher disclosure, or unreviewed mirror.
- Do not claim universal unauthenticated access, host compromise, secret theft, or fixed-version coverage beyond the exact tested configuration and source evidence.
