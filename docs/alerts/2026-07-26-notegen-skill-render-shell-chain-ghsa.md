---
title: NoteGen skill-to-chat-render-to-desktop-shell boundary chain
---

# NoteGen skill-to-chat-render-to-desktop-shell boundary chain

Two July 26 GitHub advisory records describe a reusable desktop-agent exploit path: untrusted skill or retrieved content steers model output into a permissive Markdown renderer, script runs in a privileged Tauri webview, and an overbroad native shell capability turns renderer compromise into host command execution.

Sources:

- [GHSA-gwhc-vprp-gfcg / CVE-2026-17496: NoteGen AI chat response XSS](https://github.com/advisories/GHSA-gwhc-vprp-gfcg)
- [Primary renderer replacement commit](https://github.com/codexu/note-gen/commit/ae3ba948c41d8a74b4a20f4c6f26fcdda2002298)
- [GHSA-r5ff-hq22-rhgv / CVE-2026-17497: NoteGen Tauri shell capability permits arbitrary commands](https://github.com/advisories/GHSA-r5ff-hq22-rhgv)
- [Primary shell-capability removal commit](https://github.com/codexu/note-gen/commit/00064a4a8ec4177d51094ffb3e15bf0758009c1f)
- [NoteGen v0.32.0 release](https://github.com/codexu/note-gen/releases/tag/note-gen-v0.32.0)

The GitHub records are unreviewed. The linked commits independently confirm the key code changes: the chat preview stopped using `markdown-it` with `html: true` and raw HTML insertion, while the Tauri capability files removed `shell:allow-execute` entries for `bash`, `python`, and `python3` with unrestricted arguments. Confirm behavior in the exact build under test rather than treating package presence as proof.

!!! warning "Authorized validation only"
    Use a disposable NoteGen profile or instrumented lab build, an inert skill, harmless DOM markers, and a temporary output directory. Never place credential theft, persistence, destructive commands, network callbacks, or real user content in a skill or model prompt.

## Model the whole chain

Treat this as four boundaries, not a generic XSS report:

1. **Instruction ingestion:** a skill reference, note, retrieved document, imported conversation, or tool result can influence a model prompt.
2. **Model output:** the model can reproduce attacker-selected raw HTML rather than inert Markdown text.
3. **Privileged render:** the application parses that output with raw HTML enabled and inserts it into the desktop webview DOM.
4. **Native bridge:** JavaScript in that webview can reach a Tauri command or plugin with host-level authority.

The strongest report proves each edge separately and then demonstrates the complete chain with marker-only effects. Do not jump from “the app uses Markdown” to “remote code execution.”

## Reachability prerequisites

Confirm all of the following:

- the tested build predates the relevant v0.32.0 changes or reproduces the same behavior;
- attacker-controlled skill or retrieved content is actually loaded into the active model context;
- a user action causes the resulting assistant message to render in `chat-preview` or an equivalent privileged view;
- raw HTML survives model generation, Markdown parsing, streaming, and final rendering;
- the rendered view is a Tauri webview rather than an isolated unprivileged browser origin;
- the affected window receives a shell execution capability with attacker-controlled arguments;
- process privileges, sandboxing, and OS policy permit the claimed marker effect.

Record whether skill installation, skill selection, prompt submission, message viewing, or command approval requires separate user interaction. Those are exploit preconditions, not editorial details.

## Phase 1: prove skill-to-model influence

Build an inert test skill whose `REFERENCE.md` contains a unique nonce and asks the model to reproduce one harmless HTML element containing that nonce. Do not include shell syntax or hidden instructions.

1. Start from a clean disposable profile and capture the skill inventory.
2. Install or load the canary skill through the same path available to the assessed threat actor.
3. Begin a fresh conversation and invoke the skill normally.
4. Save the skill hash, conversation identifier, model/provider, exact user request, and raw assistant response before rendering.
5. Repeat without the skill and with a second nonce.

The useful differential is **canary skill selected -> unique HTML-shaped model output appears; skill absent -> marker does not appear**. A model refusing or rewriting the instruction is evidence that this particular fixture did not reach the sink, not proof that the render path is safe.

## Phase 2: prove privileged DOM execution safely

Use a harmless event-handler canary that only sets a unique `data-*` value on the current document. It must not access storage, invoke Tauri, or make a request.

1. First submit the HTML directly through an authorized local test fixture, if the application exposes one, to separate renderer behavior from model variability.
2. Capture the raw model text and inspect the rendered node in the webview developer tools.
3. Verify that the canary changes only the chosen DOM dataset value.
4. Add controls for escaped HTML, fenced code, ordinary Markdown, and a build containing the renderer replacement.
5. Repeat through the inert skill path only after the direct render fixture is understood.

A valid result proves **attacker-influenced assistant text -> raw HTML accepted -> event executes in the application webview**. Merely seeing an HTML element proves markup injection, not JavaScript execution.

## Phase 3: inventory the desktop bridge

Before invoking anything, enumerate the authority available to the affected window:

- Tauri capability files assigned to the main/chat window;
- shell plugin allow entries, executable names, and argument constraints;
- custom `invoke` commands reachable from the frontend;
- filesystem, opener, HTTP, clipboard, notification, and process plugins;
- whether approvals are enforced in Rust/native code or only in the compromised webview;
- whether a Content Security Policy or webview isolation boundary meaningfully limits injected script.

For the reported NoteGen path, the primary commit removes `shell:allow-execute` grants for `bash`, `python`, and `python3` where `args: true` accepted arbitrary arguments. Preserve the exact capability JSON and window label as evidence.

## Phase 4: marker-only shell-chain validation

Prefer an instrumented build where the native shell handler records the requested executable and argument vector but does not spawn a process. This proves bridge reachability and argument control without host execution.

If the engagement explicitly requires end-to-end validation:

1. Use a disposable VM and create a fresh temporary directory dedicated to the test.
2. Select one permitted interpreter and construct a command that writes a single random marker file inside that directory.
3. Trigger the bridge from the harmless webview canary path.
4. Capture the frontend call, Tauri IPC method, executable, argument vector, process exit status, and marker-file hash.
5. Repeat with a fixed build or capability set where the native handler rejects the same request.
6. Delete the temporary directory after evidence is preserved.

Stop after one marker. Do not launch a shell listener, read environment variables, enumerate files, access credentials, or demonstrate persistence.

The decisive chain is:

```text
attacker-controlled skill/reference
  -> model emits chosen raw HTML
  -> chat renderer executes a harmless DOM canary
  -> compromised webview reaches an overbroad native shell grant
  -> one marker file appears in a disposable directory
```

## Variants worth hunting

Apply the same workflow to other desktop AI clients and agent consoles:

- prompt or retrieval content rendered with raw HTML, MDX, SVG, MathML, or custom components;
- streaming renderers that sanitize only the final message or only individual chunks;
- tool output, approval diffs, citations, file previews, and exported conversations rendered through a different component than normal chat;
- webview links or images that can invoke custom protocols or native openers;
- MCP, filesystem, process, updater, clipboard, or HTTP capabilities granted to the same compromised window;
- approval dialogs implemented in frontend state that injected script can modify or bypass;
- broad wildcard window labels that unintentionally grant a helper/preview window native authority.

Test every renderer and every window label independently. A safe primary chat component does not imply that previews, exports, tool traces, or secondary windows use the same policy.

## Reporting checklist

Include:

- exact app version, commit, OS, window label, and Tauri/plugin versions;
- attacker control and user-interaction prerequisites;
- skill/reference hash and raw model response;
- parser options, render sink, and DOM-execution evidence;
- capability assignment and native IPC trace;
- marker-only process evidence and fixed-build differential;
- a four-edge chain diagram with confirmed and unproven edges clearly separated.

Keep impact bounded. Raw HTML output is not automatically script execution; webview script execution is not automatically native command execution; and a native capability is not remotely exploitable until an attacker-controlled input path reaches the compromised renderer.