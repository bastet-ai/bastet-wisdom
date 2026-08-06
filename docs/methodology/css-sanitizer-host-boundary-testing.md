---
title: CSS sanitizer and host-UI boundary testing
---

# CSS sanitizer and host-UI boundary testing

Use this workflow when an application renders attacker-controlled HTML or CSS inside a trusted page, especially webmail, rich-text previews, support consoles, collaboration tools, and AI-assisted browsers. It turns PortSwigger's August 2026 webmail research into a bounded operator campaign: map what survives, preserve every parse/serialize/mutation stage, evaluate the output in the real host structure, and prove only synthetic navigation, resource, UI, or model-context effects through denied sinks.

Primary research: [Gareth Heyes, “CSS:the bomb inside your inbox”](https://portswigger.net/research/css-the-bomb-inside-your-inbox) and its [companion research materials](https://github.com/portswigger/css-the-bomb-inside-your-inbox).

!!! warning "No credential capture or active host actions"
    Use disposable accounts, inert messages, fake tokens, owned no-content resource peers, patched navigation/form/UI/model sinks, and detached or script-disabled browser fixtures. Never collect passwords or login links, trigger real mailbox actions, send indirect prompts to a live privileged agent, bypass a shared image proxy, or run active HTML/CSS under a production origin.

## Operator value

CSS safety is a composition property, not an allowlist property. A meaningful test follows untrusted content through:

```text
raw message or rich text
-> HTML parser and sanitizer
-> CSS parser / CSSOM readback
-> class and ID rewriting
-> serialization and browser reparse
-> host DOM, UI libraries, CSP, proxy, and browser engine
-> final style, resource, navigation, UI, clipboard, or model-context sink
```

This workflow is useful for finding parser differentials, CSSOM mutation, host-page selector reach, image-proxy canonicalization errors, hidden model-visible instructions, clipboard ingestion races, and application code that turns allowed attributes into more powerful DOM or CSS.

## Prerequisites and fixture

- explicit authorization for the renderer and test accounts;
- an isolated deployment or representative local renderer;
- at least two browser engines when browser behavior matters;
- raw sanitized output and post-render DOM/CSSOM capture;
- a host page containing only synthetic controls, forms, IDs, and UI actions;
- owned no-content HTTP peers plus a request recorder;
- patched resource, navigation, form, UI-action, clipboard, and model-context sinks; and
- affected/fixed or sanitizer-on/off comparisons.

Use random markers for every run. The host fixture should expose one harmless action recorder, one synthetic form, one fake token-shaped text node, and one outside-message element. Do not use authentic mailbox controls or secrets.

## 1. Inventory accepted grammar before trying to chain it

Build a table-driven corpus of harmless HTML elements, attributes, selectors, at-rules, pseudo-classes/elements, combinators, custom properties, functions, URL forms, comments, escapes, and malformed boundaries. For each input, save:

```text
raw bytes
sanitizer parse tree and decision
serialized HTML/CSS
browser DOM and CSSOM readback
matched synthetic nodes
computed-style or denied-sink result
```

Use visible color, outline, generated-text, or custom-property markers rather than network requests. Include exact safe controls and obviously denied controls. The output is an **effective grammar map**, not a vulnerability list.

## 2. Diff every parse, serialize, and mutation stage

A sanitizer may parse with the browser, inspect CSSOM objects, and serialize properties such as keyframe names or media-query text. Escapes or malformed grammar can be normalized during readback so the second parser receives different delimiters or selectors than the policy inspected.

For each accepted construct:

1. capture the original stylesheet bytes;
2. record the sanitizer's token/rule identity;
3. read the exact CSSOM property returned to application code;
4. capture the application's serialized stylesheet;
5. reparse it in a fresh, script-disabled realm; and
6. compare selectors, declarations, at-rules, and matched nodes.

Vary escaped delimiters, comments, strings, nested rules, media text, keyframe identifiers, case, control bytes, and repeated sanitize/serialize cycles. A bounded positive is **policy classifies an inert marker as one rule/name -> CSSOM or serialization changes its grammar -> browser matches a synthetic node outside the intended message wrapper**. Do not include resource-loading declarations or credential-shaped selectors in mutation discovery.

## 3. Test containment against the actual host DOM

Class-prefixing and selector rewriting can fail even when untrusted content cannot name a trusted class directly. Evaluate:

- child, adjacent-sibling, and general-sibling combinators;
- pseudo-elements that inherit the originating element's click behavior;
- `label[for]` association with predictable host IDs;
- form ownership and other ID-based element relationships;
- host custom attributes consumed by application JavaScript; and
- generated nodes or inline styles appended after sanitization.

Patch host event handlers and UI libraries so they record the selected synthetic action without performing it. A bounded positive is **sanitized message element or selector -> browser/application association crosses the message wrapper -> harmless host-action recorder activates**. Keep label association, selector reach, click interception, and completed privileged action as separate claims.

Application-added power is a **CSS/HTML gadget**: allowed input causes trusted JavaScript to append a node, property, or value that the sanitizer itself would reject. Preserve both edges—surviving source attribute and generated final node/property—before using that label.

## 4. Trace every URL to the final peer

Do not stop at a permitted `background`, image, font, or custom-property URL. Record raw URL, sanitizer normalization, generated proxy URL, proxy decoding, destination policy, DNS result, redirects, and final peer tuple. Use only owned peers with empty responses.

Build a matrix for:

- direct and proxied forms;
- relative, protocol-relative, and absolute URLs;
- user-info, case, trailing dots, encoded delimiters, and alternate ports;
- redirect and final-destination changes;
- approved-domain URLs whose mutable path or query selects another destination; and
- browser/CSP combinations that block or permit the request.

A bounded positive is **sanitizer accepts a URL -> proxy or browser canonicalization changes the authority decision -> owned denied peer receives the random marker**. A CSS selector match without the final owned request is not exfiltration. Never use metadata, loopback, private-network, or third-party endpoints.

## 5. Treat clipboard and editor ingestion as a separate route

Pasting HTML into a `contenteditable` composer may use browser-generated clipboard flavors and a different sanitizer or timing path from received-message rendering. Create an inert clipboard fixture containing text/plain and text/html representations, then compare paste, drag/drop, programmatic import, reply/forward, draft save, draft reopen, and sent-message rendering.

Run the matrix across supported browser engines and record clipboard MIME flavor, browser normalization, transient DOM before sanitization, mutation-observer timeline, persisted draft bytes, and final DOM. A bounded positive is **HTML clipboard flavor -> transient or persisted style marker reaches an outside-editor synthetic node before/after the expected sanitizer gate**. Do not place token selectors, remote URLs, active forms, or event handlers in the clipboard.

## 6. Compare human-visible and model-visible representations

Generated content, near-transparent text, off-screen nodes, accessibility trees, and extracted text can give an AI browser a different message than the user sees. Use a fake local model-context recorder—not a live agent with tools—and synthetic contradictory phrases.

Capture rendered pixels or accessibility snapshot, DOM text, generated `::before`/`::after` content, extraction pipeline output, model prompt/context, and denied navigation/tool decision. A bounded positive is **message looks like marker A in the user fixture -> extractor supplies materially different marker B -> patched model-action sink selects an unapproved synthetic action**. This proves a representation and policy-boundary issue, not autonomous compromise. Never include real names, emails, page data, or external destinations.

## 7. Evaluate state and interaction without building a keylogger

Selectors such as `:checked`, `:focus`, `:has()`, sibling chains, animations, generated content, and positioned pseudo-elements can make CSS stateful enough to select or overlay host interactions. Test the primitive with one synthetic option and one fake action recorder.

Record focus/selection state, matching selector, animation state, geometry, hit-test target, inherited click handler, and denied resource/UI sink. Strong bounded results are:

- one synthetic selection changes an inert custom-property marker;
- a pseudo-element covers the fixture and hit-testing selects the harmless recorder;
- a message label targets a synthetic host control; or
- a state change would select an owned no-content resource, but the patched loader denies it.

Do not construct password forms, per-character selectors, token brute-force corpora, realistic login overlays, or network-backed keystroke proofs. Those add sensitive collection capability without improving the boundary evidence.

## Evidence and claim boundaries

Capture:

```text
scope and fixture version:
browser engine/version:
raw input hash:
sanitizer configuration:
sanitizer parse/decision trace:
CSSOM and serialized output:
final DOM/selectors/computed style:
host structure and synthetic action IDs:
CSP/proxy/final peer trace:
human-visible versus extracted model text:
denied final sink:
affected/fixed comparison:
strongest supported claim:
excluded stronger claims:
```

Report **sanitizer grammar bypass**, **host selector/association reach**, **CSSOM mutation**, **CSS/HTML gadget**, **final-peer policy bypass**, **clipboard-route drift**, and **human/model representation drift** independently. Do not call a style change XSS, a selector match data theft, a navigation intent account takeover, or an AI-context difference tool execution without the corresponding final synthetic sink.
