---
title: Notebook, data-server, OPC UA, and proxy trust boundaries
---

# Notebook, data-server, OPC UA, and proxy trust boundaries

An August 4 advisory wave yields four reusable operator patterns: notebook metadata can redirect privileged API clients, data-server parsers can expose filesystem or evaluator authority, batched industrial-protocol calls can detach authorization from dispatch, and alternate IP spellings can split proxy policy from transport behavior.

Primary sources:

- marimo notebook metadata precedence [GHSA-v9v8-jp27-55gf / CVE-2026-67618](https://github.com/advisories/GHSA-v9v8-jp27-55gf);
- Perspective asset-root traversal [GHSA-pcjm-g28j-xmf9 / CVE-2026-67200](https://github.com/advisories/GHSA-pcjm-g28j-xmf9) and expression-evaluator boundary [GHSA-3jqr-28gj-8vq4 / CVE-2026-67195](https://github.com/advisories/GHSA-3jqr-28gj-8vq4);
- Eclipse Milo username-token oracle [GHSA-jrjq-9cmf-3h6f / CVE-2026-60007](https://github.com/advisories/GHSA-jrjq-9cmf-3h6f), diagnostics authorization [GHSA-xg6h-qgc7-qqr7 / CVE-2026-63248](https://github.com/advisories/GHSA-xg6h-qgc7-qqr7), mixed-batch method authorization [GHSA-978q-37g3-wq8g / CVE-2026-62927](https://github.com/advisories/GHSA-978q-37g3-wq8g), and copied-configuration role loss [GHSA-pvvm-cxq7-hrgr / CVE-2026-58080](https://github.com/advisories/GHSA-pvvm-cxq7-hrgr); and
- stunnel SOCKS destination canonicalization [GHSA-2x69-8qrg-27gr / CVE-2026-70367](https://github.com/advisories/GHSA-2x69-8qrg-27gr).

!!! warning "Synthetic labs and denied final sinks only"
    Use disposable notebooks, fake API keys, owned HTTP endpoints, temporary asset roots, patched evaluator/file readers, a local OPC UA server with synthetic users and methods, and an isolated proxy namespace. Never open unknown notebooks with real credentials, read server files, execute expressions, inspect production OPC UA sessions, recover passwords, or proxy to real loopback/internal services.

## 1. Trace notebook metadata into privileged client configuration

The marimo record describes PEP 723 notebook metadata overriding an AI `base_url` while an operator API key remained sourced from the environment. This is a general repository/notebook trust chain:

```text
untrusted notebook metadata
  -> session configuration merge
  -> client authority changes
  -> operator credential remains attached
  -> outbound request reaches notebook-selected origin
```

Create a disposable notebook with a random metadata key and an owned HTTPS recorder. Start the application with a fake API key and patch the HTTP transport to log authority, header names, and credential provenance while redacting values. Compare no metadata, benign model settings, caller-selected `base_url`, duplicate keys, alternate casing, and redirecting owned endpoints.

The positive is **notebook metadata selects the recorder origin while the request still carries the environment-sourced fake authorization field**. Opening a notebook is not enough; capture the merge order and final request configuration. Do not use a live provider key or require cell execution as proof if metadata is consumed earlier.

## 2. Prove data-server file and evaluator edges separately

For the Perspective records, keep static-asset confinement and expression execution as independent findings.

### Asset-root harness

Build a temporary layout with `assets/inside.txt` and a sibling `outside.txt`, both random markers. Replace the final file read with a recorder. Send raw requests that vary literal and encoded dot segments, duplicate separators, query suffixes, and proxy-normalized paths. Capture raw request-target bytes, framework-decoded path, canonical filesystem path, selected root, CORS headers, and whether the reader ran.

A bounded positive is **raw request -> canonical sibling path -> patched reader receives `outside.txt`**. Do not read host credentials. Treat wildcard CORS as an impact multiplier only after file reachability is proven.

### Expression harness

Replace Python evaluation and process creation with an AST/call recorder. Use arithmetic as the allowed control, an unknown identifier as the denial control, and inert attribute-traversal markers that contain no process, file, socket, or import target. Exercise both expression-validation and view-creation message families.

The positive is **remote expression -> evaluator receives syntax outside the documented grammar or resolves a synthetic forbidden attribute -> fixed build rejects before evaluation**. Do not publish interpreter-escape chains or execute a command.

## 3. Bind OPC UA authorization to each dispatched object

The Eclipse Milo records show three authorization seams worth testing together:

1. authorization calculated for a batch but dispatch performed on the original mixed batch;
2. a copied server configuration dropping its `RoleMapper`, changing downstream access-control behavior; and
3. diagnostics nodes or authentication errors exposing more state than the caller is authorized to observe.

Create a local server with anonymous, low-role, and admin synthetic identities; one harmless allowed method; one denied method whose handler only increments an in-memory canary; and diagnostics populated solely with fake sessions.

Run a matrix of allowed-only, denied-only, allowed-then-denied, denied-then-allowed, duplicate, malformed, and cross-node calls. For each element, record requested object/method IDs, caller roles, authorization result, dispatched handler, and returned status. Repeat with the configuration built directly and through `copy()`.

The strongest mixed-batch positive is **denied element receives a denial result but its canary handler still runs when paired with an allowed element**. The configuration positive is **the same synthetic session has roles before `copy()` but loses them afterward and reaches a method the explicit policy denies**. Never invoke operational methods or mutate a real address space.

For diagnostics, assert only whether fake session markers are visible to anonymous and low-role clients. For username-token handling, compare error class, status, length, and coarse timing across locally generated valid, malformed-padding, wrong-password, and unknown-user fixtures. A distinguishable response is evidence of an oracle surface; do not automate plaintext recovery.

## 4. Compare proxy policy parsing with final peer addresses

The stunnel SOCKS record and the Flowise mapped-address record share one durable test: an allow/deny decision made on one address representation must stay bound to the peer address the socket actually reaches.

In an isolated network namespace, run a harmless canary listener and a patched SOCKS connector that records rather than forwards. Test canonical IPv4 loopback, canonical IPv6 loopback, IPv4-mapped IPv6, unspecified IPv4/IPv6, IPv6 zone syntax, and owned DNS names resolving to each form.

Record request encoding, parsed family, canonical address, policy match, socket family, and intended final peer. The positive is **alternate spelling passes policy but canonicalizes to the denied canary peer**. Do not connect to local admin sockets, metadata endpoints, or production services.

## Reporting checklist

- [ ] Every proof uses affected-versus-corrected builds where available.
- [ ] Notebook configuration provenance distinguishes metadata, operator config, and environment credentials.
- [ ] Raw HTTP path, decoded path, canonical path, and final file-read decision are preserved.
- [ ] Expression validation and evaluator/process reachability are separate edges.
- [ ] OPC UA authorization is recorded per batch element and compared before/after configuration copying.
- [ ] Oracle evidence stops at synthetic response differentials.
- [ ] Proxy evidence binds the policy representation to the final canonical peer without reaching real internal services.