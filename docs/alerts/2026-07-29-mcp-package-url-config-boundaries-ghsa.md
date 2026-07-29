---
title: MCP session, package-index path, URL-parser, and generated-config boundaries
---

# MCP session, package-index path, URL-parser, and generated-config boundaries

Five July 29 disclosures expose reusable boundaries where a client chooses a privileged backend, stateless transport loses caller identity, a package index controls a download path, two URL parsers disagree on authority, or line breaks turn a generated configuration value into executable structure.

Sources:

- [GHSA-5h6c-295f-7pp3 / CVE-2026-16328](https://github.com/advisories/GHSA-5h6c-295f-7pp3), [GHSA-6c5r-pj95-xvqv / CVE-2026-16326](https://github.com/advisories/GHSA-6c5r-pj95-xvqv), and [HashiCorp HCSEC-2026-24](https://discuss.hashicorp.com/t/hcsec-2026-24-multiple-vulnerabilities-impacting-hashicorp-consul-mcp-server/77612): Consul MCP backend-address override and stateless cross-client credential reuse;
- [GHSA-qwm4-qh6w-59xr / CVE-2026-13346](https://github.com/advisories/GHSA-qwm4-qh6w-59xr), the [Python security announcement](https://mail.python.org/archives/list/security-announce@python.org/thread/L2BNQGGVQCEV7DROOORQ7WFKKFF2OOQX/), and [pip pull request 14110](https://github.com/pypa/pip/pull/14110): doubly encoded index URLs can select an absolute download path;
- [GHSA-mvrj-5wv7-cfg9 / CVE-2026-67201](https://github.com/advisories/GHSA-mvrj-5wv7-cfg9), the [V issue](https://github.com/vlang/v/issues/27945), and [fix commit 85859f0](https://github.com/vlang/v/commit/85859f0f3498d4091b38009c45ed390a97eeedc2): `net.urllib` and `net.http` disagree on a backslash-bearing URL authority; and
- [GHSA-c2fc-3q38-9pf4 / CVE-2026-12357](https://github.com/advisories/GHSA-c2fc-3q38-9pf4) and [ZDI-26-447](https://www.zerodayinitiative.com/advisories/ZDI-26-447/): authenticated Heimdall Data `generateFileContent` input can inject CRLF into generated content and reach root-context execution.

!!! warning "Authorized validation only"
    Use a disposable Consul cluster with fake ACL tokens, two synthetic MCP clients, an owned package index, temporary sibling directories, two local URL listeners, and a non-executing configuration parser/recorder. Never relay real Consul credentials, query metadata or internal services, overwrite user or system files, serve executable packages, or let generated content reach a production root process.

## Boundary map

| Input | Trusted transition | Bounded positive evidence |
| --- | --- | --- |
| MCP backend override | connected client selects the authority receiving server-configured Consul API requests | owned listener receives a marker request and a fake token reserved for the fixture |
| stateless MCP request | transport/session lookup selects another client's cached authenticated Consul client | client B's inert tool call is recorded under client A's canary identity |
| package-index URL | decoded URL path becomes the local download destination | a fixed marker is written to a disposable sibling path during `pip download --only-binary` |
| backslash-bearing URL | allowlist parser host becomes HTTP client's socket authority | validator logs listener A while the final connection reaches owned listener B |
| CR/LF-bearing configuration scalar | scalar becomes additional generated directives or executable configuration | offline parser sees one extra inert marker directive absent from the input model |

Keep these edges separate. A callback is not internal-service access; another client's identity at a recorder is not data theft; an outside-root download is not execution; parser disagreement is not SSRF until the final socket changes; and extra generated syntax is not root execution unless the affected privileged consumer actually accepts it.

## Consul MCP authority and session-isolation matrix

HashiCorp states that `consul-mcp-server` 0.1.0 through 0.1.3 accepted per-request Consul-address overrides and could forward its configured token to the selected destination. In stateless mode, its authenticated Consul-client cache could also reuse one client's token for another client. Version 0.1.4 fixes both issues. Credential forwarding requires a configured server token; cross-client reuse requires stateless mode and more than one connected client.

### Two-client, two-backend fixture

1. Run a disposable Consul MCP server against backend A. Give A a fake ACL token that authorizes only one marker KV read or, preferably, replace Consul with a recorder that maps each fake token to a synthetic identity.
2. Connect clients A and B with distinct transport/session identifiers and distinct canary tokens. Record client ID, session ID, transport mode, requested backend, selected backend, token fingerprint, and tool result identity.
3. For backend authority, vary only the client-controlled address field across configured A, owned listener B, malformed authority, userinfo, alternate port, redirect, hostname case/trailing dot, and controlled DNS-answer rows. B must record only request metadata and a known fake token.
4. For session isolation, alternate A and B requests, reverse connection order, reconnect one client, omit a session identifier, duplicate an identifier, and run requests concurrently. Test stateful and stateless transports as separate rows.
5. Repeat on 0.1.4. A client must not override the configured backend, and every tool call must use only the credential bound to its authenticated session.

Report the narrow result as either **client-selected backend -> server sends a fake configured credential to owned listener B** or **client B request -> server executes the inert operation with client A's synthetic identity**. Preserve the deployment preconditions instead of generalizing either result to every MCP transport.

## pip package-index URL to filesystem destination

The Python announcement says a malicious package index can supply a doubly encoded package URL that pip resolves to an arbitrary location on disk, including when the selected artifact is a wheel. A malicious package by itself is not sufficient; the index response must control the URL. The material risk called out by Python is `pip download --only-binary`, because installing source distributions from an untrusted index already permits build-time code execution.

### Disposable index/download fixture

1. Create a temporary virtual environment, download directory, sibling canary directory, and owned PEP 503-compatible index. Serve one inert wheel containing only static metadata and a marker text file; do not define build hooks or importable test code.
2. Capture the index href as raw bytes, each URL-decoding stage, resolved filename, staging path, final destination, and checksums before and after the run.
3. Establish a baseline with an ordinary relative wheel URL. Then test single-encoded, doubly encoded, mixed-case encoding, absolute-path, encoded separator, sibling-prefix, query/fragment, redirect, and platform-specific separator rows one at a time.
4. Run only a bounded command such as `python -m pip download --only-binary=:all: --no-deps --dest "$TMP/downloads" --index-url "$OWNED_INDEX" canarypkg`. Point `TMP` at a disposable tree and run as an unprivileged test user.
5. Require a real outside-destination marker write for a positive affected-build result. A decoded string that merely looks absolute is not enough. Repeat against the fixed pip build identified by the upstream advisory/patch and require rejection or confinement under the selected download directory.

Do not target shell startup files, package-manager configuration, credentials, service units, or executable search paths. Report **malicious index href -> pip's final file write escapes the chosen download directory** and separately state whether later execution was tested; it should not be needed for this proof.

## V URL parser-to-connection differential

The V disclosure covers versions through 0.5.2 and says commit `85859f0` fixes a differential in which `net.urllib.parse()` extracts an allowlisted host from a URL containing a backslash in the authority while `net.http.get()` normalizes the same input and connects to a different host.

1. Run listeners A and B on loopback aliases or an isolated test network. A is allowlisted; B is explicitly unapproved but owned. Both record only connection count, method, authority, path, and a random marker.
2. Pass the exact same raw URL bytes first to the application's validator and then to its real HTTP call. Log parsed scheme, userinfo, host, port, serialized request target, DNS answer, socket destination, redirect hops, and `Host` header.
3. Compare slash and backslash placement around userinfo and authority delimiters, percent-encoded separators, mixed separators, trailing dots, hostname case, explicit ports, and fragments. Keep redirects disabled for the core parser test, then assess them separately if the integration follows them.
4. A positive row requires the validator to approve A while the final socket reaches B. Merely producing different parsed strings without a connection is incomplete evidence.
5. Repeat on the fixed commit or a release containing it. Validation and connection must derive authority from one canonical representation, and ambiguous backslash-bearing authority forms should fail closed.

Stop at B's marker response. Never substitute metadata, loopback admin panels, RFC1918 services, corporate DNS, or VPN-only applications for the owned second listener.

## Generated configuration CRLF boundary

ZDI reports that an authenticated, high-privilege attacker can pass CRLF sequences through Heimdall Data Database Proxy's `generateFileContent` path and ultimately execute code as root; release build 25.03.01.24 is fixed. Public details do not identify the exact field or generated grammar, so first map caller role, endpoint, controllable scalar, generated file, parser, and privileged consumer without guessing an exploit payload.

1. Clone the affected behavior into an isolated fixture or instrument an approved lab appliance so generated content is diverted to a temporary file and never loaded by the production service.
2. Establish a baseline scalar and capture the structured input model plus exact generated bytes.
3. Vary CR, LF, CRLF, repeated line endings, leading/trailing whitespace, comment markers, quotes, continuation characters, and a harmless `CANARY_DIRECTIVE=1` line. Test one field at a time.
4. Feed output only to a syntax parser or no-op consumer that records directive names. Do not invoke shells, interpreters, service reloads, hooks, or root-owned production paths.
5. Confirm affected behavior only when one input scalar creates an additional parsed directive absent from the caller's model. Repeat on 25.03.01.24 and require line endings to be rejected or encoded so the marker remains scalar data.

The safe result is **authorized scalar control -> generated bytes contain extra syntax -> offline consumer recognizes one inert marker directive**. Cite ZDI for the reported root-context impact, but do not claim your fixture achieved root execution unless a separately approved lab test proves that final consumer edge.

## Evidence and reporting

Preserve exact versions and transport modes, raw address/URL/config bytes, every decoding and parser representation, selected credential fingerprints, final socket/file destinations, client/session ordering, generated bytes, parser output, and affected-versus-fixed decision tables. Redact even fake-looking values if they could be confused with live tokens. Name the crossed boundary precisely: **client to backend authority**, **session to credential identity**, **index URL to file destination**, **validation parser to socket authority**, or **scalar to generated grammar**.
