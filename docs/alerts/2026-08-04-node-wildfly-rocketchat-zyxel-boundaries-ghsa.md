---
title: Node.js proxy/SQLite, WildFly domain, Rocket.Chat file, and Zyxel WLAN boundaries
---

# Node.js proxy/SQLite, WildFly domain, Rocket.Chat file, and Zyxel WLAN boundaries

Source: hourly offensive-security scan of GitHub Security Advisories on 2026-08-04. These records were unreviewed database entries at scan time; confirm affected releases, deployment mode, caller position, feature configuration, and corrected behavior from upstream before reporting.

This wave yields five durable operator patterns:

1. an HTTP runtime may use a header omitted from every userland header view to frame a body that a forwarding proxy still pipes downstream;
2. a cached database statement can be reset and rebound while an older iterator remains able to execute it;
3. a trusted application-server subordinate can turn a relative repository selector into a read from its controller's filesystem;
4. a feature-specific public file route can bypass the storage root only when a particular backend is selected; and
5. WLAN portal authentication and administrator-only diagnostic/export command handling are distinct appliance boundaries that must be validated independently.

Primary sources:

- Node.js forwarding-proxy request desynchronization [GHSA-6hff-9f4h-85xm / CVE-2026-58044](https://github.com/advisories/GHSA-6hff-9f4h-85xm) and stale SQLite iterator [GHSA-qgrj-5wc5-7xvc / CVE-2026-58041](https://github.com/advisories/GHSA-qgrj-5wc5-7xvc), with the [Node.js July 2026 security release](https://nodejs.org/en/blog/vulnerability/july-2026-security-releases);
- WildFly domain-controller repository traversal [GHSA-62xj-w627-m337 / CVE-2026-17614](https://github.com/advisories/GHSA-62xj-w627-m337) and [Red Hat CVE record](https://access.redhat.com/security/cve/CVE-2026-17614);
- Rocket.Chat filesystem-backed custom-sound traversal [GHSA-6c37-9jgq-mgm8 / CVE-2026-56845](https://github.com/advisories/GHSA-6c37-9jgq-mgm8) and [HackerOne report 3514640](https://hackerone.com/reports/3514640); and
- Zyxel WAX650S captive-portal authentication bypass [GHSA-hq2r-whw2-gr82 / CVE-2026-8508](https://github.com/advisories/GHSA-hq2r-whw2-gr82), administrator command injection [GHSA-fq66-x242-gfpv / CVE-2026-6837](https://github.com/advisories/GHSA-fq66-x242-gfpv), and the [Zyxel advisory](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-command-injection-and-improper-authentication-vulnerabilities-in-certain-aps-fwa7-and-security-routers-08-04-2026).

!!! warning "Isolated connections, synthetic files, and inert sinks only"
    Use a one-client proxy lab, disposable databases and controller domains, random canary files, owned WLAN appliances, fake accounts, and patched file/process recorders. Never desynchronize shared traffic, read host or tenant files, request credentials or keystores, bypass a production captive portal, execute shell text, or assume that WLAN access grants appliance administration.

## Boundary map

| Surface | Trusted decision | Detached state or selector | Bounded positive |
| --- | --- | --- | --- |
| Node.js forwarding proxy | proxy rebuilds backend headers from visible `IncomingMessage` views | runtime still frames and emits a body using an omitted header | front end and backend assign one inert byte stream to different request slots |
| Node.js `SQLTagStore` | cached statement is reset/rebound for a new call | stale `StatementSyncIterator` retains execution authority | old iterator returns only a synthetic marker associated with the new binding |
| WildFly domain mode | slave host controller authenticates with a domain secret | slave-supplied relative path selects a file on the domain controller | patched reader resolves a random sibling canary outside repository root |
| Rocket.Chat custom sounds | public route may serve a configured sound | path normalization differs when storage is `FileSystem` | route selects a random sibling canary in a disposable storage fixture |
| Zyxel captive portal | WLAN client completes `social_login.cgi` flow | alternate state/parameter path grants network admission without valid portal proof | owned client reaches only an isolated canary VLAN in affected firmware |
| Zyxel export CGI | administrator may request an export | caller-controlled field crosses into a command wrapper | inert marker reaches a patched process recorder without process creation |

## 1. Reconcile Node.js framing with every userland header view

The request-desynchronization precondition is narrower than "Node.js accepts many headers." It concerns forwarding proxies that reconstruct outbound headers from `req.headers`, `req.rawHeaders`, or `req.headersDistinct`, but pipe the original request body onto a reused backend connection. Headers beyond `maxHeadersCount` or `maxHeaderPairs` can be absent from those views while still affecting Node.js message framing. In particular, the runtime can deliver a body according to a hidden `Content-Length` even though the proxy does not forward that header.

### Lab topology

Use three disposable components:

- a raw-byte client that sends one connection at a time;
- the exact Node.js forwarding-proxy implementation under test; and
- a backend recorder that parses HTTP, records byte consumption and route assignment, then closes the connection before any second client can use it.

Expose only `/first-canary` and `/residual-canary`. Do not put the harness in front of a real application, cache, or authenticated route.

### Differential workflow

1. Record the configured `maxHeadersCount` and parser limit, Node.js release, visible `headers`, `rawHeaders`, `headersDistinct`, body events, outbound serialized headers, and exact bytes piped to the backend.
2. Establish controls with an ordinary bodyless request, a valid body-bearing request, and a request exactly at the header limit.
3. Place a harmless framing header before, at, and just beyond the visibility cutoff. Use only inert marker bodies and route names; derive any edge-case ordering from the upstream regression fixture rather than inventing a production smuggling payload.
4. Determine whether Node.js emits body bytes when all proxy-visible header collections omit the framing reason, and whether the rebuilt outbound request advertises a matching body length.
5. Replay on a single backend connection while recording both parsers' message boundaries. Close immediately after the residual marker is classified.
6. Compare direct origin handling, no connection reuse, no body piping, a fixed Node.js release, and a proxy that rejects truncated header views.

The reportable positive is **same captured input -> Node.js userland sees no body-framing header but receives/pipes body bytes -> forwarding proxy serializes a different message boundary -> backend assigns an inert residual marker to another request slot -> fixed behavior converges or rejects**. A hidden header, parser error, or connection close alone is not request smuggling.

## 2. Detect stale iterator authority over rebound SQLite statements

The Node.js SQLite record concerns `DatabaseSync#createTagStore()` and its statement cache. A stale `StatementSyncIterator` can survive a direct `sqlite3_reset()` and later execute the same prepared statement after another call rebinds it with different parameters. The security impact depends on application concurrency, iterator lifetime, and whether the rebound statement crosses user or tenant scope.

Create a local database containing rows `(tenant-a, marker-a)` and `(tenant-b, marker-b)` only. Instrument statement identity, cache key, bind values, reset/finalize events, iterator creation, iterator advancement, and returned row.

1. Obtain iterator A through the application's tagged-query path but do not exhaust it.
2. Cause the same cache entry to be reused with tenant-B parameters.
3. Advance iterator A and record which binding and row it observes.
4. Repeat with the iterator exhausted, explicitly closed, garbage-collected, and created from ordinary `StatementSync` rather than `SQLTagStore`.
5. Test cache hits and misses, one and two database handles, synchronous interleavings, the affected release, and the fixed release.

A bounded positive is **iterator created under tenant A -> cache resets/rebinds the same statement for tenant B -> stale iterator A advances -> synthetic marker B is returned**. Do not claim cross-tenant disclosure unless the real application keeps an attacker-reachable iterator alive while another principal's values are rebound. Use deterministic call ordering, not stress or process-crash testing.

## 3. Treat a WildFly slave secret as controller file-read authority

The WildFly record applies to domain mode and requires either a compromised slave host controller or possession of its host-controller secret. `LocalFileRepository.getFile()` and `getConfigurationFile()` accept a relative path over the slave-to-domain-controller protocol without proving that the resolved path remains under the repository or configuration root. This is not an unauthenticated HTTP traversal.

### Disposable domain fixture

Build an isolated domain controller and one slave with generated lab secrets. Put random files in:

- the expected deployment repository;
- the expected configuration root;
- a sibling-prefix directory outside each root; and
- a deeper outside directory reached only after canonicalization.

Patch the final controller-side file open/send routine to record the requested path, lexical join, canonical target, configured root, caller identity, and protocol operation, then substitute a fixed canary response. Do not open the outside file during initial proof.

Exercise normal child paths, `..` segments, repeated separators, absolute-path syntax, encoded separators if the wire decoder transforms them, sibling-prefix names, symlinked intermediate directories, and nonexistent targets. Keep `getFile()` and `getConfigurationFile()` separate. Replay with a bad secret, a valid but unprivileged host identity where supported, affected behavior, and corrected behavior.

The strongest safe positive is **authenticated disposable slave -> protocol path selector contains traversal -> affected domain controller canonicalizes outside the intended root -> patched reader records the random outside canary target -> corrected release rejects before file access**. Report the prerequisite slave trust and the exact controller process permissions; never request `/etc/passwd`, credentials, keystores, or live server configuration.

## 4. Gate Rocket.Chat traversal on route and storage backend

The Rocket.Chat issue is reachable under `/custom-sounds/` only when CustomSounds storage uses `FileSystem`. Package version or route presence alone does not prove exposure.

1. Deploy a disposable Rocket.Chat instance with no real messages or users and a temporary CustomSounds filesystem root.
2. Place one benign sound control in the root and random text canaries in a sibling-prefix directory and a deeper outside directory.
3. Replace the final filesystem read with a recorder that logs the raw route, URL-decoded segments, normalized path, canonical path, storage backend, and root-containment result; return a fixed marker instead of file bytes.
4. Compare plain `..`, percent-encoded segments, repeated separators, mixed separators where the host OS interprets them, dot segments, sibling prefixes, and symlinked parent components.
5. Repeat with GridFS or each supported non-filesystem backend, route-disabled controls, unauthenticated and ordinary authenticated callers, and corrected releases.

A bounded positive is **unauthenticated custom-sounds route -> filesystem backend preserves an escaping selector -> canonical target leaves the temporary sound root -> recorder identifies the synthetic outside canary**. Do not read application configuration, environment files, databases, uploads, or user content. Report the feature/backend precondition prominently.

## 5. Keep Zyxel portal admission and administrator export separate

The Zyxel records affect WAX650S firmware through `7.10(ABRM.4)C0`. One issue allows a WLAN-side attacker to bypass captive-portal authentication through `social_login.cgi`; the other requires an authenticated administrator and reaches an OS-command sink through `export-cgi`. Do not present them as an unauthenticated command-execution chain unless an independent test proves that captive-portal admission also creates an administrative session—it normally should not.

### Captive-portal state matrix

Use an owned WAX650S in a disconnected RF or shielded lab with a canary-only VLAN and disposable portal identities. Capture association state, portal cookie/state token, CGI parameters, redirect target, controller decision, assigned role/VLAN, and access to one inert canary endpoint.

Compare:

- valid portal login and invalid credentials;
- missing, empty, duplicated, malformed, expired, and replayed synthetic social-login state;
- direct requests before association, after association but before portal completion, and after logout; and
- affected and corrected firmware.

The positive is **owned WLAN client lacks valid portal proof -> alternate `social_login.cgi` state is accepted -> only the canary VLAN becomes reachable**. Do not scan adjacent networks, collect another user's portal token, or imply appliance-management access from network admission.

### Administrator export recorder

Only in a disposable administrator session, patch the process-launch boundary behind `export-cgi` so it records executable and structured arguments and refuses to spawn. Compare an ordinary export name/value with separators, quoting boundaries, option-like values, whitespace, newline, and Unicode-normalization canaries. Use random marker text only—no shell commands, substitutions, redirections, or callbacks.

Report **administrator-controlled export field -> application constructs a command boundary -> recorder shows the marker becoming a new argument or shell token -> fixed firmware rejects or passes it as one literal value**. Administrator access is a material prerequisite, and a changed filename or validation error is not command execution.

## Reporting checklist

- [ ] Every finding records exact release, deployment mode, caller position/role, and feature or storage configuration.
- [ ] Node.js HTTP evidence includes visible header collections, body events, outbound raw bytes, and both parsers' message-slot decisions on one isolated connection.
- [ ] SQLite evidence binds iterator identity to reset/rebind events and synthetic tenant markers without querying real data.
- [ ] WildFly evidence states the slave-secret prerequisite and stops at a patched domain-controller file reader.
- [ ] Rocket.Chat evidence proves the `FileSystem` backend and `/custom-sounds/` route before claiming reachability.
- [ ] Zyxel portal admission and administrator export are reported as separate trust boundaries unless a distinct administrative-session transition is proven.
- [ ] No shared traffic, host/tenant file, real portal identity, appliance command, credential, keystore, or production configuration appears in evidence.
