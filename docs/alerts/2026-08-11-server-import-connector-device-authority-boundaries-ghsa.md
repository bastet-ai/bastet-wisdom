---
title: Server import, connector, and device API authority boundaries
---

# Server import, connector, and device API authority boundaries

An August 11 advisory wave exposes one reusable operator pattern across Crafty Controller, Velociraptor, and Axis devices: a named management feature can silently become file-write, network-connect, or privileged runtime authority when the final sink does not preserve the authenticated role, approved root, destination ACL, or package trust decision.

Primary records:

- Crafty Controller server import and admin-upload traversal: [GHSA-2m7h-5589-9pp5 / CVE-2026-13716](https://github.com/advisories/GHSA-2m7h-5589-9pp5);
- Velociraptor `upload_azure`, `upload_sftp`, and `upload_smb` missing `NETWORK` authorization: [GHSA-qx94-26r3-gv6g / CVE-2026-18348](https://github.com/advisories/GHSA-qx94-26r3-gv6g);
- Axis Device Configuration Framework viewer-role authentication bypass: [GHSA-wr2x-95cv-cwrg / CVE-2026-6181](https://github.com/advisories/GHSA-wr2x-95cv-cwrg);
- Axis VAPIX administrator-only parameter-to-runtime boundary: [GHSA-fxvq-h426-fg3c / CVE-2026-4757](https://github.com/advisories/GHSA-fxvq-h426-fg3c); and
- Axis unsigned-ACAP package TOCTOU and configuration validation: [GHSA-h429-j7q3-6227 / CVE-2026-5303](https://github.com/advisories/GHSA-h429-j7q3-6227), [GHSA-h4gf-wr33-6635 / CVE-2026-6505](https://github.com/advisories/GHSA-h4gf-wr33-6635), and [GHSA-xj6x-54xc-64j5 / CVE-2026-5304](https://github.com/advisories/GHSA-xj6x-54xc-64j5).

These GitHub entries were unreviewed when scanned. Confirm the exact Crafty Controller release and route, Velociraptor build and role policy, or Axis model, AXIS OS build, enabled framework, service-account privilege, and unsigned-ACAP setting before reporting. The Axis ACAP records require both unsigned application installation to be enabled and an operator to install a malicious package; do not reframe them as remote unauthenticated device compromise.

!!! warning "Disposable roots, owned peers, and denied sinks only"
    Use temporary server roots, synthetic imports, owned no-content network peers, fake cloud/file-share credentials, disposable roles, inert ACAP packages, and patched file/network/process/configuration sinks. Never overwrite application files, contact internal services, transfer evidence data, install an unknown application, execute a VAPIX payload, or mutate an operational camera or server.

## Boundary map

| Surface | Caller-controlled authority | Final sink | Bounded positive |
| --- | --- | --- | --- |
| Crafty import/upload | archive name, upload filename, import path, or destination | canonical create/replace path | sibling canary path reaches a denied writer |
| Velociraptor VQL upload | plugin and destination/server options | DNS/connect/TLS client | analyst without `NETWORK` reaches an owned denied peer |
| Axis configuration | viewer service-account request and operation selector | privileged configuration handler | viewer reaches a denied admin-only mutation |
| Axis VAPIX | administrator-supplied parameter | process/runtime operation | inert grammar changes final argv or shell representation at a denied sink |
| Axis ACAP install | package files, links, configuration, and install timing | privileged validation/copy/install lifecycle | approved object identity differs from the object selected at the denied install sink |

## 1. Build one route-to-sink trace per management feature

Start from documented UI/API traffic and source or instrumented builds. Capture:

```text
authenticated principal and role
-> route or VQL plugin selection
-> object/path/destination/package normalization
-> operation-specific authorization
-> canonical file, network peer, configuration mutation, or process sink
```

Do not infer authority from UI visibility or plugin registration. Test create, replace, import, extract, connect, upload, configure, install, upgrade, rollback, and uninstall independently because they often use different helper functions.

## 2. Resolve Crafty imports and uploads at the final filesystem operation

Create a disposable Crafty data root and a sibling directory containing only a random marker filename. Patch `open`, rename, copy, archive extraction, and server-start/process functions before sending any request. Exercise the legitimate server-import and administrator-upload routes with:

- a plain in-root filename;
- nested directories and repeated separators;
- `..`, absolute, encoded-separator, and sibling-prefix forms;
- Windows drive, UNC-looking, and backslash variants where the deployment accepts them;
- symlinked parent/final components; and
- archive member names if the import route expands archives.

Record the route, authenticated role, raw and decoded name, configured root, temporary path, canonical destination immediately before each write/rename, and denied syscall. A bounded positive is **authenticated import/upload -> canonical destination outside the temporary Crafty root -> denied writer receives the sibling path**. Do not place a script, plugin, startup file, or server executable at the destination, and do not start an imported server. File-write reach is sufficient; code execution remains a separate, unproven edge unless a safe denied runtime sink demonstrates it.

## 3. Enforce Velociraptor network authority in every upload plugin

Create an analyst-role user that intentionally lacks `NETWORK`. Configure fake Azure, SFTP, and SMB credentials that are valid only to local mock clients. Replace DNS, socket connect, TLS, SMB, SSH, and Azure SDK request methods with recorders.

For each plugin, compare:

| Role | Plugin | Destination | Expected |
| --- | --- | --- | --- |
| analyst without `NETWORK` | each upload plugin | owned allowed-looking peer | deny before DNS/connect |
| analyst without `NETWORK` | each upload plugin | owned denied-class peer | deny before DNS/connect |
| role with `NETWORK` | each upload plugin | owned no-content control | allowed to mocked connector only |
| analyst without `NETWORK` | ordinary non-network VQL control | no destination | normal role behavior |

Vary hostname/IP form, port, scheme where applicable, redirects for HTTP-backed SDKs, DNS answer changes, IPv4/IPv6, and duplicate plugin arguments. Capture the authenticated org and role, VQL query, plugin ACL declaration, authorization decision, parsed destination, resolved/final peer, credential field names, and denied connector event.

A strong result is **analyst without `NETWORK` -> one of the three upload plugins -> owned peer reaches the connector recorder**. This proves an ACL bypass and outbound-connect primitive. Do not scan ports, target internal services, send collected artifacts, or include real credentials. A timeout/status difference is not needed when the final connector trace is available.

## 4. Diff Axis service-account roles at operation level

Use disposable viewer and administrator service accounts on an isolated owned device or faithful harness. Inventory only documented Device Configuration Framework and VAPIX operations, then replace configuration mutation and runtime/process functions with denied recorders.

For every configuration operation, replay the same inert request as viewer and administrator. Vary only operation family, object identifier, method, content type, alternate versioned route, and duplicate/empty parameters. Record authenticated account, server-resolved privilege, handler, per-operation policy decision, normalized mutation, and denied sink. A bounded positive is **viewer account -> operation intended for stronger privilege -> denied configuration mutation recorder**. Authentication success alone is not an authorization bypass.

For administrator-only VAPIX parameters, preserve the high-privilege precondition in the report. Feed only inert grammar markers through an instrumented handler and capture structured arguments, option boundaries, shell reconstruction, environment, and denied process/runtime call. Compare spaces, quotes, separators, newlines, encoding transitions, option-looking values, and duplicate fields. Report parameter-to-runtime grammar loss only when the final trace changes executable, argv boundaries, or shell semantics; never execute a marker or callback.

## 5. Test ACAP package identity across the complete install lifecycle

The TOCTOU records require a package approved at one moment to differ from the object consumed later. Build two inert ACAP fixtures in a disposable package store: a valid package and a marker-only rejected variant. Both must be non-executable. Instrument signature/config validation, file identity (`dev`, `inode`, digest, link target), copy/rename, extraction, privilege transition, and final install activation.

Run normal install, upgrade, retry, concurrent replacement, symlink swap, hard-link identity, package-path rename, and configuration-file replacement controls. Pause only at explicit test hooks between validation and use; do not race an operational device. Capture the identity checked and the identity selected at every later file/configuration sink.

A bounded positive is **valid inert package passes validation -> package/config identity changes -> denied privileged install sink selects the unvalidated identity**. A race window or writable directory alone is not proof. Also verify that signed-package enforcement and the default unsigned-install setting fail closed; do not persuade an operator to install a package or enable unsigned installation outside the owned lab.

## Evidence and reporting checklist

- [ ] Exact product/build, enabled feature, listener/route, authenticated role, and corrected control are recorded.
- [ ] Crafty evidence stops at a denied canonical write and does not claim RCE from traversal alone.
- [ ] Velociraptor evidence uses owned peers and proves the final connector, not a timing oracle.
- [ ] Axis viewer and administrator preconditions remain explicit.
- [ ] VAPIX evidence stops at denied argv/runtime semantics.
- [ ] ACAP evidence joins checked and consumed file identities without installing executable content.
- [ ] Every chain edge is reported separately unless one lab trace proves the entire sequence.