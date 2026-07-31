---
title: Browser, filesystem, preset, and controller-file boundaries
---

# Browser, filesystem, preset, and controller-file boundaries

A July 31 advisory wave yields four reusable operator checks: browser-origin enforcement can disappear on a certificate-dependent WebSocket path; symlink creation can outlive per-directory authorization; a desktop preset field can become an outbound file-open authority; and managed-node report content can select files from an automation controller.

Sources:

- [MeshCentral GHSA-fcvp-v754-r7rh / CVE-2026-66420](https://github.com/advisories/GHSA-fcvp-v754-r7rh): the advisory reports that `CheckWebServerOriginName()` returned early when self-signed certificates were in use, skipping origin protection across WebSocket endpoints;
- [SFTPGo GHSA-3964-29ff-vwff / CVE-2026-10031](https://github.com/advisories/GHSA-3964-29ff-vwff): releases before 2.7.4 authorized operations against a symlink's containing directory instead of the dereferenced target's directory permissions;
- [RapidRAW GHSA-2jwx-hj3p-pj84 / CVE-2026-64816](https://github.com/advisories/GHSA-2jwx-hj3p-pj84): releases before 1.6.0 passed preset `lutPath` values to `File::open()`, including Windows UNC authorities reached through community and imported presets; and
- [Red Hat Leapp Ansible collection GHSA-9hgq-3p3x-rvvw / CVE-2026-68562](https://github.com/advisories/GHSA-9hgq-3p3x-rvvw): privileged writes to managed-node report content could influence a later remediation task so that controller-local files were copied to that node.

These are unreviewed GitHub Advisory Database records at scan time. Treat the described affected versions and code paths as source leads, not substitutes for reproducing the exact package artifact, configuration, and fixed control.

!!! warning "Disposable labs and inert canaries only"
    Use two synthetic browser origins, fake sessions, temporary SFTP roots, a recorder-only file opener, fake preset repositories, an isolated automation controller, and random marker files. Never capture session keys, forge user cookies, collect NTLM challenge responses, open real credentials, or copy controller SSH keys, vault data, inventories, or production configuration.

## Boundary matrix

| Surface | Attacker-controlled value | Authority transition | Bounded positive |
| --- | --- | --- | --- |
| MeshCentral WebSockets | browser `Origin` plus endpoint selection | self-signed-certificate branch decides whether origin policy runs | foreign owned origin reaches one no-op authenticated WebSocket action while the same policy should reject it |
| SFTPGo virtual filesystem | symlink path and dereferenced target | link-directory permissions are reused for target access | permitted link reaches one denied-directory marker under the same synthetic user |
| RapidRAW presets | `lutPath` in remote or imported preset | trusted preset processing opens a caller-selected file authority | instrumented opener records an owned UNC authority without making a network connection |
| Leapp remediation | managed-node report field consumed by a controller task | node-controlled content selects a controller-local source | one controller temp marker is copied to a disposable node destination |

Keep reachability, guard execution, sink selection, and impact separate. A foreign WebSocket handshake is not administrator compromise; creating a symlink is not restricted-file access; parsing a UNC string is not credential disclosure; and reading a report is not controller-file transfer until the relevant sink fires.

## MeshCentral certificate-mode to WebSocket-origin differential

The reusable test is not “self-signed certificates are vulnerable.” It is whether TLS configuration selects a branch that bypasses browser-origin enforcement.

1. Deploy the exact affected MeshCentral build with no managed production devices. Create one disposable administrator and replace each candidate WebSocket action with a no-op recorder where practical.
2. Run two otherwise identical configurations: the self-signed mode named by the advisory and a controlled certificate mode. Keep host, reverse-proxy route, authentication, cookie attributes, and endpoint set constant.
3. From an owned foreign origin, attempt a credentialed WebSocket handshake to each exposed endpoint. Record browser origin, request host, certificate mode, endpoint, cookie presence as a boolean, `CheckWebServerOriginName()` result, upgrade result, and no-op action count. Redact all cookie values.
4. Compare same-origin, foreign-origin, absent-origin/non-browser, unauthenticated, and fixed-build controls. Do not request session-key material or invoke device-control actions.
5. A bounded positive is **authenticated browser at a foreign owned origin -> self-signed branch skips the expected origin decision -> one harmless recorder action succeeds**, while the paired control rejects it.

Report cross-site WebSocket reachability first. Do not claim cookie forgery, arbitrary-user impersonation, or device takeover unless separately authorized and independently proven without exposing reusable authentication material.

## SFTPGo symlink target-authorization check

1. Create a disposable user with `create_symlinks`, read/write access to `/allowed`, and an explicit denial for the relevant operation on `/restricted`. Put one random text marker in `/restricted`; create no links to host or production paths.
2. Establish that direct access to the restricted marker is denied and ordinary operations inside `/allowed` succeed.
3. Create `/allowed/marker-link` pointing to the synthetic restricted marker. Exercise download, upload, overwrite, rename, and delete separately because each may use a different authorization path.
4. Capture lexical path, canonical target, link-directory permissions, target-directory permissions, operation, decision, and marker hash. Restore the fixture after each mutation test.
5. Repeat on 2.7.4 or the applicable corrected build. Authorization must be applied to the effective target and every traversed component, not only the lexical parent.

A strong positive is **allowed symlink creation -> dereferenced target remains in a denied directory -> an operation succeeds using the link directory's permissions**. Stop after the synthetic marker; never point links at another tenant, home directory, key, database, or system path.

## RapidRAW preset-to-file-authority harness

Test the two ingestion routes independently: a community preset fetched when the Community tab opens and a user-imported preset file. The trust preconditions differ even when both reach the same `lutPath` sink.

1. On an isolated Windows VM, replace or instrument the `File::open()` call so it records normalized path, path kind, authority, and call site, then returns a controlled error without opening a file or socket.
2. Serve a synthetic community repository you own and prepare a separate imported preset. Use a reserved owned hostname in a UNC-shaped `lutPath`; do not run SMB or collect authentication traffic.
3. For each route, record whether ingestion was automatic or user-initiated, preset provenance, signature/digest if any, decoded `lutPath`, canonical path classification, and recorder count.
4. Compare local relative paths, local absolute paths, UNC syntax, alternate separators, malformed authorities, and a fixed 1.6.0-or-newer build. Keep each case inert.
5. A bounded positive is **untrusted preset source -> `lutPath` reaches a network-file authority -> recorder observes an attempted UNC open**. This proves outbound file-open selection without inducing an NTLM exchange.

Report community-repository control and social import as distinct exploit preconditions. Do not start a credential-capture listener or include challenge-response data in evidence.

## Leapp managed-report to controller-file transfer

The advisory requires privileged write access to the managed node's Leapp report content and later operator execution of the affected remediation task. Preserve both preconditions.

1. Build a disposable controller and managed VM with fake inventory values and no real SSH, vault, cloud, or registry credentials. Create a random marker under a controller-only temporary directory.
2. Interpose the Ansible file lookup/copy source resolution with a recorder, then run the relevant remediation task against a known-good synthetic report to map the expected fields and source path.
3. As the lab principal with the advisory's stated managed-node write capability, change one report field at a time to select only the controller temp marker. Do not reference home directories, environment files, inventory secrets, private keys, or vault files.
4. Capture node-side report hash, parsed field, controller-side normalized source, task privilege context, destination, and copied marker hash. Distinguish controller lookup from managed-node reads.
5. Repeat with the corrected collection artifact when one is identified from the upstream source. The task should derive controller sources from trusted constants or reject node-controlled path selection before lookup/copy.

A bounded positive is **managed-node report mutation -> controller task resolves attacker-influenced local source -> one random controller marker appears at the disposable node destination**. Privileged node write access is a material precondition; do not describe this as unauthenticated controller compromise.

## Evidence and reporting

Preserve exact package versions and hashes, certificate mode, browser-origin decision traces, SFTP permission and canonical-path tables, preset provenance and file-open recorder logs, Leapp task names and source-resolution traces, plus corrected-build controls. Lead with the narrow boundary actually proven: **TLS mode to skipped origin guard**, **symlink parent permission to denied target**, **preset path to network-file authority**, or **managed report to controller-local source**.
