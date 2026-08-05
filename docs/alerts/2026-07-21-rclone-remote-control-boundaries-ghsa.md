# rclone remote-control, path, symlink, and metadata boundary checks

Source: hourly offensive-security scan, 2026-07-21 GitHub Advisory Database update. Primary entry: [GHSA-qw24-gh76-8rvv](https://github.com/advisories/GHSA-qw24-gh76-8rvv) / CVE-2026-49980.

This advisory is durable for operators because it exposes a reusable local-control-plane chain: an unauthenticated rclone Remote Control listener started with `--rc-serve` parses a remote specification from ordinary `GET` or `HEAD` paths, initializes caller-selected inline backends, and can cross into local command execution as the rclone process user. Browser subresource requests can deliver the same path to a localhost-only listener, so loopback binding alone does not remove the browser-to-local-service boundary.

!!! warning "Authorized validation only"
    Use a disposable rclone process, empty temporary config, inert command marker, synthetic files, and a lab browser profile. Do not target customer storage, real remotes, credentials, cloud metadata, internal services, production files, shell startup paths, or shared workstation RC listeners. Do not enable or reconfigure RC on a production host for testing.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-qw24-gh76-8rvv](https://github.com/advisories/GHSA-qw24-gh76-8rvv) / CVE-2026-49980 | rclone `rcd --rc-serve` / RC file-serving paths | unauthenticated `GET` and `HEAD` paths of the form `/[remote:path]/object` pass the URL-derived remote into backend initialization; inline backend options can execute local commands | Treat RC file serving as an unauthenticated backend-construction boundary, including direct network reachability and browser-to-loopback request delivery. |

Affected ranges and controls reported by the advisory:

- rclone `1.55.0` through `1.74.2`: inline backend option overrides make command execution reachable;
- rclone `1.46.0` through `1.74.2`: the same route family can expose local files through inline `local` remotes, although releases before `1.55.0` lack the command-execution path;
- first patched release: rclone `1.74.3`;
- required conditions: RC enabled, listener reachable, no global RC HTTP authentication, and `--rc-serve` enabled.

The advisory also reports that inline `global.*` options can mutate process-wide rclone configuration, including proxy state. Keep public validation focused on one inert marker and configuration decision evidence; do not redirect real process traffic.

## Recon and preconditions

1. **Establish the exact startup mode.** Look for `rclone rcd`, `--rc`, and specifically `--rc-serve` in service units, containers, desktop integrations, CI jobs, or process arguments. An installed rclone binary is not sufficient.
2. **Record listener topology.** Capture bind address, port, TLS, reverse proxy, and whether `--rc-user`, `--rc-pass`, `--rc-htpasswd`, or equivalent global HTTP authentication is active.
3. **Map request principals.** Separate remote network callers, same-host processes, and a browser on the workstation. Loopback exposure can still matter when a public page can issue an `<img>`-style subresource request.
4. **Confirm version-specific impact.** Distinguish backend initialization, local-file selection, global-option mutation, and command execution. Do not claim command execution for versions before `1.55.0` based only on the shared route.
5. **Use a throwaway process identity.** The lab rclone user should have no credentials, mounted customer data, sensitive environment variables, or access outside a dedicated temporary tree.

High-value targets include backup/orchestration hosts, developer workstations, agent sandboxes, shared service containers, and CI runners where rclone runs with more authority than the HTTP caller. Report that authority as impact context; do not exercise unrelated filesystem or storage access.

## Replayable validation boundaries

### Unauthenticated path-to-backend initialization matrix

1. Start an affected rclone release in a disposable container or VM with:
   - an empty temporary config and home directory;
   - no cloud credentials or customer mounts;
   - RC bound only to the lab interface;
   - `--rc-serve` enabled; and
   - one temporary directory for canary files and command markers.
2. Send baseline `GET` and `HEAD` requests to a normal nonexistent remote path and record status, response length, and whether backend initialization occurs.
3. Repeat with an inline remote path whose only backend-initialization effect is writing a unique inert marker under the temporary lab directory. Keep the exact command-option syntax in private evidence; the public artifact needs only the redacted path shape, process trace, and marker result.
4. Positive evidence is marker creation by the rclone process after an unauthenticated `GET` or `HEAD`. Stop immediately—do not open a shell, read environment variables, make network callbacks, or modify persistent configuration.
5. Repeat with:
   - rclone `1.74.3` or newer;
   - global RC HTTP authentication enabled and no credentials supplied;
   - `--rc-serve` disabled; and
   - a pre-`1.55.0` release if the assessment must separate local-file behavior from command execution.
6. Record the remote string as a redacted structural representation rather than publishing a copy-paste command-execution URL.

Report this as **unauthenticated RC file-serving path -> inline backend initialization -> inert command marker as the rclone process user**. Include rclone version, process identity, startup flags, authentication state, request method, marker path, and patched controls.

### Local-file selection control

For versions in the broader `1.46.0` through `1.74.2` range, create one synthetic file inside the disposable lab tree and test whether an inline `local` remote can select it through the unauthenticated file-serving path.

- Use only the known synthetic file; never request `/etc`, home directories, environment files, configs, keys, logs, or customer data.
- Compare `GET` with `HEAD` and distinguish response-body disclosure from backend initialization alone.
- Repeat with authentication enabled, `--rc-serve` disabled, and `1.74.3+`.

Report this separately as **unauthenticated URL-derived inline local remote -> synthetic file read**. Do not infer arbitrary command execution for old versions unless the command-capable inline option path is independently proven.

### Browser-to-loopback delivery check

1. Use an owned public test origin and disposable browser profile on the lab workstation.
2. Embed only a harmless `<img>` or equivalent subresource whose URL targets the lab RC listener and the inert marker path.
3. Record whether the browser sends the request and whether rclone creates the marker. Response readability is not required for a state-changing blind request.
4. Compare Firefox and the actual browser in scope, ordinary public HTTP/HTTPS origins, RC authentication enabled/disabled, and patched rclone.
5. Distinguish request delivery from CORS-enabled response access. Do not claim browser-readable local data when the proof shows only blind request delivery and marker creation.

Report this as **public browser origin -> loopback RC subresource request -> unauthenticated backend initialization**. Include browser/version, page origin, request method, listener address, authentication state, and marker-only result.

## Evidence and reporting

Capture:

- rclone version and exact RC startup flags;
- listener address, reverse-proxy topology, TLS, and global RC HTTP authentication;
- caller class: remote client, same-host process, or browser origin;
- escaped/redacted request path and method;
- backend-initialization trace and inert marker ownership;
- vulnerable-versus-fixed decision table; and
- whether the proven impact is backend initialization, synthetic local-file read, process-global option mutation, or command execution.

Lead with the exact crossed boundary: **unauthenticated URL path -> inline rclone backend configuration -> process-context side effect**. Do not publish weaponized URLs, real remote configurations, credentials, production filesystem paths, or command output beyond a unique inert marker.

## August 5 follow-up: untrusted-remote filesystem boundaries

Four reviewed rclone advisories published on August 5 extend the operator model beyond Remote Control. Three yield durable validation paths; the RC stack-trace record is useful only as adjacent version and error-surface context.

| Advisory | Boundary | Affected / fixed range | Bounded proof |
| --- | --- | --- | --- |
| [GHSA-cf44-9pgv-m4xc](https://github.com/advisories/GHSA-cf44-9pgv-m4xc) / CVE-2026-54572 | an attacker-controlled `.rclonelink` body becomes a local symlink target; a later object can follow that link outside the destination | `<= 1.74.3`; fixed in `1.74.4` | patched symlink and file-open recorders prove the final canonical path would leave a disposable destination |
| [GHSA-45pq-889g-fcgh](https://github.com/advisories/GHSA-45pq-889g-fcgh) / CVE-2026-71309 | `serve restic` accepts a leading parent path and passes it to the configured backend, whose path joining may escape its root | `1.40.0` through `1.74.4`; fixed in `1.75.0` | a synthetic sibling marker plus backend path recorder proves root escape without reading or changing unrelated objects |
| [GHSA-945v-v9p3-v5xw](https://github.com/advisories/GHSA-945v-v9p3-v5xw) | local `--metadata` applies source-supplied ownership and Go file-mode bits to copied content | `<= 1.74.3`; fixed in `1.74.4` | a patched `chown`/`chmod` sink records requested IDs and special bits for an inert file |
| [GHSA-gwfq-86j8-7qhv](https://github.com/advisories/GHSA-gwfq-86j8-7qhv) | recovered RC panics can return stack and path details in API errors | `<= 1.74.4`; fixed in `1.75.0` | ordinary synthetic error comparison only; never select host files to manufacture a panic |

!!! warning "No outside-root writes or privileged artifacts"
    Use an unprivileged disposable rclone process, synthetic remote objects, temporary destination and sibling directories, patched filesystem sinks, and no-op ownership/mode recorders. Never overwrite startup files, SSH keys, scheduled tasks, service files, repositories, backups, or customer objects. Do not create setuid/setgid files, run copied binaries, follow links into the host, or test delete semantics against a real backend.

### Symlink-following copy matrix

The relevant chain is ordered: untrusted remote object -> translated local symlink -> later descendant object -> filesystem operation follows the planted link. Test the chain without allowing the final write:

1. Create a temporary destination and a sibling directory containing one unique marker filename. Neither directory should contain sensitive data.
2. Replace or interpose the local backend's symlink and file-open operations with recorders. The symlink recorder logs the requested target but creates only an inert in-root placeholder; the open recorder resolves the would-be final path and denies the syscall.
3. Seed a synthetic source listing with a translated-link object followed lexically by one descendant object. Record object order explicitly.
4. Compare relative in-root, parent-relative, and absolute symlink targets. Do not use real home or system paths.
5. Require evidence that the affected build requests an outside-destination final path and that `1.74.4+` rejects or safely handles the same fixture.

Report **untrusted remote link metadata -> translated local symlink -> descendant write would escape destination**. A symlink target alone is weaker than proof that a later operation follows it; preserve both recorder events.

### `serve restic` backend-root matrix

The advisory identifies a backend-independent acceptance point followed by backend-specific propagation. Do not assume every backend escapes identically.

1. Start `rclone serve restic` in an isolated lab with authentication, one empty backend root, and no reusable credentials.
2. Instrument the middleware-to-backend path value and the backend's final object selector.
3. Seed an in-root canary and a synthetic sibling-root canary with distinct hashes.
4. Compare a normal object path, an encoded harmless separator control, and one parent-path structural test generated by the lab client.
5. Exercise `HEAD` or a denied read recorder first. Test write/delete dispatch only through no-op recorders; never mutate the sibling canary.
6. Repeat across the actual backend in scope and `1.75.0+`.

Evidence should bind **request path -> middleware context path -> backend selector -> final canonical/object key**. Report each backend separately. A WebDAV result does not prove identical FTP, SFTP, cloud-object, or local behavior.

### Metadata-to-privilege recorder

Test metadata handling without generating a privileged file:

1. Run rclone as an unprivileged user in a disposable mount or namespace.
2. Create one inert non-executable text object on the synthetic source.
3. Attach ordinary mode/ownership metadata as the baseline, then a canary value containing a special-mode bit and a numeric owner that the test user cannot assume.
4. Patch `chown` and `chmod` immediately before the operating-system call. Record the requested path, uid, gid, raw parsed mode, and masked ordinary permission bits, then return a denied result.
5. Compare copy with and without `--metadata`, affected `<=1.74.3`, and fixed `1.74.4+`.

The positive is a sink record showing source-controlled ownership or special-mode bits would be applied to attacker-controlled content. Do not create an executable, invoke the copied file, run the test as root, or treat ordinary permission preservation as privilege escalation.

### Follow-up evidence fields

```text
rclone version and command family:
Source trust and synthetic object order:
Destination/backend root:
Raw selector and canonical final path/key:
Symlink target recorder:
File-open/write/delete recorder:
Requested uid/gid/mode recorder:
Affected-versus-fixed result:
Strongest supported claim:
Excluded write, execution, or disclosure claims:
```

Keep the RC error disclosure as supporting recon only. A normal API error containing a synthetic path or build detail can establish response behavior, but do not repoint configuration at host files, force panics on a shared service, or publish stack addresses.
