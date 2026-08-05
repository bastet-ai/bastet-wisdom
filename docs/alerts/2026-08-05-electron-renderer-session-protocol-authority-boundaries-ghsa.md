---
title: Electron renderer, session, protocol, and platform-authority boundaries
---

# Electron renderer, session, protocol, and platform-authority boundaries

Ten August 5 Electron advisories expose a reusable desktop-application testing pattern: an app may declare renderer, origin, session, path, process-signing, or GPU-process boundaries while a later Electron API makes its decision from different authority data. Validate the exact transition with a disposable app, inert fixtures, and patched sinks rather than accessing files, devices, credentials, or host privileges.

Primary validation seeds:

- context bridge isolation bypass [GHSA-h7rp-cf8h-j98x](https://github.com/advisories/GHSA-h7rp-cf8h-j98x);
- custom-protocol cross-origin reads [GHSA-v3j7-r9gq-3gjw](https://github.com/advisories/GHSA-v3j7-r9gq-3gjw);
- iframe permission-origin confusion [GHSA-9pf5-hg6p-4pwp](https://github.com/advisories/GHSA-9pf5-hg6p-4pwp) and native-autofill UI positioning [GHSA-x8rc-wpg4-grpf](https://github.com/advisories/GHSA-x8rc-wpg4-grpf);
- HTTP redirect into the local-file loader [GHSA-v64r-4m7r-3mvq](https://github.com/advisories/GHSA-v64r-4m7r-3mvq);
- `ProtocolResponse.url` default-session cache reuse [GHSA-r4w5-6pfg-jxp5](https://github.com/advisories/GHSA-r4w5-6pfg-jxp5) and extension APIs crossing session boundaries [GHSA-m55f-7gqj-fr98](https://github.com/advisories/GHSA-m55f-7gqj-fr98);
- `shell.openPath()` embedded-NUL path disagreement [GHSA-5c9j-mhmv-5xgx](https://github.com/advisories/GHSA-5c9j-mhmv-5xgx);
- spoofable macOS same-signed-parent checks [GHSA-jm7p-cc5g-qwxx](https://github.com/advisories/GHSA-jm7p-cc5g-qwxx); and
- off-screen rendering geometry trusted across the GPU/main-process boundary [GHSA-pfmc-3mgc-p6fp](https://github.com/advisories/GHSA-pfmc-3mgc-p6fp).

!!! warning "Disposable Electron apps and denied sinks only"
    Use synthetic renderer content, canary protocol bodies, owned HTTP redirectors, temporary files, fake permission/device identifiers, empty browser sessions, detached UI screenshots, and patched file/process/device/extension sinks. Never read host files, request real camera or microphone access, load unknown extensions, inherit production TCC/keychain authority, compromise a GPU process, or execute renderer, preload, Node.js, or shell code.

## 1. Map the authority graph before testing

Inventory each `BrowserWindow`, `WebContents`, `WebFrameMain`, `session`, custom scheme, extension, and main/preload IPC handler. Record at least:

| Component | Authority data to capture | Dangerous transition |
| --- | --- | --- |
| renderer and iframe | top origin, frame origin, sandbox, `contextIsolation`, `nodeIntegration` | untrusted JavaScript to preload/main capability |
| `contextBridge` API | exposed method, Promise return, IPC channel, argument schema | page object/prototype state to isolated-world invocation |
| custom protocol | scheme privileges, handler session, request origin, response URL/session | remote origin to custom data or another network/cache partition |
| `net.fetch()` / `net.request()` | initial URL, every redirect target, final scheme and resource class | approved remote URL to local resource |
| permission handler | top frame, requesting frame, `requestingOrigin`, `details.securityOrigin` | child-frame request to camera/microphone/serial authority |
| extension | loading session, target tab session, target frame | extension privilege crossing an intended partition |
| `shell.openPath()` | raw string, validation result, platform API argument | approved filename to a different platform-parsed path |
| macOS launch | actual parent PID, code-sign identity, fuses, environment | local process to signed-app authority |

Do not treat secure-looking flags as proof. The question is whether the value used by the final privileged API is bound to the same frame, session, origin, path, or process that the app approved.

## 2. Test context-bridge Promise wrappers without executing the bypass

The context-isolation record applies when untrusted content can call Promise-returning functions exposed through `contextBridge`, a common wrapper around `ipcRenderer.invoke`. Build an affected and fixed Electron fixture with:

- one sandboxed test window loading only local inert HTML;
- a preload that exposes one Promise-returning method whose implementation returns a random marker;
- a patched bridge/IPC sink that records world identity, receiver/prototype identity, channel, and arguments; and
- no filesystem, process, network, clipboard, credential, or native-module capability.

Run ordinary calls plus controlled modifications to page-world function binding/prototype behavior. A bounded positive is **page-world state changes the invocation path so the recorder observes isolated-world object or capability access that the fixed build rejects**. Stop there. Do not expose `require`, `ipcRenderer`, shell calls, environment variables, or a command primitive.

Test sandboxed and unsandboxed windows separately. The advisory says unsandboxed or Node-integrated renderers may turn isolation failure into Node.js access, but that stronger result must not be inferred from an isolated-world marker alone.

## 3. Build a frame-origin permission matrix

For camera, microphone, and serial permission checks, use fake permission requests or patch the grant callback before it reaches a device. Test:

| Top frame | Requesting frame | Delegation | Decision fields to compare |
| --- | --- | --- | --- |
| trusted A | trusted A | direct | `requestingOrigin`, `securityOrigin`, frame identity |
| trusted A | owned cross-origin B | absent | same fields plus deny reason |
| trusted A | owned cross-origin B | explicit | same fields plus delegated feature |
| owned B | trusted A | nested control | same fields plus top-frame identity |

A positive for the origin-confusion advisory is **the vulnerable handler receives or authorizes from origin A while the actual requesting frame is B**, with a patched permission sink recording the would-be decision. No physical device should be opened.

For the native-autofill record, render a fake trusted button and a cross-origin owned iframe in a detached test window. Capture frame bounds, requested popup geometry, final native-widget bounds, and a screenshot containing no credentials. Report only if the child can place the native widget outside its own rectangle over trusted UI. Do not solicit or enter real autofill data and do not turn the fixture into a credential prompt.

## 4. Separate custom-scheme access from protocol-handler authorization

Register a canary scheme with combinations of `supportFetchAPI` and `corsEnabled`. Return only a random response marker. From same-origin and owned cross-origin frames, record:

1. request initiator origin and frame;
2. scheme privilege registration;
3. `Origin` header delivered to the handler;
4. handler authorization decision;
5. browser CORS decision; and
6. whether the page can read the marker body.

The relevant positive is **an owned cross-origin page reads the full custom-scheme marker when fetch support is enabled but CORS is not enforced**. A request reaching the handler without readable response data is not the same impact. Keep protocol-level CORS and application-level origin authorization as separate controls.

## 5. Trace every redirect to its final resource class

Patch the local-resource loader to return a synthetic marker keyed to a temporary path; do not let it open the filesystem. Use an owned HTTP server that produces one-hop and multi-hop redirects. Record the initial URL, each status and `Location`, normalized redirect URL, final scheme, loader selected, and whether the app forwards the response body.

Exercise:

- no redirect and same-origin HTTP controls;
- cross-origin HTTP redirects;
- remote-to-custom-scheme and remote-to-local-resource canaries;
- `redirect: "follow"`, `"manual"`, and `"error"`; and
- both `net.fetch()` and `net.request()` paths used by the target.

A bounded positive is **attacker-influenced remote URL -> redirect accepted -> patched local loader selected -> synthetic local marker returned to the app's response sink**. Do not name, select, or read a real local file. If the app consumes a status only and never exposes the body, report the reachable loader transition without claiming file disclosure.

## 6. Prove session isolation with paired markers

Create two in-memory or temporary partitions, A and B. Seed each cache with a different random body for the same owned URL. Register the custom protocol only in B and return a `ProtocolResponse.url` without an explicit session, then repeat with B supplied explicitly.

Capture:

- protocol-handler registration session;
- response `url` and explicit/implicit `session` field;
- network request session;
- cache key and cache-hit partition; and
- body-marker hash returned to the caller.

A positive is **handler in B -> omitted response session -> default-session/A cache marker returned**, while the explicit-B and fixed-build controls return B. Use marker hashes, not body content, in evidence.

For extension boundaries, load a locally authored inert extension into A and create marker-only tabs in A and B. Replace navigate, script, and tab-read operations with recorders. A positive requires an A extension resolving a B target and reaching a recorder that the fixed build denies. Never load third-party extensions or read real page content.

## 7. Compare string validation with platform path consumption

For `shell.openPath()`, use only temporary files with random names and patch the final platform-open call. Build a byte-aware table containing:

- raw JavaScript string and UTF-16 code units;
- embedded-NUL location;
- extension/allowlist decision;
- any `fs.stat()` or equivalent result;
- argument observed by the platform-open recorder; and
- which temporary canary would be selected.

Compare ordinary paths, allowed and disallowed-looking suffixes, an embedded NUL between them, and platform separator variants. A positive is **string validator approves one apparent suffix while the platform recorder selects the prefix before the NUL as a different file identity**. Do not open an application, executable, document, URL handler, or host file.

This is a parser differential, not generic path traversal. Keep extension-policy bypass, path canonicalization, and actual application launch as separate claims.

## 8. Treat process-sign identity as an authenticated channel

The macOS record is relevant only when an app enables fuse restrictions that permit `ELECTRON_RUN_AS_NODE` or `NODE_OPTIONS` behavior for a same-signed parent. Use a disposable, ad-hoc-signed fixture with no entitlements and fake environment markers. Patch startup before Node option processing.

Record actual parent PID, executable identity, signing requirement, audit-token/process ancestry data, result of Electron's parent check, restricted environment variables present, and denied startup decision. Compare intended same-signed parent, unsigned control parent, and the affected-versus-fixed behavior described by the advisory.

A bounded positive is **a differently signed local process is classified as an allowed same-signed parent and its fake restricted variable reaches the startup recorder**. Never run under a production app signature, request TCC entitlements, access Keychain, or execute a Node option.

## 9. Keep GPU memory-safety validation non-exploitative

The off-screen rendering record requires a separately compromised GPU process and is not a normal renderer-to-main-process primitive. First determine whether `webPreferences.offscreen` is enabled. If authorized source-level validation is needed, patch image creation and shared-memory reads, then feed synthetic geometry/stride/size metadata into an isolated harness.

Record declared dimensions, computed byte requirement, shared-memory allocation size, checked arithmetic result, and denied image creation. An affected build accepting geometry whose required range exceeds the supplied buffer is sufficient. Do not exploit a GPU process, read adjacent memory, or run a crash against a shared desktop session.

## Reporting boundaries

- Preserve affected and fixed Electron versions, app flags, frame/session identities, raw-to-normalized values, and the final denied sink.
- A context-isolation marker is not automatically Node.js code execution.
- A redirect reaching a local loader is not file disclosure unless a synthetic body reaches an app-controlled response sink.
- A permission-origin mismatch is not real device access; use patched callbacks only.
- Session-cache and extension findings require two distinct partitions and marker identities.
- NUL-path disagreement proves parser mismatch, not arbitrary file execution.
- Parent-sign spoofing must remain inside a disposable unsigned/ad-hoc-signed fixture with no real platform privileges.
- GPU metadata acceptance is enough; never extract process memory or build a crash exploit.
