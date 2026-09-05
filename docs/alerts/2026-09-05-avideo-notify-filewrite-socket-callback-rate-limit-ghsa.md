# AVideo notify file-write, socket-callback, and rate-limit boundary batch

Sources: GitHub Security Advisories published on 2026-09-05 (15:30 UTC wave).

This batch is durable because it concentrates five distinct trust-boundary families on a single widely self-hosted media platform: a **notify/IPC endpoint where decryption is treated as authentication**, a **caller-chosen path on the same endpoint**, a **hash-parameter lookup that returns complete user records unauthenticated**, a **websocket callback-name-to-global-function dispatch**, and a **bot User-Agent that disables rate limiting across all protected operations**. Each is a reusable check for any platform with notify webhooks, view-stat endpoints, real-time socket layers, and API rate limiting.

## Advisories covered

- **Unauthenticated arbitrary file write via `notify.ffmpeg.json.php`** — [GHSA-w6w9-fw29-2x88](https://github.com/advisories/GHSA-w6w9-fw29-2x88) (critical 9.8, CWE-73): the ffmpeg notify endpoint accepts a caller-chosen `avideoRelativePath` and writes the decrypted `notifyCode` payload to it. The `notifyCode` ciphertext is *decrypted but never validated* — any previously issued code (stream key, notify token, or sibling ciphertext family) replays as valid auth. Result: unauthenticated file write to the application root and subdirectories.
- **`videoViewsInfo` broken access control** — [GHSA-hr26-p4g3-798m](https://github.com/advisories/GHSA-hr26-p4g3-798m) (critical 9.1, CWE-200): when a `hash` parameter is supplied, the views-info endpoints return complete user records — password hashes, recovery tokens, and live session identifiers — to unauthenticated callers. A disclosed live session identifier is directly usable for viewer session hijack, including admin sessions.
- **Rate-limit bypass via bot User-Agent** — [GHSA-54jr-hcr3-c8jp](https://github.com/advisories/GHSA-54jr-hcr3-c8jp) (medium 6.5, CWE-307): sending a bot/crawler `User-Agent` header disables rate limiting on all eight protected operations, including the login brute-force guard. A single source IP can then brute-force any account without limit.
- **Unauthenticated XSS via YPTSocket callback dispatch** — [GHSA-jjf2-9w5j-xm7r](https://github.com/advisories/GHSA-jjf2-9w5j-xm7r) (medium 7.2, CWE-79): with the YPTSocket plugin enabled, socket messages carry a *callback name* that is resolved to a global JS function on the connected client; crafted messages target globals like `avideoConfirmHTML` whose signatures assign untrusted data into `innerHTML`, executing script in other users' browsers with no authentication or interaction.
- **Weak external-login password generation** — [GHSA-hfr9-8xm8-cq6w](https://github.com/advisories/GHSA-hfr9-8xm8-cq6w) (high 5.9, CWE-330): external-login account passwords are generated with `rand()` (31-bit integer space) and stored under unsalted MD5; with any access to a hash dump, plaintext recovery is minutes of offline brute-force.

## Operator triage

1. Treat exposed AVideo instances as critical priority when the ffmpeg/notify ingest path, video view-statistics endpoints, or the YPTSocket plugin are enabled. These five items are all reachable without credentials on default deployments that expose the media platform.
2. `notify.ffmpeg.json.php` is the headline: enumerate every `notify*` / `*.json.php` IPC callback the platform registers (RTMP on_publish/on_stat, ffmpeg hooks, encoder callbacks) and test each for (a) auth semantics — is a token merely *decrypted* or actually *validated* (signature, expiry, one-use, issuer)? — and (b) path handling — is the write destination fixed or caller-shaped?
3. For view-stat endpoints, test lookup keys (`hash`, `id`, `key` query params) with synthetic values and record the *shape* of the response: a positive is the response containing more fields than the requesting principal should see (hashes, recovery tokens, session IDs) rather than an empty/partial record.
4. Rate limiting is a control only if it survives header shaping. Re-run every authenticated state-changing endpoint (login, registration, OTP, reset, API keys) with crawler UAs (`Googlebot`, `Bingbot`, `slurp`, `YandexBot`, plus the platform's own bot list if documented) and record whether the 429/lockout still fires.
5. Socket/websocket layers: inventory the callback/event-name dispatch table on the JS side. Every event name that maps to a *global function* is a candidate for unauthenticated remote invocation; verify which globals sink untrusted arguments into `innerHTML`/`document.write`/`eval`/`Function`.
6. Weak-primitive password generation: any `rand()`-seeded, unsalted-hash, or short-charset password issuance (external logins, magic links, temp accounts) is an offline-crackable credential family. Confirm the generator and hash, note the key space; do not crack real hashes in scope.

## Durable operator value

1. **Decryption is not authentication.** Any IPC/notify token that is decrypted and then used directly — without signature verification, freshness, one-use tracking, or issuer binding — is replayable by anyone who has ever seen a valid token (logs, client caches, sibling code paths). The reusable check: for every token-shaped input, list where it is *validated* vs merely *parsed/decrypted*.
2. **Notify endpoints are file-write primitives in disguise.** Media/encoder platforms wire ingest callbacks into the filesystem (write the rendered frame, save the thumbnail, log the stat JSON). A caller-shaped path on any of those endpoints is arbitrary write → on PHP, `.php` write = RCE. Enumerate every filesystem sink behind a notify/IPC route and confirm the path is a fixed server-side constant.
3. **Hash-param lookups leak the whole object.** When a "private" lookup key (hash, token, short ID) is the *only* gate on a record endpoint, and the record is a full user row, the key is a session-hijack + credential-theft primitive. Test the differential: valid-shaped key returns full record vs. absent key returns 404 — the full record is the finding.
4. **User-Agent is an attacker-controlled rate-limit bypass vector.** Any limiter keyed on IP that special-cases crawler UAs converts bot traffic into a DoS-free brute-force channel. It is also a fingerprinting primitive: the platform's bot list is a disclosed allowlist.
5. **Callback-name dispatch is a client-side injection surface.** Websocket/event-bus layers that route message fields into *names* (function names, handlers, templates) create a remote-dispatch primitive: an attacker who can emit socket messages executes named client code with attacker arguments.
6. **Cross-reference the AVideo batch pages.** This batch extends the [2026-05-09 AVideo session/CSRF/SQL/race page](2026-05-09-avideo-session-csrf-sql-and-race-boundary-batch-ghsa.md) (session fixation, admin JSON CSRF, wallet TOCTOU, RTMP SQLi, ReceiveImage traversal) and the [2026-05-15 AVideo auth/SSRF/command/transport page](2026-05-15-avideo-auth-ssrf-command-and-transport-boundary-batch-ghsa.md) (SSRF out-param discard, 2FA-toggle CSRF, Meet filename impersonation, `on_publish` command injection). The recurring theme: AVideo puts state-changing and filesystem-touching endpoints behind different, weaker assumptions per route.

## Replayable validation boundaries

All checks use a disposable AVideo install in a lab, synthetic accounts, marker files, and owned no-content peers. Stop at decision points; do not write real files outside the scratch root, do not hijack real sessions, and do not brute-force real accounts.

1. **Notify-code replay.** Record one legitimately issued `notifyCode` (e.g., from a lab RTMP publish), then POST it to `notify.ffmpeg.json.php` with a synthetic `avideoRelativePath` pointing at a scratch marker path *outside* the media tree. A positive is the server accepting the replayed code and attempting the write; confirm the denial/acceptance decision at the sink. Do not write application root files.
2. **Views-info record shape.** Call the `videoViewsInfo` endpoints with a synthetic valid-shaped `hash`. A positive is the response containing user-record fields (hash/recovery/session fields present in the response schema). Record the field list; do not exfiltrate or reuse live sessions.
3. **UA-gated limiter.** Instrument the lab: fire N login attempts with a normal UA (expect 429/lockout), then repeat with each candidate bot UA. A positive is the lockout never firing under a bot UA while firing under the control UA.
4. **Socket callback dispatch.** With YPTSocket enabled in the lab, connect a synthetic socket client and emit a message whose callback name targets a marker global (a harmless `window.__marker` function you define in the lab page that records the arguments). A positive is the marker firing with attacker-supplied arguments. Do not target real `innerHTML` sinks with script payloads; argument capture at the marker is the proof.
5. **Password key space.** Identify the external-login password generator and hash in the source (lab build). Record the bit length and hash type as the finding; optionally recover the *lab* password offline to confirm crackability. No cracking of production dumps.

## Safety

- Disposable lab AVideo instance only; synthetic users, marker files, lab tokens, owned no-content peers, denied real file/process/network sinks outside the lab.
- No real session hijack, no real account brute-force, no real hash cracking, no writes outside the scratch root, no RCE exploitation on any host.
- Report each primitive at its boundary (acceptance decision, response shape, limiter differential, marker callback firing) without performing the high-impact action on a live deployment.

---

*Source: hourly offensive-security scan, 2026-09-05 (15:30 UTC GitHub advisory wave). Tracked in the [source index](../notes/source-index.md).*
