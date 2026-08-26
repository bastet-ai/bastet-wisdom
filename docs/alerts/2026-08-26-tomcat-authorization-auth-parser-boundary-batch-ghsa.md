# Apache Tomcat authorization, auth, and parser-boundary batch (2026-08-26)

Source: GitHub Security Advisories published feed, 2026-08-26 hourly scan. Apache Tomcat disclosed a cluster of advisories all fixed by the same patch train (`11.0.25`, `10.1.58`, `9.0.121`). These are durable because several are reusable *authorization / authentication boundary* patterns — exactly the class of bug a red-team or bug-hunter actively looks for in servlet containers — and because two of them are chained "incomplete fix" items that chain a long version saga.

Affected lines are broadly `11.0.0-M1`/`10.1.0-M1`/`9.0.0-M1` through the last-but-one release of each line; EOL lines (`8.5.x`, `7.0.x`) are explicitly affected on most items. Upgrade to `11.0.25` / `10.1.58` / `9.0.121` to clear the whole cluster.

## What changed

- **`GHSA-gcx9-497g-6cp6` / [CVE-2026-65182](https://nvd.nist.gov/vuln/detail/CVE-2026-65182) — security-constraint bypass via constraint ordering.** An improper access-control / incorrect-authorization flaw lets a security constraint be bypassed when a constraint for a *longer* path is specified before a more restrictive constraint for a *shorter* sub-path. Order-dependent constraint resolution is a classic, reusable bypass heuristic.
- **`GHSA-5q6q-ffrq-6xfc` / [CVE-2026-68569](https://nvd.nist.gov/vuln/detail/CVE-2026-68569) — improper authentication against `DataSourceRealm`.** In some circumstances (e.g. `CLIENT-CERT`, `SPNEGO`) a user is authenticated even when the user does not exist in the `DataSourceRealm`. An authentication path that succeeds without a realm principal is a high-signal finding.
- **`GHSA-h3x4-894j-xpx5` / [CVE-2026-68525](https://nvd.nist.gov/vuln/detail/CVE-2026-68525) — FORM-auth constraint bypass.** The FORM authentication process allows bypassing a security constraint that grants a user `POST` but not `GET` on a resource. Method-scoped constraint bypass.
- **`GHSA-w3xg-786f-g788` / [CVE-2026-66422](https://nvd.nist.gov/vuln/detail/CVE-2026-66422) — `security-role-ref` used as a role alias in the Realm.** Improper authorization caused by `security-role-ref` definitions being incorrectly used as role aliases inside the Realm, in addition to their correct use with `Request.isUserInRole()`. Role-name aliasing leaking into the Realm is a reusable authorization-testing pattern.
- **`GHSA-9xv2-5v5q-p794` / [CVE-2026-65905](https://nvd.nist.gov/vuln/detail/CVE-2026-65905) — DIGEST authenticator capture-replay.** Authentication bypass by capture-replay in the DIGEST authenticator: before `windowSize` requests have been made, a client that sends a DIGEST request with a `nonceCount` on the upper boundary of the replay window makes that request replayable once while the `nonceCount` remains within the window.
- **`GHSA-wrvx-pxxf-g8fg` / [CVE-2026-73180](https://nvd.nist.gov/vuln/detail/CVE-2026-73180) — WebSocket session outlives the HTTP session.** Insufficient session expiration: if the authenticated HTTP session ID is changed after a WebSocket connection has been established under that session, the WebSocket session is not closed as required by the Jakarta WebSocket spec when the HTTP session ends. A durable live channel that escapes session teardown.
- **`GHSA-h3mr-2w3q-jcv9` / [CVE-2026-65183](https://nvd.nist.gov/vuln/detail/CVE-2026-65183) — TOCTOU on Unix domain socket creation.** A time-of-check/time-of-use race when creating Unix domain sockets allows an unauthorised *local* user to access the socket. Local, not remote.
- **`GHSA-g8qj-vp23-742m` / [CVE-2026-65927](https://nvd.nist.gov/vuln/detail/CVE-2026-65927) — off-by-one in rewrite `[N]` flag.** Off-by-one on the `[N]` flag of the rewrite valves causes rewrite processing to restart at the second rule rather than the first rule. Rewrite-rule re-entry differential.
- **`GHSA-82jr-6mfr-9vq5` / [CVE-2026-68763](https://nvd.nist.gov/vuln/detail/CVE-2026-68763) — HTTP/2 backlog allocation leak.** Uncontrolled resource consumption via an allocation leak in HTTP/2 backlog tracking when a stream is reset.
- **`GHSA-f525-44xv-f2qj` / [CVE-2026-65637](https://nvd.nist.gov/vuln/detail/CVE-2026-65637) — incomplete fix for CVE-2026-32990.** Improper input validation, an incomplete fix for [CVE-2026-32990](https://nvd.nist.gov/vuln/detail/CVE-2026-32990), which itself was an incomplete fix for [CVE-2025-66614](https://nvd.nist.gov/vuln/detail/CVE-2025-66614). This is a chained incomplete-fix saga across three releases.

## Operator triage

1. **Version fingerprint first.** Tomcat version is trivially fingerprintable (server headers, error pages, `/` defaults, and `JSESSIONID`/cookie shape). Anything below `11.0.25` / `10.1.58` / `9.0.121` is in range for the whole cluster; EOL lines are in range for most items.
2. **Prioritize by blast radius and reach.**
   - *Remote, unauthenticated / low-auth, high-impact:* the security-constraint ordering bypass (65182), the `DataSourceRealm` improper authentication (68569), the FORM POST/GET method bypass (68525), and the `security-role-ref` Realm aliasing (66422). These are the ones that can be reached over the network against a running web app.
   - *Stateful / channel:* the DIGEST capture-replay (65905) and the WebSocket-escapes-session (73180) require understanding the deployed auth scheme and whether WebSockets are in use.
   - *Local / availability:* the Unix-socket TOCTOU (65183) is a local, post-adjacency primitive; the HTTP/2 backlog leak (68763) and the rewrite off-by-one (65927) are availability/behaviour differentials.
3. **The incomplete-fix saga is the reporting hook.** 65637 -> 32990 -> 2025-66614 is a three-deep incomplete-fix chain; when you confirm one, the others on the same line are likely co-present and belong in the same report.

## Replayable validation boundaries

Validate on an authorized lab Tomcat (a disposable `catalina` with a minimal webapp, a `Realm` you control, and a `security-role-ref`-annotated EJB/servlet), never against production. Use synthetic users and canary routes only; do not read real session data, real realm principals, or exfiltrate live credentials.

### Constraint-ordering bypass (65182)
- Define two constraints where the longer path is declared before the more restrictive shorter sub-path, and a route protected only by the shorter, more restrictive constraint.
- Request the shorter, protected sub-path. The vulnerable result is 200 where the shorter constraint should have forced 401/403. Record the exact `web.xml` constraint order, the request URI, and the status on both the affected and the patched build.

### `DataSourceRealm` improper authentication (68569)
- Configure `CLIENT-CERT` or `SPNEGO` with a `DataSourceRealm` and a principal that does **not** exist in the realm table.
- Present a synthetic certificate / SPNEGO token mapping to that absent principal. The vulnerable result is successful authentication for a user that has no realm row. Record the authentication decision and the realm lookup on both builds. Use a self-signed test cert / fake Kerberos ticket; never capture a live token.

### FORM POST/GET method bypass (68525)
- Set a security constraint that grants a role `POST` but not `GET` on a resource.
- As that role, issue a `GET` for the resource. The vulnerable result is 200 on `GET`; the secure result is 403. Record the constraint, the role, the method, and the status.

### `security-role-ref` Realm aliasing (66422)
- Give two logical roles the same name surface via `security-role-ref` and confirm via `Request.isUserInRole()` on a probe servlet whether the Realm honours the alias. The vulnerable result is a positive `isUserInRole` for a role the principal was not granted. Record the probe request and the boolean on both builds.

### DIGEST capture-replay (65905)
- Against a lab DIGEST-authenticated endpoint, drive the nonce counter to the upper boundary of the replay window and capture one valid request. Replay it once within the window. The vulnerable result is acceptance of the replayed request. Keep the nonce/`windowSize` values, the capture, and the replay status in the report; do not replay against production endpoints or harvest real nonces.

### WebSocket-escapes-session (73180)
- Open a WebSocket under an authenticated HTTP session, then change/invalidate the HTTP session ID. Check whether the WebSocket stays connected after the HTTP session ends. The vulnerable result is a still-open channel after session teardown. Use a synthetic session; do not read or retain real session state.

## Reporting heuristics

- Group the cluster as one version-train finding ("Tomcat `< 11.0.25 / 10.1.58 / 9.0.121` cluster") and call out each CVE's distinct boundary (constraint ordering, realm auth, method scoping, role aliasing, replay, channel persistence, socket TOCTOU, rewrite re-entry, HTTP/2 leak).
- Lead with the remote-reachable, high-impact authorization items (65182, 68569, 68525, 66422) and the incomplete-fix chain (65637 -> 32990 -> 2025-66614), which is the strongest escalation hook.
- For each: record the exact `web.xml`/Realm/valve configuration, the request, the expected vs actual status/decision, and the version before/after.
- Distinguish reachable-remotely from local (65183) and from availability (68763) so severity mapping is honest.

## Safety

- **Authorized lab only.** Run a disposable `catalina` with a minimal webapp and a Realm you own; never validate against a production container or a shared staging host.
- **Synthetic principals only.** Use synthetic users, self-signed test certs, and fake Kerberos tickets; never capture, replay, or retain real session data, real realm principals, or live credentials.
- **No destructive state changes.** Do not mutate a live realm, real users, or production `web.xml`; all constraint/realm changes happen on the lab copy.
- **Availability items last.** The HTTP/2 leak and rewrite off-by-one are availability differentials; confirm them with bounded, low-volume traffic against the lab instance only.
