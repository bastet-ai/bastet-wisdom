# Grav sandbox-escape, privilege-validation, and host/origin trust boundaries

Source: GitHub Security Advisories `unreviewed` feed, 2026-08-25 (all first published 2026-08-25): [GHSA-3625-697m-q29v](https://github.com/advisories/GHSA-3625-697m-q29v) (Email plugin unsandboxed Twig → OS command, high 8.8), [GHSA-crrc-vpp2-f5x7](https://github.com/advisories/GHSA-crrc-vpp2-f5x7) and [GHSA-mw85-cjh9-8hp7](https://github.com/advisories/GHSA-mw85-cjh9-8hp7) (Twig sandbox config-secret read, high 7.5 / 6.5), [GHSA-8vp7-8q4w-vv7m](https://github.com/advisories/GHSA-8vp7-8q4w-vv7m) (`offsetGet`/`offsetexists` User-field read, high 6.5), [GHSA-qw9m-fc79-372g](https://github.com/advisories/GHSA-qw9m-fc79-372g) (login unlock handler missing privilege check, critical 9.8), [GHSA-92vc-67q9-382j](https://github.com/advisories/GHSA-92vc-67q9-382j) and [GHSA-px9v-979x-qmh9](https://github.com/advisories/GHSA-px9v-979x-qmh9) (non-constant-time token/nonce compare, high 7.5 / medium 3.7), [GHSA-55hc-4r2f-h6wr](https://github.com/advisories/GHSA-55hc-4r2f-h6wr) (email enumeration, critical 5.3), [GHSA-qh7h-6c7g-x8m6](https://github.com/advisories/GHSA-qh7h-6c7g-x8m6) (unanchored `Referer` prefix origin bypass, critical 5.4), [GHSA-6c2c-797q-5r9x](https://github.com/advisories/GHSA-6c2c-797q-5r9x) (`sendInvitationEmail` untrusted `Host`, high 7.5), [GHSA-896w-cw95-xq7w](https://github.com/advisories/GHSA-896w-cw95-xq7w) (`deleteFile` path traversal, high 8.1), [GHSA-cpcf-vm8j-257x](https://github.com/advisories/GHSA-cpcf-vm8j-257x) (scheduler lock-file symlink, high 8.4), [GHSA-h2w4-jr6m-7c52](https://github.com/advisories/GHSA-h2w4-jr6m-7c52) (webhook DNS-rebinding SSRF, medium 5.3), and [GHSA-f549-r4pw-jw3m](https://github.com/advisories/GHSA-f549-r4pw-jw3m) (Flex Objects shortcode authorization bypass, high 7.7). Core Grav affects `2.0.16`/`3.9.2`, Login plugin `3.9.1`/`1.0.16`, Email plugin `4.2.2`, API plugin `1.0.16`, Flex Objects `1.4.0–1.4.7`.

Grav is a flat-file CMS whose page model lets content editors render Twig. This wave is durable because it concentrates a reusable set of editor-to-authority boundaries: page-editor content crossing into unsandboxed Twig evaluation, a sandbox denylist that misses config/user fields, an API row-action that omits a privilege check, and host/origin validation that trusts untrusted headers. The "editor can render a template but the template is not sandboxed" chain (Email plugin) and the "sandbox allowlist method leaks a sensitive object" chain (`offsetGet`) are the same trust-confusion family that recurs in any CMS that exposes a template engine to non-admin editors.

!!! warning "Canaries only"
    Run these checks in a disposable Grav install with synthetic users, marker files, and owned no-content peers. Use denied command/file/network sinks. Never execute a real OS command, read or delete real files, enumerate real user accounts, exfiltrate config secrets, or reach internal services.

## Boundary map

| Surface | Caller-controlled value | Privileged transition | Safe positive |
| --- | --- | --- | --- |
| Email plugin form field | Twig expression in `email.body` | page-editor content evaluated **unsandboxed** as OS command | expression is sandboxed or not evaluated; canary command is denied |
| Twig sandbox | `config.get`/`config.toArray`, `offsetGet`, dot-notation arrays | page-editor reads config/user secrets | denied paths + filtered methods block the read |
| login unlock row-action | `api.users.write` session | clears lockout on `admin.super` without privilege check | target-account privilege validated |
| `Referer`/`Host` header | attacker `Referer`/`Host` prefixing the site | origin/redirect validation treated as same-origin | anchored + scheme/port-anchored validation |
| `deleteFile` | `../`-shaped media filename | authenticated delete escapes media root | path confined to media root |
| lock-file create | pre-placed symlink at predictable temp path | scheduler overwrites an arbitrary writable file | target validated / symlink rejected |
| webhook hostname | attacker-controlled DNS | rebinding passes public validation, reaches private delivery | re-validate final resolved peer |

## Email plugin unsandboxed-Twig command execution

The most severe item. The Email plugin renders page-editor-controlled form `process.email.body` as a **non-sandboxed** Twig template. A user with only `api.access` + `api.pages.write` can place a Twig OS-command expression, publish the page, and submit the form to run a command as the PHP account.

1. In a disposable Grav with the Email plugin, create a page with a form whose `process.email.body` is a harmless Twig marker (e.g. one that would print a canary).
2. Publish and submit as a low-priv editor.
3. Record whether the expression is evaluated in a sandbox or as arbitrary Twig with full function access.

| Input | Expected secure result |
| --- | --- |
| ordinary text body | rendered, no evaluation |
| `{{ ... }}` expression | sandboxed to a denied allowlist; no OS/`system`/process access |

A bounded positive is the expression reaching an unsandboxed evaluation path that *would* reach a process sink. **Do not run a real command.** Prove the sandbox is absent with the recorded evaluation path and a denied command sink; execution is the downstream risk, reported as such without a live payload.

## Sandbox allowlist leaks: config and user fields

Three related leaks show an incomplete sandbox denylist:

- **Config secrets** — `config.get()` / `config.toArray()` (and dot-notation array access) return `system.cache.redis.password`-style values when `config_access` is enabled; `config_denied_paths` is bypassed by dot notation.
- **User fields** — allow-listed `offsetGet()`/`offsetexists()` on `User` objects lack field filtering, exposing hashed passwords and 2FA secrets to any page editor.

Test each with a synthetic user and a config containing only fake canary values:

| Probe | Expected secure result |
| --- | --- |
| `config.get('system.cache.redis.password')` | denied path; no value returned |
| `config.toArray()` | filtered arrays, no secrets |
| `user.offsetGet('password')` / `offsetGet('two_factor')` | field filtered out |

A positive is a canary config value or a synthetic user's marker password/2FA field appearing in rendered output. Report the specific allow-listed method and the missing field filter; never capture a real credential.

## Login unlock handler privilege gap

`onApiUserListRowAction` (unlock) with `api.users.write` clears login lockout counters on `admin.super` accounts without validating the target account's privilege. In a lab: as a low-priv user, clear the lockout on a synthetic admin account and record whether the highest-privilege account's brute-force protection is removed. A positive is the `admin.super` lockout cleared by a lower-privilege principal. Report the missing target-privilege check; do not target real accounts.

## Host/origin validation trust confusion

- **Unanchored `Referer` prefix match** — `Uri::referrer()`/`Pages::referrerRoute()` use `str_starts_with($referrer, $base)` with no trailing delimiter, so `https://example.com.attacker.tld` is treated as same-origin. Test with an owned domain that prefixes the victim origin and record the origin decision. A positive is the attacker origin passing the same-origin check.
- **`sendInvitationEmail` untrusted `Host`** — invitation links are built from the unvalidated `Host` header; `require_trusted_host` only guards password reset. Manipulate `Host` and record the resulting token-bearing link target. A positive is the invitation link pointing to the attacker-controlled host.
- **Email enumeration** — `register()` throws a distinct `EMAIL_NOT_AVAILABLE` for existing addresses with no rate limit. Note this as an enumeration primitive; do not enumerate real accounts, only confirm the differential response on synthetic data.

## File/symlink sinks

- **`MediaUploadTrait::deleteFile` traversal** — only the basename is validated; `../` in the directory portion reaches `unlink()`. Use a sibling marker file in a scratch root and record whether it is deleted.
- **Scheduler `createLockFile` symlink** — a pre-placed symlink at the predictable, world-writable temp lock path can be followed to overwrite an arbitrary writable file. Place a symlink to a scratch marker and record whether the scheduler writes through it. Stop at the denied `write`/`unlink`/ownership syscall against the sibling canary; do not target real files.

## Webhook DNS-rebinding SSRF

The Grav API plugin validates the configured webhook hostname with one lookup and delivers with another. Use two owned DNS answers (public for validation, private for delivery) and record the validation peer vs the delivery peer. A bounded positive is validation on an owned public peer while delivery reaches an owned private/loopback peer. Never reach cloud metadata, loopback admin routes, or internal services.

## Reporting heuristics

- Frame the Email item as "Grav Email plugin evaluates page-editor form fields as unsandboxed Twig," citing the low-priv capability set and the process sink.
- Keep the sandbox-leak items scoped to the specific allow-listed method and the missing field/denied-path filter, with a synthetic canary.
- For the host/origin items, cite the exact comparison (`str_starts_with` without delimiter, unvalidated `Host`) and the route it gates.
- Cite the per-plugin version bounds; the core CMS fixes land in `2.0.16`/`3.9.2`, plugins in their own lines.

## Safety

- Authorized, in-scope targets only; Grav sites are commonly shared hosting where "editor" may mean any content author.
- Synthetic users, fake config canaries, marker files, and owned no-content peers; denied command/file/network sinks.
- No real command execution, no real file read/delete, no real account enumeration, no config-secret exfiltration, no internal/metadata reach.
- Report the primitive at each boundary without performing the high-impact action on a live host.

## Reviewed but not promoted here

All six remaining Grav records in this wave (the second timing/nonce item, the two duplicate config-secret records, and the Flex Objects shortcode authorization bypass) are covered by the boundary map above and tracked in the source index.
