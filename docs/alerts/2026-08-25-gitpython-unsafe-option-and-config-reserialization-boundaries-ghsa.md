# GitPython unsafe-option, config-reserialization, and merge-include boundaries

Source: GitHub Security Advisories `unreviewed` feed, 2026-08-25 (all first published 2026-08-25): [GHSA-9557-234j-7rv9](https://github.com/advisories/GHSA-9557-234j-7rv9) (config multi-line write reserialization, critical 9.8), [GHSA-crmc-f4m7-33fj](https://github.com/advisories/GHSA-crmc-f4m7-33fj) (`.gitmodules` merge-includes file disclosure, high 8.4), [GHSA-7r39-6q8m-qw68](https://github.com/advisories/GHSA-7r39-6q8m-qw68) (`--separate-git-dir` clone redirect, high 7.5), [GHSA-89ff-m8wv-p99r](https://github.com/advisories/GHSA-89ff-m8wv-p99r) (`blame` `--contents`/`-S` file read, high 6.5), and [GHSA-6rj2-96f5-chj9](https://github.com/advisories/GHSA-6rj2-96f5-chj9) (`TagReference.create` `--file` file read, high 6.5). All affect `GitPython` before `3.1.59`.

This wave is durable because it exposes a reusable pattern: a Python wrapper around the `git` CLI builds an argv list from caller-controlled fields (revision strings, tag refs, clone target dir, config values, submodule files) and a denylist of "unsafe" leading-dash options is incomplete or is bypassed by a secondary code path. When a library accepts a repository it does not own — a clone target, a submodule `.gitmodules`, a packed `config`, a blame ref — an attacker who controls that repository content can inject git options that read files, write directories, or arm a later code-execution hook. The same boundary recurs across every wrapper around `git` (Go `go-git`, `dulwich`, `libgit2` bindings, CI job specs), so the check generalizes.

!!! warning "Canaries only"
    Run these checks against disposable local repositories and a scratch filesystem root. Use marker files, inert hooks, and a denied hook-execution sink. Never read credentials, shell startup files, cloud metadata, or real repo internals, and never execute an attacker-injected `core.hooksPath` payload on a shared host.

## Boundary map

| Surface | Caller-controlled value | Privileged transition | Safe positive |
| --- | --- | --- | --- |
| `Repo.blame` | revision string with `--contents=` / `-S` | library passes it to `git blame` and returns the result | mocked git records a denied `--contents` option; no outside-root file is read |
| `TagReference.create` | positional reference with `--file=` | library passes it to `git tag`/`git cat-file` | mocked git records a denied `--file`; tag message is a fixed canary |
| `Repo.clone_from` / `clone` | `separate_git_dir` argument | library adds `--separate-git-dir` outside the intended clone root | clone sink creates metadata only inside the disposable root |
| `config` write | multi-line value with embedded newline | reserialization turns a dormant quoted value into a live `core.hooksPath` directive | written config is re-parsed and the injected directive is absent or inert |
| `.gitmodules` | `[include]` directive pointing at a file | parser raises an error that embeds the target's first line | include is disabled; the raised error contains no outside-root content |

Prove the option-acceptance edge and the final sink separately. A leading-dash value that is merely accepted by the library is not enough; preserve the argv the library would hand to `git`, the resolved target file or directory, and the returned marker.

## Git option injection via library argv

The recurring primitive is that a field the library treats as "just a value" can carry a git option because it is concatenated into argv without the leading-dash guard.

1. Stand up a disposable repository and an instrumented `git` shim on `PATH` that records argv and returns a fixed marker instead of touching the real repo.
2. Drive each library entry point with an ordinary value, then with one option-shaped marker:
   - `Repo.blame(rev="--contents=<marker>")` and `blame(..., -S shaped)`;
   - `TagReference.create(repo, "--file=<marker>")`;
   - `Repo.clone_from(url, target, separate_git_dir=<outside-root-marker>)`.
3. Record, for each, the exact argv, whether the unsafe option survived the library's denylist, and the file/directory the option would resolve to.

| Input class | Expected secure result |
| --- | --- |
| ordinary ref/path | passed through as a single value, no option |
| `--contents`/`-S`/`--file`/`--separate-git-dir` marker | rejected, quoted, or resolved inside the declared root |
| leading-dash control character | never forwarded as a separate argv token |

The strongest evidence is a denied argv showing the marker token was stripped or contained, paired with a fixed-version control where the same input is accepted. Do not point `--contents` at `/etc` or credentials; use a sibling marker file inside the disposable root.

## `--separate-git-dir` clone redirect

`--separate-git-dir` is dangerous because it relocates repository metadata (including `hooks/`) to an attacker-chosen path. In a lab:

1. Configure the clone destination inside a disposable root and pass a `separate_git_dir` that escapes it.
2. Record the destination git-dir the library computes and whether it lands outside the root.
3. If the metadata path is outside the root, stop at the recorder — do **not** populate or run hooks there.

A bounded positive is the computed git-dir escaping the disposable root. Report the directory-redirection primitive and note that hook execution is the downstream risk only if the attacker also controls the metadata tree; do not claim RCE without a separate authorized inert sink proving hook invocation.

## Config multi-line write reserialization to hook execution

This is the highest-impact item. `git config` stores multi-line values as indented continuation lines; a library that re-serializes a value by naively re-emitting it can turn a *dormant* quoted value into a live directive.

1. Seed a repository `config` with a value that contains an embedded newline and a quoted `core.hooksPath` segment, using a disposable hooks directory marker.
2. Invoke an *unrelated* GitPython config write (any key, any value) through the affected API.
3. Re-read the written `config` and confirm whether the embedded newline survived as a real separator that activates `core.hooksPath`.

| Control | Expected secure result |
| --- | --- |
| single-line value | round-trips unchanged |
| multi-line value with directive | re-serialized so the directive stays quoted/inert |

The bounded positive is the written file containing a live `core.hooksPath` pointing at the disposable marker after an unrelated write. **Do not run the hook.** Prove the reserialization drift with the file content and a denied hook-execution recorder; execution of an attacker path on a shared host is out of scope.

## `.gitmodules` merge-includes disclosure

`git` merges `[include]` sections from submodule configs by default; a library that parses `.gitmodules` without disabling `merge_includes` will read the included file and can echo part of it in an error.

1. Plant a `.gitmodules` containing an `[include]` directive that points at a sibling marker file inside the disposable root.
2. Access `repo.submodules` (or the equivalent submodule-enum API) and capture the raised `MissingSectionHeaderError`.
3. Check whether the exception message embeds the marker's first line.

A positive is the outside-root (or sibling) marker content appearing in the error string. Report the include-disclosure primitive with the directive and the embedded line; never include the contents of a real sensitive file in the report.

## Reporting heuristics

- Frame each finding around the specific library entry point and the argv it would hand to `git`: "GitPython `Repo.blame` forwards `--contents` from a caller-controlled revision to the git CLI."
- Separate the primitive (file read / directory redirect / config injection) from the impact (disclosure / hook execution). Only the config-reserialization item reaches a plausible code-execution path, and only via a later hook invocation that must be proven independently.
- Cite the version bound (`< 3.1.59`) and note that all five are mitigated by a complete unsafe-option denylist plus disabling `merge_includes` on submodule config parsing.

## Safety

- Authorized, in-scope targets only; these wrappers frequently run in CI/CD and build agents where the "attacker-controlled repo" is a cloned dependency.
- Use instrumented git shims and denied sinks so the check records intent without touching real files or executing hooks.
- No credential, shell-startup, or cloud-metadata reads; marker files only inside a disposable root.
- Do not run injected `core.hooksPath` payloads or `--separate-git-dir` hooks on shared or production hosts.

## Reviewed but not promoted here

The adjacent GitPython CVE records in the same wave have no separate operator surface beyond the five boundaries above and are tracked in the source index.
