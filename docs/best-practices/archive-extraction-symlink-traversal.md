# Archive extraction: prevent path traversal + symlink escapes

Archive extraction is a common supply-chain and scanning surface (tar/zip/deb/rpm). A frequent failure mode is allowing paths or symlinks that escape the intended extraction directory.

## Threat model

An attacker provides an archive that, when extracted, causes:

- writes outside the target directory via `../` traversal or absolute paths
- writes outside the target directory via symlinks (create symlink inside dir → write through it)
- overwriting sensitive files (cron, SSH keys, config) when running as a privileged user

This matters even for “just scanning” workflows: if your scanner extracts untrusted archives, it’s part of your attack surface.

## Defensive extraction rules (portable)

### 1) Canonicalize and validate every member path

Reject entries when any of the following are true:

- path is absolute (`/etc/passwd`, `C:\\Windows\\...`)
- path contains `..` segments after normalization
- normalized path does not stay under the extraction root

### 2) Handle symlinks explicitly (don’t trust defaults)

- If you don’t need symlinks: **do not create them** (treat as suspicious and skip).
- If you allow symlinks:
  - validate the symlink *location* is within the root
  - validate the symlink *target* resolves within the root
  - on write operations, ensure you’re not writing through a symlink (use `O_NOFOLLOW` where available)

### 3) Prefer “openat-style” safe extraction

Where supported:

- open the root directory FD
- for each path segment, use `openat()` / `mkdirat()` with `O_NOFOLLOW`
- never follow symlinks while traversing

This avoids TOCTOU races and is far more robust than string checks.

### 4) Run extraction in a sandbox

Even with safe extraction, reduce blast radius:

- run as an unprivileged user
- extract into a temp directory on a dedicated filesystem
- consider container / namespace isolation (especially in CI)

## Quick regression tests

Include archives that attempt:

- `../../escape.txt`
- `/etc/cron.d/pwn`
- create `subdir/link -> ../../..` then write `subdir/link/escape`

Your extractor should either reject them or extract safely without writing outside root.

## GNU tar hardlink and restore-race operator matrix

Two August 2026 GNU tar records show why a `../`-only archive test is incomplete:

- [GHSA-4f5j-wqjr-hx49 / CVE-2026-18508](https://github.com/advisories/GHSA-4f5j-wqjr-hx49) describes a `--one-top-level` hardlink target resolving relative to the extraction working directory and composing with a pre-existing symlink; and
- [GHSA-v7fx-gjvh-347c / CVE-2026-18477](https://github.com/advisories/GHSA-v7fx-gjvh-347c) describes a TOCTOU condition in incremental `dumpdir` rename restoration where an actor able to modify the restored directory can influence later creates, renames, or overwrites outside the intended root.

Use a disposable mount namespace or temporary filesystem containing only random marker files. Record syscalls and canonical paths; never target an operational backup, restore host, home directory, or privileged path.

| Case | Controlled change | Evidence to capture |
| --- | --- | --- |
| ordinary file | regular member below a new `--one-top-level` root | expected `openat`/write remains below root |
| hardlink baseline | hardlink to an earlier in-root regular member | link source and destination remain below root |
| hardlink authority | hardlink target interpreted relative to extraction CWD | lexical target, effective CWD, canonical source/destination |
| pre-existing symlink composition | one disposable CWD component points to a sibling canary directory | `lstat`, `readlink`, and attempted link/write path; abort before replacing the canary |
| incremental rename baseline | fixed dumpdir metadata with no concurrent mutation | rename sequence stays below root |
| rename race | helper swaps only a random disposable directory component at a synchronization barrier | inode/dev before check and use, rename/open destination, escaped-path decision |
| corrected build | replay the identical archive and schedule | outside-root operations are rejected |

For the race case, use a deterministic interposer or debugger barrier rather than an unbounded timing loop. Patch or deny the final outside-root `renameat`, `linkat`, or open syscall while still recording its arguments. A safe positive is **approved extraction root -> hardlink/rename state resolves through a changed or CWD-relative component -> syscall recorder observes a canonical destination at the sibling canary**. Do not require an actual overwrite.

Keep the preconditions distinct. CVE-2026-18508 requires archive-controlled hardlink metadata plus relevant pre-existing filesystem state. CVE-2026-18477 concerns incremental restore state and an actor able to modify the restore tree at the required time; it does not require a crafted archive. Report exactly which primitive and environmental authority were proven.

## References

- GitHub Advisory example: `malcontent` symlink path traversal due to argument confusion + missing symlink validation (CVE-2026-24846)
- GNU tar `--one-top-level` hardlink boundary: https://github.com/advisories/GHSA-4f5j-wqjr-hx49
- GNU tar incremental restore TOCTOU boundary: https://github.com/advisories/GHSA-v7fx-gjvh-347c
