# CodeIgniter4 upload extension validation boundary

Source: hourly offensive-security scan, 2026-06-11. Primary entry: GitHub advisory [GHSA-2gr4-ppc7-7mhx](https://github.com/advisories/GHSA-2gr4-ppc7-7mhx) / CVE-2026-48062, with upstream advisory [codeigniter4/CodeIgniter4 GHSA-2gr4-ppc7-7mhx](https://github.com/codeigniter4/CodeIgniter4/security/advisories/GHSA-2gr4-ppc7-7mhx).

This is durable for operators because it turns a common upload-validation assumption into a replayable boundary check: framework validation that appears to restrict a filename extension may actually validate a MIME-derived guessed extension, while the application later preserves the client filename in a web-executable upload path.

## What changed

CodeIgniter4's `ext_in` upload validation rule checked the extension guessed from the file's MIME type rather than the extension in the client-provided filename. An upload such as a file named `shell.php` with GIF-like bytes could satisfy a rule chain like:

```text
uploaded[avatar]|is_image[avatar]|mime_in[avatar,image/gif]|ext_in[avatar,gif]
```

The advisory states that applications are impacted when all of these conditions line up:

- user-controlled file uploads are accepted;
- the application relies on `ext_in` to validate the uploaded filename extension;
- the application saves the upload with the original client filename, for example `$file->move($path)`;
- the destination is web-accessible; and
- the web server executes PHP or another dangerous file type from that destination.

The vulnerable package is `codeigniter4/framework < 4.7.2`; the listed patched version is `4.7.3`.

## Operator triage

1. **Find CodeIgniter4 upload surfaces.** Prioritize profile images, attachments, CMS media, imports, support-ticket files, and admin plugin/theme uploaders.
2. **Confirm the validation chain.** Look for `ext_in[...]`, `mime_in[...]`, `is_image[...]`, and `uploaded[...]` combinations in controllers, request validators, or form-request equivalents.
3. **Check filename preservation.** The important sink is saving with the original client name. `$file->move($path)` without a random safe name is stronger evidence than validation alone.
4. **Map the serving path.** Confirm whether the upload directory is reachable under the web root and whether the server treats `.php`, `.phtml`, or another uploaded extension as executable.
5. **Avoid overclaiming.** Validation bypass is enough for a finding only if the dangerous extension can persist. RCE requires the saved object to be executable through the target's serving stack.

## Replayable validation boundary

Use a lab clone or explicit customer-approved upload canaries. Do not upload a functional shell to production.

1. Prepare a harmless polyglot-style marker file with an executable-looking extension and benign image-like bytes:

    ```bash
    printf 'GIF89a\nSKILLZ-CI-UPLOAD-CANARY\n' > skillz-ci-canary.php
    ```

2. Submit it to the suspected upload field where the application expects `gif` or another image extension.
3. Record whether framework validation accepts the file even though the client filename extension is not in the intended allowlist.
4. If the application preserves the original filename, request only a harmless URL fetch for the uploaded object and capture the server behavior:
    - static download of `skillz-ci-canary.php` proves filename persistence and web reachability;
    - script execution behavior should be tested only in a lab or with a non-executing canary such as a route that prints plain text by design;
    - never deploy a command shell, reverse shell, or credential-reading payload.
5. Compare with a patched or hardened path: randomized stored name, upload directory outside web root, explicit client-extension check, or blocked script execution.

## Evidence to capture

- CodeIgniter4 version and `codeigniter4/framework` package constraint.
- The exact validation rule chain containing `ext_in`.
- The upload request metadata: field name, submitted filename, content type, and benign canary bytes.
- The server-side stored filename or returned media URL.
- Whether the destination is public and whether dangerous extensions execute, download, or are blocked.
- A negative control where a non-image byte sequence fails `mime_in`/`is_image`, showing the bypass is specifically MIME-derived extension acceptance plus filename preservation.

## Report wording

Lead with the crossed boundary:

> The upload workflow validates a MIME-derived extension with CodeIgniter4 `ext_in`, but later stores the client-controlled filename in a public upload path. A file named with a dangerous extension and benign image-like bytes is accepted and persisted under that dangerous extension.

Keep impact conditional. Use **arbitrary file upload / dangerous extension persistence** when execution is not demonstrated. Use **remote code execution** only when the target's approved test environment executes the persisted file as code.

## August 7 follow-up: CodeIgniter 4.7.4 upload, SQL, and proxy boundaries

Four later CodeIgniter4 advisories add distinct final-sink checks. They are grouped here because the useful operator question is not merely whether an application uses CodeIgniter, but whether request metadata survives into a stronger filename, SQL, or transport-security decision.

| Advisory | Affected boundary | Fixed control |
| --- | --- | --- |
| [`GHSA-mmj4-63m4-r6h5`](https://github.com/advisories/GHSA-mmj4-63m4-r6h5) / CVE-2026-63223 | `is_image` or `mime_in` accepts MIME-valid bytes while the client filename retains a disallowed extension | `codeigniter4/framework` 4.7.4 |
| [`GHSA-hhmc-q9hp-r662`](https://github.com/advisories/GHSA-hhmc-q9hp-r662) / CVE-2026-63222 | `UploadedFile::move($targetPath)` uses a client filename as a destination path | `codeigniter4/framework` 4.7.4 sanitizes only the default filename |
| [`GHSA-c9w5-rwh3-7pm9`](https://github.com/advisories/GHSA-c9w5-rwh3-7pm9) / CVE-2026-63221 | `where()` values lose their escape flag when `deleteBatch()` compiles SQL | `codeigniter4/framework` 4.7.4 |
| [`GHSA-7wmf-pw8j-mc78`](https://github.com/advisories/GHSA-7wmf-pw8j-mc78) / CVE-2026-63220 | `X-Forwarded-Proto` or `Front-End-Https` marks an HTTP request secure without binding the header to a trusted proxy peer | `codeigniter4/framework` 4.7.4 |

### 1. Test validation, stored extension, and destination separately

The earlier `ext_in` issue and the new `is_image`/`mime_in` issue converge at the same application preconditions: MIME-valid canary bytes, a dangerous-looking client extension, filename preservation, a public destination, and an executable serving policy. Do not collapse those stages into an RCE claim.

Use the benign GIF marker from the replay above and capture this tuple:

```text
submitted filename | declared MIME | detected MIME | rules passed | stored name | final path | serving behavior
```

For `move()` confinement, use a disposable upload root and a marker-only filename such as `../outside/ci-move-canary.txt`. Instrument or patch the final move sink if possible. A strong proof shows the requested name, normalized destination, and affected-versus-fixed result without writing outside the disposable fixture.

The 4.7.4 patch has an important boundary: it sanitizes the client name when `move()` is called **without** a second argument. Code such as `$file->move($path, $file->getClientName())` still gives the caller-supplied second argument filename authority and needs an independent final-path confinement check.

### 2. Verify the `deleteBatch()` bind at generated SQL

Prioritize call sites where user-controlled filters reach this exact chain:

```php
$builder->setData($rows)
    ->onConstraint(['id' => 'id'])
    ->where('jobs.name', $requestValue)
    ->deleteBatch();
```

Regular `delete()` is a negative control; the advisory concerns additional `where()` conditions on `deleteBatch()`. In a scratch database or patched query recorder, submit an inert quote-bearing marker and compare the generated statement:

```text
affected: WHERE value is substituted as SQL structure
fixed:    WHERE value remains one quoted/escaped literal
```

Do not run destructive predicates against retained data. Seed two disposable rows, wrap execution in a rollback where supported, and report **SQL injection at batch-delete query construction** only when the compiled SQL proves structure changed. A generic error or timing difference is insufficient.

### 3. Bind forwarded HTTPS claims to the immediate peer

Build a decision table from two network paths: the approved reverse proxy and a direct or lab-only backend path. Send no header, `X-Forwarded-Proto: https`, and `Front-End-Https: on`; then record `REMOTE_ADDR`, configured `proxyIPs`, `isSecure()`, redirect behavior, and any security-sensitive branch.

```text
peer          | forwarded claim       | expected secure decision
trusted proxy | https / on             | true
untrusted peer| https / on             | false
either peer   | absent or http / off   | false unless the transport itself is TLS
```

Header spoofing alone is not a high-impact finding. Establish a downstream effect such as bypassing an HTTPS-only route guard, changing an absolute callback scheme, or issuing a cookie with materially different attributes. Keep proofs to disposable sessions and inert routes; never collect another user's cookie or weaken a production proxy.

### Follow-up evidence and report boundaries

- Record the exact CodeIgniter package version and call-site method, not only a framework fingerprint.
- Preserve submitted filename, framework-derived metadata, and the final normalized destination as separate fields.
- For SQL, attach generated-query or query-recorder evidence with synthetic values and redact credentials.
- For proxy trust, include the TCP peer, trusted-proxy configuration, raw headers, and final `isSecure()` decision.
- Do not claim arbitrary file execution from path control, database compromise from a parser error, or authentication bypass from a changed secure-transport boolean without proving the next application-owned sink.

## Notes on skipped adjacent items

The same scan rechecked Disclosed, PortSwigger, Trail of Bits, ProjectDiscovery, GitHub advisory published/updated feeds, and CISA KEV. The Kolibri, Hapi inert, Keycloak, Flowise, and Arc advisories were already promoted in the adjacent 2026-06-11 batch. Newly visible GitHub items that were availability-only, duplicate of existing coverage, or lacked a stronger reusable offensive validation boundary were tracked but not promoted.
