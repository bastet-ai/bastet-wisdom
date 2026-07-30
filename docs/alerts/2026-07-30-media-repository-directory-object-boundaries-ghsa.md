---
title: Media, repository, directory-query, and object-association boundaries
---

# Media, repository, directory-query, and object-association boundaries

A July 30 advisory wave yields five durable operator workflows: uploaded media can select unsafe native-library operations; a repository locator can cross into shell command construction; LDAP attribute/filter syntax can be evaluated with unintended authority; and a child-object update can attach itself to an unauthorized parent.

Sources:

- [Rails Active Storage GHSA-xr9x-r78c-5hrm / CVE-2026-66066](https://github.com/advisories/GHSA-xr9x-r78c-5hrm): default libvips-backed variant processing did not disable operations marked unfuzzed, allowing crafted uploads to cross into file disclosure under the application process identity;
- [degit GHSA-77c7-pq4r-6mcq / CVE-2026-11572](https://github.com/advisories/GHSA-77c7-pq4r-6mcq): repository names reached `exec()`-based Git command construction in `_cloneWithGit()` and `fetchRefs()`;
- [Samba AD DC GHSA-fcqv-6jgj-4xxc / CVE-2026-58222](https://github.com/advisories/GHSA-fcqv-6jgj-4xxc): LDAP Compare attribute names could alter an internal trusted-context search and bypass normal attribute ACLs;
- [Apache Zeppelin GHSA-8cjf-mhhj-2c5p / CVE-2026-44616](https://github.com/advisories/GHSA-8cjf-mhhj-2c5p) and [GHSA-853r-vxg2-55r2 / CVE-2026-44617](https://github.com/advisories/GHSA-853r-vxg2-55r2): user and role lookup filters failed to use RFC 4515 filter-value escaping, including an incomplete fix that used RFC 4514 distinguished-name escaping instead; and
- [Apache Superset GHSA-m2w6-cg52-6hhj / CVE-2026-23981](https://github.com/advisories/GHSA-m2w6-cg52-6hhj): a user allowed to update a chart could supply dashboard IDs without write authorization to those dashboards.

!!! warning "Synthetic labs only"
    Use disposable Rails uploads, a no-shell process recorder, a local directory with synthetic confidential attributes, and two-user Superset fixtures. Never read application environments, credentials, directory authentication material, customer dashboards, or production files; never execute repository-name payloads or derive service-account passwords.

## Boundary matrix

| Surface | Attacker-controlled value | Interpreter or authority transition | Bounded positive |
| --- | --- | --- | --- |
| Active Storage/libvips | uploaded file bytes | trusted media upload selects an unfuzzed loader/operation | instrumented unsafe-operation event or one synthetic canary-file marker |
| degit | repository name/locator | data is concatenated into a shell command | intercepted sink receives tainted metacharacter-shaped input; no process runs |
| Samba LDAP Compare | attribute name and compare value | untrusted syntax reaches a trusted-context internal search | low-role user distinguishes one synthetic ACL-protected attribute |
| Zeppelin LDAP lookup | username/role filter text | DN escaping is mistaken for filter escaping | local LDAP recorder observes changed filter AST and returns one synthetic record |
| Superset chart update | dashboard ID list | chart-write permission is reused as dashboard-write permission | chart association to a foreign synthetic dashboard changes |

Keep acceptance, interpretation, authorization, and impact as separate edges. An upload accepted as an image is not file disclosure; metacharacters reaching a string are not command execution; a changed LDAP filter is not ACL bypass; and a foreign ID accepted in a request is not mutation until server state changes.

## Active Storage upload-to-libvips operation selection

The advisory requires both libvips variant processing (`config.active_storage.variant_processor = :vips`) and image uploads from untrusted users. `load_defaults 7.0` selected libvips, and generating a variant is not listed as a separate application-side precondition. Confirm the exact `activestorage` and libvips builds; the fixed Rails lines require libvips 8.13 or newer so unsafe operations can be disabled.

### Source-instrumented canary workflow

1. Reproduce the storage service, analyzer/previewer configuration, variant processor, libvips version, and asynchronous job path in an isolated Rails instance. Give the process access only to a temporary root containing one random `outside-media-canary.txt`.
2. Establish ordinary PNG/JPEG upload controls and capture every libvips operation selected while the blob is identified, analyzed, previewed, or transformed. Record operation name, whether libvips marks it unfuzzed, input/output paths, and process identity; do not log environment contents.
3. Replace the suspected unsafe operation in a test build with a recorder that returns a fixed marker and cannot open arbitrary paths. Replay a format corpus derived from the application's accepted upload types and the operation registry, not a weaponized public exploit file.
4. If an exact disclosure fixture is independently available under assessment rules, point it only at the synthetic canary and stop after its random marker is returned. Never target `/proc`, environment files, Rails credentials, cloud configuration, home directories, or source trees.
5. Repeat on Active Storage 7.2.3.2, 8.0.5.1, or 8.1.3.1 as applicable, with libvips 8.13 or newer. The fixed control should prevent unfuzzed operation selection.

Strong evidence is **untrusted upload -> Active Storage/libvips selects an operation excluded by the corrected policy -> instrumented recorder fires**, or, where explicitly permitted, **only the disposable canary marker is returned**. Report operation selection and file disclosure as separate claims; do not inflate a policy gap into remote code execution without an independently proven execution sink.

## degit repository locator to process sink

The affected ranges are before 2.8.6 and 3.0.0 before 3.3.1. Reachability depends on an application, bot, build service, or automation path accepting another user's repository name and invoking `_cloneWithGit()` or `fetchRefs()`.

1. Run the exact degit call path in a container with no credentials, network, package tokens, mounted home directory, or host Docker socket.
2. Interpose `child_process.exec` with a recorder that logs a hash and structured taint positions but never invokes a shell. Keep a separate known-good test using `spawn`/`execFile` with a fixed executable and argument array.
3. Submit normal shorthand, full owned-repository URL, branch/ref syntax, whitespace, option-shaped text, and inert shell-metacharacter-shaped strings one dimension at a time. Do not include a command or callback.
4. Capture the original locator, normalization result, selected clone/fetch function, process API, command string or argv, and recorder count.
5. Repeat on 2.8.6 or 3.3.1. A corrected implementation must reject unsafe locator grammar or keep every untrusted component in a non-shell argument boundary.

A bounded positive is **untrusted repository locator -> shell-based process API receives the tainted bytes as command grammar**. The recorder proves sink reachability without executing anything.

## LDAP grammar and authority differentials

Use a local directory with users `alice-canary` and `bob-canary`. Add one ordinary visible attribute and one ACL-protected random attribute to Alice. The protected value must be meaningless test text, not a password, key, hash, gMSA field, or production schema value.

### Samba LDAP Compare

1. Authenticate as Bob with ordinary low privileges and establish that normal search/read and a canonical Compare cannot retrieve or distinguish Alice's protected attribute.
2. Send Compare requests through the affected server path while changing only the attribute-name grammar. Use inert delimiter-shaped names against test schema aliases; do not request real sensitive AD attributes.
3. Instrument the request parser, generated internal filter/search, trusted-context flag, ACL decision, and boolean/error result.
4. Compare malformed attributes, known visible attributes, protected canary attributes, administrator control, and a corrected Samba build.
5. A positive is **low-role Compare input alters internal search structure -> search runs with trusted authority -> the protected synthetic attribute changes the observable result despite the normal ACL denial**.

Do not derive gMSA material, enumerate directory secrets, or claim domain compromise from a parser result.

### Zeppelin RFC 4514 versus RFC 4515

1. Configure the affected `ActiveDirectoryGroupRealm` or `LdapRealm` against the local LDAP recorder. Exercise user-search and post-authentication role lookup separately.
2. Build paired values for RFC 4514 DN-special characters and RFC 4515 filter-special characters. Record the intended literal value, emitted filter bytes, and parsed filter AST on the server.
3. A useful regression control includes the older incomplete-fix line: Zeppelin 0.11.1, 0.11.2, or 0.12.0 should be compared with 0.12.1. Do not assume a DN-escaped string is safe in a search-filter value.
4. Return only a synthetic user or group marker. Capture whether the injected structure broadens, narrows, or changes the result set and whether the application exposes that result.
5. Strong evidence is **user-controlled lookup text -> incorrect escaping changes the LDAP filter AST -> one out-of-scope synthetic directory record or role is returned**.

## Superset child-to-parent association authorization

The record affects Apache Superset before 6.0.0 and requires a user who can update a chart. The reusable question is whether permission on a child object authorizes caller-selected parent associations.

1. Create users A and B, dashboard A owned/writable by A, dashboard B not writable by A, and one chart A may update. Put unique harmless labels on every object.
2. Establish that A cannot edit dashboard B through its direct API/UI route and can update an ordinary chart property without changing associations.
3. As A, update the chart through the REST API while supplying dashboard A, dashboard B, a nonexistent ID, and both IDs in separate fresh fixtures.
4. Capture actor, chart owner/write decision, supplied dashboard IDs, per-dashboard write decisions, response, association rows, and before/after hashes. Restore the association immediately.
5. Repeat as B/admin and on Superset 6.0.0. Test attach, detach, replace, and duplicate IDs independently because authorization can differ by operation.

A positive is **chart-update capability + foreign dashboard ID -> no parent-dashboard write check -> chart becomes associated with the synthetic foreign dashboard**. Do not access dashboard data, alter queries, run datasets, or change production ownership.

## Evidence and reporting

Preserve exact versions and configuration; raw but synthetic inputs; operation, command, LDAP-filter, and authorization traces; object ownership tables; marker hashes; and fixed-version controls. Name only the proven boundary: **upload to unsafe operation**, **repository locator to shell grammar**, **LDAP syntax to trusted search**, **wrong escaping to changed filter AST**, or **child update to unauthorized parent association**.
