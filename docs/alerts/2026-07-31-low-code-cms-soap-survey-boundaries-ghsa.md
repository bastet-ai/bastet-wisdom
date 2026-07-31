---
title: Low-code SQL, CMS upload, SOAP code generation, and survey trust boundaries
---

# Low-code SQL, CMS upload, SOAP code generation, and survey trust boundaries

A July 31 advisory wave exposes four durable operator patterns: structured API filters crossing into raw SQL, blocked upload extensions hidden inside multi-segment filenames, remote WSDL operation names crossing into Ruby source generation, and survey inputs steering SQL or password-reset link authority. Test the nearest boundary with synthetic data and keep later execution or account-takeover claims conditional.

Primary sources:

- NocoBase [GHSA-p849-8hwh-84j9 / CVE-2026-52887](https://github.com/advisories/GHSA-p849-8hwh-84j9), with the [upstream advisory](https://github.com/nocobase/nocobase/security/advisories/GHSA-p849-8hwh-84j9) and [fix commit](https://github.com/nocobase/nocobase/commit/68d64e3fcfb8be2ae4f3bfc9e1ee3f85b87c89ce);
- REDAXO [GHSA-98pp-vccm-qm25](https://github.com/advisories/GHSA-98pp-vccm-qm25), with the [upstream advisory](https://github.com/redaxo/core/security/advisories/GHSA-98pp-vccm-qm25) and [fix commit](https://github.com/redaxo/core/commit/462e36896bb65d292ba22d711044c23c9cfb0340);
- Savon [GHSA-mx5j-mp4f-g8jg / CVE-2026-53510](https://github.com/advisories/GHSA-mx5j-mp4f-g8jg), with the [upstream advisory](https://github.com/savonrb/savon/security/advisories/GHSA-mx5j-mp4f-g8jg) and [fix commit](https://github.com/savonrb/savon/commit/8f22eb543e7436f6247172c9be47e22792d375e9); and
- LimeSurvey [GHSA-pr6f-87hf-hx24 / CVE-2026-50636](https://github.com/advisories/GHSA-pr6f-87hf-hx24) and [GHSA-5c37-5j7w-8mh8 / CVE-2026-50635](https://github.com/advisories/GHSA-5c37-5j7w-8mh8), with upstream fixes [PR 5031](https://github.com/LimeSurvey/LimeSurvey/pull/5031) and [PR 5032](https://github.com/LimeSurvey/LimeSurvey/pull/5032).

!!! warning "Synthetic fixtures only"
    Use disposable applications, users, surveys, database rows, media files, WSDL documents, mailboxes, and owned HTTP recorders. Use query, parser, source-generation, filesystem, and mail recorders instead of destructive payloads. Never extract rows, alter passwords, execute database or shell commands, upload executable code, collect a real reset token, or target another user's account.

## 1. NocoBase structured-filter to SQL boundary

The NocoBase advisory describes this path:

```text
logged-in request
  -> filter[latestMsgReceiveTimestamp][$lt]
  -> in-app notification resource
  -> template interpolation in Sequelize.literal(...)
  -> PostgreSQL parser
```

The affected notification plugin is `@nocobase/plugin-notification-in-app-message <= 2.0.60`; the listed patched version is `2.0.61`. The action is available to logged-in users. Default self-registration can make that role obtainable without administrator assistance, but verify the target's actual authenticator settings rather than assuming anonymous reach.

The advisory also describes stacked-statement and PostgreSQL-superuser preconditions in the official compose deployment. Those are separate escalation edges:

1. filter text changes SQL structure;
2. the driver accepts more than one statement;
3. the database role is a superuser; and
4. database-container execution has useful impact outside that container.

Do not infer edge 4 from edge 1.

### Prerequisites

- an affected and fixed NocoBase lab;
- a disposable member account created through the same path available in scope;
- the in-app notification plugin enabled;
- SQL capture through a mocked Sequelize connection, PostgreSQL statement logging in an isolated database, or an instrumented query builder; and
- one synthetic channel and timestamp marker.

### Validation procedure

1. Capture a normal list request and record the decoded filter object and final SQL.
2. Replace only `$lt` with an inert type mismatch, unmatched quote marker, or parenthesis marker.
3. Confirm whether the marker reaches the final SQL as grammar or remains one bound value.
4. Repeat with a JSON number, numeric string, array, object, and duplicate parameter form.
5. Compare the affected and fixed builds using the same corpus.
6. Stop after parser-error or query-shape evidence. Do not use stacked statements, delays, file operations, or row extraction.

A useful decision table is:

| Input class | Decoded value | SQL representation | Secure result |
| --- | --- | --- | --- |
| integer | one number | bound numeric value | accepted |
| numeric string | one string | cast or bound value | accepted or rejected consistently |
| quote canary | inert marker | one bound value | rejected or treated as data |
| parenthesis canary | inert marker | one bound value | cannot alter the expression tree |
| array/object | structured value | none | rejected before query construction |

For source-assisted work, trace `latestMsgReceiveTimestamp` from request decoding to `Sequelize.literal`. A reportable result requires attacker-controlled text to alter the parser structure, not merely to appear in a query log as a quoted parameter.

### Reporting boundaries

Report SQL injection separately from default-account reach and database-role escalation. Preserve:

- plugin and server versions;
- authenticator and self-registration state;
- role required by the action ACL;
- exact decoded filter shape;
- affected/fixed SQL or AST differential; and
- database role facts, if assessed, without executing privileged features.

## 2. REDAXO multi-segment upload extension boundary

REDAXO's media validator checked a blocked extension only at the filename end or immediately before the final extension. A filename shaped like:

```text
skillz-marker.php.any.jpg
```

could therefore hide a blocked segment behind an extra extension while retaining an allowed final extension. Affected releases are `redaxo/source >= 5.18.2, < 5.21.1`; the listed fixed version is `5.21.1`.

Execution is conditional. It requires all of these boundaries to line up:

```text
backend user has media upload permission
  -> validator accepts blocked non-terminal extension
  -> filename normalization preserves that segment
  -> file lands in a public media path
  -> web-server handler treats any .php segment as executable
```

Modern anchored PHP handler rules may serve the same file statically. Do not claim remote code execution from upload acceptance alone.

### Harmless filename matrix

Create plain marker files with benign GIF- or JPEG-like bytes and no PHP tags or executable syntax:

```bash
mkdir -p /tmp/skillz-redaxo-fixtures
printf 'GIF89a\nSKILLZ-REDAXO-CANARY\n' > /tmp/skillz-redaxo-fixtures/skillz.php.any.gif
printf 'GIF89a\nSKILLZ-REDAXO-CONTROL\n' > /tmp/skillz-redaxo-fixtures/skillz.gif
file --mime-type /tmp/skillz-redaxo-fixtures/*
```

Test a component-aware matrix:

| Filename shape | Purpose | Secure result |
| --- | --- | --- |
| `skillz.gif` | allowed control | accepted |
| `skillz.php` | terminal blocked extension | rejected |
| `skillz.php.gif` | two-segment control | rejected |
| `skillz.php.any.gif` | blocked interior segment | rejected |
| `skillz.PHp.any.GIF` | case normalization | rejected |
| `skillz.phar.x.gif` | alternate blocked segment | rejected |

Record the submitted filename, normalized stored filename, media URL, MIME decision, and validator result. A fixed build should tokenize every extension segment or otherwise reject blocked segments regardless of their position.

### Handler precondition without code execution

Inspect the effective lab web-server configuration instead of uploading executable bytes:

```bash
apachectl -t -D DUMP_RUN_CFG 2>&1
apachectl -M 2>&1
```

Capture relevant `AddHandler`, `AddType`, `SetHandler`, and `FilesMatch` rules from the approved configuration. Classify whether the match is end-anchored. If runtime confirmation is required, use an inert handler recorder in a disposable vhost that logs only which handler would receive the marker file.

Lead with **blocked-extension persistence in a public media path** unless the authorized lab independently proves an executable handler. Do not upload a web shell or command-bearing polyglot.

## 3. Savon WSDL operation name to Ruby source boundary

Savon's `Savon::Model.all_operations` generated methods by interpolating WSDL operation names into Ruby source passed to `module_eval`. If an application loads an attacker-controlled WSDL and calls `all_operations`, an operation name can change the generated Ruby grammar. Affected `savon` versions are `>= 0.9.8, < 2.17.2`; the listed fixed version is `2.17.2`. Explicit `.operations` configured with trusted names is outside the described path.

The attack preconditions are narrow and should be proved separately:

1. an untrusted party can influence the WSDL bytes or final WSDL URL;
2. redirects and imports remain under that influence;
3. the application uses `Savon::Model`; and
4. it invokes `.all_operations` rather than selecting trusted operations.

### Recorder-first harness

Use an owned local WSDL server and a toy Ruby process. The WSDL should expose one normal operation and one inert identifier-breaking name. Do not include a shell command, file read, environment lookup, or network callback in the name.

Instrument the source-generation boundary so it records source but does not evaluate it. One option in a disposable process is to prepend a recorder around the internal method identified in the affected version; another is to replace `module_eval` on the generated model module with a function that writes the supplied string to standard output and raises a sentinel exception.

Capture:

| Stage | Evidence |
| --- | --- |
| WSDL retrieval | owned URL, redirect chain, and content hash |
| parser output | exact operation-name bytes |
| generated source | escaped source string or AST |
| evaluator call | recorder invocation only |
| fixed control | safe method definition or rejected name |

A positive result shows the operation name escaping its intended method-name context in generated source. Do not execute that source. Also test unusual but legitimate SOAP names so the fixed behavior is not confused with a blanket parser failure.

### Recon questions

Search code and configuration for:

```text
include Savon::Model
Savon::Model
all_operations
wsdl:
```

Then trace who chooses the WSDL URL, whether the client follows redirects, whether WSDL imports fetch secondary documents, and whether the document is cached or reloaded by a privileged worker. A remote WSDL parser in the application does not establish this code-generation sink by itself.

## 4. LimeSurvey RemoteControl SQL and reset-link authority

The two LimeSurvey advisories describe independent boundaries:

- `invite_participants` and `remind_participants` pass a caller-supplied token-ID array into SQL construction; and
- the password-reset workflow can construct an emailed link from an unvalidated HTTP `Host` value.

Affected package information in the advisories lists `limesurvey/limesurvey <= 7.0.0-beta1`; no `first_patched_version` was listed in GitHub's package metadata when this page was written. Use the linked fixes and a fixed-version differential rather than guessing a release boundary.

### RemoteControl token-array to SQL

This path requires the RemoteControl JSON or XML interface to be enabled and an authenticated caller with the survey's token-update permission. Build a disposable survey with synthetic participants and replace the database connection with a query recorder where practical.

Test:

1. one valid synthetic token ID;
2. two valid IDs;
3. one nonexistent ID;
4. an empty array;
5. a quote or parenthesis canary as one array element; and
6. mixed scalar types.

Capture the decoded array and final query structure. The secure result binds every element and preserves one `IN (...)` expression. Stop at parser or query-recorder evidence; do not use time delays, stacked statements, administrator rows, participant data, or writes.

Keep authorization and injection separate. A caller legitimately holding token-update permission may still cross into database-wide authority, but the proof should use synthetic rows and should not modify an account.

### Password-reset Host authority

Use only a disposable LimeSurvey user, an owned mailbox, and two owned HTTP hosts:

- **canonical**: the configured LimeSurvey base URL; and
- **candidate**: an owned recorder that logs only path shape and a per-test correlation marker.

Run this matrix without following or replaying any reset URL:

| Request authority | Forwarding headers | Link hostname in owned mailbox | Secure result |
| --- | --- | --- | --- |
| canonical | none | canonical | baseline |
| candidate `Host` | none | canonical or request rejected | no candidate authority |
| canonical | candidate `X-Forwarded-Host` | canonical unless a trusted proxy supplied it | no client override |
| candidate | conflicting forwarded host | canonical or rejected | deterministic trusted authority |

Redact the reset path and token from evidence. Do not request a reset for another user, allow an email-security scanner to contact the candidate host with a live token, or replay the token. The emailed hostname alone is enough to prove link-authority confusion in the owned account.

Distinguish:

- **host-header-dependent reset link generation**: demonstrated by the owned email;
- **token disclosure**: requires an owned recorder to receive a synthetic token under tightly controlled conditions; and
- **account takeover**: requires replay and should not be attempted when link-generation evidence suffices.

## Evidence and report wording

Preserve exact affected and fixed versions, configuration preconditions, identities, route names, decoded structured inputs, generated SQL/source/filename/link representations, and negative controls. Keep every marker synthetic and redact bearer values.

Prefer boundary-specific titles:

- **“NocoBase notification timestamp filter changes PostgreSQL query structure for a member account.”**
- **“REDAXO accepts a blocked interior extension and preserves it in the public media filename.”**
- **“Savon `all_operations` inserts a WSDL operation name into generated Ruby source.”**
- **“LimeSurvey password-reset email derives its authority from a client-controlled Host value.”**

Do not claim anonymous NocoBase RCE without confirming registration, stacked-query, database-role, and container-impact edges; REDAXO RCE without an executable handler; Savon execution without attacker-controlled WSDL plus `all_operations`; LimeSurvey database-wide impact from route reach alone; or account takeover from reset-link hostname confusion alone.
