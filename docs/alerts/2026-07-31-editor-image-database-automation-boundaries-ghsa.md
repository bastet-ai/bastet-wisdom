---
title: Editor sanitizer, image proxy, pgAdmin, and automation event boundaries
---

# Editor sanitizer, image proxy, pgAdmin, and automation event boundaries

A late July 31 advisory wave exposes four reusable operator patterns: HTML sanitizers disagreeing with browser reparsing, image services validating a different URL or path than they use, pgAdmin route and parser policy drifting from the final backend, and automation gateways trusting caller-controlled identity headers. The useful workflow is to isolate each representation change and prove only the nearest harmless sink.

Primary sources:

- Jodit: [GHSA-45qg-252v-3f7p / CVE-2026-65841](https://github.com/advisories/GHSA-45qg-252v-3f7p), [GHSA-rxcw-mc6f-6hr3 / CVE-2026-58263](https://github.com/advisories/GHSA-rxcw-mc6f-6hr3), [GHSA-j839-gqq4-gf9j / CVE-2026-62324](https://github.com/advisories/GHSA-j839-gqq4-gf9j), and [GHSA-5957-5c94-3v7w / CVE-2026-54756](https://github.com/advisories/GHSA-5957-5c94-3v7w);
- Thumbor: [GHSA-cj54-hpcc-gj6h / CVE-2026-53502](https://github.com/advisories/GHSA-cj54-hpcc-gj6h), [GHSA-mw3h-qjxj-6xg9 / CVE-2026-53501](https://github.com/advisories/GHSA-mw3h-qjxj-6xg9), and [GHSA-6x26-6r6f-m537 / CVE-2026-53500](https://github.com/advisories/GHSA-6x26-6r6f-m537);
- pgAdmin: [GHSA-p547-rjmg-jqr4 / CVE-2026-17349](https://github.com/advisories/GHSA-p547-rjmg-jqr4), [GHSA-3h25-h4m7-gr36 / CVE-2026-17566](https://github.com/advisories/GHSA-3h25-h4m7-gr36), [GHSA-vmj8-4452-jj72 / CVE-2026-17346](https://github.com/advisories/GHSA-vmj8-4452-jj72), [GHSA-4pj2-vq9j-xj3g / CVE-2026-17350](https://github.com/advisories/GHSA-4pj2-vq9j-xj3g), [GHSA-rm8j-fq8g-rcjc / CVE-2026-17348](https://github.com/advisories/GHSA-rm8j-fq8g-rcjc), [GHSA-v5gm-27gp-4f7w / CVE-2026-17351](https://github.com/advisories/GHSA-v5gm-27gp-4f7w), and [GHSA-f649-fjv9-qgcg / CVE-2026-17347](https://github.com/advisories/GHSA-f649-fjv9-qgcg); and
- adjacent outbound and automation boundaries: [Pentestify GHSA-pj83-6473-35pq / CVE-2026-59231](https://github.com/advisories/GHSA-pj83-6473-35pq) and [AAP Gateway GHSA-9cwv-qxgx-ff4x / CVE-2026-18141](https://github.com/advisories/GHSA-9cwv-qxgx-ff4x).

The pgAdmin, Pentestify, and AAP entries were unreviewed GitHub advisories when this page was written. Treat their product-specific details as provisional and confirm them against vendor material or a fixed-version differential before reporting.

!!! warning "Synthetic fixtures only"
    Use disposable editor documents, image roots, database objects, users, event streams, and owned HTTP recorders. Use inert DOM counters, marker files, parser traces, fake credentials, no-op jobs, and recorder-only automation rules. Never render a script payload in another user's origin, read host files, fetch internal services, execute database or shell commands, use stored credentials, mutate real constraints or grants, or trigger operational automation.

## 1. Rich-text sanitizer versus browser parser

The Jodit advisories span four distinct boundaries:

1. foreign SVG or MathML element names retain case that can differ from an HTML-oriented denylist;
2. an inert first parse can hide markup as raw text, while serialization and a second parse surface a live element;
3. URL checks can inspect a pre-normalized scheme that the browser later canonicalizes differently; and
4. recursive configuration merge can accept prototype-mutating keys at a nested level.

Do not collapse them into “the editor has XSS.” Map the exact path:

```text
attacker-controlled editor input
  -> editor parser / sanitizer walk
  -> serialized editor value
  -> application storage
  -> browser parse in the final render context
  -> inert DOM marker
```

### Prerequisites

- affected and fixed Jodit builds in isolated pages;
- the exact input API used by the application, such as value assignment, insertion, paste, or source mode;
- a serializer capture before storage and a DOM snapshot after final rendering;
- Chromium and Firefox controls when parser behavior is part of the claim; and
- a harmless proof sink such as a custom element, a removed attribute, or a same-page counter.

### Round-trip differential harness

For each candidate fixture, capture four representations:

| Stage | Evidence |
| --- | --- |
| source | exact inert fixture supplied to the editor |
| post-sanitizer | editor value immediately after the sanitizer runs |
| persisted | bytes the application would store |
| final DOM | namespace, node name, and attributes after the real render path reparses it |

Start with structural markers, not executable handlers. Place a uniquely named data attribute or inert custom element in an SVG/MathML, raw-text, or integration-point carrier. A meaningful result shows the marker absent or non-elemental during the sanitizer walk but present as an element or attribute in the final DOM.

Test these mutation dimensions independently:

- HTML versus SVG versus MathML namespace;
- upper-, lower-, and mixed-case element names;
- one parse versus serialize-and-reparse;
- direct render, `innerHTML`, server-rendered document, and editor reload;
- raw-text containers and integration points; and
- bare versus nested carriers.

Record browser-specific results. A fixture that changes shape only under document parsing must not be reported as an `innerHTML` result in every browser.

### URL-scheme decision table

For editor-generated links, compare the sanitizer's string with the browser's resolved URL without navigating to an executable scheme:

| Variant | Sanitizer output | Browser-resolved scheme | Secure result |
| --- | --- | --- | --- |
| lower-case blocked scheme | captured value | captured via URL parser | removed or neutralized |
| mixed-case spelling | captured value | normalized | same decision as lower-case |
| leading C0/control byte | escaped byte trace | normalized | rejected |
| embedded tab or newline | escaped byte trace | normalized | rejected |
| ordinary owned HTTPS URL | captured value | `https` | preserved |

Use an offline URL parser or intercept the click and log the resolved scheme. Do not execute the destination. The reportable defect is the decision mismatch, not an alert box.

### Prototype-merge canary

Exercise configuration merge in a fresh page or Node process with a nested inert property such as `skillzPolluted: "marker"`. Check the target object, a fresh empty object, and an unrelated editor instance before and after configuration. Delete the marker and terminate the process after every case.

Vary `__proto__`, `constructor`, and `prototype` at the root and under existing plain-object options. A fixed build should reject or treat all three as ordinary non-merging data at every depth. Do not turn a pollution primitive into an execution chain unless an independently authorized application-specific sink is proven.

## 2. Image proxy URL, signature, and file-path consistency

The Thumbor entries expose three points where a service can approve one representation and use another:

```text
request URL
  -> route decoding
  -> signature-string construction
  -> source allowlist
  -> filter argument decoding
  -> loader path canonicalization
  -> file or HTTP fetch
```

A complete assessment logs the value at every transition. Avoid broad SSRF probing or arbitrary file reads.

### Source-host allowlist harness

Configure a disposable Thumbor instance with two owned HTTP listeners whose hostnames differ only where a literal dot appears in the approved hostname. Add exact-label negative controls and record the parsed hostname supplied to the matcher.

Test:

- exact approved host;
- owned hostname with a character substituted for a literal dot;
- approved suffix with an extra DNS label;
- userinfo, port, trailing dot, and mixed-case forms; and
- redirects between the two owned listeners.

The evidence is an owned callback from a hostname that should fail the literal-host policy. Do not use metadata, loopback applications, RFC1918 services, or unrelated public hosts.

### Signature-to-resource binding

Instrument the URL signer and loader so both record their canonical input. Use a fake signature token and an owned image fixture; do not reuse a production security key.

Compare:

| Case | Signer input | Loader resource | Expected |
| --- | --- | --- | --- |
| baseline | approved marker URL | same marker | accepted |
| repeated signature-like segment | recorded canonical URL | recorded final URL | both remain identical or request is rejected |
| encoded segment variant | recorded canonical URL | recorded final URL | identical decision |
| unsigned control | none | no fetch | rejected |

A positive result requires the signer to approve bytes that bind to a different loader resource. Merely observing repeated path text is not an authorization bypass.

### File-loader canonicalization

Create this disposable fixture:

```text
/tmp/skillz-thumbor/root/allowed.txt
/tmp/skillz-thumbor/sibling/outside.txt
```

Both files should contain non-sensitive unique markers. Exercise only the local loader and filter paths that the application exposes. Record the path before URL decoding, after decoding, after joining, and after filesystem canonicalization.

Test single- and double-encoded separators and dot segments, but stop at the sibling marker. A secure implementation decodes to a stable representation and then performs component-aware containment before opening the file. String-prefix containment is not sufficient.

The adjacent Thumbor proportion, convolution ReDoS, and divide-by-zero advisories are availability-only; do not run resource-exhaustion tests on shared systems and do not treat them as separate operator workflows.

## 3. pgAdmin route-family, tenant-clone, and parser-boundary testing

The pgAdmin wave demonstrates that a protected front door does not prove the rest of a feature is protected. It also shows three independent interpreter mismatches: application templates versus PostgreSQL identifiers, a hand-written query checker versus `psql`, and `sqlparse` versus PostgreSQL's own protocol parser.

### Route and Socket.IO permission matrix

Create two disposable users and database roles:

- **allowed**: may use the selected pgAdmin tool; and
- **denied**: authenticated but explicitly denied that pgAdmin tool permission.

Seed only synthetic rows and objects. Capture the complete browser workflow through a proxy and classify every HTTP route and Socket.IO event:

| Step | Transport | Allowed user | Denied user | Unauthenticated |
| --- | --- | --- | --- | --- |
| front-door initialization | HTTP | expected | denied | denied |
| object enumeration | HTTP/socket | expected | denied | denied |
| job creation | HTTP/socket | expected | denied | denied |
| result retrieval | HTTP/socket | expected | denied | denied |
| close/delete helper | HTTP | expected | denied | denied |

Replay direct backend calls only against the lab. Use no-op jobs and marker-only objects. A denied front door followed by an accepted helper route proves route-family drift; it does not prove new database privileges if the user's database role already permits the underlying action.

### Cross-tenant workspace clone

Create one shared server definition for user A using a fake database password and one unrelated server for user B. Trigger the ad-hoc workspace clone as B, then inspect only the new lab row.

Record whether these fields are copied, cleared, or rebound:

- owner ID;
- shared flag and shared username;
- saved-password flags;
- database and tunnel credential presence; and
- persistence after a deliberately failed connection.

Use a mock database endpoint and fake credentials. The strongest proof is that B can cause a clone to persist with A's ownership or credential-bearing fields. Do not connect with or disclose any real stored credential.

### Stored identifier to privileged query

Use a low-privilege database role to create a disposable table, publication, or subscription whose quoted identifier contains a harmless apostrophe marker. As a separate lab user, open only the affected statistics or dependency view while capturing the generated SQL through a mock connection or parser.

Prove:

1. low privilege can persist the identifier;
2. a later privileged UI action selects it;
3. template rendering changes query structure rather than preserving one quoted literal; and
4. the fixed build renders exactly one statement with the marker escaped.

Do not execute a stacked statement. Parser output or a recorder connection is sufficient.

### Query-parser differential

Build an offline table for each policy layer:

```text
candidate query bytes
  -> application checker or sqlparse tokenization
  -> rendered psql/meta-command bytes
  -> PostgreSQL Parse behavior under the configured string mode
  -> no-op recorder
```

Vary quotes, backslashes, comments, parentheses, and `standard_conforming_strings` using inert `SELECT` markers. For AI-assisted query execution, separately record whether psycopg uses simple or extended protocol; a call-site flag is not proof if connection configuration can silently select the simple protocol.

The secure control is structural: the final PostgreSQL parser rejects multi-statement text before execution, and the transaction wrapper remains intact. Never test `COPY ... PROGRAM`, transaction escape, DDL, or shell execution on a live database.

### Identity-to-command hook

Where an external identity supplies a username that is substituted into an administrator-configured hook, replace the hook with an argv recorder. Feed synthetic identities containing whitespace and shell metacharacter canaries, then compare the recorded argument vector.

A secure result preserves the whole identity as one inert argument and invokes no shell. Do not use a command payload or inspect the returned master-password material.

## 4. Report-render fetch and automation identity boundaries

### Headless report fetch

Pentestify's report-image and client-logo fields illustrate a reusable second-order SSRF path:

```text
user-controlled report field
  -> stored finding or client profile
  -> PDF/export renderer
  -> headless browser fetch
  -> owned recorder
```

Use two owned listeners and a synthetic report. Prove direct and redirected final destinations independently, recording the field, export job ID, request method, and correlation token. Return a one-pixel inert image. Do not probe internal services or attach production report data.

### Event-stream mTLS identity

The AAP Gateway entry describes event-stream URL control plus a caller-supplied HTTP subject header crossing into an mTLS identity decision. Validate this only with a recorder-backed event bus and a no-op rule:

1. establish a valid client-certificate control and record the transport-derived subject;
2. send a request without a client certificate and without an identity header;
3. add a synthetic subject header that does not match any real certificate;
4. vary the event-stream URL representation independently; and
5. record whether the no-op event reaches dispatch.

Keep transport identity, header identity, route selection, and automation dispatch as separate claims. Error text revealing an expected subject can support discovery, but it is not authentication bypass until a credential-free request reaches the recorder-only rule.

## Evidence and reporting

Preserve:

- exact affected and fixed versions;
- input API, route, socket event, filter, or report field;
- every normalized or reparsed representation;
- synthetic user, tenant, object, file, host, and job identifiers;
- signer, parser, argv, HTTP, and automation recorder output;
- negative and fixed-version controls; and
- proof that no real file, credential, database action, or workflow was reached.

Prefer boundary-specific titles:

- **“SVG namespace case mismatch leaves an inert marker in stored editor output after sanitization.”**
- **“Image loader decodes a filter path after its root-containment decision.”**
- **“Denied pgAdmin tool role can invoke an unguarded backend route directly.”**
- **“Credential-free event request reaches a no-op rule when a caller supplies the subject header.”**

Do not claim cross-site scripting from serialization drift alone, arbitrary SSRF from one owned callback, signature bypass without signer-to-loader divergence, database privilege escalation from a pgAdmin-only policy bypass, credential theft from copied field presence, or automation compromise from an error message.