---
title: Flowise workspace, runtime, and credential-authority boundaries
---

# Flowise workspace, runtime, and credential-authority boundaries

Eleven Flowise advisories published on August 4 expose a useful low-code/agent-platform review pattern: a flow-builder permission or public prediction route is not authority over every workspace file, runtime loader, execution-context property, outbound destination, OAuth credential, or billing object that a later component can select. Validate each edge independently with disposable objects and recorder-only sinks.

The first five records list `flowise <= 3.1.2` as affected and `3.1.3` as the first patched release. The two original runtime-code records also list `flowise-components <= 3.1.2` as affected and `3.1.3` as fixed. Confirm the package-specific ranges in each later advisory rather than assuming one range covers every server and component path.

Primary sources:

- JavaScript sandbox escape [GHSA-wg86-r78f-74mp / CVE-2026-69253](https://github.com/advisories/GHSA-wg86-r78f-74mp), the [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-wg86-r78f-74mp), [fix PR 6417](https://github.com/FlowiseAI/Flowise/pull/6417), and [fix commit](https://github.com/FlowiseAI/Flowise/commit/3f257bdc8196082a178da7134a075824401b13b9);
- cross-workspace file authorization [GHSA-wp74-f5hh-5f3r / CVE-2026-69252](https://github.com/advisories/GHSA-wp74-f5hh-5f3r), [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-wp74-f5hh-5f3r), and [fix commit](https://github.com/FlowiseAI/Flowise/commit/bc22bf8baec95b6a3d6e1b3563b4f03491cd6fbb);
- TypeORM `DataSource` option injection [GHSA-g32j-mmxr-gfq5 / CVE-2026-69251](https://github.com/advisories/GHSA-g32j-mmxr-gfq5) and the [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-g32j-mmxr-gfq5);
- public OAuth2 refresh and credential-bound outbound request [GHSA-r745-8hwv-h473 / CVE-2026-69250](https://github.com/advisories/GHSA-r745-8hwv-h473), [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-r745-8hwv-h473), and [fix commit](https://github.com/FlowiseAI/Flowise/commit/da8b251a9a4c59484ceaf6f71df7406aede7bef2); and
- customer-source object authorization [GHSA-2364-jh4q-m9vm](https://github.com/advisories/GHSA-2364-jh4q-m9vm), [upstream advisory](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-2364-jh4q-m9vm), and [fix commit](https://github.com/FlowiseAI/Flowise/commit/4d7899d02ca370a5510406be5c91483085a412f9);
- SQLite Record Manager path override [GHSA-x3hf-7cj6-3r4m / CVE-2026-69259](https://github.com/advisories/GHSA-x3hf-7cj6-3r4m);
- unauthenticated prediction-context property injection [GHSA-6vh2-wg4h-4vwj / CVE-2026-69258](https://github.com/advisories/GHSA-6vh2-wg4h-4vwj);
- IPv4-mapped IPv6 SSRF-policy bypass [GHSA-c6xh-wv4j-ppv5 / CVE-2026-69257](https://github.com/advisories/GHSA-c6xh-wv4j-ppv5);
- CSV Agent `pandas.read_pickle()` sink selection [GHSA-x6vm-w76m-8j7g / CVE-2026-69256](https://github.com/advisories/GHSA-x6vm-w76m-8j7g);
- CSV Agent generated-Python string breakout [GHSA-vmv7-4m6c-3cg5 / CVE-2026-69255](https://github.com/advisories/GHSA-vmv7-4m6c-3cg5); and
- caller-controlled `NodeVM` security options [GHSA-3769-jgqc-cxm7 / CVE-2026-69254](https://github.com/advisories/GHSA-3769-jgqc-cxm7).

!!! warning "Disposable Flowise labs and inert recorders only"
    Use affected and corrected local instances, two synthetic workspaces, fake API keys and OAuth credentials, owned HTTP listeners, synthetic CSV/SQLite fixtures, mocked payment-provider objects, and patched file/module/process loaders. Never enumerate customer IDs, retrieve billing records, capture real OAuth secrets, delete user files, target metadata or internal services, deserialize unknown data, load unknown JavaScript, or execute a command.

## Boundary map

| Surface | Initial authority | Detached selector or sink | Safe positive |
| --- | --- | --- | --- |
| `GET`/`DELETE /api/v1/files` | API key has an unrelated feature permission in workspace A | organization-wide listing and caller-supplied path select workspace B | B's marker reaches list/delete recorder under A's key |
| Record-manager and agent-memory nodes | builder may configure one database node | `additionalConfig` reaches TypeORM module-loading options | synthetic outside-node path reaches patched module-open recorder |
| Agent/tool base URL | builder may configure a URL | URL text is interpolated into generated JavaScript and reaches an in-process sandbox | inert grammar marker reaches evaluator recorder outside the intended string slot |
| OAuth refresh | credential creator stores provider configuration | public route selects credential ID, URL, and stored client authority | unauthenticated request triggers owned listener with fake markers and reflects its canary response |
| Customer default source | user has a valid Flowise session | query `customerId` selects a different provider object | mocked customer B reaches response recorder under user A |
| SQLite Record Manager | builder may configure one record manager | trailing object spread replaces the fixed database path | disposable sibling path reaches SQLite open recorder |
| Public prediction API | caller may submit input to one public flow | ungated `overrideConfig` replaces `chatId`, `sessionId`, history, or `$flow.*` values | synthetic foreign-session marker reaches context recorder |
| HTTP security policy | hostname passes URL checks | IPv4-mapped IPv6 survives as a different address kind | owned dual-stack canary produces a policy/transport mismatch |
| CSV Agent | builder may select CSV parsing behavior | generated Python string or preloaded `pandas` API reaches a code/deserialization sink | inert grammar or pickle-open marker reaches a denied sink |
| Custom-function sandbox | authenticated caller may supply code and data | caller `nodeVMOptions` replaces security-critical defaults | forbidden synthetic module name reaches require-policy recorder |

## 1. Diff feature gates, permissions, and storage scope

The `/api/v1/files` record separates three decisions that are often incorrectly treated as one:

1. the organization plan enables the files feature;
2. the API key has permission to perform a specific file operation; and
3. the selected path belongs to the key's active workspace.

The affected route enforced only the first decision. Listing used the active organization root, while deletion accepted a path under that organization; the active workspace was not the storage authorization boundary.

### Two-workspace fixture

Create one organization with workspaces A and B. Place a uniquely named plain-text marker in each workspace. Issue an API key for A with only an unrelated read permission. Patch the delete function so it records the resolved object and returns a sentinel without unlinking anything.

Run this matrix against 3.1.2 and 3.1.3:

| Key | Operation | Selected marker | Secure result |
| --- | --- | --- | --- |
| A, file permission | list | A | allowed control |
| A, unrelated permission | list | A | denied |
| A, unrelated permission | list | B | denied and B absent |
| A, file permission | delete recorder | A | allowed control |
| A, unrelated permission | delete recorder | B | denied before resolution |
| A, file permission | traversal/sibling-shaped synthetic path | outside workspace | rejected before storage call |

Capture the key's permission set, organization and workspace IDs, route middleware decisions, requested path, canonical storage key, selected workspace, and whether the list/delete sink ran. A 200 response alone is weak evidence. The bounded positive is **A-only unrelated key -> B marker appears in the organization-wide listing or reaches the no-op deletion sink -> fixed build denies before storage access**.

Do not perform real deletion. Keep path confinement and workspace authorization as separate findings if both fail.

## 2. Treat structured library options as a module-loader interface

The TypeORM advisory identifies record-manager and agent-memory nodes that forwarded user-controlled `additionalConfig` into `DataSource`. TypeORM options such as `entities`, `subscribers`, and `migrations` can select local JavaScript modules. A field presented as database configuration can therefore become a host module-loader selector.

### Recorder-first workflow

1. Build an affected local Flowise instance with a disposable builder account and one synthetic flow.
2. Place a non-executable marker file inside the flow fixture and another in a disposable sibling directory. Neither file should contain JavaScript syntax.
3. Replace or wrap TypeORM's glob expansion and module import boundary so it records the raw option, expanded paths, canonical paths, and loader call, then raises a sentinel before reading or evaluating a file.
4. Configure each affected node family with ordinary database settings as the control.
5. Vary `additionalConfig` by value type: omitted, empty object, expected safe scalar, array, relative marker path, absolute marker path, glob-shaped marker, and symlinked path.
6. Trigger only the operation needed to initialize the `DataSource`; abort before connecting to a production-like database or loading a module.
7. Repeat against 3.1.3 and compare both accepted option keys and loader reachability.

A reportable positive is **builder-controlled structured option -> TypeORM resolves a synthetic out-of-node file -> patched import recorder receives that path**. Do not execute a module or claim command execution solely because the option is accepted. Record the exact node type and lifecycle event, because an option stored in flow JSON may not reach `DataSource` until upsert, memory initialization, or another runtime action.

Search other low-code integrations for the same pattern:

```text
...additionalConfig
...extraOptions
...driverOptions
...entities / subscribers / migrations
object spread into constructor options
```

Compare the caller-visible schema with the full downstream library schema. Any unrestricted object spread into a library that supports callbacks, plugins, files, modules, sockets, or commands deserves a sink inventory.

## 3. Split code construction from sandbox escape

The JavaScript advisory documents a chain in which a URL-shaped node field was inserted into generated JavaScript and then evaluated through an in-process sandbox. It also shows why dependency-level input checks can behave differently when they receive attacker-controlled objects inside a JavaScript sandbox.

Keep the chain as two independently proved edges:

```text
builder-controlled base URL
  -> generated-source string context changes
  -> evaluator receives altered source

sandbox value/object capability
  -> allowed dependency consumes attacker-controlled object method
  -> module resolution escapes the intended sandbox boundary
```

### Safe source-generation differential

Instrument the function that constructs and evaluates agent/tool JavaScript. Submit:

- a normal owned HTTPS URL;
- URLs with query and fragment markers that are valid according to the application's parser;
- quote, line-break, and comment-shaped **inert grammar markers** that contain no executable statement; and
- duplicate or normalized URL forms.

Record the parsed URL components, generated source bytes, source AST if available, evaluator options, allowed modules, and sandbox selection. Replace evaluation with a parser/recorder that refuses to run the source.

The first edge is positive only if the marker changes the generated AST or leaves the intended string literal. URL acceptance by itself is not code injection.

### Safe sandbox-capability differential

Use a separate same-process harness with a fake dependency and fake locale/module resolver. The dependency should expose a validator that calls a method on a supplied object; the resolver should record a random synthetic module name and abort. Compare primitive strings with string-like objects whose methods are overridden, without referencing host paths or executable files.

The second edge is positive when an attacker-defined object method changes a trusted dependency's validation result and the synthetic name reaches the recorder outside the expected module namespace. Do not load a host file. Do not combine the two edges into runtime execution unless the authorized lab independently proves both with denied final sinks.

Evidence should state whether the affected path used the legacy in-process sandbox, an external sandbox, or no sandbox. Updating one sandbox package does not establish that every Flowise component stopped selecting a different execution path.

## 4. Bind OAuth refresh authorization, object identity, and outbound authority

The OAuth record describes a refresh route under `/api/v1/oauth2-credential/refresh/:credentialId` that was publicly reachable, loaded stored credential data by ID, sent a server-side POST to the stored `accessTokenUrl`, and reflected the remote response body. The important chain is not generic SSRF; it is a stored credential acting as a capability that a lower-trust caller can spend.

### Fake-credential harness

Use a local Flowise lab, an owned HTTP listener, and one synthetic OAuth credential whose client ID, client secret, and refresh token are obvious fake canaries. Ensure the listener has no path to metadata, RFC1918 services, or production networks.

Test independently:

| Caller | Credential selector | Token authority | Expected |
| --- | --- | --- | --- |
| authorized owner | own synthetic ID | owned listener | allowed control |
| no session | nonexistent ID | none | generic denial |
| no session | own synthetic ID | owned listener | denied before credential decrypt/fetch |
| user A | user B's synthetic ID | owned listener B | denied by object ownership |
| owner | own ID with redirect to second owned listener | two owned authorities | redirect policy recorded and bounded |

At the listener, record only the presence and length of named fake fields, never reusable values. Return a random JSON canary and compare whether it appears in the Flowise response. Capture route-auth decision, credential owner/workspace, selected URL, redirect chain, final authority, request field names, and response-reflection behavior.

A strong bounded positive is **unauthenticated request names a valid synthetic credential -> Flowise decrypts it -> owned listener receives fake credential fields -> listener canary is reflected to the caller**. Report outbound reach, stored-secret relay, and response read as separate effects. Never substitute a metadata or internal-service URL.

Generalize this review to callback, refresh, test-connection, webhook-replay, and provider-health routes. A route may need public reach for one phase, but that does not grant anonymous authority to select and spend an existing credential object.

## 5. Keep provider-object IDOR proofs synthetic

The customer-source advisory states that an authenticated request could supply a different `customerId` to `/api/v1/organization/customer-default-source`. Because real provider responses may contain email and billing metadata, do not validate this by guessing or enumerating live Stripe-style IDs.

Use a mocked provider adapter with customers A and B, each containing only random marker fields. Log the authenticated Flowise user, active organization, requested customer ID, provider object selected, authorization object, and response fields. Exercise same-user, foreign-user, foreign-organization, malformed, omitted, and nonexistent IDs.

The positive is **user A's session -> caller-supplied B ID -> mocked provider returns B -> Flowise response recorder receives B's marker without an ownership decision**. The fixed build should derive the customer ID from A's authorized organization/customer relation or explicitly compare the supplied object before calling the provider.

Do not claim predictable-ID enumeration without measuring the actual identifier source in a synthetic environment. Never retain or publish real email, balance, invoice, payment-method, or provider-token data.

## Evidence and reporting checklist

- [ ] Exact Flowise and `flowise-components` versions, deployment mode, route, node type, role, feature plan, and workspace are recorded.
- [ ] Feature availability, operation permission, workspace scope, and path confinement are separate decisions.
- [ ] File deletion, module import, source evaluation, process creation, provider fetch, and payment lookup are recorder-only sinks.
- [ ] TypeORM evidence identifies the option key, resolved path, and lifecycle event that reaches the loader.
- [ ] Code-construction and sandbox-capability edges are proved separately with inert grammar/module markers.
- [ ] OAuth evidence uses fake secrets and distinguishes route auth, credential ownership, final outbound authority, secret-field relay, and response reflection.
- [ ] Customer-source evidence uses mocked provider objects and no identifier enumeration.
- [ ] Affected-versus-3.1.3 behavior is captured with the same fixture.

Prefer boundary-specific report titles such as:

- **“Flowise API key with unrelated permission reaches a file in another workspace.”**
- **“Flowise record-manager options reach TypeORM's local module selector.”**
- **“Flowise agent-tool URL changes generated JavaScript structure before sandbox evaluation.”**
- **“Public Flowise refresh route spends a stored OAuth credential against its configured authority.”**
- **“Flowise customer-source route resolves a provider object not owned by the active organization.”**

Do not lead with remote code execution, secret exfiltration, or cross-customer disclosure unless the corresponding final edge is independently demonstrated under the safe boundaries above.

## 6. Test option precedence at the SQLite file boundary

The SQLite Record Manager record is narrower than the TypeORM module-selector issue: `additionalConfig` was spread after the intended `database` value, so a builder-controlled option could replace the database path itself. Treat this as an option-precedence and file-open test, not as an invitation to write an executable database.

Wrap the SQLite/TypeORM open call and record the configured database root, raw option object, final path, canonical path, open flags, and whether the target existed. Use an empty disposable directory with marker paths inside the intended root and a sibling temporary directory. Compare omitted, in-root, sibling, absolute, and symlink-shaped values. Abort before opening or creating the database.

A bounded positive is **builder-supplied `additionalConfig.database` -> final canonical path leaves the configured database root -> patched open recorder receives the sibling marker**. Separately record whether the container runs with elevated filesystem authority; do not infer host impact from a root UID inside a container.

## 7. Bind public prediction overrides to the authorized context schema

The prediction record identifies two ungated object spreads that could overwrite trusted flow-context fields even when node-input overrides were disabled. Build a public synthetic flow whose context consumer returns only random canaries and whose memory adapter is replaced by a read/write recorder.

Exercise an explicit property matrix:

| Property class | Examples | Secure result |
| --- | --- | --- |
| documented public input | ordinary prediction text | accepted |
| identity/session | `chatId`, `sessionId`, `chatflowId` | ignored or rejected |
| history/state | `chatHistory`, nested state marker | ignored unless explicitly enabled and schema-validated |
| template namespace | random `$flow.*` canary property | unavailable to downstream templates |
| structural keys | nested objects, arrays, prototype-shaped names | rejected before merge |

Use two disposable sessions and never place real prompts in either. Record the raw request, override feature flag, allowlisted keys, resolved context, memory selector, and template substitutions. The positive is **unauthenticated caller supplies session B's random ID or history marker -> session/context recorder for B is selected while API overrides are disabled**. Do not retrieve or alter a real conversation.

## 8. Compare address policy with the final transport destination

Flowise's SSRF check compared address kinds before CIDR matching. An IPv4-mapped IPv6 result could therefore skip IPv4 ranges without being covered by the IPv6 deny entries. Test this only with owned loopback-equivalent canary listeners in an isolated network namespace.

Record every DNS answer, parsed address kind, normalized address, matched policy range, socket family, and final peer address. Include ordinary IPv4, ordinary IPv6, IPv4-mapped IPv6, unspecified forms, redirects between owned authorities, and a rebinding-style second answer served by an owned resolver. The secure invariant is that every accepted destination is normalized to a canonical address class and rechecked at each connection.

A useful report shows **policy parser accepts the mapped form -> transport recorder resolves it to the denied canary destination -> corrected build rejects both spellings**. Never substitute cloud metadata, a local admin service, or an internal production address.

## 9. Separate generated-code, deserialization, and sandbox-option edges

The CSV Agent records expose two independent edges: untrusted data embedded into generated Python source, and a caller-selected `pandas` operation reaching a pickle deserializer despite keyword denylisting. The `NodeVM` record adds a third: caller options spread after secure defaults can replace the module policy.

Use three denied-sink harnesses rather than a shell payload:

1. **Generated Python:** replace Pyodide execution with a parser and AST recorder. Feed CSV data containing inert quote, newline, and comment markers. Report only if the marker leaves the intended string literal or changes the AST.
2. **Deserializer selection:** wrap `pandas` parser dispatch and pickle loading. Supply a locally generated pickle containing only a random scalar marker; abort at the pickle-open boundary. Report the selected API and bytes provenance, not code execution.
3. **Sandbox options:** wrap `NodeVM` construction and module resolution. Supply a random nonexistent built-in name through `nodeVMOptions`; deny resolution and compare the final effective options with secure defaults.

Keep the conclusions precise: generated-source injection, unsafe deserializer reachability, and security-option replacement are separately reportable. Claim sandbox escape or host execution only when an authorized isolated lab independently proves the final boundary without reusable payloads or sensitive output.
