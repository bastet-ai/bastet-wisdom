# Repository, pipeline, panel, and appliance authority boundaries

**Signal:** The 2026-08-07 19:16 UTC scan found a late GitHub advisory wave plus a new CISA KEV entry where delegated repository permissions, shared ML artifacts, alternate control-plane APIs, and appliance request fields reached stronger runtime authority.

!!! warning "Authorized validation only"
    Use disposable repositories, roles, artifacts, panels, and appliances. Patch process, SQL, file, session, and network sinks where possible. Never execute commands on production appliances, retrieve another tenant's data, replace retained artifacts, change usable administrator passwords, or probe internal/metadata services.

## Source cluster

### Sonatype Nexus Repository 3

The Nexus records are fixed in 3.95.0 unless the linked vendor record states otherwise.

| Advisory | Delegated input | Stronger authority to validate |
| --- | --- | --- |
| [GHSA-9pmx-p77j-955r](https://github.com/advisories/GHSA-9pmx-p77j-955r) / CVE-2026-17600 | Existing authenticated session | Permissions remain usable after account deletion, deactivation, or password change |
| [GHSA-v8cg-rx44-f2ff](https://github.com/advisories/GHSA-v8cg-rx44-f2ff) / CVE-2026-17596 | Blob-store name from a blob-store manager | Trusted health-check rendering in another user's browser |
| [GHSA-65xx-g4qc-4g4m](https://github.com/advisories/GHSA-65xx-g4qc-4g4m) / CVE-2026-17603 | HikariCP properties through DataStore configuration | `connectionInitSql` executed on new database connections; the default H2 backend can turn SQL authority into process authority |
| [GHSA-rw8g-2688-625j](https://github.com/advisories/GHSA-rw8g-2688-625j) / CVE-2026-17593 | Realm identifiers through an internal settings API | Persisted values re-evaluated by a legacy realm-loading path |
| [GHSA-jffj-qrgg-8qm5](https://github.com/advisories/GHSA-jffj-qrgg-8qm5) / CVE-2026-17599 | Initial-onboarding password endpoint | Administrator password replacement after onboarding; existing sessions remain valid |
| [GHSA-5jh3-q5p5-fq9r](https://github.com/advisories/GHSA-5jh3-q5p5-fq9r) / CVE-2026-17595 | JEXL Content Selector expression | Java object properties outside the intended expression data model; the advisory does **not** establish method invocation or RCE |
| [GHSA-m4g7-vv6g-5mpc](https://github.com/advisories/GHSA-m4g7-vv6g-5mpc) / CVE-2026-17598 | Scheduled-task properties | Internal keys select and overwrite another existing task's configuration |
| [GHSA-fpjc-8wg6-ph5j](https://github.com/advisories/GHSA-fpjc-8wg6-ph5j) / CVE-2026-17601 | Wildcard privilege update | A privilege already assigned to the caller's role is widened to administrator authority |
| [GHSA-9x3v-rxwx-3gx2](https://github.com/advisories/GHSA-9x3v-rxwx-3gx2) / CVE-2026-17594 | Two repository-format fields | Authorization checks one format while creation dispatches another |
| [GHSA-prvc-9rv9-3f72](https://github.com/advisories/GHSA-prvc-9rv9-3f72) / CVE-2026-17597 | Email test host and port | Server-side connection to an operator-selected destination |
| [GHSA-ghg9-vwgf-3fv8](https://github.com/advisories/GHSA-ghg9-vwgf-3fv8) / CVE-2026-14644 | Privilege type/update body | Type confusion widens the caller's own authority under affected role configurations |

### Adjacent high-signal records

- [GHSA-p65j-fxc2-99ww](https://github.com/advisories/GHSA-p65j-fxc2-99ww) / CVE-2026-68772: ZenML 0.94.6 `CloudpickleMaterializer` trusts `artifact.pkl` from a shared artifact store and calls `cloudpickle.load()` when another user or pipeline materializes it.
- [GHSA-27h3-c9gv-83jx](https://github.com/advisories/GHSA-27h3-c9gv-83jx) / CVE-2026-64637: Plesk before 18.0.80 lets an authenticated reseller obtain a root-user administrative session through XML-RPC.
- [GHSA-j4xg-65wf-c7hr](https://github.com/advisories/GHSA-j4xg-65wf-c7hr) / CVE-2026-64636: authenticated Plesk users can cross from panel input into panel-database SQL and read data outside their intended scope.
- [GHSA-89hj-33q6-8644](https://github.com/advisories/GHSA-89hj-33q6-8644) / CVE-2026-15732, [GHSA-wx9m-5w28-64m2](https://github.com/advisories/GHSA-wx9m-5w28-64m2) / CVE-2026-15733, and [GHSA-95wq-w6wp-f2w9](https://github.com/advisories/GHSA-95wq-w6wp-f2w9) / CVE-2026-15734: authenticated WGDashboard webhook, command, and template surfaces can reach outbound HTTP or root process authority in affected 4.2.3/4.3.2-era builds.
- [GHSA-57pc-jm9r-hgj4](https://github.com/advisories/GHSA-57pc-jm9r-hgj4) / CVE-2026-8037: Progress LoadMaster API command endpoints pass unauthenticated input into command execution. CISA added the issue to KEV on 2026-08-07. Use the [Progress bulletin](https://community.progress.com/s/article/LoadMaster-Critical-Security-Bulletin-June-2026-CVE-2026-8037-CVE-2026-33691) for product/build applicability.

## 1. Build a delegated-permission-to-final-action matrix

Start with a synthetic low-privilege Nexus account and grant one documented delegated permission at a time. Record both the policy selector and the object or action that the final handler actually uses:

```text
principal | granted permission | checked field/object | dispatched field/object | final sink | expected
repo-a    | format A admin     | requested format A  | created format B        | create     | deny
role-a    | update privilege P | privilege P         | expanded wildcard       | persist    | deny
user-a    | task type A create | new task A          | existing task B         | overwrite  | deny
```

Use marker-only repositories, roles, privileges, and tasks. Patch persistence to a recorder for destructive routes. For repository-format drift, assert that every request field that can select implementation, recipe, or format agrees with the field used by authorization. For wildcard/type-confusion flows, compare the caller's effective permissions before and after a denied update without granting a real administrative capability.

The onboarding route needs an explicit lifecycle negative control. In a lab initialized with a fake administrator, compare `onboarding=true` and `onboarding=false` while recording whether the password-change sink would run. Do not change a usable password; a patched credential sink or guaranteed rollback is the proof boundary.

## 2. Separate configuration write authority from runtime interpretation

Nexus DataStore, realm, and JEXL findings all begin with legitimate configuration privileges, but each consumer grants a different language or object surface.

### DataStore connection properties

Intercept the DataStore configuration and database-connection initialization paths. Submit an inert SQL marker such as a comment/tag that a query recorder can observe without changing schema or data. Evidence should show:

```text
API property -> persisted Hikari key -> new-connection initialization -> denied SQL recorder
```

Do not use H2 aliases, file functions, Java methods, or process-spawning statements. Establishing that an unapproved property reaches `connectionInitSql` is sufficient; RCE remains conditional on the database backend and available SQL-to-runtime primitives.

### Realm identifiers

Use one valid canary realm ID and one unregistered marker. Record API acceptance, persisted order, UI visibility, and the exact class/factory lookup attempted on reload. Deny class loading or process execution in the fixture. Distinguish persistent authentication lockout from code execution; one does not prove the other.

### JEXL property access

Seed a synthetic selector object with an intended property and a harmless marker property outside the allowed model. Compare expression results on affected and fixed builds. Stop at class/classloader **names** and never traverse into methods, fields containing secrets, object construction, or gadget execution. Report property-sandbox escape, not SSTI or RCE.

## 3. Test lifecycle, render, and outbound helpers with controlled canaries

### Session revocation

Create a disposable user, establish two sessions, then separately test password change, deactivation, deletion, and permission removal. After each event, replay a harmless `GET` and a no-op write recorder. Capture status, authenticated principal, effective permissions, and expiration timestamps. Never modify or delete retained repository content.

### Blob-store rendering

Give a lab user only the minimum blob-store permission and persist a harmless DOM marker in a synthetic blob-store name. View health status with a separate administrator fixture in a script-blocked browser or detached DOM. Prove the final HTML/DOM insertion sink before calling the issue XSS; do not use script, credential forms, navigation, or network callbacks.

### Email verification SSRF

Point the email test to two owned listeners: one allowed public callback and one synthetic denied address represented by a patched connector. Capture the requested host/port, final peer, and response/error class. Do not scan internal ranges, cloud metadata, localhost services, or third-party SMTP servers.

## 4. Treat shared ML artifacts as executable package inputs

ZenML exploitation requires attacker write authority over an artifact that a higher-value pipeline later materializes. Build the proof with a disposable artifact store and replace only a synthetic `artifact.pkl` with an inert deserialization canary that records attempted callable resolution without invoking a process.

Capture the full authority chain:

```text
writer identity -> artifact ID/version -> object-store key -> digest/provenance decision
-> materializer class -> denied cloudpickle callable -> consumer pipeline identity
```

Add controls for an immutable object version, a digest mismatch, an artifact produced by an untrusted writer, and the fixed commit. Report **shared artifact write to unsafe deserialization**. Do not claim broad pipeline takeover unless the real consumer identity and reachable downstream authority are independently established.

## 5. Replay alternate panel and appliance routes without live impact

### Plesk XML-RPC and SQL

Use a disposable reseller, customer, and administrator. For XML-RPC, record the authenticated principal, method, requested session subject, and session-mint decision with token issuance patched or immediately discarded. The expected invariant is that a reseller can mint only a session bound to its own delegated subject, never root.

For SQL, seed one canary row per tenant and route database execution to a read-only scratch schema or query recorder. Use an inert quote-bearing value and show that it remains one bound literal. Never retrieve panel credentials, license data, customer records, or password hashes.

### WGDashboard

Inventory authenticated webhook URLs, interface/settings fields, and template previews. Route each to an owned callback, denied process recorder, or inert template marker. A report should identify the exact field-to-sink chain; the sparse advisory summaries do not justify assuming that every settings field is exploitable. Never execute shell commands or render active templates on an operational WireGuard host.

### Progress LoadMaster

Because CVE-2026-8037 is both unauthenticated and known exploited, production validation should stop at ownership, exposed API route, build evidence, and authentication behavior. Only in a disposable appliance lab should request fields be traced to a denied command recorder with an inert marker. Do not publish command-injection payloads, create accounts, change virtual services, or execute operating-system commands.

## Evidence and report boundaries

- Capture exact product/package version, role, permission, lifecycle state, route family, and final sink.
- Preserve raw request fields and a normalized **checked selector vs dispatched selector** table.
- Use two-user or two-tenant fixtures for authorization findings and affected-versus-fixed builds for parser/runtime findings.
- Keep process, SQL, session, file, and connector sinks denied or disposable.
- Do not upgrade a configuration primitive to RCE, a response difference to SSRF reachability, a DOM marker to XSS, or path/role control to administrative compromise without proving the next boundary.
