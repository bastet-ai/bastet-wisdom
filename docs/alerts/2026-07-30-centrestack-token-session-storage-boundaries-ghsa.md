---
title: CentreStack token, session, API, and storage-parser exploit-path boundaries
---

# CentreStack token, session, API, and storage-parser exploit-path boundaries

A coordinated CentreStack advisory cluster describes several independent edges that can compose into appliance takeover: installation-wide token material, exposed APIs that trust encrypted identifiers, delimiter injection into custom session state, unauthenticated XML/storage handlers, and authenticated database-filter construction. Test each edge independently; do not reproduce a full takeover chain on a production appliance.

Sources:

- [GHSA-vmg2-rwj3-8rq2 / CVE-2026-54363](https://github.com/advisories/GHSA-vmg2-rwj3-8rq2): static cross-installation entropy permits forged authentication artifacts;
- [GHSA-hq66-5q6c-849x / CVE-2026-54367](https://github.com/advisories/GHSA-hq66-5q6c-849x): account-setting APIs trust encrypted account identifiers without authorization;
- [GHSA-g6j6-rqg9-wq7x / CVE-2026-54364](https://github.com/advisories/GHSA-g6j6-rqg9-wq7x): delimiters in `AccountName` cross into custom session serialization;
- [GHSA-q7f4-j8r5-hmxq / CVE-2026-54365](https://github.com/advisories/GHSA-q7f4-j8r5-hmxq): import APIs deserialize attacker-controlled storage configuration into local account/directory side effects;
- [GHSA-m68w-g32j-mw5x / CVE-2026-54366](https://github.com/advisories/GHSA-m68w-g32j-mw5x): SharePoint storage configuration fetches and parses attacker-controlled XML with external entities; and
- [GHSA-4cmj-5m56-fg8c / CVE-2026-54368](https://github.com/advisories/GHSA-4cmj-5m56-fg8c): `x-glad-filter` field grammar reaches SQL construction on directory APIs.

The advisory descriptions identify fixes before 17.2 through 17.5 depending on the issue. Verify the exact deployed build and each source separately; do not treat one version threshold as covering the whole cluster.

!!! danger "Lab or vendor-approved validation only"
    Use a disconnected disposable appliance, synthetic tenants/users, owned callback servers, fake account IDs, a mock database, and no-op side-effect recorders. Never derive or publish vendor key material, forge production authentication headers, create operating-system users, enumerate hosted tenants, read configuration files, write executable files, or run SQL against a live database.

## Map the chain before testing

| Edge | Input | Trusted transition | Safe proof |
| --- | --- | --- | --- |
| token purpose | synthetic encrypted artifact | shared material accepted for a different install/purpose | local verifier accepts a marker claim |
| account API | fake encrypted account ID | identifier validity substitutes for actor authorization | foreign marker setting is returned by no-op handler |
| session grammar | delimiter-shaped account name | extra key/value enters parsed session map | inert `canary=true` appears in test parser output |
| storage import | base64/XML-shaped config | deserialized fields reach account/directory operations | recorder increments without OS mutation |
| XML fetch | owned URL/DTD | storage handler performs secondary fetch/entity resolution | owned callback receives random nonce |
| filter grammar | header field/operator/value | field text becomes SQL identifier/expression | mock query recorder shows structure change |

Keep token construction, route authentication, identifier decoding, object authorization, parsing, side-effect dispatch, and post-auth privilege separate. The published descriptions may show a possible chain, but one positive edge does not prove every later edge.

## Artifact and API-purpose testing

1. Build two isolated lab installations with only fake tenants and capture artifacts issued for harmless operations.
2. Compare artifact structure and verifier behavior across installations and purposes without extracting secrets from binaries or publicizing constants.
3. Feed marker claims to a local verifier or instrumented appliance route that performs no state change. Vary installation, purpose, subject/account ID, expiry, and malformed ciphertext independently.
4. For account-setting APIs, use two synthetic accounts. Demonstrate normal own-account access, then substitute the other account's fake encrypted ID while keeping the same actor session.
5. Record route, actor, artifact purpose, decoded subject hash, target owner, authorization result, and no-op handler count.

A bounded positive is **artifact/identifier validates -> route omits actor-to-target or purpose binding -> foreign synthetic marker reaches a no-op response**. Do not request backup tokens, administrator tickets, cluster settings, or real identity data.

## Custom session grammar differential

1. Reproduce the session serializer/parser in a test harness or instrument a disposable appliance.
2. Establish a normal `AccountName` control and log the resulting key set.
3. Insert one newline/tab/delimiter mutation at a time in a random marker name. Compare pre-serialization input, serialized bytes, parsed keys, and authorization decision.
4. Use an inert `canary=true` key only; do not inject role, reseller, administrator, or identity values.
5. Repeat with encoding variants, duplicate keys, key order, missing terminators, fixed builds, and a parser that length-prefixes or rejects delimiters.

Report **untrusted field -> session grammar break -> additional inert key appears**. Treat authorization bypass as a separate claim requiring an approved no-op authorization fixture.

## Storage import and XML secondary-parser checks

1. Replace account creation, directory creation, and storage writes with recorder interfaces in a lab build. Use a fake UPN and random directory marker.
2. Submit benign storage configuration through each documented import route and identify which parser and operation dispatcher are reached.
3. Change one deserialized field at a time and verify whether unauthenticated input controls the recorder's user/directory arguments. Stop before any OS API runs.
4. For XML handling, point the storage URL to an owned server serving a synthetic XML document and external DTD. The entity should contain only a random literal; never reference `file:`, metadata, or internal authorities.
5. Record initial route authentication, first fetch, parser configuration, secondary callback nonce, and side-effect recorder count. Compare fixed builds and XML parsers with external resolution disabled.

Separate **unauthenticated route**, **attacker-controlled deserialization**, **OS-operation dispatch**, **outbound XML fetch**, and **entity resolution**. Do not collapse them into RCE or file disclosure without independently approved evidence.

## Filter-key-to-query construction

1. Back the lab with a disposable database containing only `id`, `name`, and `canary` columns. Log generated SQL and bind values without executing mutation statements.
2. Replay normal `x-glad-filter` headers, then mutate the field token, operator token, grouping, quoting, and delimiter placement independently.
3. Require the authenticated synthetic user expected by the affected route; do not combine this test with token bypass.
4. A positive is **field grammar changes SQL structure rather than selecting from an allowlist**, shown by the query recorder. A syntax error alone is not proof.
5. Use fixed-build and parameterized/allowlisted mock-query controls. Do not test database file export functions, stacked statements, credential tables, or executable paths.

## Reporting checklist

Preserve exact CentreStack build, route and auth state, marker-only artifact purpose/subject, actor-target ownership matrix, serialized-session byte diff, parser and callback logs, side-effect counters, generated-query structure, and corrected-build results. State which edges were observed and which remain inferred from the advisory; never include reusable keys, forged headers, real account IDs, filesystem paths, SQL payloads, or configuration contents.
