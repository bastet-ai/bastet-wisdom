---
title: NocoBase SQL-scope and Cosmos proxy-identity boundaries
---

# NocoBase SQL-scope and Cosmos proxy-identity boundaries

A July 28 reviewed-advisory wave exposes three reusable operator checks: an application SQL feature whose `SELECT` blacklist does not bind queries to the intended collection namespace, a tunnel-authentication shortcut that forwards caller-supplied identity headers, and an API route that treats any bearer-shaped value as proof of authorization.

Sources:

- [GHSA-v8vm-cqh8-q87q / CVE-2026-52888: NocoBase SQL blacklist bypass](https://github.com/nocobase/nocobase/security/advisories/GHSA-v8vm-cqh8-q87q)
- [NocoBase metadata-query fix](https://github.com/nocobase/nocobase/commit/4aecb60d151a9002004dcf984f63d62f17a6cb45)
- [GHSA-2rx5-2g7j-2659: Cosmos Constellation forward-auth header smuggling](https://github.com/azukaar/Cosmos-Server/security/advisories/GHSA-2rx5-2g7j-2659)
- [GHSA-5fqm-cc34-fcf5: Cosmos arbitrary bearer acceptance](https://github.com/azukaar/Cosmos-Server/security/advisories/GHSA-5fqm-cc34-fcf5)
- [Cosmos 0.22.19 release commit](https://github.com/azukaar/Cosmos-Server/commit/59c561d686c8f9843b3e092b50f6346c481d8bbf)

The reviewed package ranges are `@nocobase/plugin-collection-sql <2.0.62`, alpha builds before `2.1.0-alpha.46`, beta builds before `2.1.0-beta.45`, Cosmos Server `<=0.22.18` for the tunnel path, and Cosmos Server `0.22.18` for the public-device route. Confirm the exact package, enabled feature, database privileges, route configuration, caller position, and fixed-build behavior before reporting.

!!! warning "Authorized validation only"
    Use disposable NocoBase databases, synthetic tables and rows, lab-only Cosmos users/devices, fake bearer values, a canary upstream, and an isolated Constellation network. Never query password hashes, live user tables, PostgreSQL session text, customer device metadata, production internal addresses, or real administrator routes; never retain or replay real tokens.

## Boundary matrix

| Surface | Intended authority | Untrusted input | Safe proof |
| --- | --- | --- | --- |
| NocoBase SQL Collection | selected collection or approved schema | authenticated administrator's SQL text | one synthetic row in a lab-only out-of-scope table |
| Cosmos tunnel shortcut | trusted manager-generated identity | device request plus `x-cosmos-*` headers | fake principal reflected by a canary upstream |
| Cosmos public-device route | validated and authorized token | arbitrary non-empty bearer value | one synthetic device record in a temporary database |

The finding is the broken binding, not merely accepted syntax or an HTTP 200. Capture the input representation, authorization decision, canonical identity or database object, and harmless sink separately.

## NocoBase: test SQL object scope, not only verb filtering

The affected `sqlCollection:execute` path accepts administrator-supplied `SELECT` or `WITH ... SELECT` text and rejects a list of dangerous substrings. The advisory demonstrates that the list omitted sensitive PostgreSQL catalogs and application tables. The durable pattern is broader: **a read-only verb check does not prove that the query remains inside the collection or schema the feature is meant to expose**.

### Synthetic namespace fixture

1. Deploy an affected NocoBase build with PostgreSQL in a disposable network. Enable the SQL Collection plugin and create only lab users.
2. Create `allowed_collection` with marker `ALLOW-<random>` and a separate lab-only table such as `audit_canary` with marker `OUTSIDE-<random>`. Neither marker should resemble a credential or customer record.
3. Give the application database role only the minimum privileges needed for the fixture. Record the role, active schema, `search_path`, and grants.
4. Through the normal administrator UI or `POST /api/sqlCollection:execute`, run a baseline query against `allowed_collection` and capture the selected collection configuration plus returned marker.
5. Submit a single `SELECT` that addresses `audit_canary`. Record the raw query, parser/filter verdict, resolved relation, response field names, and marker hash. Stop after one row.
6. Add controls for schema-qualified names, a CTE, a nested subquery, quoted identifiers, comments between tokens, and a nonexistent relation. Keep every object synthetic.
7. Repeat on the relevant fixed line. Confirm the known metadata names are rejected, but do not assume the patch creates a general collection allowlist: the linked fix extends the blacklist with `pg_catalog`, selected `pg_*` names, and `information_schema`.

A bounded positive result is **application administrator selects the SQL Collection surface -> accepted read-only SQL resolves outside the intended collection namespace -> one synthetic out-of-scope marker is returned**. Do not query `pg_shadow`, `pg_authid`, `pg_stat_activity`, the application's real `users` table, or any credential-bearing field. A filter bypass is valuable without collecting sensitive data.

Report database privilege separately from application validation. If the application role cannot read the canary, a database denial is a negative control; it does not prove the SQL filter correctly binds object scope.

## Cosmos: test who is allowed to assert forward-auth identity

The affected Constellation branch checks tunnel source and a device key, but on auth-enabled routes it can return to the upstream before removing caller-supplied `x-cosmos-user`, `x-cosmos-role`, `x-cosmos-user-role`, and `x-cosmos-mfa` headers or applying the administrator-only gate. This requires Constellation, an enrolled device key, tunnel reachability, an auth-enabled proxy route, and an upstream that trusts Cosmos identity headers.

### Canary upstream matrix

1. Build Cosmos Server `0.22.18` in an isolated lab, enable Constellation, and enroll two synthetic devices: one manager and one ordinary member.
2. Configure an auth-enabled, administrator-only proxy route to a canary upstream. The upstream must only return a JSON object containing the identity headers it received and increment an in-memory counter; it must expose no real privileged action.
3. Establish the baseline with a valid lab administrator session. Record source device, route flags, Cosmos authentication path, upstream headers, and counter state.
4. From the ordinary enrolled device, send its valid lab device credential with a unique fake identity such as `canary-admin`. Do not use a real username.
5. Vary one factor at a time: no identity header, identity header without a device key, invalid key, non-Constellation source, ordinary member device, manager device, `AuthEnabled=false`, and `AdminOnly=false`.
6. Repeat on `0.22.19`. The release changes the shortcut so only a manager device may use it; verify this exact deployed trust model rather than claiming all forwarded identity is cryptographically bound.

The bounded positive result is **ordinary enrolled device + valid device key + caller-supplied identity header -> auth-enabled/admin-only route forwards the fake identity to the canary upstream without a Cosmos user session**. Preserve every precondition. This is not an Internet-unauthenticated path and does not establish impact where the upstream ignores these headers.

## Cosmos: distinguish bearer presence from token validation

The affected `GET /cosmos/api/constellation/public-devices` handler checks for an `Authorization` header, removes a `Bearer ` prefix, but does not validate or use the resulting value when selecting visible devices. Constellation is disabled by default, so prove that it is enabled and populated before testing.

1. Seed a temporary Cosmos database with one visible synthetic device and one invisible control. Use fake names, RFC 5737 documentation addresses, and an owned hostname.
2. Exercise the real route through the deployed middleware, not the handler in isolation.
3. Build a decision table for no header, empty bearer, malformed scheme, random bearer, invalid Cosmos-prefixed token, valid underprivileged lab token, and valid authorized lab token.
4. Capture only status, response shape, synthetic row count, and hashes of seeded names. Do not preserve addresses or metadata from any non-lab device.
5. Repeat on `0.22.19`; the linked release calls the normal permission check before serving the route.

A valid result is **arbitrary non-empty bearer value -> middleware and handler accept it -> synthetic visible-device row is returned**, while the missing-header control is rejected. Do not describe the endpoint as universally exposed: the Constellation feature and visible device data are required.

## Reporting checklist

Include:

- exact NocoBase/Cosmos versions, package or image digest, database engine, and enabled plugins/features;
- caller role, Constellation device role, network position, route `AuthEnabled`/`AdminOnly` flags, and upstream header trust;
- raw query/header class, filter or middleware branch, resolved relation/principal, and marker-only sink evidence;
- database role, schema, `search_path`, grants, and proof that all rows/devices/principals were synthetic;
- baseline, one-variable negative controls, and affected/fixed comparisons;
- a bounded claim separating SQL object-scope escape, tunnel identity injection, and arbitrary-token metadata access.

Do not include tokens, cookies, database hashes, production table names, real usernames, device inventories, internal addresses, upstream application data, or copied advisory proof-of-concept secrets.