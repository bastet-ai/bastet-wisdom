---
title: HTTP authority, WebSocket framing, Oracle SQL, and formatter-cache boundaries
---

# HTTP authority, WebSocket framing, Oracle SQL, and formatter-cache boundaries

Source: reviewed GitHub Security Advisories published or updated August 3, 2026. This wave yields four durable operator patterns: an HTTP client's policy host diverging from its transport destination, a WebSocket upgrade creating an HTTP parser differential, a type-like Oracle SQL prefix suppressing string escaping, and a formatter option becoming part of a cache pathname.

Primary sources:

- Guzzle noncanonical authority [GHSA-v5mv-p594-2x33 / CVE-2026-69246](https://github.com/advisories/GHSA-v5mv-p594-2x33) and cookie-domain scope [GHSA-f7vp-7xgx-4w4r / CVE-2026-69245](https://github.com/advisories/GHSA-f7vp-7xgx-4w4r);
- aiohttp WebSocket-upgrade request smuggling [GHSA-mfx4-hv73-q22v / CVE-2026-69243](https://github.com/advisories/GHSA-mfx4-hv73-q22v);
- Sequelize Oracle-dialect SQL injection [GHSA-v8fg-2rw7-q452 / CVE-2026-69240](https://github.com/advisories/GHSA-v8fg-2rw7-q452); and
- Black cache-path file write [GHSA-3936-cmfr-pm3m / CVE-2026-32274](https://github.com/advisories/GHSA-3936-cmfr-pm3m).

Affected releases are Guzzle before 7.15.2 and 8.0.0 before 8.0.1; aiohttp through 3.14.1; Sequelize before 6.37.4 when the Oracle dialect is selected; and Black 24.3.0 through 26.3.0. Confirm the application's exact API, transport, middleware, dialect, option provenance, and fixed behavior before reporting.

!!! warning "Owned endpoints, recorders, and disposable files only"
    Use owned HTTP/DNS endpoints, one isolated client connection at a time, synthetic Oracle rows, patched SQL/process/file sinks, and random temporary canaries. Never target metadata or internal production services, replay real cookies or credentials, desynchronize shared traffic, execute injected SQL, or overwrite an existing file.

## Boundary map

| Surface | Trusted representation | Later sink | Bounded positive |
| --- | --- | --- | --- |
| Guzzle URI | application/Guzzle inspect the literal host and `Host` header | libcurl or stream transport canonicalizes and connects to another authority | transport recorder observes an owned destination different from the policy parser's host |
| Guzzle cookie jar | textual cookie domain is treated as a registrable name | alternate numeric/escaped spelling is transported as an address | fake cookie crosses between an owned look-alike host and owned address fixture |
| aiohttp WebSocket upgrade | front end and origin agree on ordinary HTTP message boundaries | upgrade edge case leaves different residual bytes/request interpretation | two parsers assign one inert canary route to different message slots |
| Sequelize Oracle escaping | string prefix resembles `TO_DATE` or `TO_TIMESTAMP` syntax | entire caller string is emitted as trusted Oracle expression text | SQL recorder shows a bound-value field changing query structure |
| Black cache key | `--python-cell-magics` is accepted as formatter configuration | unsanitized option contributes path components to cache filename | patched file-open recorder resolves outside the disposable cache root |

## 1. Compare policy host, serialized authority, and final Guzzle destination

Build an isolated PHP harness with the application's real URI-construction path, Guzzle handler, proxy settings, redirect middleware, and cookie middleware. Use only two owned hostnames/listeners and fake headers.

1. Record the original URI text, `UriInterface::getHost()`, serialized authority, explicit `Host`, proxy/no-proxy decision, redirect header-stripping decision, DNS result, TLS name, and final socket destination.
2. Establish controls with an ordinary owned hostname and canonical test address. Then replay the upstream noncanonical classes one at a time: percent-escaped address text, mixed-base numeric text where supported, and a third-party `UriInterface` whose returned components do not serialize to one authority.
3. Instrument or mock the transport so every final destination remains owned. Do not point a bypass candidate at loopback, metadata, RFC1918 services, or any third-party host.
4. Repeat across cURL and stream handlers, direct and owned-proxy modes, redirects enabled/disabled, and fixed Guzzle. A parser mismatch in a helper is insufficient unless the application's final transport reaches the divergent owned listener.

Report **attacker-controlled URI -> policy parser approves literal host -> transport canonicalizes to a different owned authority -> canary response reaches the application**. Keep proxy routing, TLS identity, `Authorization` retention, cookie storage, and response access as separate consequences; prove only those the application reaches.

### Cookie-domain scope matrix

Enable Guzzle's cookie jar with a random fake cookie and two owned endpoints representing the address spelling and a controlled look-alike subdomain. Test both directions:

- an owned address-spelling response sets a cookie and the look-alike host requests it; and
- the look-alike host sets a parent-domain cookie and the owned address-spelling request receives it.

Record the raw `Domain`, Guzzle's normalized jar key, `matchesDomain()` result, final transport authority, and emitted fake `Cookie` header. Compare decimal, hexadecimal/mixed-base, percent-escaped rightmost-label, canonical address, normal DNS parent domain, and fixed-release controls. The positive is **cookie domain classified as a name while transport treats the equivalent spelling as an address, allowing subdomain inheritance or replay across that semantic boundary**. Never use a browser profile or real session token.

## 2. Isolate the aiohttp WebSocket-upgrade parser differential

The public advisory confirms a server-side request-smuggling edge case but does not publish a universal wire fixture. Derive the regression case from the upstream patch/tests or compare affected and 3.14.2 behavior; do not invent a production payload.

1. Put an owned raw-byte front end in front of a minimal aiohttp server exposing only `/upgrade-canary` and `/ordinary-canary` marker routes.
2. Capture exact bytes and each parser's events: request completion, upgrade decision, bytes consumed, residual bytes, connection ownership, and selected marker route.
3. Start with a valid WebSocket handshake, failed handshake, ordinary keep-alive request, and connection-close controls.
4. Replay the smallest upstream regression fixture, varying only one upgrade/framing dimension at a time. Close the connection immediately after the marker decision; never queue a victim request.
5. Compare direct-to-aiohttp, front-end-to-aiohttp, affected release, and 3.14.2. A direct parser error or disconnect alone is not request smuggling.

The bounded positive is **same captured byte stream -> front end assigns inert canary bytes to one request/upgrade state -> affected aiohttp assigns them to another HTTP request slot -> fixed release converges or rejects**. Report the exact proxy/parser pair and do not generalize to all aiohttp deployments.

## 3. Trace Oracle string values through Sequelize escaping

Use a disposable Oracle database schema containing only a public row and a distinct canary row. Prefer replacing the database transport with a SQL-and-bind recorder; if a database is required, deny DDL, file, network, procedure, and administrative privileges.

1. Confirm `dialect: 'oracle'`, Sequelize version, model field type, and the exact request/tenant field that reaches a `where`, update, or modeled expression.
2. Record generated SQL and bind metadata for an ordinary string, a quote canary, lowercase and near-miss prefixes, and strings beginning exactly with `TO_DATE` or `TO_TIMESTAMP`.
3. Use an inert boolean/result-set differential against synthetic rows; do not use stacked statements, comments that consume unrelated query text, time delays, metadata queries, or data-changing expressions.
4. Compare another dialect, an explicitly trusted Sequelize expression object, parameterized raw SQL, and Sequelize 6.37.4.

A reportable result is **untrusted JavaScript string -> Oracle-specific prefix branch suppresses ordinary quote escaping/binding -> recorded SQL structure changes or the synthetic canary row boundary changes**. Do not claim every dialect is affected and do not confuse a deliberately trusted expression API with the vulnerable string path.

## 4. Keep Black formatter options out of cache path authority

Run Black only against a scratch source file under a temporary home/cache root. Patch or interpose the final file-open/replace operation so it records the resolved path and aborts before creating anything outside the cache fixture.

1. Invoke the same Black API or CLI wrapper the target service uses and determine whether an untrusted repository, notebook, job field, or wrapper argument can influence `--python-cell-magics`.
2. Record the raw option, cache-key material, constructed filename, lexical path, canonical parent, and intended cache root.
3. Compare a normal cell-magic name, separator and traversal canaries, absolute-path syntax, empty/repeated values, cache disabled, and Black 26.3.1.
4. Use a random nonexistent sibling path as the outside-root canary. Do not target shell profiles, project files, credentials, or pre-existing paths.

The positive is **untrusted cell-magic option -> cache filename construction preserves path syntax -> file recorder selects a path outside the disposable cache root**. Package presence alone is not reachability; show how the application delegates the option.

## Reporting checklist

- [ ] Exact component version, API/handler, proxy, middleware, dialect, and option provenance are recorded.
- [ ] Guzzle evidence binds policy parsing to the final owned socket and keeps cookie consequences separate.
- [ ] aiohttp evidence contains both parsers' byte-consumption/state traces on one isolated connection.
- [ ] Sequelize proof uses generated SQL/bind traces and synthetic rows without active data-changing SQL.
- [ ] Black proof stops at a patched file-open recorder and a nonexistent temporary canary path.
- [ ] Fixed Guzzle, aiohttp 3.14.2, Sequelize 6.37.4, and Black 26.3.1 controls are replayed.
