---
title: URL parser, policy-path, tenant-object, and OAuth redirect boundaries
---

# URL parser, policy-path, tenant-object, and OAuth redirect boundaries

A late July 30 advisory wave exposes four reusable operator patterns: an SSRF validator and fetcher can disagree about URL authority; an application-layer policy and backend can normalize paths differently; object IDs can cross tenant or channel scope; and OAuth redirect matching can confuse a hostname suffix with a subdomain boundary.

Sources:

- [dssrf GHSA-cg4g-m8jx-vjv2 / CVE-2026-54722](https://github.com/advisories/GHSA-cg4g-m8jx-vjv2): raw-string `@` removal changes the authority validated by `URL`, while the original URL is fetched;
- [Swarms GHSA-v37m-33r4-9ggf / CVE-2026-67346](https://github.com/advisories/GHSA-v37m-33r4-9ggf): image/audio URL checks do not bind the hostname to its resolved and connected destination;
- [Calico GHSA-gm75-wg2c-p77x / CVE-2026-6540](https://github.com/advisories/GHSA-gm75-wg2c-p77x) and [Tigera TTA-2026-005](https://www.tigera.io/security-bulletins/tta-2026-005): Dikastes prefix rules and downstream HTTP components disagree on path normalization;
- [Julep GHSA-42mr-mcg5-367r / CVE-2026-67348](https://github.com/advisories/GHSA-42mr-mcg5-367r): `get_execution_details` accepts another tenant's execution ID;
- [Vendure GHSA-327h-gp7q-mxcj / CVE-2026-67347](https://github.com/advisories/GHSA-327h-gp7q-mxcj): stock-location and asset updates accept global IDs from another channel; and
- [MaxKey GHSA-7957-wqgw-m3j9 / CVE-2026-67345](https://github.com/advisories/GHSA-7957-wqgw-m3j9): redirect-host suffix matching does not require a DNS label boundary.

!!! warning "Authorized fixtures only"
    Use owned callback domains, local canary HTTP services, synthetic tenant records, disposable OAuth clients, and a lab Calico workload. Never target metadata services, internal production hosts, real agent executions, customer inventory/assets, victim authorization codes, or shared cluster policy.

## One decision matrix

| Boundary | Trusted decision input | Actual sink input | Bounded positive |
| --- | --- | --- | --- |
| SSRF URL | sanitized or initially resolved authority | original URL, redirect destination, or later DNS answer | owned final listener receives the canary |
| HTTP policy | raw path matched by prefix rule | backend-normalized path | permitted wire path reaches denied canary route |
| tenant object | authenticated tenant plus supplied ID | global execution/entity lookup | foreign synthetic marker is read or changed |
| OAuth redirect | suffix-matched hostname | browser's actual redirect authority | code-shaped canary reaches an owned non-client host |

Preserve validation, parsing, DNS, connection, redirect, policy, backend normalization, object lookup, and authorization as separate edges. Do not infer final-destination access from a validator return value or cross-tenant impact from a globally formatted ID.

## Validator-to-fetcher authority differential

1. Put a harmless marker service on an isolated address and an owned public listener on another address. Instrument both; return no credentials or environment data.
2. Pass the same candidate through the exact validator and HTTP client used by the application. Record the raw string, validator-normalized string, parsed username/password/hostname/port, DNS answer set, connected peer, redirect chain, and final listener.
3. Build a corpus around authority grammar rather than one payload: userinfo delimiters, percent-encoded delimiters, bracketed hosts, trailing dots, mixed-case names, multiple DNS answers, redirects, and rebinding between validation and connection.
4. For dssrf, specifically compare the raw URL parsed by the fetcher with the string produced after `@` removal. A positive requires that validation approves one authority while the unchanged fetch input reaches the owned canary authority.
5. For Swarms image/audio loaders, resolve only owned hostnames. Test whether each address is classified, whether the connected address is pinned to the approved result, and whether every redirect is revalidated.
6. Repeat against dssrf 1.0.4 or the relevant corrected Swarms commit with identical fixtures.

Report **validator authority A -> fetcher authority B -> owned final-destination receipt**. Never use cloud metadata or a production internal service as proof.

## Calico policy-to-backend path differential

The affected application-layer policy is disabled by default. First confirm that Dikastes-backed HTTP rules are actually enabled; ordinary Kubernetes NetworkPolicy is not enough.

1. Deploy a disposable workload with `/allowed/canary` and `/denied/canary`; both increment separate no-op counters.
2. Apply a Prefix policy permitting only `/allowed/`. Put a raw-byte recorder before the backend if the lab architecture permits it.
3. Send one path mutation at a time: dot segments, encoded slash forms accepted by the stack, and repeated slashes. Capture the wire target, policy decision, proxy-forwarded target, backend-decoded path, selected route, and counter delta.
4. Use negative controls for a denied canonical path, a permitted canonical path, no policy, a backend that does not normalize the candidate, and corrected Calico builds.
5. A positive is **Dikastes permits the wire path under the allowed prefix -> downstream normalization selects `/denied/canary` -> only the denied counter changes**.

Do not test destructive endpoints. This is a parser differential, not proof that every ingress, service mesh, or backend normalizes identically.

## Tenant and channel object-ID substitution

1. Create tenants/channels A and B, separate low-privilege users, and records containing random markers only.
2. Establish controls: A can access A's execution/asset/stock location; A is denied B's object through intended UI and list routes.
3. From A, substitute B's ID only in Julep execution-detail requests and Vendure asset or stock-location update requests. For Vendure, change a harmless marker field and immediately restore it.
4. Compare read, update, list, and delete independently. Capture actor tenant/channel, route, object owner, supplied ID, status, returned marker label, and before/after hash.
5. Repeat with nonexistent IDs, same-tenant IDs, an administrator, and corrected builds.

Strong evidence is **valid low-privilege session + foreign global ID -> backend object lookup succeeds without binding object scope to actor scope -> synthetic disclosure or mutation**. Do not collect prompts, task outputs, temporal tokens, catalog media, or inventory from real tenants.

## OAuth redirect hostname-boundary checks

1. Register `https://client.example.test/callback` for a disposable MaxKey client and operate a separate suffix-confusion host such as `notclient.example.test` only if both names are owned lab domains.
2. Generate authorization requests that vary exact host, true subdomain, lookalike suffix, port, scheme, path, case, trailing dot, and IDNA form one dimension at a time.
3. Stop before real authorization. Use a synthetic user and a code-shaped marker that the owned listener records but cannot exchange for production access.
4. Record registered URI, supplied URI, parser-derived hostname, match result, browser final authority, and whether the fixed build rejects it.
5. A hostname suffix is acceptable only when the implementation intentionally permits subdomains and verifies `candidate == registered` or `candidate.endsWith("." + registered)` at a canonical DNS-label boundary. Path and port policy remain separate.

Report **registered host suffix comparison -> attacker-owned lookalike host accepted -> synthetic authorization response delivered to that host**. Redact all actual codes and tokens.

## Evidence checklist

Preserve exact package/product versions, enabled feature flags, raw and normalized inputs, parser outputs, DNS and connected-peer evidence, route/policy decisions, synthetic ownership tables, and fixed-version differentials. Keep claims narrow: parser disagreement, final-destination reachability, policy bypass, foreign-object access, and redirect delivery are distinct findings.
