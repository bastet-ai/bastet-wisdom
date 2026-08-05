---
title: Odysseus embedding endpoint authority boundaries
---

# Odysseus embedding endpoint authority boundaries

Two Odysseus records expose a reusable AI-platform attack path: a route can require a session yet still let a low-privilege user replace a server-wide model backend, and that replacement can immediately become an outbound-request primitive and a later cross-user data relay.

Primary project and researcher sources:

- project issue [#132: Security - Improper Authentication](https://github.com/odysseus-dev/odysseus/issues/132) and the researcher's [embedding endpoint takeover write-up](https://aydinnyunus.github.io/2026/06/16/odysseus-embedding-endpoint-takeover);
- admin-authorization issue [#80](https://github.com/odysseus-dev/odysseus/issues/80) and project commit [`bf325f6`](https://github.com/odysseus-dev/odysseus/commit/bf325f6b2185cb42bc5d8f5713a64aecffb766d4), which applies the admin dependency to the embeddings router; and
- project commit [`87babb5`](https://github.com/odysseus-dev/odysseus/commit/87babb58d57897089b133b313e2ab6d09e7ef54e), which adds outbound URL checks before the endpoint probe.

The adjacent GitHub records, [CVE-2026-70619 / GHSA-7jfx-c8jj-p569](https://github.com/advisories/GHSA-7jfx-c8jj-p569) and [CVE-2026-70620 / GHSA-pp2c-7vpq-xf5f](https://github.com/advisories/GHSA-pp2c-7vpq-xf5f), were unreviewed mirrors when this page was written. Confirm the deployment's source revision and route behavior; do not infer an affected release range from the advisory prose alone.

!!! warning "Disposable users, synthetic text, and owned callbacks only"
    Run this workflow only on an owned lab or an explicitly authorized customer instance. Use a no-content embedding recorder and random canary strings. Never relay real chats, RAG documents, memories, vault text, credentials, or model inputs; never probe metadata, loopback, private, or third-party services.

## 1. Establish the authority model before testing the sink

Use a disposable instance with three principals:

- no session;
- an authenticated non-admin user; and
- an administrator.

Record the source revision, deployment mode, signup policy, and whether the instance is genuinely multi-user. Establish a negative control showing that the non-admin receives a denial from an unrelated admin-only route. Then build a route matrix for the global embedding controls identified by the project sources:

| Route family | No session | Non-admin | Admin | State or side effect to record |
| --- | --- | --- | --- | --- |
| set custom endpoint | expected deny | expected deny | expected allow | endpoint probe plus global URL/model write |
| clear custom endpoint | expected deny | expected deny | expected allow | global configuration deletion |
| download embedding model | expected deny | expected deny | expected allow | shared model download request |
| delete embedding model | expected deny | expected deny | expected allow | shared model deletion request |

Patch or wrap the persistence, download, and deletion functions so they only log a random marker. A meaningful authorization result is **non-admin session accepted -> global embedding handler reached -> no-op state sink records the marker**. A `200` alone is weak evidence, and an admin success is only the positive control.

Test the entire route family. Shared routers often drift when one handler receives an explicit role check while sibling POST/DELETE or model-management paths retain authentication-only middleware.

## 2. Prove endpoint takeover without collecting user content

Replace the embedding service with an owned local recorder that:

- accepts only a fixed synthetic model name;
- hashes request bodies instead of retaining plaintext;
- returns a static no-content embedding response; and
- logs time, path, caller fixture, and random marker only.

From the non-admin fixture, submit the recorder URL and synthetic model marker. Observe these boundaries separately:

1. route authentication and role decision;
2. immediate health-check request;
3. in-memory endpoint selection;
4. on-disk or environment-backed configuration write;
5. administrator read-back of the active global endpoint; and
6. a later embedding operation from a second synthetic user.

Seed the second user with a random canary such as `EMBED-<uuid>` and no natural-language content. The bounded cross-user positive is **user A changes a server-wide endpoint -> user B triggers an embedding -> owned recorder receives only the expected canary hash**. Stop there. Do not send existing chat history, documents, memory, vault entries, or production prompts through the endpoint.

Persistence increases impact but is not required to prove the authorization flaw. If restart behavior is in scope, use a disposable data directory and preserve only the endpoint hostname/model and file hash before and after restart.

## 3. Separate URL policy from the final network peer

The custom endpoint setter performs an immediate outbound request, so test authorization and SSRF as distinct findings. Replace the HTTP client or transport connector with a recorder; do not target an actual internal address.

Use an owned decision table:

| Input class | Policy observation | Transport observation |
| --- | --- | --- |
| ordinary owned HTTPS endpoint | expected allow | owned public canary peer |
| non-HTTP(S) scheme | expected deny | no connector call |
| direct link-local-shaped test value | expected deny | no connector call |
| loopback/private-shaped test value | deployment-policy dependent | no real connection; recorder only |
| hostname with multiple owned A/AAAA answers | every answer classified | selected peer recorded |
| owned redirector toward a blocked-shaped canary | redirect policy recorded | redirect must not create a second connection |
| owned DNS name that changes between policy and connect phases | both resolutions recorded | final peer must remain policy-approved |
| IPv4-mapped IPv6 and unusual textual IP forms | canonical address recorded | same decision as canonical form |

Commit `87babb5` intentionally permits loopback and private/LAN destinations by default for local-first deployments and adds `EMBEDDING_BLOCK_PRIVATE_IPS=true` for stricter exposed multi-tenant use. Report the observed deployment policy, not a universal expectation. Its pre-request resolver check is also not proof that the later HTTP connection used the same approved address. A strong parser/rebinding result requires **policy accepts owned hostname/address set A -> patched connector records a different blocked-class destination B**. Never make B a real metadata or internal service.

Do not classify a timeout, DNS error, or reflected HTTP error as internal-service access. Preserve the original URL, parsed scheme/host, all resolved addresses, policy result, redirect setting, and final connector destination.

## 4. Test configuration-to-runtime binding

Global endpoint bugs become more severe when separate subsystems consume the same mutable setting. With synthetic markers only, trace which operations select the endpoint:

- chat-time embedding;
- RAG query or document indexing;
- memory creation/search;
- vault indexing/search; and
- model health checks or startup reloads.

For each operation, record the initiating principal, workspace or collection identifier, selected endpoint configuration version, and recorder event. The invariant is that only an administrator can change shared backend authority and that every runtime consumer uses an expected, auditable configuration revision.

Also test stale-worker behavior: after an authorized admin restores the endpoint, verify that background workers and long-lived processes do not continue using the prior canary URL. Use no-op tasks and terminate the lab after the matrix.

## Reporting boundaries

- Distinguish **authenticated** from **authorized** and show the non-admin negative control plus the reached global sink.
- Distinguish the immediate health-check SSRF primitive from later embedding-data relay; each needs its own evidence.
- Do not claim cross-user data disclosure unless a second synthetic principal's canary reaches the owned recorder.
- Do not claim private-network or metadata access from an attempted URL or timeout. Use a patched connector and owned address-class fixtures.
- State whether loopback/private endpoints are intentionally allowed by deployment policy and whether strict private-IP blocking is enabled.
- Report the exact tested source revision. The available primary records describe fixes by commit, not a dependable package-version range.
