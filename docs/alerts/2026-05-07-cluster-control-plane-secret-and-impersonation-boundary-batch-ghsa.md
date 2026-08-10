# Cluster control-plane secret and impersonation boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a fresh **2026-05-07** batch where Kubernetes/GitOps control planes and container agents crossed secret, identity, and filesystem boundaries.

## Advisories covered

- **Argo CD ServerSideDiff Kubernetes Secret extraction** — [GHSA-3v3m-wc6v-x4x3](https://github.com/advisories/GHSA-3v3m-wc6v-x4x3): diff/render functionality can become a read path for Secrets when it runs with broader cluster privileges than the requesting principal.
- **Fleet Helm impersonation bypass** — [GHSA-765j-qfrp-hm3j](https://github.com/advisories/GHSA-765j-qfrp-hm3j): template rendering retained a `cluster-admin` REST client despite intended impersonation boundaries.
- **Rancher Extensions path traversal** — [GHSA-5v3h-x4wf-5c35](https://github.com/advisories/GHSA-5v3h-x4wf-5c35) / CVE-2026-25705: a malicious `UIPlugin` can abuse `compressedEndpoint` path traversal and Cluster Repo icon paths unless Rancher forces all resolved files to stay inside the extension cache/repository root.
- **Amazon ECS Container Agent for Windows information disclosure** — [GHSA-fc67-c4hg-q653](https://github.com/advisories/GHSA-fc67-c4hg-q653): host/container metadata boundaries can leak sensitive operational data when agent paths are exposed too broadly.

## Why this is durable

GitOps and container control planes are high-trust automation engines. Any helper that renders templates, computes diffs, loads extensions, or exposes agent state must execute as the requester, not as the operator's most privileged service account.

## Immediate triage

1. Patch Argo CD, Fleet, Rancher, and ECS Windows agents where present; prioritize shared clusters and internet-reachable management planes.
2. Review Argo CD ServerSideDiff usage and disable or restrict it for untrusted projects until patched.
3. Hunt for reads of Kubernetes Secret objects through diff/render endpoints and audit `impersonate` headers or service-account usage during Helm rendering.
4. Patch Rancher extension-capable managers to fixed trains: 2.14.1, 2.13.5, 2.12.9, or 2.11.13. Treat extension deployment rights as admin-equivalent until patched.
5. Inventory Rancher `UIPlugin` and Cluster Repo sources; remove unknown, writable, tenant-supplied, or non-vendor extension roots, and review extension install history for writes outside the cache/repository directory.
6. On Windows ECS hosts, review agent exposure, local access paths, and logs for unexpected metadata reads.

## Durable controls

- Enforce requester-scoped authorization at every render, diff, dry-run, and extension-read boundary.
- Use separate low-privilege service accounts for template/diff helpers; never reuse reconciler `cluster-admin` credentials for preview operations.
- Canonicalize extension file paths after decoding and symlink resolution, reject `../` before extraction, and verify `compressedEndpoint` artifacts and repo icons remain under immutable package/cache roots.
- Treat host agents as privileged daemons: bind locally, limit ACLs, redact metadata, and monitor unexpected local callers.

## August 10 follow-up: bind cross-hub messages and migration material to the authenticated hub

Two unreviewed GitHub records for Red Hat multicluster-global-hub add a reusable multi-cluster authority workflow:

- [GHSA-q5c4-r3vh-f379 / CVE-2026-71576](https://github.com/advisories/GHSA-q5c4-r3vh-f379) reports that the manager accepts a self-asserted CloudEvent source identity on Kafka status topics after authenticating only the managed hub's Kafka client certificate. A compromised hub can therefore attribute compliance, inventory, or health messages to another hub and influence that hub's database rows.
- [GHSA-v7q5-q7p3-9vjm / CVE-2026-71577](https://github.com/advisories/GHSA-v7q5-q7p3-9vjm) reports that `ManagedClusterMigration` grants all managed hubs read access to a shared communication topic containing bootstrap kubeconfigs intended for particular hubs.

Treat these records as leads until the Red Hat primary advisory, exact image digest, topic ACLs, and observed behavior confirm them. The first path requires authority already obtained on one managed hub. The second requires an active migration and access to the relevant shared topic. Neither is an unauthenticated Kubernetes API path.

!!! warning "Authorized validation only"
    Use a disposable multi-cluster lab with two synthetic hubs, fake cluster IDs, marker-only status rows, a local Kafka fixture, and bootstrap tokens that authorize no Kubernetes action. Patch database mutation, topic delivery, and token-use sinks to record and deny. Never consume production status topics, collect kubeconfigs, replay service-account tokens, alter real compliance/inventory data, or migrate operational clusters.

### CloudEvent source-to-certificate binding matrix

Create two lab identities, `hub-a` and `hub-b`, with separate Kafka client certificates. Publish inert status events through the same code path used by the manager and capture the authenticated certificate identity, topic, key, event `source`, cluster ID, selected database row, and mutation decision.

| Kafka principal | Event source | Row selected | Required result |
| --- | --- | --- | --- |
| `hub-a` | `hub-a` | `hub-a` marker | normal control |
| `hub-a` | `hub-b` | `hub-b` marker | reject before database mutation |
| `hub-a` | missing source | none | reject |
| `hub-a` | case, encoding, or path-like `hub-a` variant | none | reject unless canonical identity is exactly defined |
| `hub-b` | `hub-b` | `hub-b` marker | normal control |

A bounded positive is **authenticated Kafka principal for hub A -> event claims hub B -> manager selects hub B state -> denied database sink records the foreign row**. Do not falsify or delete a real row. Distinguish control of event content from successful cross-hub attribution; an accepted message is not enough unless the foreign object selected at the final sink is proven.

### Migration-topic audience matrix

Seed the migration controller with a fake kubeconfig-shaped object whose token is a random, nonfunctional marker. Instrument authorization and message delivery, then compare:

| Subscriber | Migration target | Expected visibility |
| --- | --- | --- |
| source hub | source-to-destination migration | only protocol fields required by its role |
| destination hub | source-to-destination migration | its synthetic bootstrap marker through the intended handoff |
| unrelated hub | source-to-destination migration | no marker and no message body |
| same unrelated hub after migration completion | none | no retained marker or topic access |

Capture topic ACLs before, during, and after migration; the authenticated subscriber identity; message key and audience fields; delivery decision; and cleanup/revocation state. A positive is **unrelated hub principal -> shared migration topic -> broker or consumer delivers another hub's synthetic bootstrap marker**. Stop at delivery metadata or a patched body recorder. Do not use the marker against an API server, and report topic-read exposure separately from any cluster access claim.

Test retries, concurrent migrations, controller restart, and failed migration cleanup. Temporary broad grants that survive an error path are a distinct finding even if the happy path revokes them.

### Reporting checklist

- exact multicluster-global-hub version and image digest;
- prerequisite authority on the compromised managed hub;
- Kafka certificate subject/principal, topic, event source, and cluster ID;
- claimed identity versus object selected at the denied database sink;
- migration source, destination, unrelated subscriber, and topic ACL timeline;
- synthetic marker only, with proof that it authorizes no action;
- affected-versus-corrected behavior and negative controls;
- separate conclusions for message attribution, message visibility, and credential usability.
