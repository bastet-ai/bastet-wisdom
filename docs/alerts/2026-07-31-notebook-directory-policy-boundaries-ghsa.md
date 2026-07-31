---
title: Notebook filesystem, LDAP oracle, and deployment-policy boundaries
---

# Notebook filesystem, LDAP oracle, and deployment-policy boundaries

A July 31 advisory wave yields four reusable operator checks: Apache Zeppelin note and folder names can escape the configured notebook root during filesystem operations; Apache Kyuubi can accept an unprefixed Spark configuration alias that bypasses its session-local-directory allowlist; a 389 Directory Server replication extended operation can turn attacker-controlled LDAP filter grammar into a privileged boolean oracle; and an OpenShift compatibility label can replace RHACS deployment identity with empty/default metadata before policy evaluation.

Sources:

- [Apache Zeppelin GHSA-5j5v-r5qf-p5c4 / CVE-2026-44615](https://github.com/advisories/GHSA-5j5v-r5qf-p5c4)
- [Apache Zeppelin pull request 5227](https://github.com/apache/zeppelin/pull/5227)
- [Apache Zeppelin pull request 5248](https://github.com/apache/zeppelin/pull/5248)
- [Apache Kyuubi GHSA-pp6r-c7gq-g5pr / CVE-2026-62391](https://github.com/advisories/GHSA-pp6r-c7gq-g5pr)
- [Apache Kyuubi announcement](https://lists.apache.org/thread/vo4k4nxz23kfzrpp120nsojb0vrkx4w1)
- [389 Directory Server GHSA-r7mx-568f-jgg3 / CVE-2026-11770](https://github.com/advisories/GHSA-r7mx-568f-jgg3)
- [389 Directory Server replication extended-operation source](https://github.com/389ds/389-ds-base/blob/main/ldap/servers/plugins/replication/repl_extop.c)
- [RHACS GHSA-vq3f-pc8h-pv73 / CVE-2026-10079](https://github.com/advisories/GHSA-vq3f-pc8h-pv73)

These were unreviewed GitHub Advisory Database records when this page was written. Treat the stated versions and behavior as source leads. Confirm the exact build, enabled backend or protocol, caller permissions, and fixed behavior before reporting.

!!! warning "Disposable labs and inert canaries only"
    Use synthetic notebooks, temporary directories, fake Spark paths, a local directory server containing only marker attributes, and an isolated Kubernetes/RHACS lab with no production workloads. Never move or delete real notebooks, select system or credential paths, enumerate production directory configuration, deploy an operationally dangerous workload, or use policy-evasion behavior to hide post-exploitation.

## Boundary matrix

| Surface | Attacker-controlled representation | Trusted transition | Bounded positive |
| --- | --- | --- | --- |
| Zeppelin repository | note/folder path used by rename or folder operation | repository operation becomes a server/Hadoop filesystem path | one synthetic notebook marker moves to a disposable sibling directory |
| Kyuubi session config | prefixed or unprefixed Spark local-directory key | client config selects an engine-local path despite Kyuubi allowlist | recorder receives an outside-allowlist temporary path through an alias |
| 389 replication extended operation | value interpolated into an LDAP search filter | unauthenticated request becomes privileged `cn=config` boolean search | true/false result distinguishes one synthetic marker attribute |
| RHACS deployment ingestion | `openshift.io/encoded-deployment-config` label | caller-supplied compatibility metadata replaces canonical deployment identity | a harmless policy marker is present in Kubernetes but absent or misattributed in RHACS |

Preserve the guard decision and the downstream sink separately. A traversal-shaped string is not an outside-root operation. A config key accepted by the frontend is not allowlist bypass until the engine receives the forbidden canary path. A response difference is not directory disclosure until controlled attributes produce a repeatable boolean oracle. A deployment accepted by Kubernetes is not RHACS bypass until the same object is omitted, misidentified, or not enforced relative to a control.

## Apache Zeppelin: canonicalize every note and folder operation

### Preconditions

- Zeppelin 0.9.0 through 0.12.0 as identified by the advisory, plus 0.12.1 as a fixed control;
- `FileSystemNotebookRepo` enabled;
- an authenticated synthetic user who may rename a note or invoke the relevant folder operation; and
- a disposable notebook root and adjacent sibling directory owned by the same lab account.

### Marker-only workflow

1. Create `notebooks/inside-note` containing only a random marker. Create an empty sibling such as `notebooks-sibling/`; do not place secrets or other users' files nearby.
2. Capture a normal note rename and each exposed folder operation. Record whether the server runs under its filesystem identity or a Hadoop identity.
3. Exercise plain names first, then inert path representations containing parent segments, repeated separators, dot segments, and encoded separators. Do not name operating-system or application configuration paths.
4. After every request, resolve and record the canonical source and destination paths. Check only whether the synthetic marker remains inside the notebook root or appears in the disposable sibling.
5. Test rename, folder move, write, and delete entry points independently. For deletion, operate only on a newly created empty marker directory; successful rename does not prove delete reachability.
6. Repeat using a user without note/folder-operation permission to preserve the authorization control.
7. Repeat on 0.12.1. Require rejection before filesystem mutation whenever canonical source or destination is outside the configured notebook root.

The bounded positive is **authorized note/folder caller -> traversal-bearing repository operation -> canonical destination escapes the notebook root -> only the disposable marker moves or is created**. Report the exact operation and backend identity. Do not infer arbitrary read, overwrite, deletion, or code execution from one rename result.

## Apache Kyuubi: test aliases at the effective Spark configuration sink

The advisory says the earlier fix for CVE-2025-66518 was incomplete: Kyuubi 1.6.0 before 1.12.0 could enforce `kyuubi.session.local.dir.allowlist` on one key spelling while a client supplied an unprefixed Spark alias that reached the same effective local-directory setting. This is a configuration-normalization differential, not ordinary `../` traversal.

### Alias differential harness

1. Run an affected Kyuubi build with a narrow allowlist containing only a temporary `allowed/` directory. Create an empty disposable `denied-canary/` sibling.
2. Replace engine startup or local-directory creation with a recorder where possible. The recorder should log the canonical effective path and refuse to create files.
3. Establish a permitted control using the documented key and an in-allowlist path.
4. Submit the out-of-allowlist canary path through each representation separately: Kyuubi-prefixed key, Spark-prefixed key, unprefixed alias named by the affected parser, duplicate aliases in both orders, and case/whitespace variants that the configuration layer actually accepts.
5. Capture four layers: raw frontend parameters, Kyuubi-normalized configuration, final Spark configuration, and recorder path. This identifies where aliases collapse.
6. Confirm that a low-privilege client can reach the frontend protocol used in the proof; do not broaden the finding to unauthenticated access unless independently demonstrated.
7. Repeat on 1.12.0. All aliases that map to the local-directory sink should be canonicalized and checked against the same allowlist after precedence resolution.

The positive is **client-supplied alias -> Kyuubi guard does not reject -> Spark effective configuration or recorder receives the canonical denied-canary path**. Do not write outside the lab tree, load Spark code, or claim host compromise from path selection alone.

## 389 Directory Server: prove LDAP grammar reachability with a synthetic boolean oracle

The record describes unauthenticated filter injection in the CleanAllRUV replication status-check extended operation. The handler reportedly searches `cn=config` with replication-plugin privileges and returns a match result. The durable bug-hunting pattern is **protocol field -> filter-string construction -> privileged search -> one-bit response**, especially in maintenance or replication operations that run before ordinary bind authorization.

### Local oracle workflow

1. Build an isolated directory instance containing only synthetic replication configuration. Seed one harmless unique attribute/value marker and a neighboring nonmatching value.
2. Enable protocol tracing at the local server. Capture a normal status-check extended operation and identify the exact request field that reaches filter construction.
3. Send baseline values that produce expected true and false results. Preserve BER request bytes, decoded field, constructed filter, search base, server identity, and normalized response.
4. Introduce inert LDAP filter metacharacter structure that refers only to the synthetic marker. Do not query password attributes, bind DNs, hashes, access controls, certificates, or real replication agreements.
5. Vary one property at a time: balanced versus malformed grammar, marker-present versus marker-absent, escaped versus raw metacharacters, anonymous versus authenticated connection, and ordinary LDAP search versus the extended operation.
6. Require repeatable true/false differentiation tied to the marker. Timing differences alone are insufficient.
7. Compare with a fixed package. The request field should remain a literal assertion value or be rejected before privileged search construction.

A safe positive is **unauthenticated extended operation -> controlled field changes LDAP filter structure -> privileged search result distinguishes only the synthetic marker**. Report this as a boolean configuration oracle unless the lab proves a broader result; do not automate enumeration or retain real configuration values.

## RHACS: compare canonical Kubernetes identity with compatibility-label identity

The RHACS record says a deployment creator can set `openshift.io/encoded-deployment-config` to `null`, causing ingestion to replace deployment identity with empty UID/name/labels and namespace `default`. This can break persistence, violation reporting, and deploy-time policy correlation. The reusable pattern is a secondary compatibility representation overriding authoritative object metadata before security-policy evaluation.

### Two-deployment identity matrix

1. Use an isolated cluster and RHACS Central/Sensor containing no production workloads. Give the test principal permission to create Deployments in one disposable namespace, but no RHACS administration rights.
2. Create a harmless deploy-time policy that detects a unique synthetic label or inert image-name marker. It must not block or alert on any real workload.
3. Submit deployment A with canonical metadata and no compatibility label. Record Kubernetes UID, namespace, name, labels, RHACS object identity, persistence, policy result, and violation correlation.
4. Submit otherwise identical deployment B with `openshift.io/encoded-deployment-config: "null"`. Use no privileged pod settings, host mounts, host networking, secret references, or executable attack image.
5. Add controls for an absent label, empty string, malformed encoded value, valid synthetic encoded metadata, literal `null`, and JSON null if the API/client can represent it. Preserve raw YAML and API-normalized JSON.
6. Compare admission, Sensor observation, Central persistence, policy evaluation, enforcement result, and later violation lookup as separate stages.
7. Repeat on a fixed RHACS build and verify that canonical Kubernetes UID/name/namespace remain authoritative or malformed compatibility metadata fails closed without dropping policy coverage.

The bounded positive is **deployment creator supplies compatibility label -> RHACS replaces or loses canonical identity -> the synthetic policy marker is omitted, misattributed, or not enforced while deployment A is correctly handled**. Do not use this to conceal a privileged, persistent, or externally communicating workload.

## Evidence and reporting

For each workflow preserve:

- exact product version, backend/protocol, feature configuration, and caller permissions;
- raw attacker-controlled representation and every normalized/canonical form;
- guard outcome and separate filesystem, engine-config, directory-search, or policy sink event;
- positive, negative, malformed, unauthorized, and fixed-version controls;
- hashes of notebook/path markers and synthetic object identifiers; and
- the narrowest demonstrated effect.

Prefer titles such as “note rename escapes `FileSystemNotebookRepo` root,” “unprefixed Spark alias bypasses session-local-directory allowlist,” “replication status operation exposes privileged LDAP boolean oracle,” or “compatibility label drops RHACS deployment identity.” Do not inflate these into arbitrary file access, cluster compromise, directory credential theft, or universal policy bypass without separate evidence.