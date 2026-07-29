---
title: Logging configuration, tenant storage, and proot restore boundaries
---

# Logging configuration, tenant storage, and proot restore boundaries

Four July 29 advisories expose reusable operator surfaces where structured control-plane values become executable configuration, opaque storage keys become filesystem paths, or archive metadata crosses host and sibling-container boundaries.

Sources:

- [GHSA-mjqf-28ph-426h / CVE-2026-54680](https://github.com/advisories/GHSA-mjqf-28ph-426h): Logging operator Fluentd configuration injection;
- [GHSA-pmwx-rm49-xv39](https://github.com/advisories/GHSA-pmwx-rm49-xv39): `activerecord-tenanted` Active Storage path traversal;
- [GHSA-9xq3-3fqg-4vg7 / CVE-2026-54574](https://github.com/advisories/GHSA-9xq3-3fqg-4vg7): `proot-distro install` symlink escape; and
- [GHSA-7h3g-4w2f-fj2f / CVE-2026-54727](https://github.com/advisories/GHSA-7h3g-4w2f-fj2f): `proot-distro restore` cross-container hardlink copy.

!!! warning "Authorized validation only"
    Use an isolated cluster, disposable storage roots, synthetic container files, inert marker commands, and locally built archives. Never read credentials, target real container root files, overwrite host configuration, or test command execution in a shared logging aggregator.

## Operator map

| Input | Trusted transition | Safe positive evidence |
| --- | --- | --- |
| namespaced `Flow` string value | CRD renderer emits shared `fluent.conf` directives | generated config contains an additional inert marker directive and a lab-only counter fires |
| blob key | tenant disk service resolves a path under its storage root | canary read/write/delete reaches only a disposable sibling marker |
| tar symlink plus later member | installer opens a path after archive-created symlink resolution | marker file appears in a disposable host sibling directory |
| restore hardlink `linkname` | restore copies from one named container root into another | synthetic marker crosses between two throwaway containers |

Do not collapse these into generic traversal or RCE claims. Preserve the exact renderer, file operation, archive entry type, source container, destination container, and runtime privilege boundary.

## Logging operator CRD-to-Fluentd grammar

The Logging operator advisory confirms that affected renderers write values such as `record_transformer.records` directly into `fluent.conf`. Embedded newlines can terminate the intended record/filter block and introduce a new Fluentd directive. A syntax-only dry run is not a security boundary: valid injected configuration passes it. The fixed source commit is `cf437d7f1e056c78740bf5716ac8bdebcf002425`; release 6.6.0 includes the fix.

### Recorder-only validation

1. Build a disposable Kubernetes cluster with a Fluentd aggregator and a namespace-scoped tenant allowed to create only the `Flow`/`Output` objects under review.
2. Establish a normal `record_transformer` baseline. Save the CRD value, rendered Secret/ConfigMap bytes, parsed directive tree, selected plugin, and aggregator service account.
3. Replace one synthetic record value with newline, closing-tag, opening-tag, indentation, and interpolation canaries one at a time. Use an inert local plugin or wrapper whose only effect is incrementing a counter in a temporary volume.
4. Compare whether the renderer preserves the value as data or emits a sibling directive. Confirm the operator's dry-run result separately.
5. Repeat with release 6.6.0 or the fixed commit. The rendered structure must remain identical to the intended CRD model or reject the value.

Strong evidence is **tenant-writable CRD scalar -> rendered directive tree gains an operator-unmodeled block -> inert aggregator-local counter fires**. Do not use shell callbacks, metadata endpoints, cluster Secrets, or production logs.

## Tenant-aware Active Storage key confinement

`activerecord-tenanted <0.7.0` overrides `ActiveStorage::Service::DiskService#path_for` without proving the resolved path remains under the storage root. Exploitability requires an application path that lets an untrusted actor influence a blob key; normal framework-generated opaque keys are not enough.

### Key provenance and operation matrix

1. Trace key creation, direct-upload completion, attachment import, signed-ID resolution, background processing, and custom storage adapters. Mark whether each route accepts a caller-selected key or only a server-generated value.
2. In a disposable storage root, create `tenant-a/` and a similarly prefixed sibling such as `tenant-a-proof/`, each with unique marker files.
3. Exercise read, write, existence, download, delete, and compose/promotion operations independently with literal `..`, encoded separators if an upstream decoder exists, absolute-path forms, and sibling-prefix cases.
4. Capture the input key, decoded key, tenant prefix, lexical path, canonical parent, operation, and touched inode. Never point the fixture at real application files.
5. Repeat on `activerecord-tenanted` 0.7.0. Confirm both path confinement and tenant namespace binding.

Report only when a realistic untrusted-key path reaches an outside-root canary. A sink-level unit test without application-controlled key provenance is a hardening observation, not a demonstrated remote exploit path.

## `proot-distro` archive phase boundaries

The two advisories are related but distinct:

- `install`/`reset` through 5.1.4 can create a symlink with an archive-controlled absolute target and then follow it while writing a later member. Version 5.1.5 addresses this host-write path.
- `restore` through 5.1.5 can accept a hardlink whose source names a different installed container. Both paths remain under the global containers directory, yet data crosses the expected source/destination container binding. Version 5.1.6 addresses this path.

### Two-archive harness

1. Use Termux/proot only on a disposable test device or emulator. Create `attacker` and `victim` containers with fixed marker files; do not place keys, tokens, shell startup files, or package-manager configuration in either.
2. For install testing, build a tar with one symlink entry and one later regular-file entry that traverses only into a temporary host canary directory created for the fixture.
3. For restore testing, build one hardlink entry whose destination belongs to `attacker` and whose source names a marker in `victim`; reverse the direction in a separate case.
4. Record archive order, member name, type, `linkname`, lexical destination, canonical source/destination, selected container, and final marker checksum.
5. Include negative controls for `..` member names, absolute regular-file names, same-container hardlinks, nonexistent sources, and reversed archive order.
6. Test 5.1.5 and 5.1.6 separately: the former closes the install symlink route but remains the affected restore baseline; the latter must reject cross-container hardlink selection.

A host marker proves **archive symlink to outside-host write**. A copied marker proves **archive-selected sibling-container source/destination confusion**. Neither alone proves Android sandbox escape, privilege escalation, or access outside the Termux app's filesystem authority.

## Evidence and reporting

Preserve exact package versions, caller permissions, raw structured input, generated configuration or archive listing, canonical paths, touched marker inode/checksum, affected/fixed decision tables, and the narrow privilege context. Keep claims phase-specific: **scalar-to-config grammar**, **key-to-filesystem path**, **archive symlink-to-host write**, or **hardlink source-to-sibling container copy**.
