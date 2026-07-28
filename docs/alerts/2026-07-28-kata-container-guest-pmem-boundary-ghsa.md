---
title: Kata container-to-guest virtio-pmem boundary from a July 28 GHSA update
---

# Kata container-to-guest virtio-pmem boundary from a July 28 GHSA update

CVE-2026-24834 exposes a reusable sandbox-runtime test: a root filesystem advertised as read-only at the hypervisor layer may still be writable from an unprivileged workload when the guest block-device path and memory mapping disagree about write protection. In the affected Kata Containers and Cloud Hypervisor combination, a container with `CAP_MKNOD` could address `/dev/pmem0`, alter the guest microVM's private root-filesystem view, and cross from the container into guest-root execution.

Sources:

- [GHSA-wwj6-vghv-5p64 / CVE-2026-24834](https://github.com/advisories/GHSA-wwj6-vghv-5p64)
- [Kata Containers security advisory](https://github.com/kata-containers/kata-containers/security/advisories/GHSA-wwj6-vghv-5p64)
- [Kata Containers fix commit](https://github.com/kata-containers/kata-containers/commit/6a672503973bf7c687053e459bfff8a9652e16bf)
- [Kata Containers 3.27.0 release](https://github.com/kata-containers/kata-containers/releases/tag/3.27.0)
- [NVD record for CVE-2026-24834](https://nvd.nist.gov/vuln/detail/CVE-2026-24834)
- [Red Hat CVE-2026-24834 record](https://access.redhat.com/security/cve/CVE-2026-24834)

The reviewed GHSA was updated on July 28. Kata 3.27.0 identifies CVE-2026-24834 as a security fix. The linked change disables `virtio-pmem` for Cloud Hypervisor, forces the image path to read-only `virtio-blk`, disables DAX for that root filesystem, and overrides incompatible configuration. Confirm the runtime implementation, hypervisor, architecture, image transport, effective configuration, and vendor backport rather than deciding exposure from a package string alone.

!!! warning "Disposable runtime lab only"
    Use an isolated node, a custom guest image, a throwaway pod/VM, and marker-only files. Snapshot the image before testing. Never map or modify a production guest root, replace standard system binaries, install persistence, use callbacks, target the host filesystem, or infer host escape from guest-root impact. Stop at a synthetic guest marker or an inert lab-only execution counter.

## Model the three filesystem views

Record each layer separately:

```text
Kata runtime and commit:
RuntimeClass / handler:
Cloud Hypervisor version:
Architecture:
Guest kernel version:
Guest image digest before test:
Configured vm_rootfs_driver:
Effective Cloud Hypervisor device:
DAX enabled:
disable_image_nvdimm:
Container capabilities:
Container device cgroup / LSM decision:
Guest-visible pmem devices:
Container-visible pmem devices before device creation:
Backing image digest after test:
Guest image state after reboot:
Fixed-build control:
```

The important views are:

1. **Host backing file:** the guest image stored outside the microVM.
2. **Guest-private mapping:** the Cloud Hypervisor mapping observed by the guest while the VM is alive.
3. **Container namespace:** the workload's filesystem and device namespace inside that guest.

The advisory says `discard_writes=on` opened the backing file read-only and used a private mapping. Writes therefore appeared in the live guest mapping but did not persist to the host file. That is still a container-to-guest boundary break, but it is not automatically a persistent image modification or a host escape.

## Establish reachability before writing anything

### Runtime and device-path checks

1. Confirm the pod actually uses Kata with Cloud Hypervisor. A `runc`, QEMU, Firecracker, or confidential-guest path is not equivalent.
2. Capture the effective runtime configuration, not only the template. Check whether the image is attached as `virtio-pmem`/NVDIMM or read-only `virtio-blk`.
3. From the guest or trusted lab instrumentation, record `/proc/cmdline`, block-device inventory, mount options, DAX state, and the major/minor numbers assigned to the pmem device.
4. From the container, record effective capabilities and device-controller/LSM behavior. The advisory requires `CAP_MKNOD`; it does not require `CAP_SYS_ADMIN`.
5. Test whether creation and opening of a block-device node for the observed pmem major/minor are permitted. Do not guess device numbers and do not read arbitrary offsets.
6. Repeat without `CAP_MKNOD` and with the fixed runtime. Both are required negative controls.

A container image that happens to contain `mknod` is not enough. The decisive prerequisite is the effective capability plus permission to open the resulting device node, backed by the affected live pmem device.

## Marker-only live-view mutation proof

Prepare the target image offline so no standard guest files need to be touched.

1. Add a fixed-size file such as `/opt/skillz/pmem-boundary-marker` containing a random non-secret marker. Make it guest-root-owned and ensure no service treats it as configuration or executable content.
2. While the image is offline, record its partition start, logical sector size, filesystem block size, inode, extent map, file length, and absolute byte range. Store the calculation with the image digest.
3. Start one disposable Kata sandbox from that exact image and verify the original marker from a trusted guest-side observer outside the test container.
4. In the container, create only the lab pmem device node using the observed major/minor numbers. Write a second equal-length marker to the precomputed marker-file range. Do not scan the device, modify metadata, cross an extent boundary, or touch an offset not reserved for this test.
5. From the trusted guest observer, read the marker by its normal filesystem path. A changed value proves that the container altered the guest root-filesystem view.
6. From the host, hash the backing image before stopping the VM. It should remain unchanged for the private-mapping behavior described by the advisory.
7. Reboot or destroy and recreate the sandbox from the same host image. Record whether the original marker returns. This distinguishes live guest mutation from persistence.
8. Repeat on Kata 3.27.0 or a confirmed vendor backport. The effective rootfs attachment should be read-only `virtio-blk`, and the same container-side write path should fail before mutation.

Use a byte-for-byte fixed-length marker so the proof does not require filesystem allocation, directory changes, or writes to unrelated blocks. If the offline extent cannot be shown to remain stable for the exact image digest, do not perform the write.

## Optional inert guest-execution edge

Guest-view mutation and guest-root execution are separate claims. If the engagement requires the second edge, build it into the disposable image before testing:

1. Add a dedicated lab-only root service or timer that invokes one dedicated file under `/opt/skillz/` and whose only permitted effect is writing a random counter to `/run/skillz-pmem-proof`.
2. Record the baseline file, timer, expected counter, image digest, and invocation time. Do not reuse `systemd-tmpfiles`, a shell startup file, package hook, agent binary, or another normal guest component.
3. Reserve the complete extent for the lab-only invoked file and prepare two equal-size inert variants offline: baseline and counter-writing proof.
4. Use the affected container path to exchange only those prepared bytes. Wait for the dedicated invocation and observe the counter from the trusted guest side.
5. Show that the same exchange is denied on the fixed runtime and that recreating the affected sandbox restores the baseline from the unchanged host image.

Do not publish or use a reverse shell, network callback, credential read, command runner, or modification of a standard privileged binary. A dedicated counter proves that bytes controlled by the container were later executed in the guest-root context without creating a reusable payload.

## Decision table

| Variant | Expected affected behavior | Expected fixed behavior |
|---|---|---|
| No `CAP_MKNOD` | device-node creation denied | denied |
| `CAP_MKNOD`, wrong/nonexistent device | open fails; no marker change | open fails; no marker change |
| `CAP_MKNOD`, correct pmem device, reserved marker range | guest-side marker changes | no writable pmem rootfs path |
| Host backing image after live mutation | unchanged for private mapping | unchanged |
| Sandbox recreated from same image | original marker returns | original marker remains |
| Lab-only invocation counter | appears only if separately exercised | does not appear from container write path |

Unexpected persistence is materially different from the GHSA's described Cloud Hypervisor copy-on-write behavior. Stop, preserve the image and configuration evidence, and investigate the architecture, QEMU/NVDIMM mode, and backing-file flags before making a broader claim. The advisory specifically notes uncertainty around arm64 QEMU where NVDIMM read-only support differs; do not generalize Cloud Hypervisor results to that path.

## Extend the technique to other sandbox runtimes

Apply the same view-separation and marker matrix when reviewing:

- root images exposed through NVDIMM, pmem, DAX, shared memory, loop, or device-mapper paths;
- hypervisor flags that promise discarded writes while the guest block layer still advertises a writable device;
- workload capabilities that permit recreating hidden devices by major/minor number;
- read-only container mounts backed by a separately reachable raw block device;
- snapshot or overlay modes where writes are nonpersistent but still affect privileged guest services;
- architecture-specific fallbacks that silently choose a different rootfs transport.

Do not equate “host image unchanged” with “isolation intact.” A transient write can still cross into a more privileged guest context and influence agents, services, or sibling containers inside the same sandbox VM.

## Reporting checklist

Include:

- exact Kata/runtime/hypervisor versions, architecture, handler, image digest, and vendor build;
- configured and effective rootfs transport, DAX/NVDIMM flags, block-device inventory, and mount state;
- container capability, device-node creation result, and device-access decision;
- offline extent calculation for the dedicated fixed-size marker;
- guest marker before/after, host image hashes, and recreate/reboot behavior;
- affected-versus-fixed decision table;
- separate evidence for mutation and any lab-only execution counter;
- an explicit scope statement: container-to-guest microVM, not proven host escape, cross-VM escape, or persistent image overwrite.

A strong finding is **ordinary container workload plus `CAP_MKNOD` -> writable access to the live guest rootfs pmem device -> reserved guest-root marker changes outside the container -> fixed runtime rejects the same path**. Keep stronger impact claims bounded to edges actually demonstrated in the disposable lab.
