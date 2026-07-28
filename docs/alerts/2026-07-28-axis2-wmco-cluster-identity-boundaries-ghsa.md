---
title: Axis2 cluster-channel and OpenShift WMCO node-identity boundaries
---

# Axis2 cluster-channel and OpenShift WMCO node-identity boundaries

A July 28 advisory wave exposes three reusable operator checks: Java clustering ports that deserialize messages before authenticating a cluster peer, certificate auto-approvers that accept an allowed organization alongside an additional privileged organization, and operators that transfer node credentials over SSH without binding the session to the expected host key.

Sources:

- [GHSA-fhh8-qfj4-g948 / CVE-2026-66713: Apache Axis2 Tribes deserialization](https://github.com/advisories/GHSA-fhh8-qfj4-g948)
- [Apache Axis2 advisory](https://lists.apache.org/thread/fgggbv3sjjqw7p6q0j88gspt9b2rb728)
- [Axis2 commit removing the clustering feature](https://github.com/apache/axis-axis2-java-core/commit/e6f53b230bddcb40577c84ff290ba51e7265fa15)
- [GHSA-x82v-328r-gf3h / CVE-2026-54099: WMCO CSR organization validation](https://github.com/advisories/GHSA-x82v-328r-gf3h)
- [Red Hat CVE-2026-54099 VEX record](https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-54099.json)
- [GHSA-q3jf-4x8j-368q / CVE-2026-54100: WMCO SSH host-key verification](https://github.com/advisories/GHSA-q3jf-4x8j-368q)
- [Red Hat CVE-2026-54100 VEX record](https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-54100.json)
- [Red Hat RHSA-2026:47173](https://access.redhat.com/errata/RHSA-2026:47173)

The GitHub records are unreviewed. Treat the Apache and Red Hat primary records, exact deployed artifact, and observed behavior as authoritative. Axis2 is exposed only when its Tribes clustering feature is enabled; it is off by default and removed in Axis2 2.0.1. The WMCO findings require OpenShift with WMCO and Windows workers. The CSR path additionally starts from a compromised Windows worker holding WICD credentials; the SSH path requires adjacent interception or redirection during node configuration.

!!! warning "Authorized validation only"
    Use an isolated Axis2/Tomcat cluster, a no-op deserialization canary, disposable OpenShift clusters, synthetic Windows workers, locally generated CSRs, lab-only organization names, fake bootstrap values, and test SSH host keys. Never deliver gadget chains, request `system:masters`, mint an administrator certificate, intercept a production provisioning session, collect real WICD/kubelet credentials, or alter production cluster roles.

## Model the three trust transitions

| Surface | Data accepted | Trust decision that must bind it | Safe evidence |
| --- | --- | --- | --- |
| Axis2 Tribes channel | serialized cluster message | authenticated cluster peer and expected message type | listener reachability plus no-op deserialization counter |
| WMCO CSR approver | subject organizations and node identity | exact permitted subject, not set membership | approve/deny decision table against a fake privileged organization |
| WMCO SSH bootstrap | server host key and node address | pinned/known host identity | two-host-key lab matrix with fake credential markers |

The useful finding is not merely an open port, an approved CSR, or an SSH connection. Show where untrusted peer, subject, or server identity crosses into a privileged operation without an exact binding.

## Axis2: find unauthenticated clustering deserialization

### Preconditions and recon

Confirm all of the following before active validation:

- Apache Axis2/Java is at or below 2.0.0;
- Axis2 clustering is configured and the Tribes implementation is in use;
- the clustering listener is reachable from the authorized test position;
- network controls do not already authenticate or isolate cluster members;
- the tested port is the cluster channel, not an unrelated Tomcat service.

Start from deployment manifests, Axis2 configuration, Tomcat clustering configuration, service inventories, and approved port scans. Record bind address, port, transport, expected peer addresses, and whether the listener exposes any protocol response. A silent TCP accept is reachability evidence, not proof of deserialization.

### No-gadget listener harness

1. Build two disposable fixtures from the same configuration: an affected Axis2 release and Axis2 2.0.1 or the linked removal commit.
2. Replace or instrument `Axis2ChannelListener#messageReceived` so the deserialization boundary increments a local counter and rejects immediately. Do not place a gadget library or executable callback on the classpath.
3. Send a normal cluster control message from an enrolled peer and capture transport metadata, peer identity, listener entry, and counter state.
4. Send an inert serialized canary object from a non-member lab host. The object should contain only a unique string and have no custom deserialization methods.
5. Repeat with random bytes, a truncated stream, the same canary from an expected source address, and a valid message after the malformed controls.
6. Confirm that 2.0.1 has no equivalent Axis2 clustering path rather than inferring a fix from a closed port alone.

A bounded positive result is **non-member network peer -> cluster port -> serialized input reaches the Axis2 deserialization boundary before peer authentication**. This establishes the precondition described by CVE-2026-66713 without executing code. Do not publish or run a Java gadget chain.

## WMCO: test exact CSR subject binding

The reported auto-approver checks that a CSR contains `system:wicd-nodes` but does not reject an additional organization. This is a general authorization error: proving the presence of one allowed value is weaker than proving that the complete subject is allowed.

### Offline-first decision table

Instrument or unit-test the approver with locally generated CSRs. Use `test:wicd-nodes` as the allowed lab organization and `test:privileged` as the forbidden canary; never request Kubernetes privileged groups.

| CSR fixture | Organizations | Expected decision |
| --- | --- | --- |
| baseline | `test:wicd-nodes` | follows normal lab policy |
| extra organization | `test:wicd-nodes`, `test:privileged` | deny |
| forbidden only | `test:privileged` | deny |
| duplicate allowed | `test:wicd-nodes`, `test:wicd-nodes` | deny or normalize explicitly |
| empty organization | none | deny |
| lookalike | case/whitespace/Unicode variant | deny |

Capture the parsed subject, all organization values, identity-to-node binding, approver decision, and whether any signer call would occur. Stub the signer in the first pass.

If an end-to-end lab proof is required, use a disposable cluster with a fake non-privileged organization and a role that permits only reading one synthetic ConfigMap. Show that an affected approver signs the extra-organization CSR and that the fixed build rejects it. Delete the test certificate and role afterward. Do not request `system:masters`, read Secrets, or demonstrate cluster-admin takeover.

A valid result is **WICD-authenticated worker + required organization present + additional organization present -> CSR auto-approved**. Preserve the compromised-worker and WICD-credential preconditions in the report; this is not an unauthenticated Kubernetes API path.

## WMCO: verify SSH server identity before bootstrap transfer

The second WMCO record describes SSH connections to Windows workers without server host-key verification. The offensive value is the control-plane-to-node identity boundary, not generic SSH interception.

### Two-listener lab

1. Create a disposable WMCO/OpenShift fixture and two lab SSH listeners: the expected Windows worker and a redirect listener with a different host key.
2. Replace WICD and kubelet bootstrap values with fake unique markers that authorize nothing.
3. Run normal provisioning against the expected listener and capture destination, resolved address, negotiated host-key algorithm, key fingerprint, and bootstrap stage.
4. Redirect only the lab node address to the second listener. Do not proxy onward.
5. Record whether WMCO rejects before authentication or accepts the changed key and begins transmitting a fake marker.
6. Repeat after RHSA-2026:47173 with the same expected key, a changed key, a missing known-host entry, and a rotated key installed through the documented trust path.

The safe positive result is **node address redirected -> unexpected SSH host key accepted -> fake bootstrap marker reaches the wrong lab listener**. Stop after the first synthetic marker. Do not capture real credentials or attempt to use the marker as a node identity.

## Chain analysis without chain execution

These records describe adjacent but distinct paths:

1. SSH host-key failure may expose WICD or kubelet bootstrap material during a favorable provisioning window.
2. A principal already holding WICD credentials may submit a CSR containing the required organization plus an additional organization.
3. A permissive approver may sign that subject.

Test each edge separately with fake credentials, a stub signer, and non-privileged canary groups. Do not claim the full chain unless the exact deployed WMCO version reaches every edge. Do not combine production interception with a privileged CSR.

## Reporting checklist

Include:

- exact Axis2, Tomcat, OpenShift, and WMCO versions or image digests;
- whether Axis2 Tribes clustering and Windows workers are actually configured;
- cluster-port bind address, authorized test position, and expected peer controls;
- listener-entry and no-op counter evidence, not an RCE payload;
- complete CSR subject and organization list, parsed values, decision, and signer-call state;
- worker identity, WICD credential precondition, and synthetic organization names;
- SSH destination, expected and observed host-key fingerprints, and the stage at which the fake marker was sent;
- affected/fixed comparisons and negative controls;
- separate impact statements for deserialization reachability, CSR approval, and SSH server-identity failure.

Keep claims bounded. Network reachability is not code execution; an extra-organization approval is not cluster-admin unless that organization is privileged and accepted by authorization; an SSH key mismatch is not credential theft unless data is actually sent; and the two WMCO issues do not automatically form a remotely exploitable chain.
