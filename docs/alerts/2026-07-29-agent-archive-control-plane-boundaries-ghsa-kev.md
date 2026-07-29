---
title: Agent confirmation, Unicode archive, and control-plane identity boundaries
---

# Agent confirmation, Unicode archive, and control-plane identity boundaries

Four advisories published on July 29 expose durable operator surfaces where a stored event becomes tool authority, filesystem-equivalent names bypass archive reasoning, or a session/credential crosses directly into a privileged control plane.

Sources:

- [GHSA-8qg5-x5vm-75jx / CVE-2026-18236](https://github.com/advisories/GHSA-8qg5-x5vm-75jx) and the [Google ADK fix commit](https://github.com/google/adk-python/commit/c03f333769feaeaa9fe8910fbe95cb9f2d513f54): forged continuation events can resume an unauthorized or argument-swapped tool call;
- [GHSA-m52r-27c6-4q88 / CVE-2026-13723](https://github.com/advisories/GHSA-m52r-27c6-4q88), [CERT VU#293714](https://www.kb.cert.org/vuls/id/293714), and the still-open [app-builder pull request 163](https://github.com/develar/app-builder/pull/163): APFS Unicode-equivalent names can turn a ZIP symlink plus regular entry into an outside-root overwrite;
- [GHSA-3j6g-pxmx-58qg / CVE-2026-60112](https://github.com/advisories/GHSA-3j6g-pxmx-58qg), the [AIT-GUI fix commit](https://github.com/NASA-AMMOS/AIT-GUI/commit/beb8fc0813eded89f985d3eb9a73535dd327726d), and [AIT-GUI 2.5.1](https://github.com/NASA-AMMOS/AIT-GUI/releases/tag/2.5.1): unauthenticated session creation reaches a command-dispatch path; and
- [CVE-2026-20316](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and the [Cisco Secure FMC advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-static-cred-BET3Cjh): static low-privilege credentials provide remote FMC access and a chaining foothold. Cisco reports active exploitation.

!!! warning "Authorized validation only"
    Use recorder-only tools, synthetic session history, disposable ZIP roots on a test Mac, a no-op AIT command bus, and customer/vendor-supplied FMC lab credentials. Never dispatch spacecraft commands, overwrite real files, use leaked/default credentials, access firewall data, or exercise post-login privilege-escalation chains.

## Boundary map

| Input | Authority transition to test | Bounded positive evidence |
| --- | --- | --- |
| confirmation response plus `originalFunctionCall` | session history authorizes a tool invocation | an unregistered, non-confirmable, missing-history, cross-agent, or argument-mismatched canary reaches a recorder |
| ZIP symlink and Unicode-equivalent regular filename | validated archive name becomes an OS-resolved destination | a marker-only file outside the extraction root changes on disposable APFS storage |
| unauthenticated AIT session request | session possession authorizes command dispatch | a no-op command reaches an isolated recorder without credential proof |
| static FMC account | credential possession becomes appliance identity | an approved lab account reaches only its documented low-role canary route |

Keep the edges separate. A forged-looking transcript without tool dispatch is not execution; two names comparing differently in application code is not an overwrite unless the filesystem aliases them; unauthenticated session issuance is not command authority until the dispatcher accepts it; and FMC product exposure is not proof that a secret is known or that privilege escalation is possible.

## Google ADK confirmation-provenance matrix

The fixed ADK processor enforces three bindings before resuming a call: the named tool must be registered to the executing agent, the tool must require confirmation statically or have requested it dynamically, and the `originalFunctionCall` ID, name, and arguments must exactly match the session-history call. The patch also leaves another agent's authored call for that agent's processor rather than treating a shared history as global authority.

### Recorder-only harness

1. Create two lab agents, each with a different recorder tool. Give one tool static confirmation, one argument-dependent confirmation, and one no-confirmation policy. Every tool should append only its agent, call ID, and inert argument marker to a temporary log.
2. Capture a valid baseline sequence: original function call, dynamic confirmation request if applicable, user-authored confirmation response, resumed call, and recorder entry.
3. Replay one mutation at a time: unknown tool name, tool registered only to the other agent, tool that never requested confirmation, nonexistent original call ID, reused call ID with another name, same name with changed arguments, and confirmation attached to another agent's event.
4. Include duplicate and stale confirmations in separate cases. Record whether a prior completed response prevents replay without accidentally making the latest user event a universal approval boundary.
5. Run the same corpus against the affected build and commit `c03f333769feaeaa9fe8910fbe95cb9f2d513f54`. The fixed build must reject every mutated binding before recorder dispatch while preserving the exact baseline.

Strong evidence is **attacker-influenceable session event -> forged confirmation resolves to a different/non-confirmable tool call -> inert recorder fires**. If the attacker cannot inject or modify session history, preserve that missing precondition rather than reporting tool execution from a synthetic internal object alone.

## APFS Unicode-equivalence plus symlink workflow

The app-builder report is narrower than ordinary Zip Slip. The disclosed single-archive fixture creates a symlink named `ss` to an outside target and later writes a regular entry named `ß`. On a default case-insensitive APFS/HFS+ filesystem with full Unicode case folding, those names can resolve to the same directory entry even though an extractor's byte/string checks treat them as different. The proposed patch rejects escaping symlink targets and opens regular destinations with a no-follow flag. Pull request 163 was still open when this page was written, so do not label a release fixed without retesting it.

1. Use a disposable macOS APFS volume. Confirm its case-sensitivity and normalization/case-fold behavior; do not infer the result from a Linux filesystem.
2. Create an extraction root and a sibling canary file containing a known marker. Build a ZIP with only a symlink entry, padding entries if scheduling requires them, and a final regular entry whose name is filesystem-equivalent to the link name.
3. Capture the ZIP central-directory names as raw bytes and decoded strings, entry order, symlink target, extractor lexical destination, `lstat` result, final inode, and canary checksum.
4. Test controls independently: identical names, non-equivalent Unicode names, reversed order, in-tree relative symlink, escaping symlink without a later colliding file, a pre-existing destination symlink, and a case-sensitive APFS volume.
5. Repeat against the proposed patch and any claimed fixed release. Require both checks: escaping link creation is rejected, and a regular write cannot follow a symlink already present at the resolved destination.

A changed sibling marker proves **archive entry equivalence + symlink following -> outside-root overwrite by the extractor user**. It does not by itself prove code execution, privilege escalation, or portability to filesystems with different comparison semantics.

## AIT-GUI session-to-command authority

The advisory says affected AIT-GUI versions before 2.5.1 allow `Sessions.create()` to issue a valid session without a credential check, after which `handle_cmd()` forwards commands to the AIT command bus. Validate this only in a fully isolated development fixture whose command bus has been replaced with a recorder.

1. Deploy an affected AIT-GUI build with no spacecraft, radio, simulator actuator, or production telemetry path attached. Replace the command bus transport with a local stub that accepts one fixed `STATUS_CANARY` command and records all others as rejected.
2. Compare no session, random session, unauthenticated newly created session, authenticated lab session, expired session, and another user's session.
3. For each case, record credential proof at session creation, session owner/expiry, handler authorization decision, command allowlist decision, and recorder count.
4. Stop at the first no-op recorder event. Do not test operational command names or reconnect the fixture to a real command bus.
5. Repeat on 2.5.1. Both session creation and command handling must require a valid authenticated identity; a handler-side gate is still required even when ordinary UI flows authenticate first.

Report the two edges independently: **credential-free session issuance** and **session-to-command authorization**. A public session endpoint without acceptance at `handle_cmd()` is not arbitrary command execution.

## Cisco Secure FMC static-account boundary

Cisco states that on-premises Secure FMC is affected regardless of device configuration, while cloud-delivered FMC, FDM, ASA, FTD, and Security Cloud Control are not the affected product. The vendor supplies hot fixes for FMC release lines 7.0, 7.2, 7.4, 7.6, 7.7, and 10.0 and notes that the low-privilege account can be chained with other FMC issues. Do not search for, recover, guess, or publish the static credential.

1. Establish product identity and management-interface reachability without credential spraying. Preserve whether the target is on-premises FMC and the exact release/hot-fix evidence.
2. Proceed with login testing only when the customer or vendor has supplied a dedicated lab credential and confirmed it represents the affected account class. Use one attempt and redact the value from captures.
3. Establish a documented normal low-role account as a negative/role control. Compare route status, object count, and field presence only against synthetic FMC lab objects.
4. Inventory post-login API and UI route families, but invoke only a harmless identity/status route and one customer-created canary object. Do not access policy, device, event, credential, certificate, backup, or diagnostic data.
5. Test a hot-fixed image with the same controlled credential. The affected static identity must no longer authenticate; ordinary lab accounts should retain their documented behavior.

Positive evidence is **approved affected-account credential -> on-premises FMC issues a low-role session -> synthetic canary route is reachable**. Do not claim the vendor-mentioned privilege-escalation chain unless a separate authorized lab test proves every additional boundary.

## Evidence and reporting

Preserve exact source/build versions, platform/filesystem semantics, caller control over history or archives, raw synthetic events, original/confirmed call tuples, agent/tool registration, ZIP listing and inode/checksum evidence, session creation and handler decisions, appliance identity, role matrices, and fixed-build negatives. Redact all credentials and session tokens. Name the narrow transition crossed: **history event to tool authority**, **archive name to filesystem identity**, **session to command dispatcher**, or **static account to appliance role**.
