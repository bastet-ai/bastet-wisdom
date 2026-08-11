# TP-Link Aginet appliance authority boundary testing

TP-Link's August 10 advisory groups five flaws across ISP-managed Aginet networking products. The durable operator lesson is not a model-specific request: appliance management authority must remain bound across route dispatch, role checks, stored-secret encryption, USB-backed file serving, and system-command wrappers.

Use this workflow only on owned lab devices or customer-approved appliances. The affected set includes ISP-specific regional and operator builds, so identify the exact model, hardware revision, firmware string, and provider customization before testing. Use TP-Link's affected-product table as the source of truth rather than inferring exposure from the product family alone.

## Authority map

| Boundary | Advisory signal | Safe proof target |
| --- | --- | --- |
| Anonymous request -> privileged web handler | CVE-2025-30237 reports inconsistent authentication on sensitive endpoints | A route/handler decision table with a denied mutation recorder |
| Low-privilege session -> administrative user management | CVE-2025-30238 reports missing operation-level authorization | A disposable low-role user and an instrumented create/update sink |
| Firmware key -> stored configuration identity | CVE-2025-30239 reports hardcoded keys protecting configuration data | Offline firmware comparison plus synthetic encrypted canaries |
| USB HTTPS path -> final device file | CVE-2025-30240 reports symlink following from external storage | A disposable USB image, an in-lab sibling canary, and final-path traces |
| Web field -> privileged process | CVE-2025-30241 reports command injection before system execution | An inert grammar corpus and a denied process recorder |

Do not treat one passing route, role, path, or input check as proof for a neighboring operation. Build the matrix from the final privileged sink backward.

## Prerequisites and evidence setup

- Record the model, hardware region/revision, complete firmware build, management origin, and whether the image is ISP-customized.
- Keep the management plane on an isolated lab segment. Do not test ISP-operated remote-management infrastructure.
- Create only synthetic accounts and configuration objects. Never export subscriber, Wi-Fi, VoIP, provisioning, or service credentials.
- Replace account/config mutation, file-open, and process-launch functions with recorders where source or an instrumented firmware harness is available.
- Capture request method, raw path, normalized route, authenticated role, selected handler, authorization result, and whether the final sink was reached.

## 1. Enumerate route-level authentication drift

Start from legitimate browser traffic for the same firmware build. Inventory management routes without guessing hidden actions, then replay inert requests under three identities:

1. no session;
2. a disposable low-privilege session;
3. a disposable administrator control.

For each route, vary only one representation at a time: method, trailing slash, duplicate slash, encoded path separator, case, content type, or alternate API/UI route family. Stop at handler-selection evidence; route all state-changing handlers into a denied mutation recorder.

| Route form | Anonymous | Low role | Admin control | Handler selected | Mutation sink reached |
| --- | --- | --- | --- | --- | --- |
| Canonical UI request | | | | | denied |
| Canonical API request | | | | | denied |
| Alternate method | | | | | denied |
| Normalization variant | | | | | denied |

A strong finding shows that the same privileged handler is selected without the authentication decision required by the canonical control. A different status code, redirect, or error body alone is not proof of privileged execution.

## 2. Separate login from operation-level authorization

Exercise user-management and critical-configuration handlers with a disposable low-role account. Test create, read, update, role assignment, password reset, and delete as separate operations because shared UI visibility does not imply shared server-side policy.

Use fake object IDs and intercept the final mutation. Record:

- the principal and server-resolved role;
- the target object's current owner and role;
- caller-supplied capability or role fields;
- the policy function reached;
- the normalized mutation that would have been committed.

The control is the same request under an administrator. Report a boundary failure only when a low-role principal reaches an administrator-only mutation sink; do not create a retained privileged account on the appliance.

## 3. Test configuration-key reuse offline

Acquire firmware only through the provider/vendor path authorized for the engagement. In an offline workspace:

1. inventory constants and key-loading call sites across two affected builds or variants;
2. identify the configuration encryption format and key-selection inputs;
3. create a synthetic configuration canary with the lab firmware or a compatible harness;
4. test whether material recovered from one image opens only that synthetic canary in another image or device context;
5. record key identity, derivation inputs, authenticated-encryption checks, and failure behavior.

Hardcoded bytes are evidence of embedded material, not automatically proof that production configuration can be decrypted. The finding becomes actionable when the same static material reaches the real configuration cryptographic path without a device-, tenant-, or deployment-specific binding. Do not decrypt retained appliance backups or publish key material.

## 4. Resolve USB HTTPS paths at the final file sink

Create a disposable USB filesystem containing:

- a normal marker file;
- a symlink to another marker inside the USB root;
- a symlink to a synthetic canary in a sibling directory on the lab appliance;
- broken, relative, absolute, and chained-link controls.

Request only those markers through the documented USB HTTPS feature. Instrument or deny the final `open`-equivalent so the sibling canary is never read. Capture the requested path, mounted root, link chain, canonical final path, and allow/deny result.

| Entry | Lexically inside USB root | Final object inside root | Expected |
| --- | --- | --- | --- |
| Normal marker | yes | yes | allow |
| Internal symlink | yes | yes | policy-dependent |
| Relative escape link | yes | no | deny |
| Absolute link | yes | no | deny |
| Chained escape | yes | no | deny |

This proves a final-path confinement error without reading device secrets. Do not target configuration, password, certificate, provisioning, or system files.

## 5. Trace web input to the final process invocation

Use legitimate web requests to identify fields that reach command-backed appliance functions. Replace the execution function with a recorder, then submit an inert corpus covering spaces, quotes, separators, substitutions, newlines, option-looking prefixes, and encoding transitions. The recorder should preserve the exact final executable and argument vector or shell string while refusing execution.

Classify each flow:

- **structured argv preserved:** attacker data remains one non-option argument;
- **option injection:** a value becomes a new switch or changes command behavior;
- **shell grammar reached:** a wrapper reconstructs a shell command from attacker-controlled text;
- **rejected before sink:** validation blocks the value consistently across UI and API paths.

Do not run a shell marker, reverse shell, downloader, persistence action, or network callback. A final process trace that shows grammar or argument-boundary loss is sufficient evidence.

## Chain and reporting boundaries

The advisory cluster suggests a possible sequence from unauthenticated route access to privileged operation, configuration access, filesystem reach, or command execution. Do not report that as a complete chain unless every transition is independently observed on the same affected firmware and trust boundary.

Include:

- exact model, revision, firmware, region/provider customization, and lab topology;
- route/role/path/process decision tables with positive and negative controls;
- the final privileged sink reached or denied;
- redacted synthetic marker evidence;
- explicit separation between confirmed behavior and inferred chain impact.

## Sources

- [TP-Link: Multiple vulnerabilities in ISP-managed TP-Link networking products (CVE-2025-30237 to CVE-2025-30241)](https://www.tp-link.com/us/support/faq/5239/)
- [GHSA-gcr6-hgjr-2h8p / CVE-2025-30237](https://github.com/advisories/GHSA-gcr6-hgjr-2h8p)
- [GHSA-vhwm-f68v-4vg9 / CVE-2025-30238](https://github.com/advisories/GHSA-vhwm-f68v-4vg9)
- [GHSA-9f5f-7wxj-73g8 / CVE-2025-30239](https://github.com/advisories/GHSA-9f5f-7wxj-73g8)
- [GHSA-8vgw-m5fh-hwg3 / CVE-2025-30240](https://github.com/advisories/GHSA-8vgw-m5fh-hwg3)
- [GHSA-6v23-65fj-8g7c / CVE-2025-30241](https://github.com/advisories/GHSA-6v23-65fj-8g7c)