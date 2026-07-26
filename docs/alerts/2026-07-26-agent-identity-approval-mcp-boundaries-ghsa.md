---
title: Agent identity, approval, MCP, and registration boundaries from July 26 GHSA updates
---

# Agent identity, approval, MCP, and registration boundaries from July 26 GHSA updates

A late July 26 GitHub advisory wave yields four reusable operator checks: mutable chat profile data treated as an allowlist identity, unauthenticated loopback callbacks supplying the identity used by an approval check, approval cards that omit execution-relevant fields, and low-privilege or anonymous routes reaching privileged MCP and device-registration actions.

Sources:

- [GHSA-6r3x-gc73-h69w / CVE-2026-17432: Hermes SimpleX authorization record](https://github.com/advisories/GHSA-6r3x-gc73-h69w)
- [Primary Hermes issue #44729](https://github.com/NousResearch/hermes-agent/issues/44729)
- [Hermes commit that introduced display-name matching](https://github.com/NousResearch/hermes-agent/commit/490c486ff65b766d9de0fe0e6f26e1778aaa8fb3)
- [GHSA-6frr-4xvp-cwch / CVE-2026-17433: NanoClaw loopback approval callback](https://github.com/advisories/GHSA-6frr-4xvp-cwch)
- [Primary NanoClaw issue #2761](https://github.com/nanocoai/nanoclaw/issues/2761)
- [GHSA-m5r3-634q-m3rj / CVE-2026-17434: NanoClaw MCP approval representation mismatch](https://github.com/advisories/GHSA-m5r3-634q-m3rj)
- [Primary NanoClaw issue #2762](https://github.com/nanocoai/nanoclaw/issues/2762)
- [NanoClaw fix PR #2998](https://github.com/nanocoai/nanoclaw/pull/2998)
- [GHSA-hp8g-g2qj-wgpj / CVE-2026-66012: SiYuan anonymous Publish-to-MCP chain](https://github.com/advisories/GHSA-hp8g-g2qj-wgpj)
- [Primary SiYuan advisory GHSA-cvhv-7xhj-xjp8](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-cvhv-7xhj-xjp8)
- [SiYuan authorization fix](https://github.com/siyuan-note/siyuan/commit/c72ca4cd09019e5f64afdee8f8c6ec5ef34858db)
- [GHSA-jg8p-j9v5-g5x5 / CVE-2026-66013: OpenRemote console registration](https://github.com/advisories/GHSA-jg8p-j9v5-g5x5)
- [Primary OpenRemote advisory GHSA-gpfc-h59v-63cv](https://github.com/openremote/openremote/security/advisories/GHSA-gpfc-h59v-63cv)

The GitHub records in this wave are unreviewed. There is a material versioning discrepancy for Hermes: the record labels release `2026.6.5` affected and describes commit `490c486...` as a patch, while the linked primary issues state that `v2026.6.5` is unaffected and that this commit **introduced** display-name matching on unreleased `main`. Treat the exact source revision and observed authorization decision—not the sparse record—as authoritative evidence.

!!! warning "Authorized validation only"
    Use synthetic contacts, disposable agent groups, inert pending approvals, fake MCP server values, temporary SiYuan workspaces, fake device tokens, and two-user labs. Never send commands to a production agent, approve a live shell/write/spend action, read real notes or credentials, install a plugin, overwrite a real notification token, or use another tenant's asset identifier.

## Build an identity-and-authority map

For every messaging or agent control surface, record these values separately:

| Boundary | Untrusted representation | Authority-bearing representation | Safe proof |
| --- | --- | --- | --- |
| Chat ingress | display name, handle, nickname | stable platform contact ID | allow/deny decision table |
| Loopback callback | JSON `user.id` | authenticated gateway or OS peer | inert pending approval remains/clears |
| Human approval | rendered card | complete stored payload and digest | visible-vs-applied field diff |
| MCP route | anonymous/reader session | tool-specific role and capability | harmless tool inventory or marker note |
| Device registration | request-supplied asset ID | asset owner/session binding | fake token update in two-user lab |

Do not collapse these into one generic “missing authorization” claim. The useful finding identifies where an attacker-controlled representation is first mistaken for authenticated identity or privileged authority.

## Hermes SimpleX: stable contact ID versus mutable display name

The primary Hermes issues trace a SimpleX `newChatItem` through the adapter into `SessionSource`. The adapter preserves the stable `contactId` as `user_id` but also copies mutable display-name data into `user_name`. An unreleased `main` change then adds `user_name` to the set that can satisfy `SIMPLEX_ALLOWED_USERS`.

### Reachability prerequisites

Confirm:

- the tested source revision contains the SimpleX display-name matching branch;
- the SimpleX gateway is enabled and reachable by the test contacts;
- `SIMPLEX_ALLOWED_USERS` contains a display name rather than only a stable contact ID;
- the second owned contact can choose the same display name;
- authorization gates an agent or tool path that matters to the engagement.

### Two-contact decision table

1. Create two disposable SimpleX contacts with distinct stable IDs.
2. Give both contacts the same harmless display-name canary.
3. Configure the lab gateway first with contact A's stable ID only.
4. Submit the same inert text message from both contacts and capture `user_id`, `user_name`, allowlist values, and the final authorization result.
5. Replace the allowlist with only the colliding display name and repeat.
6. Add controls for a non-colliding display name and the exact stable ID of contact B.

A positive result is **different authenticated contact ID + matching mutable display name -> authorization succeeds**. Stop at an inert message acknowledgement; do not invoke terminal, filesystem, browser, or external-service tools.

Report the tested commit range explicitly. Do not claim released `v2026.6.5` is vulnerable unless that tag independently reproduces the branch.

## NanoClaw: unauthenticated loopback approval identity

NanoClaw's gateway bridge can start a temporary webhook on `127.0.0.1`. The issue reports that the callback accepts a forwarded interaction body without a signature, bearer token, or peer binding, then passes body-supplied `interaction.user.id` to a downstream authorization check. The downstream comparison may be correct while its identity input is forged.

### Marker-only replay

1. Use a disposable NanoClaw instance with a canary agent group and one inert pending channel-registration approval.
2. Record the random loopback port and confirm the listener is reachable only from the local test context.
3. Submit a control interaction carrying an unrelated synthetic user ID; the approval must remain pending and group membership must not change.
4. Submit the same body with the expected approver's synthetic ID.
5. Capture the callback authentication state, parsed identity, authorization decision, pending-row state, and canary membership change.
6. Repeat against a fixed or instrumented build that requires a one-time secret, authenticated IPC peer, or signed gateway envelope.

The proof is **local untrusted process -> unsigned callback body -> forged approver identity -> inert pending action accepted**. Loopback binding reduces network exposure; it does not authenticate every local process or container sharing that network namespace.

## NanoClaw: bind approval display to the exact applied payload

The `add_mcp_server` issue describes a representation mismatch. The agent-controlled request contains `name`, `command`, `args`, and `env`; the vulnerable approval card showed only `name` and `command`; approval later persisted all four fields into runtime configuration.

### Approval-diff fixture

1. Instrument the MCP server apply/start boundary so it records configuration but never launches a process.
2. Submit a baseline request with a harmless command name, empty arguments, and empty environment.
3. Submit a second request with the same visible name/command plus a unique inert argument and fake environment marker.
4. Save the raw request, rendered approval card, stored approval payload, post-approval database row, materialized runtime config, and launch-recorder output.
5. Confirm whether the two requests look identical to the approver but apply different runtime configuration.
6. Repeat with the fix from PR #2998, which renders all fields, escapes invisible/fence-breaking content, bounds the card, and redacts secret-shaped values while retaining a fingerprint.

A valid result proves **execution-relevant field omitted from approval representation -> human approves incomplete view -> hidden field persists into the exact configuration later consumed**. Do not put real secrets in `env`; use a fake marker and do not start the MCP command.

Extend this test to tool approvals, workflow diffs, package installs, mounts, network destinations, cloud actions, and database queries. Compare the canonical object—not hand-built prose—to what is signed, stored, approved, and applied.

## SiYuan: anonymous Publish identity reaching workspace-wide MCP tools

The SiYuan record describes a cross-route chain: anonymous Publish mode causes a reverse proxy to attach a reader-role JWT, the kernel `/mcp` route applies only a general authentication check, and tool-level admin/read-only enforcement is absent. The dangerous outcome comes from the mismatch between the **reader identity minted by one subsystem** and the **capabilities accepted by another**.

### Bounded role/tool matrix

1. Create a temporary SiYuan workspace containing one unique canary note and no real account, sync, or plugin data.
2. Run separate fixtures for Publish disabled, Publish with authentication, and anonymous Publish.
3. For each fixture, test direct and Publish-proxied access as unauthenticated, reader, and admin identities.
4. Inventory only tool names and declared schemas first; do not invoke file-delete, rename, plugin, process, or broad workspace-read functions.
5. If authorization permits execution, invoke one harmless note/read operation scoped to the synthetic canary and one marker-only write inside the disposable workspace.
6. Capture the external route, proxy-added claims, kernel route decision, tool-level decision, and resulting marker.
7. Compare with v3.7.2 or the linked authorization fix.

The decisive evidence is **anonymous Publish request -> reader token added by proxy -> `/mcp` accepted -> a capability beyond reader intent performs a canary-only action**. Do not reproduce the published credential-read or plugin-execution chain; route, claims, tool inventory, and one disposable marker are sufficient.

## OpenRemote: create registration is not update authorization

The OpenRemote record reports that a console registration endpoint can update an existing console asset when given its identifier without authenticating or binding the request to the asset owner. This is a common device-enrollment flaw: a route intended to bootstrap a new console silently becomes an unauthenticated update primitive when an ID already exists.

### Two-user registration matrix

1. Create two synthetic tenants/users and one disposable console asset per principal.
2. Assign each asset a fake push token and unique metadata marker.
3. Replay the normal unauthenticated new-console registration with a fresh ID as a baseline.
4. Submit the same request shape with the existing ID of your second lab asset and a new fake token.
5. Query state only through the owning lab account and record whether token or metadata changed.
6. Test missing, random, same-owner, cross-owner, malformed, and duplicate IDs.
7. Repeat on 1.26.2 or the primary advisory's fixed revision.

A valid finding proves **unauthenticated registration input + known existing asset ID -> update path selected -> another synthetic owner's token/metadata changes**. Do not enumerate IDs, intercept notifications, or overwrite a production registration.

## Reporting checklist

Include:

- exact product version, commit, deployment mode, and affected route;
- attacker position: remote contact, local process, prompt-influenced agent, anonymous Publish user, or unauthenticated registrant;
- stable identity, mutable/display identity, proxy-added claims, and final authorization input;
- raw canonical payload, human-visible approval representation, stored payload, and applied configuration;
- complete allow/deny or role/tool decision tables with negative controls;
- marker-only state changes and a fixed-build comparison;
- source discrepancies, especially unreleased-versus-released version claims.

Keep impact bounded. A display-name collision is not a released-package flaw without revision evidence; a loopback callback requires local reachability; an incomplete card still requires human approval; an MCP route is only as impactful as the reachable tool set; and a known-ID update path is not ID enumeration unless a separate oracle is proven.