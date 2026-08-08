---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [MCP identifier lifecycle path-confinement testing](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#trace-one-identifier-across-every-file-lifecycle-operation)
- [MCP project and Git wrapper process-boundary testing](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#git-and-server-command-wrappers)
- [Calico tier-scoped DeleteCollection authorization](alerts/2026-08-08-calico-policy-debug-authority-boundaries-ghsa.md#2-compare-single-object-delete-with-deletecollection)
- [Calico pprof listener reachability without body capture](alerts/2026-08-08-calico-policy-debug-authority-boundaries-ghsa.md#3-treat-pprof-paths-as-privileged-process-state-capabilities)
- [Kiota OpenAPI install-guidance provenance testing](alerts/2026-07-24-kiota-codegen-deserialization-boundaries-ghsa.md#dependency-command-trust-handoff)
- [Calico HTTP prefix-policy normalization testing](alerts/2026-07-30-url-policy-tenant-oauth-boundaries-ghsa.md#calico-policy-to-backend-path-differential)
- [MCP PDF and chart wrapper argument validation](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#git-and-server-command-wrappers)
- [MCP argument-to-process wrapper validation](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#git-and-server-command-wrappers)
- [MCP journey identifier file-capability checks](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#journey-ids-and-filenames-are-file-capabilities)
- [WordPress file-to-provider and guest-upload authority](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#keep-local-file-selection-separate-from-provider-delivery)


























































## What lives here

- **Skills**: installable, tool-specific guides that agents can execute step by step
- **Recon**: workflows for turning scope into a prioritized asset map
- **Exploit Paths**: concrete attack chains that are specific enough to replay during authorized testing
- **Templates**: reusable report skeletons and delivery formats
- **Notes**: editorial guidance, taxonomy, and source tracking
- **Blog**: short updates when major skills or exploit paths land

Older alert and mitigation-oriented reference pages may remain in the repo, but the primary site surface is intentionally centered on pentesting, red-team, and bug-bounty operator workflows.

## How the skills are written

Each skill page is structured so it can be reused outside the wiki:

- When to use the tool
- Required inputs and prerequisites
- Command patterns worth reusing
- Expected outputs and what to capture
- Safety constraints and scope boundaries

!!! warning "Authorized use only"
    These pages are for lawful research, lab work, and authorized assessments. Do not apply them to systems you do not own or lack explicit permission to test.
