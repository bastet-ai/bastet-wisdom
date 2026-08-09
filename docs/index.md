---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [MCP path authority by read, write, replace, and delete operation](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#map-path-authority-by-operation-not-by-parameter-name)
- [Server-rendered text to Vue runtime-compiler boundary testing](alerts/2026-08-03-report-renderer-updater-trust-boundaries-ghsa.md#vue-mount-boundaries-test-the-browsers-second-interpretation)
- [MCP project-name to recursive-scan-root confinement testing](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#treat-project-names-as-recursive-scan-capabilities)
- [Flowise final-peer SSRF destination and redirect testing](alerts/2026-08-04-flowise-workspace-runtime-credential-boundaries-ghsa.md#23-validate-destination-classes-and-redirects-at-the-final-peer)
- [MCP identifier lifecycle path-confinement testing](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#trace-one-identifier-across-every-file-lifecycle-operation)
- [MCP project and Git wrapper process-boundary testing](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#git-and-server-command-wrappers)
- [Calico tier-scoped DeleteCollection authorization](alerts/2026-08-08-calico-policy-debug-authority-boundaries-ghsa.md#2-compare-single-object-delete-with-deletecollection)
- [Calico pprof listener reachability without body capture](alerts/2026-08-08-calico-policy-debug-authority-boundaries-ghsa.md#3-treat-pprof-paths-as-privileged-process-state-capabilities)
- [Kiota OpenAPI install-guidance provenance testing](alerts/2026-07-24-kiota-codegen-deserialization-boundaries-ghsa.md#dependency-command-trust-handoff)
- [Calico HTTP prefix-policy normalization testing](alerts/2026-07-30-url-policy-tenant-oauth-boundaries-ghsa.md#calico-policy-to-backend-path-differential)





























































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
