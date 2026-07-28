---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Goal-driven agent fuzzing and variant-analysis campaigns](methodology/agent-guided-fuzzing-campaigns.md)
- [MCP exposure and WordPress identity, object, and restore-state boundaries](alerts/2026-07-28-mcp-wordpress-identity-restore-boundaries-ghsa.md)
- [zip-lib multi-stage symlink and path-prefix extraction boundary](alerts/2026-07-28-zip-lib-multi-stage-symlink-boundary-ghsa.md)
- [Kata container-to-guest virtio-pmem boundary](alerts/2026-07-28-kata-container-guest-pmem-boundary-ghsa.md)
- [Kubernetes proxy impersonation and agent-auth boundaries](alerts/2026-07-28-kubernetes-proxy-identity-boundaries-ghsa.md)
- [Joomla Regular Labs code, AJAX, database, and client-IP boundaries](alerts/2026-07-28-joomla-regular-labs-extension-boundaries-ghsa.md)
- [VeloCloud Orchestrator internal-function command boundary](alerts/2026-07-27-velocloud-orchestrator-internal-function-command-boundary-kev.md)
- [Identity, tenant, webhook, and package boundaries](alerts/2026-07-27-identity-tenant-package-boundaries-ghsa.md)
- [Hostname, LAN transfer, and template-runtime boundaries](alerts/2026-07-27-hostname-lan-transfer-template-runtime-boundaries-ghsa.md)
- [pay-uz unauthenticated executable-hook write boundary](alerts/2026-07-27-pay-uz-executable-hook-write-boundary-ghsa.md)













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
