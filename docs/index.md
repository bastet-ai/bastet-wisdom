---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Joomla Regular Labs code, AJAX, database, and client-IP boundaries](alerts/2026-07-28-joomla-regular-labs-extension-boundaries-ghsa.md)
- [VeloCloud Orchestrator internal-function command boundary](alerts/2026-07-27-velocloud-orchestrator-internal-function-command-boundary-kev.md)
- [Identity, tenant, webhook, and package boundaries](alerts/2026-07-27-identity-tenant-package-boundaries-ghsa.md)
- [Hostname, LAN transfer, and template-runtime boundaries](alerts/2026-07-27-hostname-lan-transfer-template-runtime-boundaries-ghsa.md)
- [pay-uz unauthenticated executable-hook write boundary](alerts/2026-07-27-pay-uz-executable-hook-write-boundary-ghsa.md)
- [Directory, cluster, agent-fetch, and signed-document boundaries](alerts/2026-07-27-directory-cluster-agent-document-boundaries-ghsa.md)
- [WordPress identity, token, route, and file-write boundaries](alerts/2026-07-27-wordpress-identity-token-route-boundaries-ghsa.md)
- [Agent identity, approval, MCP, and registration boundaries](alerts/2026-07-26-agent-identity-approval-mcp-boundaries-ghsa.md)
- [datamodel-code-generator `customBasePath` follow-up](alerts/2026-07-24-kiota-codegen-deserialization-boundaries-ghsa.md#july-26-follow-up-json-schema-custombasepath-to-generated-python-import)
- [NoteGen skill-to-chat-render-to-desktop-shell boundary chain](alerts/2026-07-26-notegen-skill-render-shell-chain-ghsa.md)













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
