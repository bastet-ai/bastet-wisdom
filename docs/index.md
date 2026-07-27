---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Hostname, LAN transfer, and template-runtime boundaries](alerts/2026-07-27-hostname-lan-transfer-template-runtime-boundaries-ghsa.md)
- [pay-uz unauthenticated executable-hook write boundary](alerts/2026-07-27-pay-uz-executable-hook-write-boundary-ghsa.md)
- [Directory, cluster, agent-fetch, and signed-document boundaries](alerts/2026-07-27-directory-cluster-agent-document-boundaries-ghsa.md)
- [WordPress identity, token, route, and file-write boundaries](alerts/2026-07-27-wordpress-identity-token-route-boundaries-ghsa.md)
- [Agent identity, approval, MCP, and registration boundaries](alerts/2026-07-26-agent-identity-approval-mcp-boundaries-ghsa.md)
- [datamodel-code-generator `customBasePath` follow-up](alerts/2026-07-24-kiota-codegen-deserialization-boundaries-ghsa.md#july-26-follow-up-json-schema-custombasepath-to-generated-python-import)
- [NoteGen skill-to-chat-render-to-desktop-shell boundary chain](alerts/2026-07-26-notegen-skill-render-shell-chain-ghsa.md)
- [Browser navigation and static-root canonicalization boundaries](alerts/2026-07-26-browser-navigation-static-root-boundaries-ghsa.md)
- [Agent, filesystem, prompt, and HTTP boundary checks](alerts/2026-07-24-agent-filesystem-prompt-http-boundaries-ghsa.md)
- [Bedrock AgentCore package delimiter follow-up](alerts/2026-06-19-framework-report-iac-mcp-cms-package-boundaries-ghsa.md#july-24-delimiter-neutralization-follow-up)












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
