---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Report-renderer fetch and desktop-updater trust boundaries](alerts/2026-08-03-report-renderer-updater-trust-boundaries-ghsa.md)
- [FlowIntel Vue interpolation and MFP document-object boundaries](alerts/2026-08-03-vue-mfp-render-object-boundaries-ghsa.md)
- [NLTK verify-before-write package integrity](alerts/2026-06-06-nltk-nicegui-picklescan-ml-archive-boundaries-ghsa.md#august-3-follow-up-verify-nltk-package-bytes-before-writing-or-extracting)
- [WordPress object, identity, upload, and role-selector checks](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#august-3-follow-up-cross-check-object-identity-upload-and-role-selectors)
- [Bouncy Castle certificate, signature, AEAD, and authenticated-content boundaries](alerts/2026-08-03-bouncy-castle-crypto-policy-boundaries-ghsa.md#august-3-follow-up-bind-every-authenticated-result-to-all-of-its-inputs)
- [Transformers named-chat-template file-write validation](alerts/2026-06-30-model-parser-deserialization-identity-boundaries-ghsa.md#august-2-transformers-named-chat-template-file-write-follow-up)
- [Vikunja principal-type and project/view authorization boundaries](alerts/2026-08-02-vikunja-principal-object-boundaries-ghsa.md)
- [ArcadeDB MCP principal, cluster-token, and trigger-authority checks](alerts/2026-07-16-arcadedb-nuclio-pheditor-boundaries-ghsa.md#august-2-arcadedb-mcp-principal-and-server-authority-follow-up)
- [Better Auth path-normalization and passkey-object checks](alerts/2026-07-07-better-auth-aider-netfoil-ckan-mcp-boundaries-ghsa.md#august-2-better-auth-path-and-passkey-object-follow-up)
- [FreeRDP media and clipboard memory-safety fixtures](alerts/2026-08-01-http-identity-router-rdp-boundaries-ghsa.md#august-2-freerdp-server-to-client-media-and-clipboard-follow-up)





































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
