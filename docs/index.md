---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Odysseus embedding endpoint authority boundaries](alerts/2026-08-05-odysseus-embedding-endpoint-authority-boundaries-ghsa.md)
- [Flowise workspace, runtime, and credential-authority boundaries](alerts/2026-08-04-flowise-workspace-runtime-credential-boundaries-ghsa.md)
- [Ghost fetch, upload, import, and offer-state boundaries](alerts/2026-08-04-ghost-fetch-upload-import-offer-boundaries-ghsa.md)
- [Agent tool, browser action, and stored-query boundaries](alerts/2026-08-04-agent-tool-render-stored-query-boundaries.md)
- [Open WebUI DNS, inline-model knowledge, and cleanup-parent checks](alerts/2026-05-16-open-webui-rag-ssrf-and-knowledge-boundary-batch-ghsa.md#august-4-follow-up-bind-dns-decisions-inline-models-and-cleanup-children)
- [Open WebUI transport-role, shared-folder, tool-source, and render-error checks](alerts/2026-05-16-open-webui-auth-session-and-api-authorization-boundary-batch-ghsa.md#august-4-follow-up-test-every-transport-grant-tier-cascade-and-error-renderer)
- [Open WebUI browser-loader, NAT64, and Vega request boundaries](alerts/2026-05-16-open-webui-rag-ssrf-and-knowledge-boundary-batch-ghsa.md#august-4-follow-up-normalize-transition-addresses-and-intercept-every-browser-request)
- [Open WebUI OAuth-client and terminal-preview origin boundaries](alerts/2026-05-16-open-webui-auth-session-and-api-authorization-boundary-batch-ghsa.md#august-4-follow-up-bind-bearer-proofs-to-the-client-and-preview-origin)
- [Open WebUI alternate image path and message-authorship checks](alerts/2026-05-08-open-webui-model-channel-and-knowledge-boundary-batch-ghsa.md#august-4-follow-up-alternate-feature-paths-and-message-authorship)
- [Notebook, data-server, OPC UA, and proxy trust boundaries](alerts/2026-08-04-notebook-data-opcua-proxy-boundaries-ghsa.md)












































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
