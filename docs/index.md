---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Assemblyline remote artifact identifier-to-file boundary](alerts/2026-08-05-workspace-fetch-object-interpreter-boundaries-ghsa.md#treat-remote-artifact-identifiers-as-paths-until-proven-otherwise)
- [Agent control-plane, tool-policy, file, and fetch authority boundaries](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md)
- [Quay mirror-fetch and VuFind handler-termination authority boundaries](alerts/2026-08-06-quay-mirror-vufind-handler-authority-boundaries-ghsa.md)
- [CRLF header-injection expansion for HTTP desync campaigns](methodology/http-desync-research-campaigns.md#crlf-header-injection-expansion)
- [Langflow validation, cache, memory, and filesystem authority follow-up](alerts/2026-06-19-langflow-mailpit-outerbase-miniflux-render-boundaries-ghsa.md#august-5-second-follow-up-validation-cache-memory-and-filesystem-authority)
- [Gitea migration and OAuth final-peer SSRF follow-up](alerts/2026-06-17-gitea-langchain4j-hapi-agent-websocket-boundary-batch-ghsa.md#august-5-gitea-migration-and-oauth-fetch-follow-up)
- [Traefik route, transport, and namespace authority boundaries](alerts/2026-08-05-traefik-route-transport-namespace-boundaries-ghsa.md)
- [Nuxt server-island component and DevTools RPC authority follow-up](alerts/2026-08-05-nuxt-route-payload-cache-boundaries-ghsa.md#august-5-follow-up-server-island-component-and-devtools-rpc-authority)
- [Nuxt route-rule and SSR payload-cache authority boundaries](alerts/2026-08-05-nuxt-route-payload-cache-boundaries-ghsa.md)
- [rclone encoding, archive, tenant-path, protocol, and redirect follow-up](alerts/2026-07-21-rclone-remote-control-boundaries-ghsa.md#august-5-second-follow-up-encoding-archive-tenant-path-protocol-and-redirect-boundaries)





















































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
