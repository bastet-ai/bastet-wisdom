---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Traefik route, transport, and namespace authority boundaries](alerts/2026-08-05-traefik-route-transport-namespace-boundaries-ghsa.md)
- [Nuxt server-island component and DevTools RPC authority follow-up](alerts/2026-08-05-nuxt-route-payload-cache-boundaries-ghsa.md#august-5-follow-up-server-island-component-and-devtools-rpc-authority)
- [Nuxt route-rule and SSR payload-cache authority boundaries](alerts/2026-08-05-nuxt-route-payload-cache-boundaries-ghsa.md)
- [rclone encoding, archive, tenant-path, protocol, and redirect follow-up](alerts/2026-07-21-rclone-remote-control-boundaries-ghsa.md#august-5-second-follow-up-encoding-archive-tenant-path-protocol-and-redirect-boundaries)
- [HTTP desync research campaigns](methodology/http-desync-research-campaigns.md)
- [rclone path, symlink, and metadata boundary follow-up](alerts/2026-07-21-rclone-remote-control-boundaries-ghsa.md#august-5-follow-up-untrusted-remote-filesystem-boundaries)
- [Jenkins and MarkLogic authority-boundary validation](alerts/2026-08-05-jenkins-marklogic-authority-boundaries-ghsa.md)
- [Langflow provider, MCP, environment, and host-authority follow-up](alerts/2026-06-19-langflow-mailpit-outerbase-miniflux-render-boundaries-ghsa.md#august-5-provider-mcp-environment-and-host-authority-follow-up)
- [Keycloak CIBA, JWE request-object, and parameter-precedence follow-up](alerts/2026-06-04-keycloak-mlflow-auth-boundary-batch-ghsa.md#august-5-ciba-jwe-request-object-and-parameter-precedence-follow-up)
- [TeamCity agent-polling protocol authority validation](alerts/2026-08-05-teamcity-agent-polling-authority-cve-2026-63077.md)


















































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
