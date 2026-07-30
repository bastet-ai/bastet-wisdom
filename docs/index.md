---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [CHARX EV charging controller service, backend, firmware, and privilege boundaries](alerts/2026-07-30-charx-ev-charging-control-boundaries-ghsa.md)
- [WordPress payment, workflow-state, registration, identity, and client-IP boundaries](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#july-30-follow-up-bind-public-workflow-state-to-server-authority)
- [VaahCMS template supply-chain and browser-execution boundaries](alerts/2026-07-30-vaahcms-template-supply-chain-boundary-ghsa.md)
- [WebSphere/Liberty proxy-parser request-smuggling boundary](alerts/2026-06-11-undertow-proxy-parser-request-smuggling-boundary-ghsa.md#july-30-ibm-websphere-and-liberty-follow-up)
- [GitLab CI, import, AI, and project-authorization boundaries](alerts/2026-07-29-gitlab-ci-ai-import-boundaries-ghsa.md)
- [MCP session, package-index path, URL-parser, and generated-config boundaries](alerts/2026-07-29-mcp-package-url-config-boundaries-ghsa.md)
- [Agent confirmation, Unicode archive, and control-plane identity boundaries](alerts/2026-07-29-agent-archive-control-plane-boundaries-ghsa-kev.md)
- [Spring LDAP, WebSocket, and HATEOAS identity-binding boundaries](alerts/2026-07-29-spring-identity-binding-boundaries-ghsa.md)
- [Easy!Appointments object, OAuth, and CalDAV boundaries](alerts/2026-07-29-easyappointments-object-oauth-ssrf-boundaries-ghsa.md)
- [Logging configuration, tenant storage, and proot restore boundaries](alerts/2026-07-29-logging-storage-proot-boundaries-ghsa.md)























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
