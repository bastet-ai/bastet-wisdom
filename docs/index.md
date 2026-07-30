---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [CentreStack token, session, API, storage-import, XML, and query boundaries](alerts/2026-07-30-centrestack-token-session-storage-boundaries-ghsa.md)
- [SSRF authority, Calico policy-path, tenant-object, and OAuth redirect boundaries](alerts/2026-07-30-url-policy-tenant-oauth-boundaries-ghsa.md)
- [Spring JavaScript escaping boundary](alerts/2026-07-30-spring-web-resource-session-boundaries-ghsa.md#javascript-escaping-follow-up)
- [OpenCost Helm-values disclosure and unset-token checks](alerts/2026-07-14-kimai-facturascripts-auth-boundaries-ghsa.md#july-30-opencost-helm-values-disclosure-follow-up)
- [Spring Web versioned-resource traversal, shared-cache, and session-rotation boundaries](alerts/2026-07-30-spring-web-resource-session-boundaries-ghsa.md)
- [flyto-core outbound authority, environment, and file-write parity checks](alerts/2026-07-06-flyto-mcp-ssrf-boundaries-ghsa.md#july-30-follow-up-outbound-authority-secret-and-file-write-parity)
- [MCP Ruby session-ownership and browser-origin transport checks](alerts/2026-07-29-mcp-package-url-config-boundaries-ghsa.md#july-30-mcp-ruby-transport-follow-up)
- [OliveTin shell-type and synchronous-output authorization checks](alerts/2026-06-24-olivetin-openam-concrete-boundaries-ghsa.md#july-30-olivetin-shell-type-and-synchronous-output-follow-up)
- [Kubernetes credential relay, proxy certificate identity, and ACME fetch boundaries](alerts/2026-07-30-kubernetes-credential-relay-proxy-identity-acme-boundaries-ghsa.md)
- [Uniswap v4 hook authorization, pool-identity, accounting, and callback boundaries](methodology/uniswap-v4-hook-boundary-testing.md)
- [OpenSSH client-side X11 abstract-socket binding boundary](alerts/2026-07-30-openssh-x11-socket-binding-boundary-ghsa.md)

























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
