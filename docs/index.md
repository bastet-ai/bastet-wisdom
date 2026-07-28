---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Webhook and OAuth client trust boundaries](alerts/2026-07-28-webhook-oauth-client-trust-boundaries-ghsa.md)
- [Registry provenance and JWT purpose boundaries](alerts/2026-07-28-registry-provenance-jwt-purpose-boundaries-ghsa.md)
- [Workflow SSRF, CI evaluator, unpack, TLS, and redirect boundaries](alerts/2026-07-28-workflow-ci-unpack-tls-redirect-boundaries-ghsa.md)
- [Pocket ID refresh and reauthentication lifecycle boundaries](alerts/2026-07-27-identity-tenant-package-boundaries-ghsa.md)
- [WordPress nonce, pretix payment, and SICK device filesystem boundaries](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md)
- [Goal-driven agent fuzzing and variant-analysis campaigns](methodology/agent-guided-fuzzing-campaigns.md)
- [MCP exposure and WordPress identity, object, and restore-state boundaries](alerts/2026-07-28-mcp-wordpress-identity-restore-boundaries-ghsa.md)
- [zip-lib multi-stage symlink and path-prefix extraction boundary](alerts/2026-07-28-zip-lib-multi-stage-symlink-boundary-ghsa.md)
- [Kata container-to-guest virtio-pmem boundary](alerts/2026-07-28-kata-container-guest-pmem-boundary-ghsa.md)
- [Kubernetes proxy impersonation and agent-auth boundaries](alerts/2026-07-28-kubernetes-proxy-identity-boundaries-ghsa.md)















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
