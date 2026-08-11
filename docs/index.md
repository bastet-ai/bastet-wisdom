---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Server import, connector, and device API authority testing](alerts/2026-08-11-server-import-connector-device-authority-boundaries-ghsa.md)
- [mcp-grafana override-header final-peer testing](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#august-11-follow-up-override-headers-are-destination-capabilities)
- [OpenShift AI dashboard internal-listener identity testing](alerts/2026-08-10-ai-feature-control-plane-tenant-boundaries-ghsa.md#august-11-follow-up-bind-dashboard-identity-to-the-authenticated-listener)
- [SAP edge session, tenant, callback, WebSocket, and backend authority testing](alerts/2026-08-11-sap-edge-session-tenant-authority-boundaries-ghsa.md)
- [TP-Link Aginet route, role, firmware-key, USB-path, and command authority testing](alerts/2026-08-11-tplink-aginet-appliance-authority-boundaries-ghsa.md)
- [AI feature-store and cluster control-plane tenant testing](alerts/2026-08-10-ai-feature-control-plane-tenant-boundaries-ghsa.md)
- [Airflow team-scoped secrets-backend fallback testing](alerts/2026-06-30-ai-artifact-airflow-boundaries-ghsa.md#august-10-follow-up-bind-secrets-backend-fallback-to-the-active-team)
- [Flowise anonymous private Assistants-file authority testing](alerts/2026-08-04-flowise-workspace-runtime-credential-boundaries-ghsa.md#24-bind-anonymous-download-routes-to-public-objects-and-file-ownership)
- [Hugging Face Accelerate checkpoint-shard path testing](alerts/2026-06-30-model-parser-deserialization-identity-boundaries-ghsa.md#august-10-follow-up-bind-sharded-checkpoint-entries-to-the-checkpoint-root)
- [Python `unearth` archive traversal and symlink composition](best-practices/archive-extraction-symlink-traversal.md#python-unearth-traversal-and-symlink-composition-follow-up)


































































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
