---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Koollab LMS and WordPress identity, workflow, and callback boundaries](alerts/2026-07-29-koollab-wordpress-identity-workflow-boundaries-ghsa.md)
- [Undertow, Rust, and Apache Traffic Server proxy-parser boundaries](alerts/2026-06-11-undertow-proxy-parser-request-smuggling-boundary-ghsa.md)
- [WordPress import-upload and plugin-provenance boundaries](alerts/2026-07-29-wordpress-import-plugin-provenance-boundaries-ghsa.md)
- [WordPress role, nonce, payment-response, and device filesystem boundaries](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md)
- [Agent skill supply-chain testing](methodology/agent-skill-supply-chain-testing.md)
- [Kiota and datamodel-code-generator source, fetch, and file boundaries](alerts/2026-07-24-kiota-codegen-deserialization-boundaries-ghsa.md)
- [Ghost, goshs, and export file-boundary checks](alerts/2026-07-02-ghost-goshs-export-boundaries-ghsa.md)
- [NocoBase SQL-scope and Cosmos proxy-identity boundaries](alerts/2026-07-28-nocobase-cosmos-data-identity-boundaries-ghsa.md)
- [Litestar and Fission builder boundary checks](alerts/2026-06-10-litestar-fission-builder-boundary-batch-ghsa.md)
- [Axis2 cluster-channel and OpenShift WMCO node-identity boundaries](alerts/2026-07-28-axis2-wmco-cluster-identity-boundaries-ghsa.md)


















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
