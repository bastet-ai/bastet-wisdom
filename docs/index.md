---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Template, signing-key, upload, and alternate-route authority boundaries](alerts/2026-08-05-template-key-route-authority-boundaries-ghsa.md)
- [Ghost filter, caption, and feature-fetch follow-up](alerts/2026-08-04-ghost-fetch-upload-import-offer-boundaries-ghsa.md#august-5-follow-up-filters-captions-and-feature-specific-fetchers)
- [Workspace, outbound-fetch, object-scope, and interpreter boundaries](alerts/2026-08-05-workspace-fetch-object-interpreter-boundaries-ghsa.md)
- [AWS Nitro Enclave KMS boundary testing](methodology/aws-nitro-enclave-kms-boundary-testing.md)
- [Route, trusted-context, and controller-authority boundaries](alerts/2026-08-05-route-context-controller-authority-boundaries-ghsa.md)
- [Signed-request, object-scope, and WordPress authority boundaries](alerts/2026-08-05-signed-request-object-scope-wordpress-authority-boundaries-ghsa.md)
- [CPython archive relocation and platform-path validation](best-practices/archive-extraction-symlink-traversal.md#cpython-relocation-and-platform-path-matrix)
- [Odysseus embedding endpoint authority boundaries](alerts/2026-08-05-odysseus-embedding-endpoint-authority-boundaries-ghsa.md)
- [Flowise workspace, runtime, and credential-authority boundaries](alerts/2026-08-04-flowise-workspace-runtime-credential-boundaries-ghsa.md)
- [Ghost fetch, upload, import, and offer-state boundaries](alerts/2026-08-04-ghost-fetch-upload-import-offer-boundaries-ghsa.md)
- [Agent tool, browser action, and stored-query boundaries](alerts/2026-08-04-agent-tool-render-stored-query-boundaries.md)
















































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
