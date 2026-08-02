---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [WordPress object, identity-proof, delegated-API, and render boundaries](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#august-2-follow-up-bind-every-proof-selector-and-delegated-capability-to-one-object)
- [Keycloak client-policy and delegated-admin lifecycle differentials](alerts/2026-06-11-kolibri-hapi-keycloak-flowise-arc-boundary-batch-ghsa.md#august-2-keycloak-client-policy-and-delegated-admin-follow-up)
- [Keras HDF5 external-link file-authority validation](alerts/2026-06-30-model-parser-deserialization-identity-boundaries-ghsa.md#august-2-keras-hdf5-external-link-file-authority-follow-up)
- [Privileged PID-file symlink boundary validation](alerts/2026-08-01-privileged-pidfile-symlink-boundary-ghsa.md)
- [HTTP client, identity, router, CI, and RDP boundary checks](alerts/2026-08-01-http-identity-router-rdp-boundaries-ghsa.md)
- [AI dataset deserialization, scheduler fetch, and stale-session boundaries](alerts/2026-08-01-ai-scheduler-session-boundaries-ghsa.md)
- [File-browser subtitle, agent file, and GraphQL recovery boundaries](alerts/2026-07-31-file-agent-graphql-boundaries-ghsa.md)
- [Template, CMS, token, model, signature, and HTTP-proxy trust boundaries](alerts/2026-07-31-template-cms-token-model-proxy-boundaries-ghsa.md)
- [Low-code SQL, CMS upload, SOAP code generation, and survey trust boundaries](alerts/2026-07-31-low-code-cms-soap-survey-boundaries-ghsa.md)
- [Editor sanitizer, image proxy, pgAdmin, and automation event boundaries](alerts/2026-07-31-editor-image-database-automation-boundaries-ghsa.md)


































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
