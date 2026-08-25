---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [3X-UI authenticated log-path import to arbitrary file write and RCE](alerts/2026-08-24-3x-ui-xray-log-path-import-file-write-ghsa.md)
- [Cloudreve remote-download path-escape and context-hint share-revocation follow-up](alerts/2026-07-20-cloudreve-pillow-token-image-boundaries-ghsa.md#august-24-remote-download-path-escape-and-context-hint-revocation-follow-up)
- [Mattermost federated shared-channel file-sync path traversal (CVE-2026-6961)](alerts/2026-06-01-mattermost-shared-channel-ai-secret-boundary-batch-ghsa.md#federated-shared-channel-file-sync-path-traversal-check)
- [ChromaDB tenant-authorization bypass and model-loading RCE wave](alerts/2026-08-24-chromadb-tenant-authorization-and-model-rce-ghsa.md)
- [django CMS page-cache Vary poisoning and plugin-tree cyclic-reparenting DoS](alerts/2026-08-24-django-cms-cache-vary-poisoning-and-cyclic-reparenting-ghsa.md)
- [Oracle WebLogic Proxy Plug-in improper access control KEV (CVE-2026-21962)](alerts/2026-08-24-oracle-weblogic-proxy-plug-in-improper-access-control-kev-cve-2026-21962.md)
- [GitLab package-registry traversal and docker-socket-proxy read-endpoint boundaries](alerts/2026-08-23-gitlab-registry-traversal-and-docker-socket-proxy-read-gating-ghsa.md)
- [WordPress registration role, permission-filter, and invoice-file selector follow-up](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#august-23-follow-up-bind-registration-role-selection-permission-filter-rewrites-and-invoice-file-selectors-to-final-authority)
- [TrueConf server 4307/TCP authority and sandbox-breakout validation (KEV)](alerts/2026-08-21-trueconf-server-kev-boundaries.md)
- [JSONata expression sandbox escape and arbitrary-code-execution boundaries](alerts/2026-08-22-jsonata-expression-sandbox-escape-code-execution-ghsa.md)


































































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
