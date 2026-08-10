---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Archive creation and extraction symlink authority testing](best-practices/archive-extraction-symlink-traversal.md#archive-creation-and-extraction-need-separate-link-checks)
- [Cross-hub CloudEvent identity and migration-topic audience testing](alerts/2026-05-07-cluster-control-plane-secret-and-impersonation-boundary-batch-ghsa.md#august-10-follow-up-bind-cross-hub-messages-and-migration-material-to-the-authenticated-hub)
- [Unicode-dot TLS and document/workflow authority testing](alerts/2026-08-10-hostname-document-workflow-authority-boundaries-ghsa.md)
- [CTI graph and raw-object HTML-resolver sink inventory](alerts/2026-08-03-report-renderer-updater-trust-boundaries-ghsa.md#graph-and-raw-object-viewers-enumerate-every-html-resolver)
- [OpenCart extension-installer extraction boundary](best-practices/archive-extraction-symlink-traversal.md#opencart-extension-installer-extraction-boundary)
- [Apache Ranger connector, download, token, script, and privilege authority](alerts/2026-08-10-apache-ranger-control-plane-authority-boundaries-ghsa.md)
- [GNU cpio absolute hard-link target validation](best-practices/archive-extraction-symlink-traversal.md#gnu-cpio-absolute-hard-link-target-matrix)
- [WordPress authentication, reset, fetch, file, booking, and commerce authority](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#august-10-follow-up-bind-authentication-fetch-file-and-commerce-authority-at-the-final-sink)
- [MCP article/model/proxy final-peer and document/session path authority](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#apply-final-peer-enforcement-to-mcp-url-and-uri-capabilities)
- [NLTK RFC 6598 strict-mode SSRF destination testing](alerts/2026-07-31-library-tenant-commerce-file-boundaries-ghsa.md#nltk-special-use-destination-matrix)

































































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
