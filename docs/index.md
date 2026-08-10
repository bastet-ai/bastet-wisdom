---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Apache Ranger connector, download, token, script, and privilege authority](alerts/2026-08-10-apache-ranger-control-plane-authority-boundaries-ghsa.md)
- [GNU cpio absolute hard-link target validation](best-practices/archive-extraction-symlink-traversal.md#gnu-cpio-absolute-hard-link-target-matrix)
- [WordPress authentication, reset, fetch, file, booking, and commerce authority](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#august-10-follow-up-bind-authentication-fetch-file-and-commerce-authority-at-the-final-sink)
- [MCP article/model/proxy final-peer and document/session path authority](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#apply-final-peer-enforcement-to-mcp-url-and-uri-capabilities)
- [NLTK RFC 6598 strict-mode SSRF destination testing](alerts/2026-07-31-library-tenant-commerce-file-boundaries-ghsa.md#nltk-special-use-destination-matrix)
- [WordPress alternate-route, management-proof, query-selector, and cart authority](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#august-9-follow-up-bind-alternate-routes-remote-management-proofs-and-selectors-to-final-authority)
- [MCP path authority by read, write, replace, and delete operation](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#map-path-authority-by-operation-not-by-parameter-name)
- [Server-rendered text to Vue runtime-compiler boundary testing](alerts/2026-08-03-report-renderer-updater-trust-boundaries-ghsa.md#vue-mount-boundaries-test-the-browsers-second-interpretation)
- [MCP project-name to recursive-scan-root confinement testing](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#treat-project-names-as-recursive-scan-capabilities)
- [Flowise final-peer SSRF destination and redirect testing](alerts/2026-08-04-flowise-workspace-runtime-credential-boundaries-ghsa.md#23-validate-destination-classes-and-redirects-at-the-final-peer)

































































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
