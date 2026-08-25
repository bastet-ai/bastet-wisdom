---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Gitea diff/patch git-hook installation KEV (CVE-2026-60004)](alerts/2026-08-25-gitea-diffpatch-git-hook-installation-kev-cve-2026-60004.md)
- [gRPC-Erlang wire-deserialization, transcoding, and body-boundary batch](alerts/2026-08-25-grpc-erlang-wire-deserialization-and-transcoding-boundary-batch-ghsa.md)
- [GitPython unsafe-option, config-reserialization, and merge-include boundaries](alerts/2026-08-25-gitpython-unsafe-option-and-config-reserialization-boundaries-ghsa.md)
- [Adminer DSN/ODBC injection, SQLite RCE, and admin-panel CSRF boundaries](alerts/2026-08-25-adminer-dsn-odbc-injection-and-sqlite-rce-boundaries-ghsa.md)
- [Grav sandbox-escape, privilege-validation, and host/origin trust boundaries](alerts/2026-08-25-grav-sandbox-escape-and-privilege-host-origin-boundaries-ghsa.md)
- [3X-UI authenticated log-path import to arbitrary file write and RCE](alerts/2026-08-24-3x-ui-xray-log-path-import-file-write-ghsa.md)
- [Cloudreve remote-download path-escape and context-hint share-revocation follow-up](alerts/2026-07-20-cloudreve-pillow-token-image-boundaries-ghsa.md#august-24-remote-download-path-escape-and-context-hint-revocation-follow-up)
- [ChromaDB tenant-authorization bypass and model-loading RCE wave](alerts/2026-08-24-chromadb-tenant-authorization-and-model-rce-ghsa.md)
- [django CMS page-cache Vary poisoning and plugin-tree cyclic-reparenting DoS](alerts/2026-08-24-django-cms-cache-vary-poisoning-and-cyclic-reparenting-ghsa.md)
- [Oracle WebLogic Proxy Plug-in improper access control KEV (CVE-2026-21962)](alerts/2026-08-24-oracle-weblogic-proxy-plug-in-improper-access-control-kev-cve-2026-21962.md)


































































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
