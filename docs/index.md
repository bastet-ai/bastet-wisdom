---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [MCE hub-controller label/name/URL-path cross-cluster authority follow-up](alerts/2026-05-07-cluster-control-plane-secret-and-impersonation-boundary-batch-ghsa.md#august-26-follow-up-mce-hub-controllers-derive-cross-cluster-authority-from-labels-names-and-url-paths)
- [DB-GPT unauthenticated skill-upload path-to-write primitive](alerts/2026-08-26-db-gpt-skill-upload-path-write-boundary-ghsa.md)
- [Apache Tomcat authorization, auth, and parser-boundary batch](alerts/2026-08-26-tomcat-authorization-auth-parser-boundary-batch-ghsa.md)
- [Spring Security DPoP proof cache-based replay](alerts/2026-08-26-spring-security-dpop-proof-replay-cache-batch-ghsa.md)
- [OpenStack Keystone delegated-auth scope-escape and credential-minting](alerts/2026-08-26-keystone-delegated-auth-scope-and-credential-minting-ghsa.md)
- [ClipBucket V5 installer shell execution and BlueZ crafted-EIR overflow](alerts/2026-08-26-clipbucket-installer-shell-and-bluez-eir-overflow-ghsa.md)
- [Gitea diff/patch git-hook installation KEV (CVE-2026-60004)](alerts/2026-08-25-gitea-diffpatch-git-hook-installation-kev-cve-2026-60004.md)
- [gRPC-Erlang wire-deserialization, transcoding, and body-boundary batch](alerts/2026-08-25-grpc-erlang-wire-deserialization-and-transcoding-boundary-batch-ghsa.md)
- [GitPython unsafe-option, config-reserialization, and merge-include boundaries](alerts/2026-08-25-gitpython-unsafe-option-and-config-reserialization-boundaries-ghsa.md)
- [Adminer DSN/ODBC injection, SQLite RCE, and admin-panel CSRF boundaries](alerts/2026-08-25-adminer-dsn-odbc-injection-and-sqlite-rce-boundaries-ghsa.md)


































































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
