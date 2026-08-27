---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Silverstripe email-field to code-execution cluster (userforms/advancedworkflow RCE + framework media-embed XSS)](alerts/2026-08-27-silverstripe-email-field-code-execution-cluster-ghsa.md)
- [Kyverno `generator.apply()` cross-namespace RoleBinding authority (CVE-2026-54523)](alerts/2026-08-27-kyverno-generator-apply-cross-namespace-authority-ghsa.md)
- [File-write and install-path escape batch (IzPack unpacker, libreoffice-convert, n8n-sqlite3 `db_path`, Crossplane cosign TOCTOU)](alerts/2026-08-27-file-write-and-install-path-escape-batch-ghsa.md)
- [Apache Camel inbound header-to-Exchange mapping and deserialization wave](alerts/2026-08-27-apache-camel-inbound-header-mapping-and-deserialization-wave-ghsa.md)
- [asyncssh SCP path-traversal and AuthorizedKeysFile username-escape](alerts/2026-08-27-asyncssh-scp-filename-and-authorizedkeys-username-escapes-ghsa.md)
- [Senaite LIMS unauthenticated eval injection (CVE-2026-54569)](alerts/2026-08-27-senaite-lims-unauthenticated-eval-injection-ghsa.md)
- [MCE hub-controller label/name/URL-path cross-cluster authority follow-up](alerts/2026-05-07-cluster-control-plane-secret-and-impersonation-boundary-batch-ghsa.md#august-26-follow-up-mce-hub-controllers-derive-cross-cluster-authority-from-labels-names-and-url-paths)
- [DB-GPT unauthenticated skill-upload path-to-write primitive](alerts/2026-08-26-db-gpt-skill-upload-path-write-boundary-ghsa.md)
- [Apache Tomcat authorization, auth, and parser-boundary batch](alerts/2026-08-26-tomcat-authorization-auth-parser-boundary-batch-ghsa.md)
- [Spring Security DPoP proof cache-based replay](alerts/2026-08-26-spring-security-dpop-proof-replay-cache-batch-ghsa.md)


































































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
