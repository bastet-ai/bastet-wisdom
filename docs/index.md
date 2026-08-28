---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Yamcs StreamSQL Janino RCE, function-AC fail-open wave, and Phalcon router ReDoS](alerts/2026-08-28-yamcs-streamsql-janino-rce-and-funcac-fail-open-wave-ghsa.md)
- [Phalcon Volt `join` filter compile-time PHP code injection (GHSA-hrwp-4hh9-c8r8)](alerts/2026-08-28-phalcon-volt-join-filter-compile-time-code-injection-ghsa.md)
- [Klever KLV token-minting via royalty-overflow and marketplace TOCTOU](alerts/2026-08-28-klever-klv-token-minting-royalty-overflow-toctou-ghsa.md)
- [free5GC NRF NF-registration poisoning via unvalidated NF Profile endpoints](alerts/2026-08-28-free5gc-nrf-nf-registration-poisoning-ghsa.md)
- [SunEditor embed-plugin DOM XSS via script-element recreation (GHSA-w93q-cq9w-58p7)](alerts/2026-08-28-suneditor-embed-plugin-dom-xss-ghsa-w93q-cq9w-58p7.md)
- [Silverstripe email-field to code-execution cluster (userforms/advancedworkflow RCE + framework media-embed XSS)](alerts/2026-08-27-silverstripe-email-field-code-execution-cluster-ghsa.md)
- [Kyverno `generator.apply()` cross-namespace RoleBinding authority (CVE-2026-54523)](alerts/2026-08-27-kyverno-generator-apply-cross-namespace-authority-ghsa.md)
- [File-write and install-path escape batch (IzPack unpacker, libreoffice-convert, n8n-sqlite3 `db_path`, Crossplane cosign TOCTOU)](alerts/2026-08-27-file-write-and-install-path-escape-batch-ghsa.md)
- [Apache Camel inbound header-to-Exchange mapping and deserialization wave](alerts/2026-08-27-apache-camel-inbound-header-mapping-and-deserialization-wave-ghsa.md)
- [asyncssh SCP path-traversal and AuthorizedKeysFile username-escape](alerts/2026-08-27-asyncssh-scp-filename-and-authorizedkeys-username-escapes-ghsa.md)


































































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
