---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [PaperCut NG/MF unauth auth-bypass → RCE chain: KEV, actively exploited (CVE-2026-82078 + CVE-2026-81578)](alerts/2026-08-31-papercut-ngmf-auth-bypass-to-rce-kev-cve-2026-82078-cve-2026-81578.md)
- [MariaDB connector multi-byte-charset SQL injection, cleartext auth-plugin leak, and charset-confusion boundaries (8 GHSAs)](alerts/2026-08-31-mariadb-connector-charset-sqli-and-cleartext-auth-boundaries-ghsa.md)
- [vm2 sandbox breakout via indirect-call dangerous-mutator shadowing (GHSA-cfcw-xp6x-25gj / CVE-2026-47698)](alerts/2026-08-31-vm2-indirect-call-mutator-sandbox-breakout-ghsa.md)
- [Piccolo-Admin superuser escalation via session-token disclosure on read-only CRUD routes (GHSA-2gh4-jmwq-rr8w)](alerts/2026-08-30-piccolo-admin-session-token-disclosure-superuser-escalation-ghsa.md)
- [RestrictedPython guard-hook shadowing via positional-only arguments (GHSA-ffg3-p8fm-mjx2 / CVE-2026-55830)](alerts/2026-08-30-restrictedpython-guard-hook-shadowing-sandbox-escape-ghsa.md)
- [Keycloak unauthenticated account takeover via reset-credentials flow bypass (CVE-2026-18963)](alerts/2026-08-29-keycloak-unauth-ato-reset-credentials-flow-bypass-ghsa.md)
- [Apache Camel header-filter bypass follow-up wave (30 GHSAs)](alerts/2026-08-27-apache-camel-inbound-header-mapping-and-deserialization-wave-ghsa.md#august-29-follow-up-camel-header-filter-bypass-wave-30-ghsas)
- [Pimcore DataObject RCE, Hotspotimage PHP deserialization, Studio SQLi, and reset-URL ATO (5 GHSAs)](alerts/2026-08-28-pimcore-dataobject-rce-sqli-and-reset-url-ato-ghsa.md)
- [9router unauthenticated LLM-proxy access: Host-header spoofing and /codex rewrite bypass (2 GHSAs)](alerts/2026-08-28-9router-unauth-llm-proxy-host-and-codex-rewrite-bypass-ghsa.md)
- [Yamcs StreamSQL Janino RCE, function-AC fail-open wave, and Phalcon router ReDoS](alerts/2026-08-28-yamcs-streamsql-janino-rce-and-funcac-fail-open-wave-ghsa.md)


































































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
