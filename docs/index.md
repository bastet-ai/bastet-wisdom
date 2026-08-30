---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Keycloak unauthenticated account takeover via reset-credentials flow bypass (CVE-2026-18963)](alerts/2026-08-29-keycloak-unauth-ato-reset-credentials-flow-bypass-ghsa.md)
- [Apache Camel header-filter bypass follow-up wave (30 GHSAs)](alerts/2026-08-27-apache-camel-inbound-header-mapping-and-deserialization-wave-ghsa.md#august-29-follow-up-camel-header-filter-bypass-wave-30-ghsas)
- [Pimcore DataObject RCE, Hotspotimage PHP deserialization, Studio SQLi, and reset-URL ATO (5 GHSAs)](alerts/2026-08-28-pimcore-dataobject-rce-sqli-and-reset-url-ato-ghsa.md)
- [9router unauthenticated LLM-proxy access: Host-header spoofing and /codex rewrite bypass (2 GHSAs)](alerts/2026-08-28-9router-unauth-llm-proxy-host-and-codex-rewrite-bypass-ghsa.md)
- [Yamcs StreamSQL Janino RCE, function-AC fail-open wave, and Phalcon router ReDoS](alerts/2026-08-28-yamcs-streamsql-janino-rce-and-funcac-fail-open-wave-ghsa.md)
- [Phalcon Volt `join` filter compile-time PHP code injection (GHSA-hrwp-4hh9-c8r8)](alerts/2026-08-28-phalcon-volt-join-filter-compile-time-code-injection-ghsa.md)
- [Klever KLV token-minting via royalty-overflow and marketplace TOCTOU](alerts/2026-08-28-klever-klv-token-minting-royalty-overflow-toctou-ghsa.md)
- [free5GC NRF NF-registration poisoning via unvalidated NF Profile endpoints](alerts/2026-08-28-free5gc-nrf-nf-registration-poisoning-ghsa.md)
- [SunEditor embed-plugin DOM XSS via script-element recreation (GHSA-w93q-cq9w-58p7)](alerts/2026-08-28-suneditor-embed-plugin-dom-xss-ghsa-w93q-cq9w-58p7.md)
- [Kyverno `generator.apply()` cross-namespace RoleBinding authority (CVE-2026-54523)](alerts/2026-08-27-kyverno-generator-apply-cross-namespace-authority-ghsa.md)


































































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
