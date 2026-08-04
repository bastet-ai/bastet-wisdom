---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Sensor-proxy controller trust and CMS draft/render boundaries](alerts/2026-08-04-sensor-cms-trust-boundaries-ghsa.md)
- [Data workflow, AI corpus, command-wrapper, and device-adoption boundaries](alerts/2026-08-03-data-workflow-device-trust-boundaries-ghsa.md)
- [Python `cryptography` wildcard name-constraint differential](alerts/2026-08-03-bouncy-castle-crypto-policy-boundaries-ghsa.md#python-cryptography-name-constraint-and-path-cost-follow-up)
- [Python `cryptography` PKCS#7 oracle follow-up](alerts/2026-08-03-bouncy-castle-crypto-policy-boundaries-ghsa.md#python-cryptography-pkcs7-oracle-follow-up)
- [HTTP authority, WebSocket framing, Oracle SQL, and formatter-cache checks](alerts/2026-08-03-http-authority-websocket-sql-file-boundaries-ghsa.md)
- [GitPython `Commit.count()` truncation follow-up](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#commit-count-unguarded-output-sink)
- [undici request serialization, retry framing, and cookie-attribute checks](alerts/2026-08-03-undici-serialization-retry-cookie-boundaries-ghsa.md)
- [IP-literal SSRF classification differential matrix](best-practices/url-allowlists-canonicalization.md#ip-literal-classification-differential-matrix)
- [GitPython option-to-filesystem follow-up](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#august-3-gitpython-option-to-filesystem-follow-up)
- [Shared-cache whitespace-around-equals follow-up](best-practices/shared-http-cache-boundary-testing.md#whitespace-around-equals-follow-up)








































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
