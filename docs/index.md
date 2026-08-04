---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [ASUSTOR privileged IPC and WordPress object-authority boundaries](alerts/2026-08-04-asustor-wordpress-authority-boundaries-ghsa.md)
- [Static firmware TLS-key fingerprint workflow](methodology/weak-public-key-recon.md#static-firmware-key-follow-up)
- [Zyxel ZLD configuration-file traversal validation](alerts/2026-08-04-node-wildfly-rocketchat-zyxel-boundaries-ghsa.md#6-bind-appliance-configuration-execution-to-the-approved-file-root)
- [LINE Android profile-template render boundary](alerts/2026-08-04-sensor-cms-trust-boundaries-ghsa.md#4-trace-mobile-profile-templates-to-the-final-script-authority)
- [Node.js proxy/SQLite, WildFly, Rocket.Chat, and Zyxel appliance boundaries](alerts/2026-08-04-node-wildfly-rocketchat-zyxel-boundaries-ghsa.md)
- [Sensor-proxy controller, CMS, and mobile profile-render boundaries](alerts/2026-08-04-sensor-cms-trust-boundaries-ghsa.md)
- [Data workflow, AI corpus, command-wrapper, and device-adoption boundaries](alerts/2026-08-03-data-workflow-device-trust-boundaries-ghsa.md)
- [Python `cryptography` wildcard name-constraint differential](alerts/2026-08-03-bouncy-castle-crypto-policy-boundaries-ghsa.md#python-cryptography-name-constraint-and-path-cost-follow-up)
- [Python `cryptography` PKCS#7 oracle follow-up](alerts/2026-08-03-bouncy-castle-crypto-policy-boundaries-ghsa.md#python-cryptography-pkcs7-oracle-follow-up)
- [HTTP authority, WebSocket framing, Oracle SQL, and formatter-cache checks](alerts/2026-08-03-http-authority-websocket-sql-file-boundaries-ghsa.md)








































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
