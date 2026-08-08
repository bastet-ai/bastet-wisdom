---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [MCP argument-to-process wrapper validation](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#git-and-server-command-wrappers)
- [MCP journey identifier file-capability checks](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#journey-ids-and-filenames-are-file-capabilities)
- [WordPress file-to-provider and guest-upload authority](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#keep-local-file-selection-separate-from-provider-delivery)
- [WordPress API-key type and workflow-authority checks](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#treat-api-keys-as-typed-exact-secrets)
- [WatchGuard low-privilege command-boundary discovery](alerts/2026-08-08-watchguard-client-web-authority-boundaries-ghsa.md#2-mobile-vpn-discover-the-low-privilege-to-command-boundary)
- [WatchGuard non-default installation-root ACL validation](alerts/2026-08-08-watchguard-client-web-authority-boundaries-ghsa.md#3-non-default-installation-roots-join-acl-reachability-to-a-system-consumer)
- [WatchGuard Fireware Host-to-WebUI sink matrix](alerts/2026-08-08-watchguard-client-web-authority-boundaries-ghsa.md#4-fireware-webui-separate-host-reflection-navigation-script-and-cache-effects)
- [Consul Vault credential-file authority matrix](alerts/2026-08-07-consul-file-session-listener-authority-boundaries-ghsa.md#vault-connect-ca-credential-file-authority)
- [Consul session-delete route-family ACL parity](alerts/2026-08-07-consul-file-session-listener-authority-boundaries-ghsa.md#session-delete-route-family-acl-parity)
- [Consul custom-listener L7 path normalization](alerts/2026-08-07-consul-file-session-listener-authority-boundaries-ghsa.md#custom-listener-l7-path-normalization)

























































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
