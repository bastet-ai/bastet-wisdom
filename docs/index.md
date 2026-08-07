---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [GitPython final-argv, config, submodule, and filesystem authority](alerts/2026-07-21-developer-agent-proxy-control-boundaries-ghsa.md#august-7-gitpython-final-argv-config-submodule-and-file-authority-follow-up)
- [Postiz file, SuperTokens tenant, libvirt config, and redirect/browser peer authority](alerts/2026-08-07-file-tenant-network-config-authority-boundaries-ghsa.md)
- [WordPress commerce-proof, shortcode, and protected-content boundaries](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#august-7-commerce-proof-shortcode-and-protected-content-follow-up)
- [DOMPurify `IN_PLACE` detached-subtree lifecycle testing](methodology/css-sanitizer-host-boundary-testing.md#dompurify-in_place-detached-subtree-follow-up)
- [SEBLOD path selection and SP Page Builder privileged-editor rendering](alerts/2026-07-08-joomla-page-builder-coldfusion-kev-boundaries.md#august-7-follow-up-separate-joomla-file-selection-from-editor-rendering)
- [Smarty nested-resource and symlink final-file authority](alerts/2026-08-07-template-passkey-webmail-authority-boundaries-ghsa.md#2-test-template-sandboxes-at-the-final-file-identity)
- [Craft CMS passkey assertion replay and persisted credential state](alerts/2026-08-07-template-passkey-webmail-authority-boundaries-ghsa.md#3-treat-webauthn-state-as-a-one-time-server-owned-tuple)
- [TeamDavid Webbox local-path, UNC-peer, and response authority](alerts/2026-08-07-template-passkey-webmail-authority-boundaries-ghsa.md#4-model-webmail-path-fields-as-a-shared-authority-surface)
- [NLTK cross-package shared-namespace resource poisoning](alerts/2026-07-31-library-tenant-commerce-file-boundaries-ghsa.md#august-7-follow-up-test-nltk-package-identity-at-the-final-extracted-resource)
- [Phoca Commander read, upload, copy, move, and delete path confinement](alerts/2026-07-08-joomla-page-builder-coldfusion-kev-boundaries.md#august-7-follow-up-bind-phoca-commander-actions-to-one-canonical-file-manager-root)
























































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
