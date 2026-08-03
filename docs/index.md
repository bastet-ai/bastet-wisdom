---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Agentic DAST behavioral-audit and proof-provenance workflow](methodology/agentic-dast-benchmark-validation.md#audit-behavior-not-only-solves)
- [PostCSS missing-base-path source-map confinement checks](alerts/2026-07-23-postcss-phpspreadsheet-authjs-boundaries-ghsa.md#august-3-follow-up-missing-from-residual-after-path-confinement)
- [Angular i18n event-handler attribute boundary checks](alerts/2026-06-15-angular-hydration-transferstate-cache-boundary-ghsa.md#august-3-follow-up-translation-metadata-reaches-event-handler-attributes)
- [SAML, repository, SSH-channel, CMS, and publish-mode trust boundaries](alerts/2026-08-03-saml-repository-channel-content-boundaries-ghsa.md)
- [Angular SSR raw-content and transfer-cache collision checks](alerts/2026-06-15-angular-hydration-transferstate-cache-boundary-ghsa.md#august-3-follow-up-raw-content-serialization-and-transfer-cache-key-ambiguity)
- [Report-renderer fetch and desktop-updater trust boundaries](alerts/2026-08-03-report-renderer-updater-trust-boundaries-ghsa.md)
- [FlowIntel Vue interpolation and MFP document-object boundaries](alerts/2026-08-03-vue-mfp-render-object-boundaries-ghsa.md)
- [NLTK verify-before-write package integrity](alerts/2026-06-06-nltk-nicegui-picklescan-ml-archive-boundaries-ghsa.md#august-3-follow-up-verify-nltk-package-bytes-before-writing-or-extracting)
- [WordPress object, identity, upload, and role-selector checks](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#august-3-follow-up-cross-check-object-identity-upload-and-role-selectors)
- [Bouncy Castle certificate, signature, AEAD, and authenticated-content boundaries](alerts/2026-08-03-bouncy-castle-crypto-policy-boundaries-ghsa.md#august-3-follow-up-bind-every-authenticated-result-to-all-of-its-inputs)





































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
