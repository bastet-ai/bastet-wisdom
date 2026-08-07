---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Keras archive extraction destination-vs-CWD boundary](alerts/2026-06-30-model-parser-deserialization-identity-boundaries-ghsa.md#archive-extraction-destination-matrix)
- [Keras `DiskIOStore` layer-name final-path authority](alerts/2026-06-30-model-parser-deserialization-identity-boundaries-ghsa.md#diskiostore-layer-name-matrix)
- [Django shared-cache grammar and principal isolation](alerts/2026-05-08-django-cache-upload-and-session-boundary-batch-ghsa.md#shared-cache-decision-matrix)
- [Django signed-cookie namespace collision](alerts/2026-05-08-django-cache-upload-and-session-boundary-batch-ghsa.md#signed-cookie-namespace-collision-matrix)
- [Nexus delegated repository and privilege authority](alerts/2026-08-07-repository-pipeline-appliance-authority-boundaries-ghsa-kev.md#1-build-a-delegated-permission-to-final-action-matrix)
- [Nexus configuration-to-runtime interpretation boundaries](alerts/2026-08-07-repository-pipeline-appliance-authority-boundaries-ghsa-kev.md#2-separate-configuration-write-authority-from-runtime-interpretation)
- [Nexus lifecycle, render, and outbound-helper checks](alerts/2026-08-07-repository-pipeline-appliance-authority-boundaries-ghsa-kev.md#3-test-lifecycle-render-and-outbound-helpers-with-controlled-canaries)
- [ZenML shared-artifact deserialization provenance](alerts/2026-08-07-repository-pipeline-appliance-authority-boundaries-ghsa-kev.md#4-treat-shared-ml-artifacts-as-executable-package-inputs)
- [Plesk, WGDashboard, and LoadMaster control-plane route authority](alerts/2026-08-07-repository-pipeline-appliance-authority-boundaries-ghsa-kev.md#5-replay-alternate-panel-and-appliance-routes-without-live-impact)
- [CodeIgniter MIME and stored-extension upload boundary](alerts/2026-06-11-codeigniter-upload-extension-boundary-ghsa.md#1-test-validation-stored-extension-and-destination-separately)
























































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
