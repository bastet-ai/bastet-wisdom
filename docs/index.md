---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Laravel Backpack CRUD admin-panel authority boundaries](alerts/2026-08-20-laravel-backpack-crud-admin-panel-authority-boundaries-ghsa.md)
- [Apache CXF JNDI config injection and OAuth2 token-claim follow-up](alerts/2026-08-06-apache-cxf-oauth-wsdl-jms-authority-boundaries-ghsa.md#august-20-follow-up-jndi-config-injection-oauth2-token-claim-validation-and-inverted-ip-binding)
- [NocoBase storage-root redirection and backup-restore shell interpolation](alerts/2026-07-28-nocobase-cosmos-data-identity-boundaries-ghsa.md#august-20-nocobase-follow-up-storage-root-redirection-and-backup-restore-shell-interpolation)
- [GeoServer FreeMarker SSTI follow-up](alerts/2026-06-11-geoserver-wsgidav-openfga-devguard-filament-boundary-batch-ghsa.md#august-20-geoserver-freemarker-template-injection-follow-up)
- [MLflow webhook redirect, registry source, and run-permission boundaries (KEV)](alerts/2026-08-19-mlflow-webhook-redirect-and-registry-permission-boundaries-ghsa-kev.md)
- [SearXNG/FAF/Contentful MCP and agent-catalog option-to-sink testing](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#august-19-follow-up-llm-controlled-options-are-destination-capabilities)
- [Lemur certificate-management authority-boundary testing](alerts/2026-08-18-lemur-certificate-management-authority-boundaries-ghsa.md)
- [Code-editor extension webview and file-write boundary testing](methodology/editor-extension-webview-file-write-boundary-testing.md)
- [OpenSign and Attendize object-authority follow-ups](alerts/2026-08-10-hostname-document-workflow-authority-boundaries-ghsa.md#august-11-follow-up-trace-every-parse-cloud-function-separately)
- [OpenShift Console fetch-authority and Helm catalog-provenance testing](alerts/2026-08-10-ai-feature-control-plane-tenant-boundaries-ghsa.md#august-11-follow-up-console-fetch-authority-and-helm-catalog-provenance)
- [CTI-Transmute state-changing GET and CSRF testing](alerts/2026-08-03-report-renderer-updater-trust-boundaries-ghsa.md#state-changing-get-and-csrf-follow-up)


































































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
