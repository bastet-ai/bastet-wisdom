---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [MLflow webhook redirect, registry source, and run-permission boundaries (KEV)](alerts/2026-08-19-mlflow-webhook-redirect-and-registry-permission-boundaries-ghsa-kev.md)
- [SearXNG/FAF/Contentful MCP and agent-catalog option-to-sink testing](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#august-19-follow-up-llm-controlled-options-are-destination-capabilities)
- [Lemur certificate-management authority-boundary testing](alerts/2026-08-18-lemur-certificate-management-authority-boundaries-ghsa.md)
- [Code-editor extension webview and file-write boundary testing](methodology/editor-extension-webview-file-write-boundary-testing.md)
- [OpenSign and Attendize object-authority follow-ups](alerts/2026-08-10-hostname-document-workflow-authority-boundaries-ghsa.md#august-11-follow-up-trace-every-parse-cloud-function-separately)
- [OpenShift Console fetch-authority and Helm catalog-provenance testing](alerts/2026-08-10-ai-feature-control-plane-tenant-boundaries-ghsa.md#august-11-follow-up-console-fetch-authority-and-helm-catalog-provenance)
- [Portainer Docker-proxy canonicalization testing](alerts/2026-05-14-portainer-control-plane-host-boundary-batch-ghsa.md#august-11-proxy-canonicalization-follow-up)
- [authentik SCIM source-binding and name-collision testing](alerts/2026-05-29-authentik-cc-tweaked-keras-identity-and-model-boundary-batch-ghsa.md#august-11-follow-up-bind-scim-adoption-to-the-provisioning-source)
- [Prefect Git branch argument-boundary testing](alerts/2026-05-22-prefect-camel-imagemagick-airflow-boundary-batch-ghsa.md#replayable-validation-boundaries)
- [Windmill job, schema, and orphan-draft authority testing](alerts/2026-07-10-mcp-agent-package-workflow-boundaries-ghsa.md#august-11-windmill-job-schema-and-orphan-draft-follow-up)
- [CTI-Transmute state-changing GET and CSRF testing](alerts/2026-08-03-report-renderer-updater-trust-boundaries-ghsa.md#state-changing-get-and-csrf-follow-up)
- [EAP/WildFly ORB, IIOP, SAML, and AJP listener-authority testing](alerts/2026-08-04-node-wildfly-rocketchat-zyxel-boundaries-ghsa.md#august-11-follow-up-test-listener-trust-before-application-authorization)


































































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
