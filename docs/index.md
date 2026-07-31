---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Keycloak URI, introspection, broker, group, revocation, and parameter-precedence follow-up](alerts/2026-06-11-kolibri-hapi-keycloak-flowise-arc-boundary-batch-ghsa.md#july-31-keycloak-identity-policy-differential-follow-up)
- [WordPress authentication-proof, payment, email-routing, backup, and deserialization follow-up](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#july-31-follow-up-authentication-proofs-workflow-authority-and-artifact-exposure)
- [MCP Toolbox OAuth, route-scope, dataset, redirect, package-argument, and Node permission boundaries](alerts/2026-07-31-mcp-toolbox-package-permission-boundaries-ghsa.md)
- [MeshCentral WebSocket origin, SFTPGo symlink permission, RapidRAW preset, and Leapp controller-file boundaries](alerts/2026-07-31-browser-filesystem-controller-boundaries-ghsa.md)
- [OpenClaw transcript-to-dashboard DOM rendering follow-up](alerts/2026-07-02-openclaw-mcp-memory-agent-boundaries-ghsa.md#july-31-transcript-to-dashboard-rendering-follow-up)
- [SGLang inference API, safe-loader, model-transfer, and multimodal fetch boundaries](alerts/2026-07-30-sglang-inference-api-boundaries-ghsa.md)
- [Control-plane default authority, route coverage, capability composition, and stale-session checks](alerts/2026-07-30-control-plane-auth-session-boundaries-ghsa.md)
- [Tika and Leantime secondary file-reference boundaries](alerts/2026-07-30-tika-leantime-file-reference-boundaries-ghsa.md)
- [Langflow file-route, traversal, and Chroma namespace checks](alerts/2026-06-19-langflow-mailpit-outerbase-miniflux-render-boundaries-ghsa.md#july-30-file-route-traversal-and-chroma-namespace-follow-up)
- [AWS Amplify component-schema to generated JSX and event-binding boundaries](alerts/2026-07-24-kiota-codegen-deserialization-boundaries-ghsa.md#july-30-aws-amplify-component-schema-follow-up)



























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
