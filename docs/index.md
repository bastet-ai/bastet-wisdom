---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Downloader artifact, remote-file synchronization, and MCP URI boundaries](alerts/2026-07-24-downloader-artifact-integration-boundaries-ghsa.md)
- [Open WebUI terminal, model, file, and fetch-policy follow-up](alerts/2026-05-08-open-webui-model-channel-and-knowledge-boundary-batch-ghsa.md#late-july-24-follow-up-terminal-model-file-and-fetch-policy-boundaries)
- [Budibase identity, role, metadata, and SQL follow-up](alerts/2026-06-22-budibase-gogs-skillctl-nuxt-automation-boundaries-ghsa.md#july-24-budibase-identity-role-metadata-and-sql-follow-up)
- [Cloudreve scope, share-event, WOPI, and directory follow-up](alerts/2026-07-20-cloudreve-pillow-token-image-boundaries-ghsa.md#july-24-cloudreve-scope-share-event-wopi-and-directory-follow-up)
- [OpenAM class-loading, deserialization, and consent-rendering follow-up](alerts/2026-06-22-container-openam-xwiki-comfyui-boundaries-ghsa.md#july-24-openam-pre-auth-class-loading-deserialization-and-consent-rendering-follow-up)
- [Camel HTTP-to-producer control-header follow-up](alerts/2026-05-22-prefect-camel-imagemagick-airflow-boundary-batch-ghsa.md#july-24-camel-http-to-producer-control-header-follow-up)
- [Framework authentication, static-path, and policy-field boundaries](alerts/2026-07-24-framework-auth-static-policy-boundaries-ghsa.md)
- [Open WebUI channel, realtime, knowledge, and delegated-execution follow-up](alerts/2026-05-08-open-webui-model-channel-and-knowledge-boundary-batch-ghsa.md#july-24-follow-up-channel-realtime-knowledge-and-delegated-execution-boundaries)
- [Claude Code worktree sandbox path-confusion follow-up](alerts/2026-06-10-claude-code-action-mcp-and-baileys-event-boundaries-ghsa.md#july-24-claude-code-worktree-path-confusion-follow-up)
- [Git config, template, OAuth, and object-path boundaries](alerts/2026-07-24-git-template-oauth-object-boundaries-ghsa.md)









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
