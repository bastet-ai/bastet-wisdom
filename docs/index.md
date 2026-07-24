---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Framework authentication, static-path, and policy-field boundaries](alerts/2026-07-24-framework-auth-static-policy-boundaries-ghsa.md)
- [Open WebUI channel, realtime, knowledge, and delegated-execution follow-up](alerts/2026-05-08-open-webui-model-channel-and-knowledge-boundary-batch-ghsa.md#july-24-follow-up-channel-realtime-knowledge-and-delegated-execution-boundaries)
- [Claude Code worktree sandbox path-confusion follow-up](alerts/2026-06-10-claude-code-action-mcp-and-baileys-event-boundaries-ghsa.md#july-24-claude-code-worktree-path-confusion-follow-up)
- [GitPython option transformation and diff-output follow-up](alerts/2026-07-24-git-template-oauth-object-boundaries-ghsa.md#late-follow-up-gitpython-option-transformation-and-diff-output)
- [React Router unstable RSC CSRF action follow-up](alerts/2026-06-03-react-router-redirect-rsc-and-manifest-boundary-batch-ghsa.md#july-24-unstable-rsc-csrf-action-follow-up)
- [Git config, template, OAuth, and object-path boundaries](alerts/2026-07-24-git-template-oauth-object-boundaries-ghsa.md)
- [Markdown file inlining and Trix rich-text model boundaries](alerts/2026-07-24-markdown-file-trix-model-boundaries-ghsa.md)
- [Kiota code-generation and Seroval deserialization boundaries](alerts/2026-07-24-kiota-codegen-deserialization-boundaries-ghsa.md)
- [Better Auth passwordless, Stripe organization, and SCIM provider follow-up](alerts/2026-07-07-better-auth-aider-netfoil-ckan-mcp-boundaries-ghsa.md#july-24-follow-up-passwordless-pre-account-billing-target-and-scim-namespace-boundaries)
- [Ray WebDataset default-decoder deserialization follow-up](alerts/2026-05-05-minio-ray-kirby-execution-and-storage-boundary-batch-ghsa.md#july-24-follow-up-ray-webdataset-default-decoder-deserialization)









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
