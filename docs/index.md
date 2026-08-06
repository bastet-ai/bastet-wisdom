---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Nx remote-cache extraction and restore boundaries](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#2-treat-a-remote-build-cache-as-a-write-authority)
- [Contao path and crawler final-authority testing](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#4-preserve-the-authorized-path-segment-through-canonicalization)
- [Mermaid embedding-realm and host-DOM boundaries](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#6-test-diagram-state-in-the-embedding-realm-and-host-dom)
- [Statamic identity, route, upload, and interpreter authority](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#7-differential-test-cms-route-identity-and-interpreter-authority)
- [eScriptorium serializer, WebSocket, and import authority boundaries](alerts/2026-08-06-escriptorium-sanitizer-authority-boundaries-ghsa.md#1-build-one-final-authority-trace)
- [`html_sanitize_ex` active browser-context boundary testing](alerts/2026-08-06-escriptorium-sanitizer-authority-boundaries-ghsa.md#6-test-sanitizers-in-the-final-browser-context)
- [LangGraph SQL namespace segment-matching follow-up](alerts/2026-06-12-budibase-swiftnio-langgraph-chisel-boundary-batch-ghsa.md#august-6-langgraph-sql-namespace-segment-matching)
- [LudusMCP CLI-wrapper and guide-path follow-up](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#4-differential-test-approval-parsing-against-execution-parsing)
- [Traefik rewrite, identity-header, route-cache, namespace, and derived-key boundaries](alerts/2026-08-05-traefik-route-transport-namespace-boundaries-ghsa.md#4-diff-raw-routed-rewritten-and-backend-paths)
- [Traefik proxied CONNECT backend-pool differential](methodology/http-desync-research-campaigns.md#proxied-connect-body-and-backend-pool-differential)























































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
