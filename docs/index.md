---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [eScriptorium serializer, WebSocket, and import authority boundaries](alerts/2026-08-06-escriptorium-sanitizer-authority-boundaries-ghsa.md#1-build-one-final-authority-trace)
- [`html_sanitize_ex` active browser-context boundary testing](alerts/2026-08-06-escriptorium-sanitizer-authority-boundaries-ghsa.md#6-test-sanitizers-in-the-final-browser-context)
- [LangGraph SQL namespace segment-matching follow-up](alerts/2026-06-12-budibase-swiftnio-langgraph-chisel-boundary-batch-ghsa.md#august-6-langgraph-sql-namespace-segment-matching)
- [LudusMCP CLI-wrapper and guide-path follow-up](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#4-differential-test-approval-parsing-against-execution-parsing)
- [Traefik rewrite, identity-header, route-cache, namespace, and derived-key boundaries](alerts/2026-08-05-traefik-route-transport-namespace-boundaries-ghsa.md#4-diff-raw-routed-rewritten-and-backend-paths)
- [Traefik proxied CONNECT backend-pool differential](methodology/http-desync-research-campaigns.md#proxied-connect-body-and-backend-pool-differential)
- [OpenChamber and LudusMCP route, file, and process boundaries](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#2-compare-route-authentication-across-operating-modes)
- [Apache Answer object-state and KubeVirt final-syscall boundaries](alerts/2026-08-05-route-context-controller-authority-boundaries-ghsa.md#5-bind-object-lookup-to-tenant-scope)
- [Apache CXF OAuth, WSDL-import, and JMS authority boundaries](alerts/2026-08-06-apache-cxf-oauth-wsdl-jms-authority-boundaries-ghsa.md)
- [Polaris storage-location and WSO2 token-authority boundaries](alerts/2026-08-06-polaris-wso2-storage-token-authority-boundaries-ghsa.md)























































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
