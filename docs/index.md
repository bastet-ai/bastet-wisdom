---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [CSS sanitizer, host-UI, clipboard, and model-context boundary testing](methodology/css-sanitizer-host-boundary-testing.md)
- [Duplicate authority fields across HTTP/2-to-HTTP/1.1 bridges](methodology/http-desync-research-campaigns.md#duplicate-authority-fields-across-an-http2-bridge)
- [Repository blame-report process-boundary testing](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#12-audit-repository-analysis-wrappers-at-the-final-process-sink)
- [Craft CMS preview, interpolation, class-factory, and draft-label boundaries](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#preview-route-versus-asset-visibility)
- [Embedded PDF renderer inventory and denied-sink validation](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#8-inventory-the-renderer-actually-shipped)
- [Sanitizer parse-serialize-reparse differential testing](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#9-diff-sanitizer-parse-serialization-and-host-reparse)
- [Browser-equivalent URL normalization testing](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#10-normalize-urls-the-way-the-final-browser-does)
- [Craft CMS post-transform and sibling-route authority](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#11-re-check-cms-authority-after-every-transformation)
- [Nx remote-cache extraction and restore boundaries](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#2-treat-a-remote-build-cache-as-a-write-authority)
- [Contao path and crawler final-authority testing](alerts/2026-08-06-build-cms-render-authority-boundaries-ghsa.md#4-preserve-the-authorized-path-segment-through-canonicalization)























































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
