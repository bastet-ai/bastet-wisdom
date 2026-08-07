---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [Consul Vault credential-file authority matrix](alerts/2026-08-07-consul-file-session-listener-authority-boundaries-ghsa.md#vault-connect-ca-credential-file-authority)
- [Consul session-delete route-family ACL parity](alerts/2026-08-07-consul-file-session-listener-authority-boundaries-ghsa.md#session-delete-route-family-acl-parity)
- [Consul custom-listener L7 path normalization](alerts/2026-08-07-consul-file-session-listener-authority-boundaries-ghsa.md#custom-listener-l7-path-normalization)
- [Nanobot MCP capability-class policy matrix](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#3-recompute-deny-policy-after-every-tool-injection)
- [Nanobot shell allow-list and login-environment checks](alerts/2026-08-06-agent-tool-policy-file-fetch-boundaries-ghsa.md#compare-curated-environments-with-the-shells-reconstructed-environment)
- [Nanobot provider-returned image URL authority](alerts/2026-07-27-directory-cluster-agent-document-boundaries-ghsa.md#august-7-follow-up-provider-returned-image-urls-are-a-separate-fetch-authority)
- [Grav missing-webhook-token fail-closed matrix](alerts/2026-05-13-cms-identity-and-permission-boundary-batch-ghsa.md#missing-webhook-proof-must-not-mean-anonymous-success)
- [TestLink attachment parent-project authorization](alerts/2026-05-13-cms-identity-and-permission-boundary-batch-ghsa.md#attachment-ids-need-parent-project-authorization-at-the-download-sink)
- [Keras deserializer entry-point and ambient safe-mode matrix](alerts/2026-06-30-model-parser-deserialization-identity-boundaries-ghsa.md#deserializer-entry-point-and-ambient-policy-matrix)
- [Showdown metadata and generated-attribute render contexts](alerts/2026-05-09-render-markdown-and-preview-boundary-batch-ghsa.md#parse-serialize-and-host-render-matrix)

























































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
