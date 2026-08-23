---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [GitLab package-registry traversal and docker-socket-proxy read-endpoint boundaries](alerts/2026-08-23-gitlab-registry-traversal-and-docker-socket-proxy-read-gating-ghsa.md)
- [WordPress registration role, permission-filter, and invoice-file selector follow-up](alerts/2026-07-28-wordpress-payment-device-boundaries-ghsa.md#august-23-follow-up-bind-registration-role-selection-permission-filter-rewrites-and-invoice-file-selectors-to-final-authority)
- [TrueConf server 4307/TCP authority and sandbox-breakout validation (KEV)](alerts/2026-08-21-trueconf-server-kev-boundaries.md)
- [JSONata expression sandbox escape and arbitrary-code-execution boundaries](alerts/2026-08-22-jsonata-expression-sandbox-escape-code-execution-ghsa.md)
- [Xinference Llama3 tool-call eval() and LLM-output-to-execution boundaries](alerts/2026-08-22-xinference-llama3-tool-call-eval-code-execution-ghsa.md)
- [Zimbra SNMP-notification SMTP command-injection authority validation (KEV)](alerts/2026-08-21-zimbra-snmp-notification-smtp-command-injection-cve-2026-73570.md)
- [Canonicalization differentials at security gates (Mailpit WS origin bypass)](methodology/canonicalization-differentials-at-security-gates.md)
- [Laravel Backpack CRUD admin-panel authority boundaries](alerts/2026-08-20-laravel-backpack-crud-admin-panel-authority-boundaries-ghsa.md)
- [MLflow webhook redirect, registry source, and run-permission boundaries (KEV)](alerts/2026-08-19-mlflow-webhook-redirect-and-registry-permission-boundaries-ghsa-kev.md)
- [Lemur certificate-management authority-boundary testing](alerts/2026-08-18-lemur-certificate-management-authority-boundaries-ghsa.md)


































































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
