# Report-renderer fetch and desktop-updater trust-boundary checks

Source: hourly offensive-security scan of the GitHub Security Advisory feed on 2026-08-03. These records were unreviewed when this page was written; confirm the exact product version, reachable content field, render path, updater behavior, and fixed behavior before reporting.

This wave yields two durable operator patterns:

- rich-text content can become a server-side URL or file selector when a report renderer resolves embedded resources; and
- TLS does not authenticate a software update when the client accepts every certificate and then executes an unsigned, unhashed installer.

Sources:

- [GHSA-7gc9-2qrw-frvj / CVE-2026-69078: CTI-Transmute evaluation-report SSRF and local-file fetch](https://github.com/advisories/GHSA-7gc9-2qrw-frvj)
- [CTI-Transmute restrictive WeasyPrint fetcher fix](https://github.com/MISP/cti-transmute/commit/20f35307bcb706c8dd8ca3884a88fb36b05b5244)
- [GHSA-gw22-gf8m-29g5 / CVE-2026-0392: eParakstītājs 3.0 unauthenticated update chain](https://github.com/advisories/GHSA-gw22-gf8m-29g5)
- [CERT.LV vulnerability record](https://cvd.cert.lv/inbox/view/vuln-all-1689187061)

!!! warning "Authorized validation only"
    Use a disposable CTI-Transmute instance, synthetic report content, an owned callback service, a fake local canary service, an isolated Windows VM, a locally controlled update endpoint, and a harmless installer recorder. Never target metadata or internal production services, read host files, intercept real update traffic, redirect vendor domains outside an isolated lab, or execute an untrusted installer.

## Preconditions and trust map

| Workflow | Attacker-controlled input | Privileged interpreter | Required precondition | Bounded positive |
| --- | --- | --- | --- | --- |
| CTI-Transmute report | conversion name, description, or comment rendered from Markdown | HTML conversion followed by WeasyPrint resource fetching | attacker content reaches evaluation-report PDF generation | owned HTTP canary or synthetic local-service marker reaches a no-content fetch recorder |
| eParakstītājs updater | update descriptor and installer response | permissive TLS client followed by updater execution | approved lab can redirect or interpose the updater's vendor authority | fake certificate is accepted, descriptor chooses an owned URL, and inert installer reaches a process-start recorder |

Keep each transition separate. A Markdown preview, a URL-shaped string in a PDF, an update request, or acceptance of a test certificate does not by itself prove the final privileged sink.

## Report rendering: trace content through every resource resolver

The CTI-Transmute advisory describes conversion names, descriptions, and comments passing through Markdown-to-HTML conversion and then WeasyPrint. The renderer's default URL fetcher accepted `http:`, `https:`, and `file:` references. The important review question is therefore: **which resource references survive the first content parser and what authority does the final renderer use to resolve them?**

### Disposable fetch matrix

1. Deploy an affected CTI-Transmute revision in a network-isolated lab. Create a low-privilege author, a report-generating user, and one synthetic conversion/evaluation object.
2. Start two owned recorders:
   - an external callback endpoint with a random per-test token; and
   - a fake local HTTP service bound only inside the lab, returning a non-sensitive random marker.
3. Instrument or wrap WeasyPrint's URL fetcher if possible. Record the final scheme, canonical host, port, path, redirect count, calling report ID, and whether response bytes are embedded. Redact ambient headers.
4. Place unique inert references in each candidate field and context: Markdown image, HTML image if preserved, stylesheet/font reference, and link-only control. Start with the owned external endpoint.
5. Trigger PDF generation through the normal application workflow. Positive evidence requires a callback produced by rendering, not by browser preview, validation, or link checking.
6. Repeat with the fake local service only after proving the external callback. Stop when the request reaches the recorder; do not target metadata endpoints, loopback admin panels, cloud APIs, or unrelated internal hosts.
7. For the `file:` branch, patch the file opener or use a synthetic file inside a disposable fixture. Record the attempted canonical path and return only a sentinel. Do not read `/etc/passwd`, application configuration, keys, tokens, databases, or user files.
8. Exercise redirects from the owned external endpoint to the fake local service. Preserve both the initially accepted URL and final authority; this distinguishes initial-only validation from per-hop enforcement.
9. Repeat against the fixed revision. The cited patch supplies a restrictive fetcher that permits self-contained `data:` resources and removes intentional external font fetching. Require network and filesystem references to fail before dispatch while a benign embedded `data:` image still renders.

A bounded positive is **low-privilege rich-text field -> Markdown/HTML resource reference -> report generation -> WeasyPrint dispatch to an owned or synthetic local canary**. Report local-file behavior through the opener recorder, not by returning file content.

### Generalize the renderer check

Apply the same matrix to:

- invoice, ticket, dashboard, wiki, and compliance PDF exports;
- headless-browser screenshot or print-to-PDF jobs;
- server-side SVG, CSS, font, and image processing;
- email-template previews and document conversion queues; and
- imports that rewrite Markdown or HTML before a second renderer sees it.

For each pipeline, preserve the representations before and after Markdown parsing, HTML sanitization, URL normalization, redirect handling, and final fetch. A sanitizer that blocks scripts may still preserve resource-loading primitives.

## Desktop updating: verify every binding before process start

The eParakstītājs record describes a compound failure: the XML descriptor was fetched over TLS while a permissive `TrustManager` and always-true hostname verifier accepted any certificate; the descriptor was not signed; and the selected installer was executed without an Authenticode or checksum decision. Prove these as separate links rather than collapsing them into “updater RCE.”

### Isolated updater harness

1. Snapshot an isolated Windows VM containing the affected application. Disable access to real credentials, documents, smart-card material, network shares, and production DNS.
2. Redirect the updater authority only inside the lab using a hosts-file entry or a DNS/proxy harness you own. Do not alter shared DNS and do not intercept another user's traffic.
3. Present a locally generated certificate that is untrusted, hostname-mismatched, or both. Capture the TLS decision and stop the first run before returning an update descriptor.
4. For the next run, serve a synthetic XML descriptor whose version and download URL point to the owned lab service. Change only one field at a time and retain the raw descriptor plus parsed URL decision.
5. Serve an inert test executable that performs no action. Replace or instrument process creation so the evidence is an argv/hash recorder rather than execution. The file should contain no shell, network, persistence, credential, or filesystem behavior.
6. Test the bindings independently:
   - trusted certificate and matching hostname;
   - certificate-chain failure;
   - hostname mismatch;
   - descriptor signature absent, invalid, and valid where supported;
   - installer checksum mismatch;
   - installer signer absent, wrong, and expected where supported; and
   - descriptor URL authority differing from the original update authority.
7. Affected behavior is established only if the fake TLS identity is accepted, the unsigned descriptor controls the installer URL, and the untrusted installer reaches the process-start recorder without an independent integrity decision.
8. Repeat on the fixed version. Require failure at the earliest invalid binding and confirm that an expected signer or pinned digest is checked over the exact bytes handed to the execution sink.

The bounded chain is **local network/DNS redirection in an approved lab -> unauthenticated TLS peer -> unsigned descriptor selects owned executable -> missing installer integrity check -> inert process-start recorder**. Do not execute arbitrary code merely to prove that the updater would launch the selected file.

## Reporting checklist

- [ ] Exact affected and fixed product versions are recorded.
- [ ] Report author, report generator, field, representation, and final renderer dispatch are shown separately.
- [ ] SSRF proof uses owned callbacks, a synthetic local service, and a patched file opener rather than production/internal targets or real files.
- [ ] Redirect behavior records both initial and final authorities.
- [ ] Updater evidence separates certificate-chain, hostname, descriptor authenticity, installer checksum/signature, and process-start decisions.
- [ ] DNS or proxy redirection is confined to a disposable VM.
- [ ] No real update traffic, credentials, documents, smart-card material, host files, or executable payloads appear in evidence.
- [ ] Claims stop at the first callback, opener, or process-start recorder and do not overstate downstream code execution or data access.
