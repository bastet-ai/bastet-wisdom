# httpx (ProjectDiscovery) - Fast HTTP Probing for Bug Bounty

Last updated: 2025-09-01

## Overview
 is a fast and versatile HTTP toolkit by ProjectDiscovery for probing hosts and enumerating web properties at scale. It accepts hosts from stdin, performs HTTP/HTTPS requests in parallel, and enriches results with metadata useful for bug bounty reconnaissance and triage.

Repository: https://github.com/projectdiscovery/httpx

## Installation


## Core Features
- High-performance HTTP/HTTPS probing with concurrency control
- Status code, length, words, lines, time, redirect chain
- Title extraction, server header, content-type, IP/CDN/CNAME/ASN
- TLS probing (protocols/ciphers), SNI, certificate subject/SANs
- HTTP/2, pipeline, custom methods/headers, custom ports
- Tech fingerprinting, favicon mmh3 hashing
- Virtual host (vhost) discovery and host header probing
- Path probing (/) with smart defaults
- Filters/matchers on status, content-length, words, lines, regex
- Output formats: plain, JSON, CSV; response storage

## Common Options (selected)


## Bug Bounty Workflows

### 1) Alive host and web service discovery

Quickly identify which subdomains expose HTTP(S) and capture key metadata.

### 2) Prioritize interesting targets
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	modified:   mkdocs.yml

Untracked files:
  (use "git add <file>..." to include in what will be committed)
	docs/tools/httpx.md
	scope_hot.txt
	wisdom/

no changes added to commit (use "git add" and/or "git commit -a")
Prioritize by status/title/tech; feed into deeper scanners.

### 3) Fingerprint via favicon mmh3 hash

Correlate mmh3 hashes with known tech (e.g., hashlists/Shodan).

### 4) Path probing for low-hanging fruit

Check common disclosure files and policy endpoints.

### 5) VHost and Host header probing

Surface name-based virtual hosts that differ from the apex.

### 6) TLS inventory & misconfig triage

Review protocol/cipher support, certificates, and network attributes.

### 7) Redirect mapping & takeover hints

Map redirect chains; investigate dangling targets or misrouted CNAMEs.

### 8) JSON output → triage pipeline

Produce structured feeds for further automation and dashboards.

## Tips & Good Practices
- Combine with , , , and  for full-stack reconnaissance.
- Start broad, then filter (e.g., ) to reduce noise.
- Use / responsibly to avoid throttling.
- Store responses for reproducibility () and redact before sharing.
- Rotate user-agent and honor program policies; avoid disruptive probing.

## References
- ProjectDiscovery httpx: https://github.com/projectdiscovery/httpx
- ProjectDiscovery ecosystem: https://projectdiscovery.io
