---
title: Hostname, LAN transfer, and template-runtime boundaries from July 27 GHSA updates
---

# Hostname, LAN transfer, and template-runtime boundaries from July 27 GHSA updates

A July 27 GitHub advisory wave yields three durable operator workflows: an ASCII hostname that changes identity after IDNA conversion, an unauthenticated LAN transfer name escaping its download root, and unauthenticated template data reaching a PHP math evaluator. The reusable lesson is to preserve every representation and prove each boundary with inert markers rather than jumping directly to destructive impact.

Sources:

- [GHSA-w2q5-6q6x-x959 / CVE-2026-39821: `golang.org/x/net/idna` ASCII-only Punycode labels](https://github.com/advisories/GHSA-w2q5-6q6x-x959)
- [Go issue 78760: `ToUnicode` accepts Punycode labels encoding pure ASCII labels](https://go.dev/issue/78760)
- [GO-2026-5026 affected symbols and fixed `golang.org/x/net` release](https://pkg.go.dev/vuln/GO-2026-5026)
- [GHSA-5xhx-w5wq-c68v / CVE-2026-66050: NitroShare LAN transfer path traversal](https://github.com/advisories/GHSA-5xhx-w5wq-c68v)
- [Researcher's NitroShare disclosure](https://github.com/cduram/NotCVE-2026-0009)
- [GHSA-43hg-f3wj-j2m6 / CVE-2026-61511: vBulletin `runMaths()` eval injection](https://github.com/advisories/GHSA-43hg-f3wj-j2m6)
- [Karma(In)Security technical disclosure](https://karmainsecurity.com/KIS-2026-13)
- [vBulletin vendor security-patch announcement](https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4509358-security-patch-released-for-vbulletin-6-2-1-6-2-0-and-6-1-6)

The GitHub records were unreviewed when scanned. Confirm product identity, reachable feature, affected build, and fixed-build behavior from the linked primary sources before reporting. The NitroShare research repository includes a weaponized persistence path, and the vBulletin research links exploit code; neither is needed for a safe validation.

!!! warning "Authorized validation only"
    Use owned domains, a disposable Go harness, an isolated LAN and transfer root, benign text files, a disposable vBulletin instance, and an instrumented no-op PHP function/counter. Never send files to another user's workstation, write startup or application paths, publish an eval payload, alter forum data, or execute operating-system commands.

## Boundary matrix

| Surface | Attacker-controlled representation | Decision made too early | Safe proof |
| --- | --- | --- | --- |
| Go IDNA | ASCII hostname such as an `xn--` label | authorization or allow/deny decision on pre-conversion text | raw/canonical decision table using owned names only |
| NitroShare | JSON item-header `name` | transfer acceptance before canonical destination confinement | text marker in a disposable sibling directory |
| vBulletin | `pagenav[pagenumber]` reaching the `pagenav` template | regex character allowlist treated as safe expression grammar | instrumented evaluator counter in a lab, with no shell/file/network primitive |

For each test, record the exact raw input, every decode/normalization stage, the policy decision, the final sink, the harmless marker result, and the fixed-version control.

## Go IDNA: authorization must bind to one canonical hostname

CVE-2026-39821 describes `ToASCII` and `ToUnicode` accepting Punycode labels that decode to ASCII-only labels. The primary example is `xn--example-.com` becoming `example.com` instead of failing. If policy checks the former and routing or lookup later uses the latter, two strings can become one authority after the decision. GO-2026-5026 identifies `golang.org/x/net/idna` before `v0.55.0` as affected and names `ToASCII`, `ToUnicode`, and their profile methods.

### Representation decision table

Build a small Go harness that calls the same `idna.Profile` and sequence used by the application. Use only reserved or owned canary names.

| Input class | Raw policy key | `ToASCII` result | `ToUnicode` result | Fixed expectation |
| --- | --- | --- | --- | --- |
| ordinary ASCII | exact input | stable | stable | accept consistently |
| valid non-ASCII IDN | exact UTF-8 | canonical A-label | canonical U-label | one documented identity |
| ASCII-only Punycode alias | `xn--` form | capture result/error | would become an ASCII-only label on affected versions | reject |
| mixed-case/trailing-dot variant | exact input | capture | capture | normalize once before policy |
| malformed label | exact input | error | error | fail closed |

1. Run the table against the application's affected `x/net/idna` dependency and `v0.55.0` or later.
2. Instrument the policy lookup and downstream dial/router lookup separately; do not make external network requests.
3. Seed a deny entry for one owned canonical hostname and submit only its crafted alias to the lab policy function.
4. A positive result requires **raw alias permitted -> IDNA conversion produces the denied canonical hostname -> downstream selection uses that canonical hostname**.
5. Repeat with policy applied after canonicalization. The alias and canonical name should produce one identical decision.

Do not report package presence alone. Establish that attacker-controlled host text reaches an affected conversion **after** an allowlist, blocklist, tenant, cookie, proxy, or credential-routing decision.

## NitroShare: bind transfer names to a canonical destination

The disclosure says NitroShare Desktop through `0.3.4` listens on TCP `40818` on all interfaces, has TLS disabled by default, and accepts a JSON item-header `name` without proving that its resolved destination remains under the NitroShare download directory. The reusable bug is **unauthenticated transfer metadata -> path join/canonicalization -> outside-root write**. Startup-folder execution is downstream impact, not a necessary proof.

### Marker-only LAN fixture

1. Isolate two disposable VMs on a host-only network; install NitroShare `0.3.4` only on the receiver.
2. Configure a transfer root and a sibling proof directory under one temporary parent. Put no personal files in either location.
3. Confirm baseline protocol handling with one ordinary text file and capture the transfer header, item header, and resulting path.
4. Send a second benign text marker whose item-header name uses the minimum traversal needed to resolve into the sibling proof directory. Do not target a startup folder, home-directory content, application files, or an executable extension.
5. Trace file opens/writes and capture the raw name, joined path, canonical path, transfer root, file hash, and whether any approval or authentication gate appeared.
6. Add controls for absolute paths, forward and backslash separators, a directory item, an empty name, TLS/pairing enabled if supported, and a build containing a vendor fix if one becomes available.
7. Delete the marker and tear down the host-only network after the test.

A decisive result is **unpaired LAN client -> accepted item header -> canonical destination outside the configured root -> exact text marker written**. Listening on `0.0.0.0:40818` is recon evidence, not proof of traversal. A sibling-directory marker proves arbitrary relative placement within the service user's write authority; do not claim persistence or code execution unless a separately authorized lab reproduces a later load edge.

## vBulletin: trace template data into the evaluator, not into a shell

The disclosure identifies affected vBulletin `5.x` through `5.7.5` and `6.x` through `6.2.1`; version `6.2.2` is the fixed control. It traces unauthenticated data from the `ajax/render/[template]` route, through the default `pagenav` template's `pagenav[pagenumber]` value and `{vb:math}` tag, into `vB5_Template_Runtime::runMaths()`. The affected method removes characters outside a mathematical-looking allowlist and then evaluates the remaining expression. The vulnerability is the assumption that a character allowlist defines a safe expression language.

### Non-weaponized sink validation

Do **not** copy the linked public exploit or construct PHP using encoded operators. Prove the chain in a disposable instance with instrumentation:

1. Install an affected lab build with no real users, plugins, credentials, mail, or outbound network access.
2. Confirm that an unauthenticated client can reach the render route for the stock `pagenav` template using an ordinary integer page number.
3. Add temporary lab instrumentation immediately before the evaluator to record a nonce, input hash, call count, and stack location. Do not log full hostile payloads.
4. Submit a harmless non-constant arithmetic expression made only of documented math characters and verify that the request-controlled value reaches `runMaths()` and changes only the rendered numeric result.
5. If stronger sink evidence is required, replace `eval` **in the lab copy** with a recorder that flags grammar outside a strict numeric-expression parser. Never provide a PHP-code or command-execution string to the real evaluator.
6. Run identical requests against `6.2.2` or the vendor-patched build and capture route availability, input handling, evaluator reachability, and output.
7. Restore the instrumented files and compare their hashes with the pristine lab package.

The bounded finding is **unauthenticated render parameter -> stock template variable -> `{vb:math}` -> dynamic evaluator**, with affected/fixed behavior. Do not claim exploitation from a version banner alone, and do not run public exploit code against an internet-facing forum.

## Reporting checklist

Include:

- exact product/package version, platform, route or feature, network placement, and authentication state;
- raw input plus each ASCII/Unicode, path, or template representation;
- policy lookup key, canonical hostname/path, or evaluator call-site evidence;
- baseline, malformed, fixed-version, and sink-disabled controls;
- marker hashes, evaluator counters, and cleanup evidence;
- a narrow impact statement separating hostname policy confusion, outside-root write, evaluator reachability, and any untested downstream execution edge.

Redact host inventories, user paths, forum cookies, source-tree secrets, and complete exploit strings. A conversion differential is not automatically SSRF, a marker write is not persistence, and evaluator reachability is not operating-system command execution.