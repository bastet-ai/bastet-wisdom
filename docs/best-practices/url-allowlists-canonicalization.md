# URL allowlists: canonicalize, parse, and ban userinfo

**Problem:** URL allowlists are frequently implemented with **string checks** (e.g., `url.startsWith("https://good.example/")`). Attackers can exploit differences between **raw string representation** and the **actual network destination** after URL parsing.

This shows up in SSRF defenses, “trusted domain” checks, webhook allowlists, build-time fetchers, and agent tooling.

## Durable guidance

### 1) Never enforce allowlists on raw strings
- Don’t use `startsWith`, `includes`, regexes, or naive splitting.
- Use a URL parser and enforce policy on **structured fields**:
  - scheme/protocol
  - hostname (after normalization)
  - port (explicit and implicit)
  - path (if relevant)

### 2) Reject URL **userinfo** outright
- The `username:password@host` form is rarely needed.
- It is a common source of **allowlist bypasses** because the `@` changes what the parser treats as the real host.

### 3) Normalize before compare
- Normalize punycode/IDNA, lowercase hostnames, and apply consistent port rules.
- Avoid comparing raw input to stored allowlist strings.

### 4) Defend in depth with egress controls
- For high-risk contexts (CI/build hosts, automation/agents): prefer **network egress allowlisting** at the firewall/proxy layer.
- If SSRF would be catastrophic, block access to:
  - cloud metadata IPs/hostnames
  - RFC1918 ranges (as appropriate)
  - link-local ranges

## Related examples
- webpack build-time fetch allowlist bypass via userinfo: https://github.com/advisories/GHSA-8fgc-7cc6-rx7x

## Backslash authority parser-differential matrix

[fast-uri GHSA-7p8r-x3mc-p8w7 / CVE-2026-18446](https://github.com/advisories/GHSA-7p8r-x3mc-p8w7) demonstrates a policy-parser versus network-parser differential. Affected fast-uri releases required literal `//` for an authority, while Node's WHATWG URL parser treats backslashes as separators for special schemes. A value that the policy layer resolves beneath an allowed host can therefore reach `fetch`, undici, or an HTTP client as a different authority. Fixed releases are listed as 2.4.4, 3.1.5, and 4.1.2.

Test with an allowed local origin and an owned foreign-origin recorder. Patch the final transport so it records destination scheme, hostname, port, and path without sending a request.

| Reference form | Policy parser output | Transport parser output |
| --- | --- | --- |
| `//owned.invalid/canary` | record | record |
| `\\\\owned.invalid/canary` | record | record |
| `/\\owned.invalid/canary` | record | record |
| `\\/owned.invalid/canary` | record | record |
| `https:\\\\owned.invalid/canary` | record | record |
| percent-encoded separators | record | record |
| same-origin relative path | allowed-origin control | allowed-origin control |

Run the exact string through the validation parser, resolver, serializer, redirect handler if present, and final transport parser. Capture structured authority at every stage. Do not infer an SSRF from parser disagreement alone: prove **policy accepts the input as the allowed authority -> actual transport recorder selects the owned foreign authority**. Repeat on a corrected fast-uri release and require both parsers to agree or the policy layer to reject the ambiguous form.

This same matrix is useful for redirect validation, webhook allowlists, proxy routing, and agent fetch tools. Keep DNS and network rebinding out of this test; authority parsing is the only changed variable.
