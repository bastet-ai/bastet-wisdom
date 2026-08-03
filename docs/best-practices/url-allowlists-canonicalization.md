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

## IP-literal classification differential matrix

Three reviewed `ip-address` advisories published on August 3, 2026 add reusable SSRF-policy checks:

- [GHSA-mwp4-54f8-5fhr](https://github.com/advisories/GHSA-mwp4-54f8-5fhr): `Address4` through 10.3.0 parses leading-zero octets as decimal while common network resolvers can interpret them as octal; fixed in 10.3.1.
- [GHSA-4xrf-jv44-h6hh](https://github.com/advisories/GHSA-4xrf-jv44-h6hh): `ip-address` 10.1.1 through 10.2.1 lets a caller-supplied CIDR suffix suppress special-use classification; fixed in 10.2.2.
- [GHSA-22jq-vg5j-6vgg / CVE-2026-54272](https://github.com/advisories/GHSA-22jq-vg5j-6vgg): versions 10.1.1 through 10.2.0 classify IPv4-mapped and NAT64 IPv6 wrappers without consistently classifying the embedded IPv4 destination; fixed in 10.2.1.

Use two owned listeners representing a permitted and a synthetic denied destination. Patch or instrument the final transport so it records the destination selected by the operating-system resolver without contacting metadata or another internal service.

| Family | Inputs to compare | Evidence |
| --- | --- | --- |
| IPv4 radix | ordinary decimal, one leading-zero octet, all leading-zero octets | library numeric form, special-use flags, `getaddrinfo` bytes, transport destination |
| caller CIDR | no suffix, host-width suffix, `/0`, shorter prefixes | parsed address, retained prefix, every special-use predicate, transport destination |
| embedded IPv4 | IPv4-mapped IPv6 and NAT64 forms carrying public, RFC1918, loopback, link-local, and unspecified canaries | wrapper class, embedded IPv4 class, final destination |

Run the exact application path rather than testing the library in isolation. Capture raw input, parser version, normalized address, prefix length, `isPrivate`/`isLoopback`/`isLinkLocal` result, resolver output, redirect revalidation, and final owned listener. Require the application to prove **policy classifies a literal as permitted -> transport resolves the same raw value to the denied owned canary**. A wrong label without a reachable outbound fetch is only a library observation.

Keep DNS rebinding, redirects, and URL-authority ambiguity as separate test axes. Correct behavior should reject ambiguous legacy IPv4 syntax and caller-supplied prefixes before policy, recursively classify embedded IPv4 addresses, and reapply the same canonical destination policy after every redirect and DNS resolution.
