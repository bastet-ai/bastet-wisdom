# Apache Camel inbound header-to-Exchange mapping and deserialization wave

**Date reviewed:** 2026-08-27  
**Advisories:** the July 6 Camel CVE wave plus the JMS ObjectMessage deserialization advisory  
**Severity:** Critical and High (multiple CVSS 9.x)  
**Boundary class:** inbound transport headers → Exchange property mapping without `HeaderFilterStrategy`; unsafe Java/`ObjectInputStream` deserialization in several Camel components

## What is durable here

This is a multi-component Camel wave with one recurring trust-boundary
pattern that is worth generalizing for any Camel route audit:

**Inbound transport headers are mapped into the Exchange without a
`HeaderFilterStrategy`.** When a Camel endpoint receives untrusted
inbound messages (HTTP, JMS, AMQP, SNS, CometD/Bayeux, Vertx-HTTP,
Netty-HTTP, Elasticsearch-REST), the transport's native headers are
copied into `Exchange` properties. If the route (or a default filter
that is absent) does not strip headers outside the `Camel-` namespace,
an attacker who controls inbound headers can:

- inject `Camel-*` headers that downstream components treat as
  routing/instruction material (SSRF via `CamelHttpUri`, header-based
  endpoint reselection, expression injection),
- reach components that **deserialize** Exchange property values with
  `java.io.ObjectInputStream` (JMS `ObjectMessage`, Vertx-HTTP /
  Netty-HTTP response bodies, Hazelcast managed instances, PQC AWS
  Secrets Manager key metadata),
- bypass the default `ObjectInputFilter` where the default pattern is
  permissive enough to admit `java.net.**` (enables DNS-based
  disclosure / OOB exfiltration even where full gadget chains are not
  available).

The individual advisories in this wave:

| Advisory | Component | Boundary |
| --- | --- | --- |
| [GHSA-r9cc-j7wr-p329](https://github.com/advisories/GHSA-r9cc-j7wr-p329) / CVE-2026-46454 | camel-cometd | Inbound Bayeux message headers mapped into the Exchange without a `HeaderFilterStrategy` |
| [GHSA-m5vh-3fw5-5wgh](https://github.com/advisories/GHSA-m5vh-3fw5-5wgh) / CVE-2026-40860 | camel-jms / sjms / sjms2 / amqp | Unsafe deserialization of JMS `ObjectMessage` |
| [GHSA-rp9m-hfv5-pfvr](https://github.com/advisories/GHSA-rp9m-hfv5-pfvr) / CVE-2026-46453 | camel-elasticsearch-rest-client | Exchange header constants without the `Camel` prefix bypass inbound HTTP header filtering |
| [GHSA-f755-xp6r-8q84](https://github.com/advisories/GHSA-f755-xp6r-8q84) / CVE-2026-40860, CVE-2026-43866 | camel-jms | JMS deserialization filter bypass |
| [GHSA-xww8-mxqw-m84w](https://github.com/advisories/GHSA-xww8-mxqw-m84w) / CVE-2026-43865 | camel-hazelcast | Unsafe Java deserialization in default-configured managed Hazelcast instances |
| [GHSA-6qw3-4796-5984](https://github.com/advisories/GHSA-6qw3-4796-5984) / CVE-2026-40859 | camel-vertx-http / camel-netty-http | Unsafe Java deserialization of HTTP response bodies via raw `ObjectInputStream` |
| [GHSA-w2v8-8q6c-3rhr](https://github.com/advisories/GHSA-w2v8-8q6c-3rhr) / CVE-2026-46456, CVE-2026-56140 | camel-aws2-sns | Inbound Camel-namespace filter added to `Sns2HeaderFilterStrategy` (prior versions did not strip) |
| [GHSA-7cmx-qjh8-7v3v](https://github.com/advisories/GHSA-7cmx-qjh8-7v3v) / CVE-2026-40048, CVE-2026-43867, CVE-2026-46590 | camel-pqc | AWS Secrets Manager key-lifecycle manager deserializes persisted key metadata with `java.io.ObjectInputStream` |
| [GHSA-rpv3-6645-2vqc](https://github.com/advisories/GHSA-rpv3-6645-2vqc) / CVE-2026-40047 | camel-docling | Insufficient validation of custom CLI arguments enables argument injection and path traversal |
| [GHSA-8h6p-jvhf-9hcr](https://github.com/advisories/GHSA-8h6p-jvhf-9hcr) / CVE-2026-42527 | camel (core) | Permissive default `ObjectInputFilter` pattern admits `java.net.**` (DNS-based disclosure) |

## Recon: enumerate Camel endpoints and header flows

1. **Find the Camel version.** The July 6 wave is the most recent CVE
   publication batch; the JMS `ObjectMessage` deserialization advisory
   ([GHSA-m5vh-3fw5-5wgh](https://github.com/advisories/GHSA-m5vh-3fw5-5wgh))
   was published earlier. Check `camel-core`, the transport
   components in use (`camel-vertx-http`, `camel-netty-http`,
   `camel-jms`, `camel-amqp`, `camel-cometd`, `camel-hazelcast`,
   `camel-aws2-sns`, `camel-docling`, `camel-elasticsearch-rest-client`),
   and `camel-pqc`.
2. **Map inbound endpoints.** For each `from()` that accepts untrusted
   inbound messages, note which transport is used and whether a
   `HeaderFilterStrategy` (or `CamelHttpUri`-style filtering) is
   registered on that endpoint or globally.
3. **Check the default `ObjectInputFilter`.** If the Camel version
   predates the filter fix, the default pattern admits `java.net.**`.
   Even without a full deserialization gadget chain, an attacker who
   can control an Exchange property value that reaches a
   `ObjectInputStream` can trigger DNS lookouts (OOB disclosure /
   exfiltration of the serialized payload's reachable state).
4. **Identify the `ObjectMessage` path.** If the route uses
   `camel-jms` / `camel-amqp` with `ObjectMessage` support and the
   deserialization filter is absent or bypassable (the JMS filter
   bypass advisory), a JMS broker that accepts attacker-controlled
   `ObjectMessage` payloads is a direct RCE primitive.

## Validation workflow (authorized lab / customer-approved)

### Header-injection proof (no code execution)

1. Identify an inbound HTTP endpoint that maps to a Camel route with
   no `HeaderFilterStrategy`.
2. Send a request with a benign `Camel-` namespaced header, e.g.
   `Camel-Test-Trace: skillz-canary`. If the header appears in the
   Exchange (visible in route logs, a downstream HTTP request's
   `Camel-Test-Trace` header, or a route that echoes Exchange
   properties), the mapping is unfiltered.
3. Record the route and the specific header that crossed. Do not use
   `CamelHttpUri` or other instruction headers that would cause
   SSRF / endpoint reselection during the proof.

### Deserialization-boundary proof (no code execution)

1. Confirm the component is present and the deserialization path is
   reachable (e.g. a JMS `ObjectMessage` consumer, a Vertx-HTTP
   response-body deserialization, a Hazelcast managed instance).
2. Do **not** send a gadget-chain payload. The proof is that the
   deserialization sink is reachable with attacker-controlled bytes.
   Record the component, the Exchange property that carries the bytes,
   and the route.
3. If a permissive `ObjectInputFilter` is present, a DNS-lookup canary
   (a serialized `java.net.InetAddress`-adjacent object that triggers
   an outbound DNS query to an owned domain) is acceptable OOB
   evidence. Do not use it to exfiltrate data.

### Negative evidence

- A `400`/`403` on the inbound endpoint, or the absence of the
  attacker header in the Exchange, is negative evidence.
- If the `HeaderFilterStrategy` is present but the route still
  deserializes, the finding moves from "header injection" to
  "deserialization boundary" and the proof changes accordingly.

## Reporting heuristic

- Lead with the **specific transport and route** that maps untrusted
  headers into the Exchange without filtering. The generic "Camel
  header injection" framing is not useful; the value is the route
  map.
- State the Camel version and the components in use. The advisory
  range is component-specific.
- Separate "header injection" (routing / instruction) from
  "deserialization boundary" (RCE primitive). They are different
  findings with different proofs.
- Do not publish gadget-chain payloads. The proof is the reachable
  sink + the unfiltered header mapping.

## Safety constraints

- Do not execute arbitrary code on the target.
- Do not use `CamelHttpUri` or similar instruction headers to
  redirect traffic during the proof.
- Use owned DNS callback domains only for OOB disclosure.
- Do not test against production JMS brokers or Hazelcast instances
  with live data.
