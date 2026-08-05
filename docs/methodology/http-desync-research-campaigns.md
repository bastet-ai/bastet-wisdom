---
title: HTTP desync research campaigns
---

# HTTP desync research campaigns

Use this workflow to turn protocol specifications, parser oddities, and HTTP anomaly observations into replayable desync research without treating every strange response as request smuggling. It adapts PortSwigger's August 2026 HTTP Terminator research into a bounded operator methodology: generate testable hypotheses, evaluate cross-request contamination with deterministic controls, isolate weaponization from discovery, and feed confirmed behavior into a human-reviewed research cascade.

Primary research: [James Kettle, “Can AI do novel security research? Meet the HTTP Terminator”](https://portswigger.net/research/http-terminator).

!!! warning "Authorized, isolated testing only"
    Use disposable front-end/back-end pairs, owned callback services, synthetic sessions, and customer-approved test windows. Never run high-volume desync probes against shared production infrastructure, target live users, capture queued responses, or reuse a contaminated connection across tenants. On an operational target, stop at the lowest-impact parser differential the owner approved.

## Operator value

HTTP desync is a composition flaw: a front end and back end disagree about where one message ends or how a request should be interpreted. A useful campaign must therefore preserve both parsers and prove an effect across requests. Source review of one server or a malformed response alone is only a lead.

This workflow is useful when you need to:

- explore parser behavior beyond familiar `Content-Length` and `Transfer-Encoding` cases;
- distinguish ordinary HTTP pipelining from cross-request contamination;
- measure transformations performed by an intermediary without relying on header reflection;
- convert protocol anomalies into reusable lab fixtures;
- evaluate an AI-assisted hypothesis generator without allowing it to decide whether its own exploit worked; or
- report exactly which parser boundary was crossed without collecting another user's data.

## Required inputs

- an explicit authority and request-rate budget;
- an isolated front-end/back-end topology representative of the target;
- raw-byte request control, such as Burp Repeater or a bounded Turbo Intruder script;
- server-side logs or instrumented parsers for the lab pair;
- two synthetic routes with stable, distinct response fingerprints;
- a unique campaign/run identifier; and
- a known-good clean request plus malformed negative controls.

Pin product versions, configuration, upstream protocol, connection-pool behavior, and image digests. A finding that depends on upstream HTTP/1.1 may disappear when the edge uses HTTP/2 to the origin, and the reverse is also possible.

## 1. Define one testable hypothesis

A hypothesis should name an input feature, the expected parser disagreement, and an observable result. Keep ideation separate from proof.

```text
Input feature:
Front-end interpretation:
Back-end interpretation:
Expected connection state:
Observable synthetic response change:
Negative control:
```

Prefer narrow questions such as “does this request-only parser process a response-specific header semantic?” over “find request smuggling.” PortSwigger's research found that broad prompts reproduced familiar vectors, while small specification fragments produced more varied hypotheses. When using an LLM:

1. provide one to three sentences of protocol inspiration at a time;
2. ask for a small number of structurally distinct hypotheses;
3. normalize and deduplicate before testing;
4. explicitly reject already-known families and impossible deployment assumptions; and
5. treat every generated request as untrusted test data requiring human review.

Do not let specification text, issue comments, or model output expand the authorized target list or rate limit.

## 2. Use protocol limits as measurement rulers

When an intermediary transforms a header but the origin does not reflect it, a stable parser limit can reveal the transformation indirectly.

1. Find a harmless header or request-line length boundary in the isolated origin.
2. Binary-search the largest baseline value accepted consistently.
3. Replace a short portion with the candidate byte sequence while preserving all other bytes.
4. Measure how far the acceptance threshold moves.
5. Repeat across direct-to-origin and front-end-to-origin paths.

Interpret only reproducible deltas:

| Observation | Candidate explanation | Required control |
| --- | --- | --- |
| threshold decreases by a stable amount | intermediary expanded or inserted bytes | direct-origin comparison |
| threshold increases | bytes were removed or normalized shorter | unrelated-byte substitution |
| candidate is rejected before the origin | edge validation or decoding | edge and origin request logs |
| threshold varies between attempts | routing, compression, or unstable parser state | pin connection and backend |

This can surface header removal, replacement, Unicode/mojibake expansion, and client-IP header rewriting. It does not by itself prove desynchronization. Preserve raw request hashes and byte counts rather than screenshots alone.

## 3. Build a deterministic cross-request evaluator

The core signal is not a particular error string. It is a stable victim/control request receiving a response fingerprint that it cannot receive in the baseline sequence after a candidate trigger is sent on the relevant connection topology.

Create three synthetic routes:

- **baseline route:** stable status, length, and body marker;
- **alternate route:** a different stable marker used only by the lab probe; and
- **negative route:** a stable ordinary error fingerprint.

For each candidate:

1. send the baseline request enough times to establish its normal fingerprint;
2. open the exact front-end connection pattern under test;
3. send the candidate trigger with a harmless synthetic follow-up marker;
4. send the victim/control request over a separate client connection when the hypothesis requires shared upstream reuse;
5. record response order, raw bytes, connection IDs, origin request boundaries, and route markers; and
6. reset the front-end pool or rebuild the fixture before the next candidate.

A strong positive requires both sides of the differential:

```text
client writes -> front-end request boundaries -> upstream bytes
             -> origin request boundaries -> response order
             -> front-end response assignment -> synthetic marker mismatch
```

Never use another user's request as the victim control. A per-run synthetic marker is enough to prove cross-request contamination.

## 4. Eliminate pipelining and client-reuse false positives

Two responses following two bytestrings are not automatically a desync. Explicitly test:

- candidate and follow-up on one client connection with no shared upstream pool;
- the same sequence with client-side reuse disabled;
- direct-to-origin behavior;
- a clean, RFC-valid single request;
- malformed requests that are obviously two parseable requests; and
- affected versus normalized/fixed parser configurations.

Instrument the evaluator so the AI or operator cannot override success conditions. PortSwigger reports that autonomous agents repeatedly mistook normal pipelining or client-side reuse for exploitation. Keep response classification in deterministic code and require the synthetic alternate marker to appear on the wrong logical request before marking contamination.

If the only evidence is “one connection produced two expected responses,” label it **pipelining/ambiguous framing**, not request smuggling.

## 5. Separate discovery, classification, and impact

Classify the strongest proven primitive:

| Evidence | Supported claim |
| --- | --- |
| different edge/origin acceptance | parser differential |
| transformed byte count | intermediary normalization behavior |
| clean single request produces multiple origin requests/responses | request splitting or response-forking lead |
| synthetic control receives another synthetic route's response | cross-request response contamination |
| deterministic lab queue assignment changes | response queue poisoning primitive in the lab |

Do not claim account takeover, credential theft, cache poisoning, or cross-user disclosure from a parser differential alone. Production impact can often be established from architecture and a synthetic marker matrix without retrieving live responses.

Keep weaponization behind a separate approval gate. If deeper validation is authorized, use disposable accounts, non-sensitive endpoints, unique canaries, one connection at a time, and an early-exit condition. Do not test high-volume race strategies against shared services.

## 6. Turn anomalies into a research cascade

Unexpected output that fails the desync condition can still be a valuable lead. Store anomalies separately with raw evidence, then ask:

1. How can the same behavior be detected on another parser pair?
2. Does the parser behavior expose a different attack surface?
3. Is a response-only semantic being applied to requests, or vice versa?
4. Did the harness accidentally mutate the request?
5. Can a clean request reproduce the anomaly?

Useful anomaly fingerprints include:

- multiple status lines after one clean request;
- text followed by unexplained binary data;
- duplicate HTML/document starts;
- a request protocol token copied into a response status line;
- response-only header semantics affecting request parsing; and
- stable response ordering changes without a known framing pattern.

PortSwigger calls the broader response/request code-reuse concept **Shared-Parser Confusion**. Treat it as a hypothesis family, not a vulnerability label. Prove the exact semantic that crosses from one parser context into another.

Every promoted anomaly should become a fixture with:

```text
raw candidate and clean control
front-end/origin versions and configuration
connection topology
expected parser traces
synthetic success marker
known false-positive controls
fixed/normalized comparison
```

## 7. Design AI-assisted campaigns so they improve over time

Split responsibilities between model, code, and reviewer:

| Component | Responsibility |
| --- | --- |
| model | hypothesis generation, clustering, explanation candidates |
| deterministic code | byte serialization, rate limits, scope allowlist, response fingerprinting, success gates |
| human reviewer | authorization, novelty review, anomaly interpretation, impact boundary, publication |

Run discovery, evidence harvesting, and report drafting in fresh contexts. Pass only the approved request, raw evidence, and deterministic classification forward. This prevents a confident early hypothesis from contaminating later validation.

Log rejected hypotheses and why they failed. When one family reaches a fixed attempt threshold, vary only one dimension at a time—method, protocol version, header grammar, body eligibility, or connection topology—rather than combining random mutations immediately. Random permutations are useful later, but they make causal claims harder.

## Evidence bundle

Capture:

```text
Scope and approved rate:
Campaign/run ID:
Front end / origin versions and digests:
Upstream protocol and pool behavior:
Hypothesis and inspiration fragment:
Raw request SHA-256 values:
Baseline and alternate fingerprints:
Client, front-end, and origin connection IDs:
Front-end and origin request-boundary traces:
Deterministic evaluator result:
Clean and malformed controls:
Affected/fixed comparison:
Strongest supported claim:
Excluded stronger claims:
```

A report should lead with the parser disagreement and the synthetic cross-request effect. Keep live credentials, unrelated response bodies, weaponized bulk-scanning settings, and customer topology secrets out of the wiki and disclosure artifact.

## Tools and source

PortSwigger released the HTTP Terminator source alongside updates to HTTP Request Smuggler, Turbo Intruder's MCP interface, and Param Miner. Use [HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) for bounded target validation; the research describes HTTP Terminator as a research factory rather than a quick per-target scanner.

- Research: https://portswigger.net/research/http-terminator
- HTTP Terminator source: follow the release link from the primary research page so the repository and version remain source-aligned.
