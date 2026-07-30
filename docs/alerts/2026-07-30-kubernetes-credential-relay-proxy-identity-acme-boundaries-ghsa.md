---
title: Kubernetes credential relay, proxy identity, and ACME fetch boundaries
---

# Kubernetes credential relay, proxy identity, and ACME fetch boundaries

A July 30 GitHub advisory wave exposes three reusable control-plane testing patterns: a tenant-editable custom resource can choose where a privileged operator sends credentials, an HTTP edge can preserve caller-supplied certificate identity headers, and an ACME validator can follow an approved name to a different final destination.

Sources:

- [GHSA-8jfr-h5wv-8vhv / CVE-2026-18378](https://github.com/advisories/GHSA-8jfr-h5wv-8vhv): koku-metrics-operator upload URL receives a cluster-global Red Hat Cloud pull-secret bearer token;
- [GHSA-wfh6-5fvj-2qcg / CVE-2026-18381](https://github.com/advisories/GHSA-wfh6-5fvj-2qcg): koku-metrics-operator upload URL receives the operator service-account bearer token;
- [GHSA-3f36-c5m8-4frw / CVE-2026-18382](https://github.com/advisories/GHSA-3f36-c5m8-4frw): koku-metrics-operator OAuth endpoint receives a tenant Red Hat SSO client ID and secret;
- [GHSA-ccmj-8c3p-4qwj / CVE-2026-46579](https://github.com/advisories/GHSA-ccmj-8c3p-4qwj): OpenShift Router plain-HTTP routes preserve `X-SSL-Client-*` headers; and
- [GHSA-g3fm-cr7x-pwvj / CVE-2026-18369](https://github.com/advisories/GHSA-g3fm-cr7x-pwvj): Dogtag PKI ACME HTTP-01 validation accepts IP literals and follows redirects without revalidating the final destination.

The GitHub records were unreviewed when this page was written. Confirm the affected product build, deployment mode, caller permissions, route settings, backend behavior, and corrected build against the vendor material before reporting.

!!! warning "Authorized validation only"
    Use a disposable cluster, fake credentials, two owned HTTP listeners, synthetic client-certificate identities, and a lab ACME account. Never collect live pull secrets, service-account tokens, OAuth secrets, certificate identities, or ACME responses; never point a validator at metadata endpoints, cluster services, private production addresses, or systems you do not own.

## Build one trust-transition matrix

| Surface | Caller-controlled value | Privileged context added later | Bounded proof |
| --- | --- | --- | --- |
| koku token upload | `CostManagementMetricsConfig` upload URL | cluster-global pull-secret bearer | fake bearer reaches owned listener |
| koku operator upload | `CostManagementMetricsConfig` upload URL | operator service-account bearer | synthetic service-account marker reaches owned listener |
| koku service-account auth | OAuth token endpoint | tenant SSO client ID and secret | fake client credentials reach owned listener |
| OpenShift edge route | plain-HTTP `X-SSL-Client-*` fields | backend treats edge-supplied certificate metadata as identity | synthetic principal marker changes at a no-op backend |
| Dogtag ACME HTTP-01 | identifier and redirect target | PKI server performs the fetch | final owned listener records a random challenge canary |

Keep **selector acceptance**, **credential/header attachment**, **network connection**, **backend identity decision**, and **response disclosure** as separate edges. A custom resource that accepts a URL is not yet credential disclosure; an edge that forwards a header is not yet authentication bypass unless the application trusts it; and a redirect-following fetch is not proof of access to an internal service.

## koku-metrics-operator: CRD authority versus credential authority

The three koku records share the same confused-deputy shape but involve different secrets and configuration branches. Test each branch independently; do not infer one from another.

### Disposable credential-relay harness

1. Create an isolated cluster with no production pull secrets, cloud credentials, or shared service accounts. Install the exact operator build under review.
2. Give a synthetic tenant only the real permissions required to edit `CostManagementMetricsConfig`. Preserve the RBAC subject, verb, resource, namespace, and admission decision.
3. Replace every credential with a unique inert marker. Use different markers for the cluster-global pull secret, operator service account, tenant OAuth client ID, and tenant OAuth client secret.
4. Run two owned TLS listeners, `approved` and `unlisted`, with locally trusted certificates. Each listener should record only method, normalized authority, header names, redacted marker IDs, body hash, and final peer.
5. Exercise the normal upload URL and OAuth endpoint first. Then select the unlisted listener through one field at a time. Test omitted schemes, explicit ports, hostname/IP aliases, redirects between the listeners, and DNS changes only inside the isolated fixture.
6. Compare the default `token` branch, the `service-account` authentication branch, and the operator's upload branch. Record which secret class is attached before and after redirects.
7. Repeat against the vendor-corrected build or configuration. The operator must reject the unapproved authority or withhold credentials; preserve the negative-control decision table.

Strong evidence is **tenant-authorized CR edit -> operator selects an unapproved owned authority -> one identified fake credential class is attached**. Report the exact credential class and scope. Do not call a fake pull-secret marker a cluster takeover, and do not use a real Kubernetes token merely to demonstrate impact.

## OpenShift Router: bind certificate identity to the TLS hop

The OpenShift record applies when a Route uses `insecureEdgeTerminationPolicy: Allow`: the plain-HTTP frontend reportedly does not remove `X-SSL-Client-*` headers. Exploitability still depends on a backend consuming those headers as authenticated client-certificate identity.

### Four-path identity differential

Use a backend that returns only a synthetic principal label and records whether the edge, not the client, established TLS:

| Path | Client transport | Header source | Expected identity |
| --- | --- | --- | --- |
| A | trusted mTLS route | edge-generated certificate fields | certificate canary |
| B | trusted mTLS route | caller duplicates certificate fields | edge-owned canonical value or rejection |
| C | plain HTTP with `Allow` | caller supplies certificate fields | anonymous/rejected |
| D | plain HTTP with `Allow` | no certificate fields | anonymous |

1. Inventory the Route termination mode, `insecureEdgeTerminationPolicy`, HTTP and HTTPS listeners, header-normalization rules, and backend framework or auth middleware.
2. Use a disposable certificate whose subject, SAN, and fingerprint contain only lab canaries. Never copy a real client certificate identity.
3. Replay A-D with `X-SSL-Client-*` spelling, case, duplicates, comma joining, dash/underscore aliases only where the actual proxy stack normalizes them, and conflicting subject/fingerprint fields.
4. Capture raw edge request bytes and backend-received headers separately. At the backend, replace authorization with a no-op decision recorder.
5. Repeat with the corrected router build. Path C must not produce the certificate canary principal.

A reportable positive is **plain client-controlled HTTP header -> router preserves it across the trust boundary -> backend selects the synthetic mTLS principal**. If the backend ignores the field, report only header preservation; do not claim authentication bypass.

## Dogtag PKI: validate every ACME fetch destination

The Dogtag record says the HTTP-01 validator accepts IP address literals as DNS identifiers and follows redirects without checking that the target remains public. The `InMemory` database backend reportedly can return fetched response content in a challenge error. Treat fetch reachability and response disclosure as two different findings.

### Two-listener redirect fixture

1. Run a fake ACME client and Dogtag instance on an isolated network. Use only a random HTTP-01 token and account created for the test.
2. Put listener A on the accepted test authority and listener B on a second owned address that represents a prohibited destination class. Do not use real loopback services, cluster APIs, metadata services, or third-party addresses.
3. Compare a direct public-name challenge, direct IP literal, A-to-A redirect, A-to-B redirect, cross-port redirect, hostname-to-IP redirect, redirect loop, and an over-limit chain.
4. For every hop, capture requested identifier, parsed URL, DNS answer, normalized authority, redirect status/location, final peer, and whether any response bytes enter the ACME error object.
5. Return only a random body canary from B. Confirm disclosure by matching its hash or marker, not by fetching sensitive content.
6. Repeat with the corrected build. Destination policy must be applied to the initial URL and every redirect after resolution, with the final peer bound to the approved result.

Strong evidence is **accepted ACME identifier -> validator follows a redirect -> owned prohibited-class listener B receives the challenge request**. Add **B's random body marker appears in the ACME error** only if independently observed.

## Evidence and reporting checklist

Preserve:

- exact product/operator build, cluster version, Route mode, authentication branch, ACME backend, and vendor-fixed control;
- caller RBAC and the narrow action that makes each selector writable;
- raw CR field or header, parsed and normalized authority, DNS result, redirect chain, final peer, and TLS state;
- credential class using only a fake marker ID, never a complete token or secret;
- edge-received versus backend-received headers and the synthetic identity decision;
- direct, redirected, omitted, malformed, unlisted-authority, anonymous, and corrected-build controls; and
- separate claims for configuration acceptance, credential relay, header preservation, identity selection, outbound fetch, and response disclosure.

Stop at the smallest replayable proof. Do not use the operator's authority, a forged certificate identity, or the ACME fetch channel to access real cluster, cloud, PKI, or application resources.
