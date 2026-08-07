---
title: Consul file, session, and custom-listener authority boundaries
---

# Consul file, session, and custom-listener authority boundaries

HashiCorp's [HCSEC-2026-25 bulletin](https://discuss.hashicorp.com/t/hcsec-2026-25-multiple-vulnerabilities-impacting-hashicorp-consul/77629) contains three durable offensive validation patterns: privileged configuration selecting a server-local credential file, a transaction route omitting an ACL enforced by the dedicated route, and a custom Envoy listener enforcing path intentions against a differently normalized request. The same bulletin includes five availability issues; those are not expanded here because they do not add a distinct non-destructive operator workflow.

Source records:

- [GHSA-jgv4-5fjv-3xp7 / CVE-2026-19017](https://github.com/advisories/GHSA-jgv4-5fjv-3xp7): Vault Connect CA JWT/AppRole credential-file scope;
- [GHSA-7qhj-3fg3-mh5r / CVE-2026-19016](https://github.com/advisories/GHSA-7qhj-3fg3-mh5r): transaction API session-delete ACL parity; and
- [GHSA-h928-jqxm-5f3x / CVE-2026-15970](https://github.com/advisories/GHSA-h928-jqxm-5f3x): custom public listener request-normalization and L7 intention parity.

HashiCorp lists Consul Community Edition `2.0.3` and Enterprise `1.21.17`, `1.22.11`, and `2.0.3` as fixed. The affected lower bounds differ by CVE; use the bulletin and the exact deployed edition/version rather than treating package presence as exposure.

!!! warning "Disposable Consul/Vault/Envoy fixtures only"
    Use synthetic credential files, a mock Vault endpoint, random lab sessions, canary services, and an isolated mesh. Never read host files, forward real JWT/AppRole material, delete production sessions, disrupt locks or leader election, or send normalization probes through a shared proxy or service mesh.

## Boundary map

| Input | Missing binding | Bounded positive evidence |
| --- | --- | --- |
| Connect CA auth configuration | caller's `operator:write` authority versus server-local credential directory | mock Vault sees only a random canary from a disposable out-of-scope file |
| transaction operation containing session ID | transaction route versus dedicated session API `session:write` check | denied mutation recorder sees the known lab session ID only on the transaction path |
| HTTP path through `envoy_public_listener_json` | path normalization used by L7 deny intention versus origin route | custom listener reaches a denied canary route while standard listener blocks the same semantic path |

Keep the impacts separate. Configuration-to-file relay is not arbitrary file read unless the selected bytes reach the mock peer; knowing a session ID is not deletion authority; and a path-normalization difference is not an L7 bypass unless the same protected origin route is reached.

## Vault Connect CA credential-file authority

CVE-2026-19017 requires `operator:write`, the Vault Connect CA provider, and JWT or AppRole file-backed authentication. HashiCorp says Kubernetes auth and deployments without this CA provider are not affected. The failure is an admin-like logical permission crossing into broader host-file authority and then into an outbound Vault request.

1. Build a disposable Consul server root with `allowed/credential.canary` and `sibling/credential.canary`, each containing a different random marker.
2. Replace Vault with an owned HTTPS recorder that accepts no real authentication and stores only marker identity, field name, and byte count.
3. Create a synthetic token with exactly `operator:write`; verify a read-only token cannot update the Connect CA configuration.
4. Exercise JWT and AppRole file selectors across allowed file, sibling file, `..`, absolute path, sibling-prefix path, symlink, missing file, and Kubernetes-auth control.
5. Capture raw selector, canonical path, directory-policy decision, file-open target, auth request field, and mock peer. Patch the file/open sink if the test cannot keep every target under one temporary parent.
6. Repeat on a fixed build and, where applicable, set the startup-owned `token_dirs` boundary described by HashiCorp.

A positive is **`operator:write` Connect CA update -> canonical path outside the intended credential directory -> synthetic sibling marker reaches mock Vault**. Do not point the selector at `/etc`, service tokens, environment files, or real Vault; do not infer general filesystem read beyond the exact auth-method consumer.

## Session-delete route-family ACL parity

CVE-2026-19016 concerns session deletion through the transaction path while the dedicated session API correctly requires `session:write`. It also requires network access to the server RPC port and knowledge of a randomly generated session ID. mTLS can narrow who reaches RPC but does not supply the missing resource permission for an authenticated caller.

Create two random lab sessions with inert lock records and a principal that can reach RPC but lacks `session:write`. Replace transaction commit/session deletion with a recorder, or use sessions whose deletion cannot affect any shared workload. Compare:

| Principal / route | Dedicated session delete | Transaction session delete | Expected |
| --- | --- | --- | --- |
| no `session:write`, known ID | deny | deny | parity |
| `session:write`, known ID | allow canary mutation | allow canary mutation | positive control |
| no `session:write`, random ID | deny/not found | deny/not found | no enumeration oracle |
| no client certificate where mTLS is required | transport deny | transport deny | reachability control |

Record transport identity, ACL token fingerprint, operation type, session ID provenance, authorization result, and denied mutation sink. The bounded positive is **same low-authority principal and known canary ID -> dedicated route denies -> transaction path reaches the deletion recorder**. Never delete operational sessions or use the test to disturb locks, health checks, or elections.

## Custom-listener L7 path normalization

CVE-2026-15970 requires `envoy_public_listener_json`, path-based L7 deny intentions, and a mesh workload already allowed to connect to the destination service. Standard listeners are the negative control. HashiCorp attributes the bypass to custom-listener xDS configuration missing the request-normalization settings used by standard listeners.

1. Deploy a canary HTTP service with `/allowed` and `/denied/marker`; neither route mutates state.
2. Add a path-based deny intention for the marker route and verify a normal request is blocked.
3. Run equivalent standard and custom public listeners against the same service and policy.
4. Generate a low-volume normalization matrix: dot segments, repeated separators, percent-encoded separators/dots, mixed encoding depth, path parameters, empty segments, and absolute-form where the listener accepts it.
5. At each layer capture raw request target, Envoy-normalized path, intention input/decision, origin path, listener type, response marker, and xDS filter settings.
6. Repeat on the fixed build. Do not use traversal strings that target files; every variant must resolve only to the two canary routes.

The decisive trace is **same semantic denied route -> standard listener denies -> custom listener's policy sees a different representation -> origin serves `/denied/marker`**. A status-code difference without origin-route evidence is only a parser differential. Do not generalize the result to services without custom listeners or to L4 intentions.

## Reporting checklist

- State edition, exact build, affected feature configuration, listener exposure, and caller permission.
- Include affected-versus-fixed traces and a standard-listener or dedicated-route control.
- Preserve canonical paths and marker identities, not file contents or credentials.
- Separate RPC reachability, session-ID knowledge, ACL omission, and final mutation.
- For path tests, include raw target, every normalized representation, policy decision, and origin route.
- Bound impact to the proven sink: synthetic credential relay, denied session mutation, or canary path reachability.
