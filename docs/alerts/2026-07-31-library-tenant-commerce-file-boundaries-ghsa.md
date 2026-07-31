---
title: Library URL, tenant authority, commerce binding, and file-boundary checks
---

# Library URL, tenant authority, commerce binding, and file-boundary checks

A July 31 advisory wave exposes reusable operator boundaries across SDK URL construction, SSRF validation, Kubernetes tenant controllers, payment callbacks, corpus readers, local developer servers, file-sharing tools, workflow imports, and server templates.

Sources:

- [GHSA-g956-2f74-rmv7](https://github.com/advisories/GHSA-g956-2f74-rmv7) covers unencoded path and query values in `hashi-vault-js` through 0.5.1;
- [GHSA-5846-7qm3-r52j](https://github.com/advisories/GHSA-5846-7qm3-r52j) covers `dssrf` accepting a loopback name after an empty DNS result through 1.0.4;
- [GHSA-qvv7-cg9c-w4x3](https://github.com/advisories/GHSA-qvv7-cg9c-w4x3) covers DNS rebinding between NLTK URL validation and connection through 3.9.4;
- [GHSA-jr6p-8pjj-mfx6](https://github.com/advisories/GHSA-jr6p-8pjj-mfx6) covers Capsule `TenantResource` raw-item and generator paths retaining cluster-scoped controller authority in 0.13.0 through 0.13.7;
- [GHSA-x83g-979r-f5fh](https://github.com/advisories/GHSA-x83g-979r-f5fh) and [GHSA-rc52-c4hv-w89p](https://github.com/advisories/GHSA-rc52-c4hv-w89p) cover Sylius Mollie Plugin order-token disclosure and payment-to-order misbinding;
- [GHSA-6hm5-jgcp-p838](https://github.com/advisories/GHSA-6hm5-jgcp-p838) and [GHSA-xh95-f55m-82fw](https://github.com/advisories/GHSA-xh95-f55m-82fw) cover NLTK corpus-reader paths that bypass `nltk.pathsec` through 3.9.4;
- [GHSA-g2r8-wvmj-jf5w](https://github.com/advisories/GHSA-g2r8-wvmj-jf5w) covers wildcard CORS on the `nx graph` local server;
- [GHSA-22p9-r2f5-22mf](https://github.com/advisories/GHSA-22p9-r2f5-22mf) and [GHSA-v833-3823-cmhp](https://github.com/advisories/GHSA-v833-3823-cmhp) cover OnionShare symlink following and disabled-upload sink enforcement before 2.6.4;
- [GHSA-g29c-rgq6-gxgj](https://github.com/advisories/GHSA-g29c-rgq6-gxgj) covers `awxkit` YAML `!include` traversal;
- [GHSA-f6vj-48fm-hmvx](https://github.com/advisories/GHSA-f6vj-48fm-hmvx) covers GCS object names escaping an Airflow Samba destination before provider 4.12.6; and
- [GHSA-pfvc-3p5h-x7h6](https://github.com/advisories/GHSA-pfvc-3p5h-x7h6) covers user-editable Pterodactyl egg values reaching Wings daemon configuration templates before 1.12.3.

!!! warning "Canaries only"
    Run these checks in disposable applications, clusters, stores, corpora, shares, repositories, and game-server nodes. Use fake Vault tokens, owned DNS/listener pairs, inert Kubernetes objects, synthetic orders and payments, marker-only files, no-op help commands, and fake template values. Never call a live Vault administrative endpoint, alter a real order, read customer data, access real local files, or retrieve node tokens and registry credentials.

## Boundary map

| Surface | Caller-controlled value | Privileged transition | Safe positive |
| --- | --- | --- | --- |
| Vault SDK | path segment or query value | application token sends a different Vault request | mocked transport records changed path or parameters |
| SSRF helper | hostname and DNS outcome | validation result authorizes a later socket | owned listener B receives after listener A was approved |
| Capsule controller | raw item or generated kind | tenant object is applied with controller authority | admission recorder sees an inert cluster-scoped canary |
| Payment integration | order ID and provider payment ID | public route returns an order capability or mutates another order | synthetic two-order decision table differs by foreign ID |
| Corpus reader | file ID, frame name, or corpus index value | helper bypasses the documented path gate | parser returns an outside-root marker file |
| Local dev server | browser origin | arbitrary website reads loopback project responses | owned foreign origin reads a synthetic graph marker |
| Share/import/workflow tool | symlink, upload part, include, or object name | local process reads or writes beyond its stated boundary | disposable marker is read or written, with no sensitive target |
| Wings template | editable egg value | tenant input resolves against node configuration | fake non-secret config marker appears in a server file |

Prove authority, selection, and final sink separately. A malformed value accepted by a parser is not enough; preserve the final URL, Kubernetes object, selected order, opened path, written path, browser-readable response, or rendered marker.

## SDK URL-construction differential

Use a mocked HTTP adapter that cannot reach Vault. Configure a fake base such as `https://vault.invalid/v1/skillz/` and a token with no real authority.

1. Call each SDK method with an ordinary identifier and record the method, raw URL, normalized path, query multimap, headers, and body.
2. Repeat with one path-separator marker, one dot-segment marker, one percent-encoded marker, and one query-delimiter marker.
3. Parse the final URL with the same HTTP stack the application uses.
4. Compare vulnerable and fixed releases.

| Input class | Expected secure result |
| --- | --- |
| path identifier | remains exactly one encoded path segment |
| query scalar | remains exactly one value under the documented key |
| delimiter or dot-segment canary | rejected or encoded before transport dispatch |

A report should identify the application-controlled SDK method and the authority of its Vault token. Do not equate a path-normalization difference with access to an administrative endpoint unless an isolated fake Vault and a deliberately restricted token prove that separate authorization edge.

## SSRF validation-to-connection drift

Test both the empty-resolution branch reported for `dssrf` and the validation/connect-time rebinding reported for NLTK with owned infrastructure only.

### Empty-answer matrix

Stub the resolver so the same hostname produces each controlled outcome:

| Validation outcome | Address set | Secure policy |
| --- | --- | --- |
| public answer | owned public test address | allow only according to policy |
| loopback/private answer | synthetic blocked address | reject |
| empty/NXDOMAIN | no usable address | reject closed |
| resolver error | exception or timeout | reject closed |

The key assertion is that an empty answer must not turn a literal localhost or unresolved host into an allowed destination. Record the validator result and confirm that no socket was attempted.

### Rebinding harness

Use two owned listeners and deterministic resolver instrumentation:

```text
validation lookup -> owned listener A
connection lookup -> owned listener B
```

Listener B should return only `SKILLZ-FINAL-DESTINATION`. Capture lookup order, approved address set, connected peer, redirects, and response marker. A valid positive shows the validator approving A while the HTTP client independently resolves and connects to B. Do not use cloud metadata, loopback administration routes, or production private services.

## Capsule alternate-path authority check

The reusable lesson is to test every representation accepted by a controller after a security fix, not only the route named by the guard.

### Preconditions

- disposable Kubernetes cluster and Capsule deployment;
- tenant owner with no direct cluster-scoped create permission;
- audit logging or a fake apply client;
- an inert custom resource or marker-only cluster-scoped fixture with no RBAC rules, webhook callbacks, or workload effects.

Build a matrix across `NamespacedItems`, `RawItems`, and `Generators`:

| Input path | Namespaced canary | Cluster-scoped inert canary | Expected secure result |
| --- | --- | --- | --- |
| selected item | allowed in tenant namespace | rejected before apply | scope guard covers selection |
| raw item | allowed in tenant namespace | rejected before apply | scope guard covers decode/render path |
| generator | allowed in tenant namespace | rejected before apply | scope guard covers generated objects |

Record the tenant principal, selected controller client, object GVK, namespace before and after rendering, discovery result for resource scope, and whether the apply sink was reached. Setting `metadata.namespace` is not confinement for a cluster-scoped kind. Stop at an inert marker and never create a `ClusterRole`, webhook configuration, CRD, namespace, or other operational cluster object.

## Payment and order object-binding workflow

Use a local Sylius store, a mocked Mollie adapter, and two disposable orders:

```text
Order A -> provider payment PA -> owner session A
Order B -> provider payment PB -> owner session B
```

No real payment is needed. Seed provider responses so both fake IDs have explicit synthetic status.

### Capability-disclosure edge

Request the QR and thank-you route families as anonymous, owner A, and owner B while substituting A, B, absent, and malformed order IDs. Capture status, redirect target shape, response schema, session changes, and whether any order capability appears. Redact the capability itself.

A positive requires a foreign or anonymous request to obtain a capability associated with the synthetic order. Do not follow it into customer pages or collect names, email addresses, addresses, or order lines.

### Payment-to-order binding edge

Replay the webhook handler through a local request recorder:

| Provider ID | Order ID | Expected secure result |
| --- | --- | --- |
| `PA` | A | process A according to mocked provider status |
| `PB` | B | process B according to mocked provider status |
| `PA` | B | acknowledge safely, no mutation |
| unknown | A | no mutation |

Preserve the incoming pair, server-side payment ID stored on the order, mocked provider result, transition decision, and before/after synthetic state. The finding is an object-binding failure, not a payment-provider verification bypass: one identifier may be valid while belonging to a different object.

## NLTK corpus sandbox coverage

Create this disposable layout:

```text
/tmp/skillz-nltk/
  corpus/                 # configured root
  sibling/
    marker.xml            # synthetic parser-valid canary
```

Enable `nltk.pathsec.ENFORCE = True`, instrument both `CorpusReader.open()` and the builtin file-open sink, and exercise:

- `NKJPCorpusReader` public methods with ordinary and traversal-shaped `fileids`;
- `FramenetCorpusReader.frame()` with an ordinary name and a sibling-marker name;
- FrameNet document and lexical-unit filenames sourced from a synthetic corpus index; and
- fixed-version controls using the identical fixture.

Capture requested logical name, normalized absolute path, required root, which open helper was called, and returned marker. The strongest evidence shows that the documented secure mode is active but a specialized reader reaches builtin `open()` without invoking the central validator. Never target `/etc`, home directories, credentials, notebooks, datasets, or model artifacts.

## Loopback developer-server browser boundary

Start `nx graph` against a repository containing only synthetic project names and a help command that prints `SKILLZ-NX-HELP`. Keep it bound to loopback. From an owned foreign-origin page, issue browser `fetch()` requests to the graph and help routes.

Record:

- bind address and port;
- browser page origin;
- request method and preflight behavior;
- response CORS headers;
- whether JavaScript can read the synthetic graph/help marker; and
- vulnerable/fixed release results.

The valid finding is cross-origin readability of loopback responses. The advisory notes that the help command comes from existing workspace configuration rather than the browser request. Do not claim browser-supplied command execution, and do not place a malicious command in a real repository merely to amplify the result.

## Share, import, and workflow filesystem checks

### OnionShare symlink read

Create a share directory and a sibling marker, then place a symlink inside the share pointing only to that marker. Test Website mode, individual Share download, and generated archive paths separately. Capture index mapping, dereferenced path, archive listing, and returned marker. Raw URL traversal is a different hypothesis and should not be claimed from a symlink result.

### OnionShare disabled-upload sink

Start Receive mode with file uploads disabled and submit a small multipart canary named `skillz-marker.txt`. Instrument the stream factory and receive directory. A positive requires file creation or a write event despite the disabled setting; hiding the browser input or omitting the file from later accounting is not sink enforcement. Delete the fixture immediately.

### `awxkit` include boundary

Use a disposable import directory and a sibling YAML marker containing only `skillz: include-canary`. Import a synthetic document whose `!include` value selects that sibling. Record the importer's normalized path and parsed marker. Do not point the include at credentials, AWX configuration, SSH material, or shell files.

### Airflow GCS-to-Samba write boundary

Use fake GCS and SMB adapters backed by temporary directories. Seed one normal object name and one object name that would normalize to a sibling marker path. Record source object name, configured destination root, normalized destination, containment decision, and write-recorder event. The positive is an outside-root marker write caused by object metadata; do not connect to a real bucket or Samba share.

## Wings egg-to-node template boundary

Run Panel and Wings in an isolated node whose configuration contains only a fake field such as:

```yaml
skillz_canary: NODE-CONFIG-MARKER
```

Use a stock-like egg fixture where an editable environment variable is rendered into a server-owned configuration file. Submit a harmless template-shaped value that references only `skillz_canary`, then record:

1. the user-editable value accepted by Panel;
2. the replacement definition sent to Wings;
3. the template context keys exposed by Wings; and
4. whether the server file contains the literal placeholder or `NODE-CONFIG-MARKER`.

Do not request `token`, `token_id`, registry credentials, environment variables, or any real daemon field. A report should distinguish editable-variable permission, Panel substitution, Wings template evaluation, and server-file readability. The canary proves the authority transition without obtaining reusable credentials.

## Evidence and reporting

For every workflow, preserve:

- exact package, version, configuration, and reachable application feature;
- low-privilege or anonymous precondition;
- normal, malformed, foreign-object, and fixed-version controls;
- normalized URL, destination, object identity, or template context at the final sink;
- marker-only output and cleanup confirmation; and
- the narrow authority gained by the tested edge.

Prefer titles such as “Vault SDK path identifier changes the mocked downstream route,” “Capsule raw-item path reaches apply with a cluster-scoped canary,” “paid-provider ID is accepted for a different synthetic order,” or “Wings renders a user-editable value against node configuration.” Avoid generic Vault compromise, cluster-admin takeover, payment fraud, arbitrary file theft, or node compromise unless those stronger outcomes were independently authorized and safely proven.