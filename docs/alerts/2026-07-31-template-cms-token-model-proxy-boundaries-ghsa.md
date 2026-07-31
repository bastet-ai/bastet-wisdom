---
title: Template, CMS, token, model, signature, and HTTP-proxy trust boundaries
---

# Template, CMS, token, model, signature, and HTTP-proxy trust boundaries

A late July 31 advisory wave yields eight durable operator themes: template sandboxes that expose type constructors, CMS fields crossing into script or process-global authorization state, URI-bearing HTML attributes omitted from sanitizer policy, host-derived server fetches, caller-selected JWKS schemes, local model artifacts bypassing remote-code policy, signing-time checks drifting from key-validity policy, and HTTP intermediaries disagreeing about request framing.

Primary sources:

- Jinjava [GHSA-m49c-g9wr-hv6v / CVE-2025-59340](https://github.com/advisories/GHSA-m49c-g9wr-hv6v);
- ApostropheCMS SEO [GHSA-wf43-fpp3-cf65 / CVE-2026-53608](https://github.com/advisories/GHSA-wf43-fpp3-cf65), pretty URL [GHSA-34pj-2622-jvxq / CVE-2026-53607](https://github.com/advisories/GHSA-34pj-2622-jvxq), and prototype-pollution [GHSA-6h5j-32cf-4253 / CVE-2026-53609](https://github.com/advisories/GHSA-6h5j-32cf-4253) records;
- sanitize-html [GHSA-vccv-cmxp-4j9h / CVE-2026-53606](https://github.com/advisories/GHSA-vccv-cmxp-4j9h);
- PyJWT [GHSA-993g-76c3-p5m4 / CVE-2026-48522](https://github.com/advisories/GHSA-993g-76c3-p5m4);
- sentence-transformers [GHSA-jhr6-gm9c-rqjv / CVE-2026-68770](https://github.com/advisories/GHSA-jhr6-gm9c-rqjv) and MONAI [GHSA-89gg-p5r5-q6r4](https://github.com/advisories/GHSA-89gg-p5r5-q6r4);
- sigstore-go [GHSA-wqqc-jjcq-vfxm / CVE-2026-54787](https://github.com/advisories/GHSA-wqqc-jjcq-vfxm); and
- Hiawatha [GHSA-8mxp-hf23-8hp4 / CVE-2026-51785](https://github.com/advisories/GHSA-8mxp-hf23-8hp4) with the detailed [Fenrisk request-smuggling disclosure](https://fenrisk.com/hiawatha-http-smuggling).

The sentence-transformers and Hiawatha records were unreviewed GitHub Advisory Database entries at scan time. Confirm the exact artifact, configuration, and fixed-build behavior rather than treating database metadata as reproduction evidence.

!!! warning "Recorder-first, disposable fixtures only"
    Use inert template expressions, synthetic CMS fields and documents, owned HTTP listeners, fake JWKS and JWT claims, toy model directories, generated test keys, and isolated raw-byte proxy labs. Never read local secrets, query production internal services, execute generated/template/model code, poison shared caches, capture another user's request, forge production tokens, or sign operational artifacts.

## Boundary map

| Surface | Attacker-controlled value | Authority transition | Bounded positive |
| --- | --- | --- | --- |
| Jinjava | template expression and constructed `JavaType` | sandboxed expression reaches Jackson type construction/deserialization | recorder observes selection of a harmless canary class that direct sandbox policy denies |
| Apostrophe SEO | editor-controlled tracking/tag-manager ID | string enters a raw JavaScript body rendered on every page | inert syntax marker changes the generated script AST in an owned draft/site |
| Apostrophe patch operators | dot-notation key | document patch mutates `Object.prototype`, then inherited option changes authorization | canary inherited property appears process-wide and a no-data route decision changes |
| sanitize-html | enabled tag, attribute, and URI | allowlisted attribute skips scheme validation | dangerous-scheme marker survives a non-default URI-bearing attribute but not `href` control |
| Apostrophe pretty URL | request `Host` plus known public file slug | CMS constructs and fetches an upstream URL | owned second listener receives the constrained attachment path and returns a marker |
| PyJWT `PyJWKClient` | configured or token-derived JWKS URI | URL loader accepts non-HTTP schemes and supplies verification keys | mocked opener selects `file`, `ftp`, or `data` before any real I/O |
| sentence-transformers / MONAI | local model directory or pickle path | trusted local-path branch imports code or deserializes bytes | import/pickle recorder fires for a toy canary artifact without executing it |
| sigstore-go | signed timestamp and long-lived key validity window | verifier accepts a signature outside configured key validity | generated expired-key fixture verifies only on the affected build |
| Hiawatha | raw `Content-Length` plus `Transfer-Encoding` bytes | front-end and back-end disagree on message boundary | two attacker-owned requests show route-marker reassociation on one isolated connection |

## 1. Jinjava template sandbox to Jackson type construction

The advisory describes a path from the built-in `____int3rpr3t3r____` object through interpreter configuration to an `ObjectMapper`. Direct access to `Class`, `ClassLoader`, and selected methods may be blocked while `TypeFactory.constructFromCanonical()` and `ObjectMapper.readValue(..., JavaType)` remain reachable. This distinction matters: a sandbox denylist can block obvious reflection and still expose an equivalent type-selection primitive.

Affected ranges are `com.hubspot.jinjava:jinjava >= 2.7.0, < 2.7.5` and `2.8.0`; listed corrected releases are `2.7.5` and `2.8.1`.

### Safe validation

1. Run the exact affected and fixed Jinjava artifacts in a process with no credentials, network access, sensitive files, or dangerous classpath gadgets.
2. Replace or instrument `ObjectMapper.readValue(String, JavaType)` so it records the canonical type and returns a sentinel without deserializing.
3. Establish controls: a normal expression succeeds; direct access to a documented blocked class or method fails.
4. Use a template expression that reaches only a harmless test class such as `lab.skillz.TemplateCanary` through `constructFromCanonical()`.
5. Record each resolver edge: built-in interpreter object, config property, mapper, type factory, canonical type, and recorder invocation.
6. Repeat on the fixed build and with alternate property/method syntax. Stop before URL construction, file access, process creation, JNDI, script engines, or class loading with side effects.

A reportable result is **the sandbox denies direct type/class access but an equivalent `JavaType` path reaches the deserialization sink**. Do not claim file read, SSRF, or code execution from type selection alone; each requires a concrete reachable class and should not be exercised when recorder evidence is sufficient.

## 2. ApostropheCMS script-body and process-global policy boundaries

### SEO identifier to raw JavaScript

`@apostrophecms/seo <= 1.4.2` inserted `seoGoogleTrackingId` and `seoGoogleTagManager` into raw script bodies. The listed corrected release is `1.5.0`. The key test is not generic HTML reflection: it is whether an editor-controlled scalar escapes a JavaScript string inside a site-wide trusted script node.

Use a disposable editor and draft-only site. Set each field to:

- a valid-looking identifier control;
- a quote and parenthesis marker containing no executable call;
- newline, backslash, Unicode separator, and template-literal markers; and
- oversized or malformed identifiers to map storage validation separately.

Capture the stored scalar, server-side render-node representation, final script text, and parser AST. A bounded positive is an inert marker producing an extra statement or otherwise escaping the intended string node. Do not use cookie access, network callbacks, privileged actions, or a production publish operation.

### Patch key to `Object.prototype` to authorization decision

Apostrophe `<= 4.30.0` passed caller-controlled dot-notation keys from patch operators such as `$pullAll` into `apos.util.set()`. Prototype segments could mutate process-global inherited state. The advisory identifies `publicApiProjection` as a concrete option consumed before `canAccessApi()`. The listed corrected release is `4.31.0`.

Validate the edges separately:

1. Create a disposable editor, one synthetic piece type, and an unauthenticated route that returns no content but records whether `publicApiCheck()` ran.
2. Run the patch implementation in an isolated worker with a benign canary key under a test-only inherited object. Prefer direct function instrumentation over sending dangerous `__proto__` paths through a live CMS.
3. Record whether path parsing rejects `__proto__`, `constructor`, and `prototype` at every nesting and encoding variant.
4. In a disposable affected process only, use a non-privileged marker property and confirm whether it appears on unrelated fresh objects; restart immediately after the test.
5. Use a mocked options object and authorization recorder to show how inherited versus own `publicApiProjection` changes the guard decision. Return zero documents in both branches.
6. Repeat on 4.31.0. The path should be rejected before mutation, and authorization should not trust inherited configuration.

Preserve **pollution**, **gadget reachability**, **authorization-guard change**, and **document visibility** as four separate claims. Never retrieve users, globals, unpublished content, or another tenant's records.

## 3. sanitize-html URI-bearing attribute policy differential

The default `allowedSchemesAppliedToAttributes` covered `href`, `src`, and `cite`, while applications could separately allow URI-bearing attributes such as `action`, `formaction`, `data`, `poster`, or `background`. In `sanitize-html >= 1.18.0, <= 2.17.4`, those attributes could bypass the scheme check; `2.17.5` is listed as fixed. Default configuration is not the advisory's vulnerable case.

Build a pure string-to-string harness and never open the output in a production browser:

```javascript
const sanitize = require('sanitize-html');

const fixtures = [
  ['a', 'href'],
  ['form', 'action'],
  ['button', 'formaction'],
  ['object', 'data'],
  ['video', 'poster']
];

for (const [tag, attribute] of fixtures) {
  const input = `<${tag} ${attribute}="javascript:SKILLZ_CANARY">x</${tag}>`;
  const output = sanitize(input, {
    allowedTags: [tag],
    allowedAttributes: { [tag]: [attribute] }
  });
  console.log(JSON.stringify({ tag, attribute, output }));
}
```

`SKILLZ_CANARY` is deliberately not executable JavaScript. Compare affected and fixed versions across mixed case, ASCII controls, entity encoding, whitespace before the colon, protocol-relative URLs, and allowed `https:` controls. Record sanitizer configuration and serialized output. Then parse output into a detached DOM or AST recorder without navigation.

A strong report says **non-default URI-bearing attribute skips scheme policy while the `href` control is stripped**. Do not generalize to default configuration, and do not call every surviving URL script execution without a browser/sink-specific control.

## 4. Apostrophe pretty URL to Host-derived server fetch

When `@apostrophecms/file` uses `prettyUrls: true` with local upload storage, Apostrophe `<= 4.30.0` could combine the raw request `Host` with a locally generated `/uploads/attachments/<id>-<slug>.<ext>` path and fetch it. `4.31.0` is listed as corrected. S3/CDN absolute attachment URLs and installations without pretty URLs do not follow the described relative-path branch.

Use two owned listeners and one public synthetic file:

1. On listener A, create a disposable Apostrophe site and upload a random marker file.
2. On listener B, expose only a recorder for the exact constrained attachment path. Return a random response marker and no sensitive content.
3. Request the public pretty URL from A while varying `Host`, absolute-form request target, trusted-proxy mode, `X-Forwarded-Host`, port, IPv6 authority, and duplicate headers one at a time.
4. Record incoming authority, derived attachment URL, final fetch URL, outbound destination, path, status, and whether response bytes were relayed.
5. Compare local versus S3-style attachment URLs and affected versus corrected builds.

Do not probe metadata addresses, RFC1918 services, localhost daemons, or production internal names. Because the path is fixed by an existing file record, lead with **Host-derived outbound authority and constrained response relay**, not unrestricted SSRF.

## 5. PyJWT JWKS URI scheme and verification-authority composition

`PyJWKClient` in PyJWT `>= 2.0.0, <= 2.12.1` passed its URI to `urllib.request.urlopen()`, whose default handlers include `file`, `ftp`, and `data`. The listed corrected release is `2.13.0`. The advisory explicitly separates scheme acceptance from token forgery: forgery additionally requires attacker influence over the JWKS URI and control of valid JWKS bytes at the selected source.

### No-I/O scheme matrix

Monkeypatch the URL opener before constructing the client:

```python
from unittest.mock import patch
from jwt import PyJWKClient

uris = [
    "https://keys.example.invalid/jwks.json",
    "http://keys.example.invalid/jwks.json",
    "file:///tmp/skillz-jwks-canary.json",
    "ftp://keys.example.invalid/jwks.json",
    'data:application/json,{"keys":[]}',
]

with patch("urllib.request.urlopen", side_effect=RuntimeError("SKILLZ_FETCH_RECORDER")) as opener:
    for uri in uris:
        try:
            PyJWKClient(uri).fetch_data()
        except Exception as exc:
            print(uri.split(":", 1)[0], type(exc).__name__, opener.call_count)
```

Keep `/tmp/skillz-jwks-canary.json` nonexistent so an accidental unpatched file open cannot read anything. The expected corrected behavior rejects disallowed schemes before the opener. Also test mixed-case schemes, empty schemes, leading whitespace, userinfo, and an HTTPS-only policy if the application exposes one.

### Composition test with fake keys

If the application derives the JWKS URL from an unverified `jku`, tenant setting, issuer metadata, or request field, use a mocked transport and a generated disposable keypair. Record:

```text
unverified token header
  -> selected JWKS URI
  -> scheme/authority decision
  -> returned synthetic key set
  -> kid selection
  -> signature decision
  -> issuer/audience/expiry decisions
```

Do not write a JWKS outside a temporary lab directory or mint a token accepted by a real service. Report scheme acceptance, URL control, key-source control, and forged-claim acceptance as separate edges.

## 6. Local model artifacts crossing code and pickle boundaries

### sentence-transformers local-path trust drift

The unreviewed record says `import_module_class()` treated an existing local `model_name_or_path` as sufficient to load classes referenced by `modules.json`, even with `trust_remote_code=False`. The important differential is **remote-code policy versus local artifact trust**, not whether Python imports can execute code in general.

1. Create a toy local model directory containing only synthetic metadata and a module whose top level calls a patched import recorder.
2. Replace `importlib`/module execution with a loader that records module name and file path, then raises `SKILLZ_IMPORT_BLOCKED` before evaluating bytes.
3. Load the same directory with `trust_remote_code=False` and `True`; compare an absent path, existing trusted path, existing untrusted path, and the corrected build.
4. Record `modules.json` class reference, canonical directory, provenance, trust flag, branch condition, and loader call.
5. Never place model fixtures in a shared cache or use environment reads, network calls, process creation, or serialized executable objects.

A positive is **an existing caller-controlled directory causes the loader to select repository code despite `trust_remote_code=False`**. The attacker must still control or influence that directory's contents.

### MONAI explicit pickle loader

MONAI's `algo_from_pickle()` read caller-selected bytes and passed them to `pickle.loads()` before `1.6.0`. Test only sink reachability:

1. Patch `pickle.loads` to hash input, record the call site, and raise a sentinel.
2. Write random non-pickle canary bytes to a temporary file.
3. Call the exact application path that eventually invokes `algo_from_pickle()`; do not call only the library helper if the assessed app never exposes it.
4. Record who selects the path, artifact provenance/signature, worker privilege, and recorder invocation.
5. Compare 1.6.0 and the application's replacement loading path.

Do not build a `__reduce__` payload. A pickle sink on trusted administrator-generated artifacts is not remotely exploitable until an untrusted write/import/upload path is independently established.

## 7. sigstore-go signed time versus long-lived key validity

The sigstore-go issue affects self-managed long-lived public keys wrapped in `ExpiringKey`, not the standard certificate-authority workflow. Releases `<= 1.2.0` are listed as affected; `1.2.1` is corrected. Verification could accept a valid cryptographic signature whose trusted signing timestamp fell outside the configured key-validity interval.

Use generated keys and inert payload bytes:

1. Generate one disposable signing key and a one-line marker artifact.
2. Define a validity window that ends before the synthetic signing timestamp.
3. Build a bundle in the self-managed long-lived-key workflow and verify it on affected and fixed versions.
4. Run controls for a timestamp inside the window, before `notBefore`, after `notAfter`, exactly at each boundary, and without trusted time evidence.
5. Capture key fingerprint, validity bounds, signed timestamp, time-evidence source, signature result, and policy result. Destroy the private key after the test.

A bounded positive is **cryptography succeeds but key-validity policy should fail at the trusted signing time**. Do not claim the certificate-backed Sigstore flow is affected, and do not sign or verify operational release artifacts.

## 8. Hiawatha HTTP framing and intermediary-role differential

Hiawatha `<= 12.1` checked `Content-Length` before chunked `Transfer-Encoding`. As a reverse proxy, it could forward both framing fields, allowing a compliant back end to parse a different boundary. The Fenrisk report distinguishes two topologies:

- **Hiawatha as front end:** CL.TE differential against a back end that accepts both fields and frames on chunked encoding; and
- **Hiawatha as back end:** TE.CL differential only when the front end forwards both fields and reuses the upstream connection.

Hiawatha `12.2` rejects requests carrying both fields with `400`.

### Isolated raw-byte validation

1. Build a private lab with Hiawatha, a minimal raw-byte recorder backend, and no shared users. Disable all real authentication and sensitive routes.
2. Use one synthetic public route and one denied canary route that return random markers. Keep cache disabled for the first framing test.
3. Send a single ambiguous request followed by a second request you also own on the same connection. Use a harmless method/path reassociation marker, not another user's traffic.
4. Capture exact client bytes, Hiawatha-to-backend bytes, connection IDs, parser-consumed byte counts, backend route order, and response order.
5. Reverse the topology and repeat only if the front-end fixture's behavior is fully known. Test duplicate and comma-joined framing fields separately from the advisory's dual-field baseline.
6. Compare 12.1 and 12.2. The corrected build should reject ambiguity before forwarding it.

Only after the parser differential is established in a disposable environment should you test a no-data ACL recorder or cache key/route mismatch. Never poison a shared cache, target authenticated routes, reuse another user's connection, or collect request fragments. Report **single-connection parser disagreement** separately from cross-user impact.

## Evidence and report wording

Preserve exact package versions and hashes, configuration preconditions, source provenance, decoded input, canonical representation at each trust boundary, recorder output, and corrected-build controls. Prefer narrow titles such as:

- **“Jinjava sandbox exposes Jackson `JavaType` construction to template expressions.”**
- **“Apostrophe editor-controlled tracking ID escapes its JavaScript string context.”**
- **“Apostrophe patch key mutates inherited policy state before an API authorization guard.”**
- **“sanitize-html skips scheme validation for an enabled `formaction` attribute.”**
- **“Apostrophe pretty-file route derives outbound authority from the client `Host`.”**
- **“Token-derived PyJWT JWKS URI reaches a non-HTTP URL handler.”**
- **“Local sentence-transformers model metadata selects code despite `trust_remote_code=False`.”**
- **“sigstore-go accepts a self-managed-key signature outside the configured key-validity interval.”**
- **“Hiawatha and the lab backend disagree on one ambiguous request boundary.”**

Do not collapse a reachable sink into maximum impact. Preserve each required composition edge and stop when inert recorder evidence proves the boundary.