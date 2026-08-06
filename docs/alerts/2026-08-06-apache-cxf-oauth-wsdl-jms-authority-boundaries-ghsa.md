---
title: Apache CXF OAuth, WSDL-import, and JMS authority boundaries
---

# Apache CXF OAuth, WSDL-import, and JMS authority boundaries

Nine Apache CXF records published on August 6 expose three reusable testing themes: signed or encrypted protocol objects outlive the authorization decision they were meant to represent, protections on a top-level document disappear at an import boundary, and a message transport turns broker write access into Java object-reconstruction authority.

Source records:

- self-issued OIDC token claim validation: [GHSA-9rwm-8rh4-8q53 / CVE-2026-65583](https://github.com/advisories/GHSA-9rwm-8rh4-8q53) and the [Apache announcement](https://lists.apache.org/thread/fzj8yzgfl53gclxrcdrnrx3grcpkq51j);
- repeated redemption in `DefaultEncryptingCodeDataProvider`: [GHSA-7mxw-qv85-693m / CVE-2026-68079](https://github.com/advisories/GHSA-7mxw-qv85-693m) and the [Apache announcement](https://lists.apache.org/thread/6m06gdqz4rxhy9g90qz9lyqx2gqmf13o);
- dynamic client registration scope self-assignment: [GHSA-pwwh-3685-58r7 / CVE-2026-61466](https://github.com/advisories/GHSA-pwwh-3685-58r7) and the [Apache announcement](https://lists.apache.org/thread/2l1r16g79tpxd7fzrzr2q9oscwrjgljs);
- revoked encrypted token acceptance and active introspection: [GHSA-5c8v-93q6-cjxj / CVE-2026-68481](https://github.com/advisories/GHSA-5c8v-93q6-cjxj) and the [Apache announcement](https://lists.apache.org/thread/88c0h10yjb2b8201o1km3st71fs2zw2b);
- signed request-object claim overwrite in `JwtRequestCodeFilter`: [GHSA-7hjx-472h-3f7q / CVE-2026-63687](https://github.com/advisories/GHSA-7hjx-472h-3f7q) and the [Apache announcement](https://lists.apache.org/thread/drcq4chmt0btx86f17o47j17r378hzpw);
- concurrent authorization-code redemption in `JCacheCodeDataProvider`: [GHSA-4qr2-3mpc-grqm / CVE-2026-57818](https://github.com/advisories/GHSA-4qr2-3mpc-grqm) and the [Apache announcement](https://lists.apache.org/thread/7q08mz8bcbosp25wok7gr537zlp15mfz);
- XXE through imported WSDL/XSD documents: [GHSA-jvhw-7q2c-2r65 / CVE-2026-65432](https://github.com/advisories/GHSA-jvhw-7q2c-2r65) and the [Apache announcement](https://lists.apache.org/thread/5qs207krzg51jl3zs3cvnl5lt9njp8c3);
- omitted OIDC Hybrid Flow `c_hash` validation: [GHSA-h8f8-97w2-2925 / CVE-2026-57817](https://github.com/advisories/GHSA-h8f8-97w2-2925) and the [Apache announcement](https://lists.apache.org/thread/pj63c3pf7kkp1xhr53do704fwj3t3htn); and
- native deserialization of inbound JMS `ObjectMessage` bodies: [GHSA-gvw8-rcrx-9fxx / CVE-2026-66909](https://github.com/advisories/GHSA-gvw8-rcrx-9fxx) and the [Apache announcement](https://lists.apache.org/thread/lr5d4tg6tf7j29jmw8wt242oowonjqpx).

The GitHub entries were unreviewed mirrors when this page was written. Apache's records recommend CXF 4.2.3, 4.1.8, or 3.6.12. Confirm the deployed provider, flow, transport, and exact version before testing: several paths are optional and the self-issued-token validator is not enabled by default.

!!! warning "Disposable issuers, brokers, and denied sinks only"
    Use throwaway OAuth clients, synthetic identities, fake tokens, an owned XML callback, a disposable JMS broker, patched token/XML/object sinks, and inert marker objects. Never replay real authorization codes or tokens, register privileged clients in a shared identity service, read host files through XML entities, enqueue serialized gadgets, or target an operational broker.

## 1. Build a protocol-object authority map

Record each object from creation to final use:

```text
caller and client identity
  -> outer HTTP/JMS/XML input
  -> signature, encryption, cache, or parser decision
  -> claims / fields copied into internal state
  -> one-time, revocation, scope, or import policy
  -> principal, token, resource fetch, or deserializer selected
  -> patched final sink
```

Do not treat cryptographic validity as current authorization. A correctly signed request object can still overwrite stronger outer-request state; decryptable tokens can be revoked; an authorization code can be valid but already consumed; and a trusted top-level WSDL can import an untrusted parser context.

## 2. Diff outer OAuth parameters from signed request-object claims

The `JwtRequestCodeFilter` record requires a client capable of producing a validly signed request JWT. Use a disposable confidential client and fake secret. Send matching controls first, then vary only one duplicated field between the outer request and signed object:

| Field | Outer request | Signed request object | Capture |
| --- | --- | --- | --- |
| `code_challenge` | marker A | marker B | value bound to the issued code |
| `code_challenge_method` | expected method | alternate method | verifier branch selected |
| `nonce` | marker A | marker B | value returned and later validated |
| `state` | marker A | marker B | server-side state correlation |

Place recorders immediately before parameter-map merge, code issuance, and token exchange. Do not complete a real login. A bounded positive is **valid client request JWT -> security-sensitive inner claim replaces the already-established outer value -> patched code/token sink records the replacement**.

Test claim precedence rather than assuming every duplicate is exploitable. Preserve negative controls for an invalid signature, wrong client, unknown key, omitted inner claim, and fixed build.

## 3. Test authorization-code single use in serial and concurrent modes

Use synthetic codes that can mint only a token carrying a harmless canary scope. Exercise the providers separately:

1. redeem once, then replay serially against `DefaultEncryptingCodeDataProvider`;
2. redeem once, revoke or remove, then introspect provider state;
3. send two synchronized redemption requests against `JCacheCodeDataProvider`;
4. repeat with enough synchronization to reach the same cache entry, but keep request volume low; and
5. run the same fixtures against a fixed build.

Patch token issuance to return distinct random marker IDs without creating usable bearer tokens. Capture:

```text
code hash
-> provider/cache lookup
-> consume/remove decision
-> atomicity or lock boundary
-> token-issuance recorder
```

Supported findings differ:

- two serial recorder hits prove a missing consume/remove transition;
- two concurrent hits with one serial success prove a race in one-time use;
- a second HTTP success without a second issuance hit may be response replay or error handling, not duplicate token issuance.

Never race a shared identity deployment or retain reusable token material.

## 4. Verify revocation at use and introspection sinks

For `DefaultEncryptingOAuthDataProvider`, create fake encrypted access and refresh tokens in a disposable provider. Compare active, revoked, expired, malformed, and wrong-key controls. After revocation, send the same marker to both the resource-token validator and `TokenIntrospectionService`.

Record decryption separately from authorization:

```text
encrypted marker decrypts
-> token identifier and type recovered
-> revocation state loaded
-> expiry/audience/scope checks
-> introspection active decision
-> patched resource principal
```

A bounded positive is **revoked marker still decrypts -> revocation state is not enforced -> introspection reports `active:true` or a patched protected-resource sink receives the synthetic principal**. Successful decryption alone is not a bypass; prove the later active/use decision.

## 5. Test client-registration scope authority

Dynamic client registration is relevant only when the endpoint is enabled and the caller can reach it. Configure a disposable authorization server with:

- one public canary scope;
- one synthetic elevated scope that reaches only a no-op recorder; and
- an explicit registration-time allowlist that excludes the elevated scope.

Submit registration requests with the public scope, elevated scope, mixed scopes, unknown scope, duplicates, and omitted scope. Record raw metadata, normalized scope set, AS allowlist decision, persisted client metadata, and the scopes accepted during a later patched grant.

The strong proof is **registration accepts an excluded synthetic scope -> persists it on the new client -> a later authorization decision treats it as client authority**. Stored text without grant-time effect is a metadata-validation finding, not privilege escalation. Do not request real administrative or user-data scopes.

## 6. Validate self-issued ID tokens and Hybrid Flow code binding

Keep two separate harnesses because these records have different preconditions.

### Self-issued tokens

Enable self-issued ID-token support explicitly in a disposable relying party. Generate throwaway keys and vary issuer, subject, audience, time claims, and `sub_jwk` binding one at a time. The final sink should record only whether a synthetic principal would be established.

A valid signature with omitted or mismatched required claims must not authenticate. Report the exact omitted check; do not generalize this to default CXF configurations where self-issued tokens are not accepted.

### Hybrid Flow `c_hash`

Use an owned mock IdP and synthetic authorization codes. Compare:

- correct `c_hash`;
- incorrect `c_hash`;
- omitted `c_hash`;
- code from a second synthetic flow; and
- non-Hybrid Flow controls.

Capture ID-token validation, code binding, token exchange selection, and the patched session sink. The Apache record requires a non-compliant or misconfigured IdP that omits `c_hash`; establish that precondition. A missing claim that produces an error is not vulnerable, and code substitution is not proven until the mismatched code reaches the exchange or session decision.

## 7. Trace WSDL hardening across imports

Serve a top-level WSDL and imported WSDL/XSD from owned local fixtures. The top-level document should be harmless. Put an inert external-entity URL in an imported document and direct it only to an owned no-content callback recorder.

Test:

1. top-level DTD/entity as a negative control;
2. one imported WSDL containing the canary entity;
3. one imported XSD containing the canary entity;
4. nested imports;
5. same-origin and cross-origin owned imports; and
6. affected and fixed builds.

Instrument resolver and parser creation:

```text
top-level URL
-> StaxUtils feature flags
-> wsdl:import / xsd:import resolution
-> WSDL4J parser feature flags
-> external-entity resolver
-> denied callback recorder
```

A bounded positive is **top-level parser rejects the DTD control while an imported document reaches the owned denied entity resolver under weaker settings**. Do not use `file:` entities, cloud metadata, loopback services, or internal network targets. Callback reachability proves external-entity resolution, not local-file disclosure.

## 8. Treat JMS destination write access as a deserialization boundary

The JMS issue requires the ability to place a message on the service's destination. In a disposable broker, map producer identity, destination ACL, CXF consumer, classpath, and message-type handling. Replace native deserialization with a recorder or JVM serialization filter that logs the root class and rejects before object construction side effects.

Send only inert fixtures:

- ordinary `TextMessage` and `BytesMessage` controls;
- an `ObjectMessage` containing a serializable marker class with no callbacks;
- an unexpected but harmless JDK value class;
- a malformed serialization stream; and
- affected and fixed/default-disabled configurations.

Capture broker authentication, destination, JMS type, consumer dispatch, `ObjectMessage.getObject()` or equivalent entry, class-resolution request, and rejection. A bounded positive is **authorized or otherwise reachable producer -> CXF consumes `ObjectMessage` -> unrestricted native class resolution begins before a type policy decision**.

Do not enqueue gadget chains or claim RCE from native deserialization alone. RCE additionally requires a suitable reachable gadget classpath and execution sink; keep that as an untested precondition.

## Evidence bundle

```text
CXF version and exact provider/transport:
Optional feature configuration:
Synthetic client, issuer, broker, or XML fixture:
Raw outer object and nested/imported object hashes:
Signature/encryption/parser/cache decision trace:
One-time, revocation, scope, or binding decision:
Patched final sink result:
Affected-build result:
Fixed-build result:
Supported claim:
Explicitly excluded stronger claims:
```

The durable operator lesson is to follow protocol objects past their first successful validation. Preserve evidence for the final authority decision: code consumption, token activity, scope grant, principal creation, import parser, or object reconstruction.