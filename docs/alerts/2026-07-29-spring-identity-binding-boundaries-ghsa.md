---
title: Spring LDAP, WebSocket, and HATEOAS identity-binding boundaries
---

# Spring LDAP, WebSocket, and HATEOAS identity-binding boundaries

Three Spring advisories updated on July 29 expose reusable testing boundaries: an LDAP username/password pair can become an RFC 4513 unauthenticated bind, a predictable WebSocket session identifier can be mistaken for authorization, and alternate hypermedia deserializers can bypass Jackson property controls.

Sources:

- [GHSA-jrv5-8w28-4265 / CVE-2026-41720](https://github.com/advisories/GHSA-jrv5-8w28-4265) and the [Spring LDAP advisory](https://spring.io/security/cve-2026-41720/): empty-password LDAP authentication bypass;
- [GHSA-q723-847q-5g8g / CVE-2026-41838](https://github.com/advisories/GHSA-q723-847q-5g8g) and the [Spring Framework advisory](https://spring.io/security/cve-2026-41838/): predictable WebSocket session IDs; and
- [GHSA-7fxc-486f-32q9 / CVE-2026-41006](https://github.com/advisories/GHSA-7fxc-486f-32q9) and the [Spring HATEOAS advisory](https://spring.io/security/cve-2026-41006/): Collection+JSON and UBER property binding outside Jackson's access-control annotations.

Two adjacent advisories concern retry-cache and HATEOAS heap exhaustion. They are intentionally omitted because they do not add a non-availability operator workflow.

!!! warning "Authorized validation only"
    Use a local LDAP server, disposable identities, two lab WebSocket clients, synthetic model properties, and recorder-only application actions. Never test passwords against real users, subscribe to another tenant's live messages, modify production roles, or use sensitive model fields as proof.

## Boundary map

| Input | Trust decision to test | Bounded positive evidence |
| --- | --- | --- |
| valid LDAP username plus empty/null password | bind result is treated as authenticated proof | lab application grants the canary user session after the LDAP server records an unauthenticated bind |
| WebSocket session ID | identifier possession substitutes for principal/object authorization | client B can resolve or act on A's synthetic session with no stronger A-bound proof |
| Collection+JSON or UBER property | alternate deserializer ignores a Jackson write restriction | a setter-only canary changes through alternate media type while ordinary JSON rejects or ignores it |

Keep server acceptance separate from application authorization. An LDAP server accepting an unauthenticated bind is not sufficient until the application grants authenticated state; predicting an ID is not sufficient until a route uses it as authority; and reaching a setter is not privilege escalation until that property controls a security-relevant application action.

## Empty-password LDAP bind differential

Spring LDAP's affected `DirContextAuthenticationStrategy` implementations do not reject a non-empty username paired with an empty or null password. RFC 4513 section 5.1.2 classifies that request as an unauthenticated bind. Exploitation requires an LDAP server that permits the bind and an application that interprets its success as password authentication.

### Lab matrix

1. Run an isolated LDAP directory with one disposable user and bind telemetry. Configure unauthenticated binds explicitly for the affected fixture; keep anonymous and authenticated bind results distinguishable.
2. Connect a minimal application through the same Spring LDAP authentication strategy used by the target. Record the supplied username/password shape, LDAP bind form, server result, resulting principal, session issuance, and one harmless authorization decision.
3. Test these inputs independently: valid username/correct password, valid username/wrong password, valid username/empty string, valid username/null if the application can represent it, unknown username/empty string, and empty username/empty password.
4. Repeat with the LDAP server configured to reject unauthenticated binds. This proves the server-side precondition rather than attributing every empty-password attempt to Spring.
5. Repeat on the applicable fixed line: 4.0.4, 3.3.8, 3.2.18, or 2.4.5. The application must reject the empty/null secret before treating the bind as authenticated.

The Spring primary advisory lists affected ranges as 4.0.0-4.0.3, 3.3.0-3.3.7, 3.2.0-3.2.17, and 2.4.4 or earlier. Preserve the exact dependency line because GitHub's package range currently ends the 3.2 branch at 3.2.16 while Spring includes 3.2.17.

Strong evidence is **valid lab username + empty secret -> LDAP server logs RFC 4513 unauthenticated bind -> application issues an authenticated canary principal**. Do not report password compromise; no password was verified or recovered.

## WebSocket identifier-versus-authority workflow

The Spring Framework advisory states that `spring-websocket` session IDs are not cryptographically unpredictable and may be exploitable only in combination with inadequate authorization rules. Treat this as an application route review, not automatic session hijacking.

1. Create users A and B and one uniquely marked WebSocket session for each. Capture IDs only from each user's own client or server-side lab telemetry.
2. Generate a short sequence of A-owned session IDs across fresh connections. Record whether IDs are sequential, time-derived, process-local, or otherwise predictable without brute-forcing the endpoint.
3. Inventory every HTTP, messaging, broker-relay, disconnect, subscription, diagnostics, and application API path that accepts or returns a WebSocket session ID.
4. As B, submit A's already observed lab ID to each candidate path. Do not enumerate unknown IDs. Record whether the server independently binds the operation to B's principal, destination authorization, and tenant/object ownership.
5. Prove only one harmless effect: resolve A's synthetic marker, subscribe to an A-owned canary destination, or disconnect A's disposable session. Stop after the first reversible result.
6. Repeat on 7.0.8, 6.2.19, 6.1.28, or 5.3.49 as appropriate. Also retain a negative control where authorization rejects a known foreign ID even on an affected framework version.

Report the two edges separately: **ID predictability** and **foreign-ID authorization failure**. A predictable value with correct per-principal authorization is not a demonstrated confidentiality or integrity issue.

## Alternate hypermedia property-binding differential

The HATEOAS issue requires all of these conditions: Collection+JSON or UBER is enabled, a controller accepts a `RepresentationModel` subclass or `EntityModel` as `@RequestBody`, and the model has a security-sensitive setter protected only by Jackson annotations. The affected reflection path does not consult those annotations.

### Three-codec canary

1. Build a disposable Spring controller with one normal string property and one inert `setterReached` property. Give the latter a setter that increments a local counter, but mark it with the same Jackson write restriction used by the application under review.
2. Submit equivalent bodies as ordinary JSON, Collection+JSON, and UBER. Use the endpoint's declared model type and normal parser; do not invoke `PropertyUtils` directly as the sole proof.
3. For each request, capture content type, selected converter/deserializer, parsed property map, setter counter, validation result, controller entry, and committed canary state.
4. Repeat with no setter, a server-derived field, DTO-to-domain mapping, constructor binding, and explicit application validation. These controls identify whether annotation bypass actually reaches a meaningful sink.
5. If the real model contains role, owner, status, price, workflow, or file-selector fields, replace it in the lab with a marker-only equivalent. Demonstrate one reversible state transition rather than changing a real privilege or business object.
6. Repeat on 3.0.4, 2.5.3, 2.4.2, 2.3.5, or 1.5.7 as appropriate. The alternate media types must honor the intended write policy or reject the property.

Strong evidence is **same logical property + ordinary JSON blocked + Collection+JSON/UBER reaches the restricted setter + marker-only application effect**. Without an enabled alternate media type, request-body model, reachable setter, and application impact, report only a non-exploitable dependency observation.

## Evidence and reporting

Preserve framework and dependency versions, server configuration, exact content type, raw synthetic request, principal/session/object IDs, LDAP bind classification, WebSocket route authorization decision, selected message converter, setter counter, and fixed-version negatives. Name the narrow boundary crossed: **bind result to authenticated principal**, **session identifier to authority**, or **media-type parser to property policy**.