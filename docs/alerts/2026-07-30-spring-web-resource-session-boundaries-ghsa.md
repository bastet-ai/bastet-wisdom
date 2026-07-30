---
title: Spring Web static-resource and session-rotation boundaries
---

# Spring Web static-resource and session-rotation boundaries

Three Spring Framework advisories expose two durable application-testing patterns: static-resource resolution can cross handler and filesystem boundaries, while concurrent WebFlux session rotation can leave an attacker-known identifier attached to authenticated state.

Sources:

- [GHSA-72pg-x5f8-j25j / CVE-2026-41843](https://github.com/advisories/GHSA-72pg-x5f8-j25j) and the [Spring advisory](https://spring.io/security/cve-2026-41843): versioned filesystem resources may resolve outside configured locations;
- [GHSA-mq64-j8f9-9gcj / CVE-2026-41841](https://github.com/advisories/GHSA-mq64-j8f9-9gcj) and the [Spring advisory](https://spring.io/security/cve-2026-41841): a shared static-resource cache may return an authenticated handler's resource through a public handler with the same name; and
- [GHSA-4hfh-6x8g-gwpp / CVE-2026-41839](https://github.com/advisories/GHSA-4hfh-6x8g-gwpp), the [Spring advisory](https://spring.io/security/cve-2026-41839), and the [session-store fix](https://github.com/spring-projects/spring-framework/commit/b8ddd2c690fe3f00bb5e3d9f913a37504aab49a0): a race in the in-memory WebFlux session store may exchange an attacker-known session ID for an authenticated user's ID.

The vendor lists Spring Framework 7.0.0–7.0.7, 6.2.0–6.2.18, 6.1.0–6.1.27, and 5.3.48 and earlier as affected, with fixes in 7.0.8 and 6.2.19 plus support-channel builds. GitHub's package-range fields differed from the vendor text when this page was written; use the vendor advisory and the exact deployed artifact as the version authority.

!!! warning "Authorized lab validation only"
    Use synthetic static files, two disposable users, an isolated cache, and an application with no production sessions or data. Never traverse to real secrets, retrieve another user's files, fixate a real user's session, or race a shared production login.

## Build one boundary matrix

| Surface | Attacker-controlled input | State reused across the boundary | Bounded proof |
| --- | --- | --- | --- |
| versioned resources | URL path plus guessed resource metadata | version resolver and filesystem location | one out-of-root canary hash |
| shared resource cache | public handler request and filename | cache entry populated under another handler/location | synthetic protected canary returned publicly |
| WebFlux session rotation | known pre-auth session ID and request timing | in-memory session object during `changeSessionId()`/`save()` | authenticated marker remains reachable under the known ID |

Keep **route match**, **resolver selection**, **cache key**, **filesystem candidate**, **authorization decision**, **session-ID rotation**, and **authenticated-state attachment** as distinct edges. A path-shaped request is not traversal without an out-of-root result; a cache collision is not disclosure unless it crosses an authorization boundary; and knowing a session ID is not account access unless authenticated state remains bound to it.

## Versioned filesystem resource traversal

The Spring advisory requires all of these conditions: MVC or WebFlux, filesystem-backed static resources, versioned-resource support, and knowledge or a guess of the target resource's metadata. Do not assume classpath-only resources or unversioned handlers are affected.

### Canary-only workflow

1. Build the smallest application matching production configuration. Map one handler to a disposable resource root and enable the same version strategy, resource chain, URL pattern, and resolver order.
2. Place `public.txt` inside the root and a random `outside-canary.txt` in a sibling directory. Both files should contain generated markers only; put no credentials, source, configuration, keys, or user data in the fixture.
3. Establish controls for the ordinary public URL, a missing resource, an incorrect version, an unversioned handler, a classpath-backed handler, and the corrected Spring build.
4. Generate candidate requests from the application's legitimate versioned URL format. Vary one normalization dimension at a time: dot segments, encoded separators, repeated separators, mixed encoding, and version/path placement. Do not publish a weaponized path for a real deployment.
5. Capture the raw request target, framework-decoded path, selected handler and resolver, normalized filesystem candidate, returned status, content type, body length, and body hash.
6. A positive is **versioned request -> configured resource root is escaped -> sibling canary hash is returned**. Stop immediately; do not enumerate neighboring files.

The metadata precondition belongs in the report. Record whether it means a content hash, fixed version string, filename-derived token, manifest entry, or another application-specific value, and how the synthetic value was obtained.

## Shared static-resource cache collision

The cache advisory requires multiple resource handlers with different locations, at least one authenticated handler, and a cache shared by those configurations. The vendor describes the protected object becoming reachable when a public resource with the same name is resolved first and cached. Test both ordering directions rather than inferring the exact key composition.

### Two-handler, two-user differential

1. Configure `/public/**` and `/private/**` with separate disposable locations but the same resource filename, such as `logo.txt`. Give each file a different random body marker.
2. Require authentication for the private handler and use the deployment's actual cache implementation and sharing arrangement. Record whether the cache object is process-local, distributed, framework-managed, or application-supplied.
3. With a fresh cache, replay these sequences independently:

| Sequence | First request | Second request | Expected public result |
| --- | --- | --- | --- |
| A | anonymous public name | anonymous public name | public marker |
| B | authenticated private name | anonymous public same name | public marker or denial, never private marker |
| C | anonymous public name | authenticated private same name | private route returns only private marker to the authenticated user |
| D | authenticated private different name | anonymous public name | public marker |

4. Repeat with handler registration order reversed, case and encoding variants accepted by the actual server, cache eviction between runs, separate caches, and the corrected build.
5. Preserve cache-key hashes and marker labels, not cache dumps or resource bodies.

Strong evidence is **one handler primes a shared cache -> another handler with a different authorization/location context reuses that entry -> the anonymous response contains only the synthetic protected marker**. Report the priming order observed; do not generalize it beyond the measured configuration.

## WebFlux in-memory session rotation race

The vendor requires WebFlux and a compromised sibling subdomain, for example through XSS. The published fix adds locking around in-memory session save and ID rotation. Treat sibling-domain cookie placement, concurrent request timing, ID rotation, and authenticated-state reuse as separate preconditions.

### Recorder-only race harness

1. Use a disposable WebFlux application backed by `InMemoryWebSessionStore`, two owned sibling hostnames, one synthetic user, and a test-only authentication endpoint that sets an inert `role=user` marker. Do not use production cookies or identity providers.
2. Verify whether the session cookie's `Domain`, `Path`, `Secure`, and `SameSite` attributes let the owned sibling supply a known pre-auth ID to the application. If not, record the failed precondition and stop.
3. Instrument `retrieveSession`, `save`, `changeSessionId`, and authentication completion. Log opaque request labels, old/new ID hashes, session-object identity, and marker presence; never log complete cookies.
4. Establish a sequential control: start with the known ID, authenticate, and verify that rotation makes the old ID unusable while the new ID alone reaches the marker.
5. In the lab only, place barriers around session save/rotation and release two benign requests in controlled orders. Compare old-ID lookup before, during, and after authentication. Avoid unbounded timing loops.
6. Repeat with a fresh store for every schedule, an unrelated ID, no sibling cookie placement, one request only, a persistent session-store implementation if actually deployed, and the corrected build.
7. A bounded positive is **attacker-known pre-auth ID -> concurrent in-memory save/rotation schedule -> authenticated canary state remains retrievable with that known ID**. Stop at the synthetic marker; do not perform account actions.

Do not call a stale map entry session fixation unless it remains usable after authentication. Conversely, do not require a real victim or real XSS: owned sibling cookie placement and a deterministic barrier schedule are safer, stronger evidence.

## Evidence and reporting checklist

Preserve:

- exact Spring artifacts, versions, MVC versus WebFlux mode, resource-handler configuration, version strategy, cache implementation, and session-store implementation;
- raw and normalized paths, selected handler/resolver, configured root, and synthetic returned-file hash;
- cache state and request order, opaque key hashes, route authorization context, and public/private marker labels;
- cookie scope, old/new session-ID hashes, request schedule, session-object identity, and authenticated marker decision;
- vulnerable and corrected build results using identical fixtures; and
- separate claims for path escape, response disclosure, cache-context collision, session race, old-ID persistence, and authenticated-state access.

Stop at the smallest synthetic proof. These advisories do not by themselves establish arbitrary file read in every Spring application, universal cache poisoning, XSS on a sibling domain, or compromise of a production account.
