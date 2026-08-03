# Bouncy Castle certificate, signature, and authenticated-content boundary checks

Sources: hourly offensive-security scan, 2026-08-03 GitHub Security Advisory feed and the [Bouncy Castle Java security-advisory index](https://github.com/bcgit/bc-java/wiki). Primary entries are linked in the matrices below.

The Bouncy Castle 1.85 advisory wave exposes a durable testing rule: a cryptographic API returning success is not enough. The application must prove that the accepted proof is bound to the intended certificate, signer, hostname, content, policy, and authenticated-decryption result.

!!! warning "Authorized validation only"
    Use locally generated keys, certificates, CMS/OpenPGP objects, LDAP entries, and ciphertext in a disposable JVM harness. Do not replay production certificates, signatures, mail, keystores, directory queries, or encrypted traffic. Keep parser-cost and oracle tests offline and bounded.

## Affected branches and prerequisites

- Bouncy Castle for Java before `1.85` is affected by the entries below.
- Java LTS and FIPS artifact fix levels differ by component; use each linked Bouncy Castle advisory as the source of truth rather than assuming the community version number applies to every artifact.
- Build one affected fixture and one patched fixture with the same application code and generated test corpus.
- Record exact Maven/Gradle coordinates because `bcprov`, `bcpkix`, `bctls`, `bcpg`, and mail artifacts can resolve independently.

```bash
mvn -q dependency:tree -Dincludes=org.bouncycastle
./gradlew -q dependencyInsight --dependency bouncycastle --configuration runtimeClasspath
```

Capture artifact, resolved version, provider order, API entry point, input fixture ID, result, exception class, and whether any plaintext or side effect became observable before final validation.

## Certificate and identity-policy matrix

| Boundary | Primary source | Differential fixture | Positive evidence |
| --- | --- | --- | --- |
| Stapled OCSP response -> certificate being checked | [GHSA-j295-77c3-9frf](https://github.com/advisories/GHSA-j295-77c3-9frf) / [CVE-2026-58062](https://github.com/bcgit/bc-java/wiki/CVE-2026-58062) | Generate certificates A and B under a test CA, staple a valid response for A while validating B, and compare with the correctly bound A/A control. | The affected path accepts a response whose certificate ID does not identify B; the patched path rejects it before treating B as good. |
| X.509 name constraint -> canonical mailbox or URI host | [GHSA-9pwp-9qqc-pr26](https://github.com/advisories/GHSA-9pwp-9qqc-pr26) / [CVE-2026-8763](https://github.com/bcgit/bc-java/wiki/CVE-2026-8763) | Use a constrained synthetic domain and compare exact, subdomain, trailing-dot, mixed-case, and out-of-scope `rfc822Name` and URI values. | A trailing dot changes the decision without changing the intended DNS identity boundary. |
| TLS endpoint identity -> SAN/CN policy | [GHSA-8rxj-3p7p-rq39](https://github.com/advisories/GHSA-8rxj-3p7p-rq39) / [CVE-2026-59638](https://github.com/bcgit/bc-java/wiki/CVE-2026-59638) | Generate a certificate with a matching CN but absent or non-matching SAN; run with default settings and explicit CN-fallback opt-in. | The affected default accepts CN fallback even though the behavior is documented as opt-in; patched default and explicit opt-in diverge. |
| S/MIME validation time -> trusted validation clock | [GHSA-vgvx-fcjw-w4m8](https://github.com/advisories/GHSA-vgvx-fcjw-w4m8) / [CVE-2026-59641](https://github.com/bcgit/bc-java/wiki/CVE-2026-59641) | Sign synthetic mail with a certificate outside its validity window and vary only the signer-asserted `signingTime`. | Caller-controlled signed metadata changes path-validity acceptance instead of a trusted validation-time input controlling the decision. |

For every identity test, preserve both the textual input and the canonical identity used by the application. A parser difference is not yet impact: show that it reaches certificate acceptance, trust-path selection, or endpoint authorization.

## Signature and content-binding matrix

| Boundary | Primary source | Differential fixture | Positive evidence |
| --- | --- | --- | --- |
| CMS verification success -> at least one required signer | [GHSA-r3rc-x3pq-jmw7](https://github.com/advisories/GHSA-r3rc-x3pq-jmw7) / [CVE-2026-59639](https://github.com/bcgit/bc-java/wiki/CVE-2026-59639) | Compare valid one-signer, invalid one-signer, and structurally valid zero-signer `SignedData`. | `verifySignatures()` returns true for zero signers and the application equates that vacuous result with an authenticated artifact. |
| CMS `AuthenticatedData` MAC -> exact content returned to the caller | [GHSA-cfjh-c47f-gprf](https://github.com/advisories/GHSA-cfjh-c47f-gprf) / [CVE-2026-59642](https://github.com/bcgit/bc-java/wiki/CVE-2026-59642) | With `authAttrs` present, mutate only the synthetic content while preserving the authenticated attributes and MAC fixture. | Verification succeeds while the returned content is not the bytes bound by the MAC. |
| OpenPGP inline-signature policy -> overall verification result | [GHSA-r7xx-x336-xqqr](https://github.com/advisories/GHSA-r7xx-x336-xqqr) / [CVE-2026-59643](https://github.com/bcgit/bc-java/wiki/CVE-2026-59643) | Build a locally signed message that is cryptographically valid but violates one configured inline-signature policy, alongside valid and bad-signature controls. | The policy callback records failure but the affected high-level operation still reports success. |
| Authenticated decryption -> plaintext release | [GHSA-cwc6-73j8-3qm6](https://github.com/advisories/GHSA-cwc6-73j8-3qm6) / [CVE-2026-58061](https://github.com/bcgit/bc-java/wiki/CVE-2026-58061) | Encrypt a short canary under CCM, alter only the tag, and instrument caller-buffer writes before finalization. | Unauthenticated plaintext reaches the caller buffer before tag failure; do not claim disclosure unless the application can consume or retain those bytes. |

### Application-level validation sequence

1. Identify the high-level operation the application trusts: package import, signed configuration, S/MIME approval, authenticated message, or decrypted record.
2. Interpose a recorder immediately after the Bouncy Castle call. Record whether the application checks signer count, required signer identity, policy callbacks, final authentication status, and content digest.
3. Change one binding at a time. Do not combine a zero-signer object, content mutation, and policy failure into one opaque fixture.
4. Run the same corpus against affected and patched artifacts. Keep application logic and provider order fixed.
5. Report the full chain: **crafted local object -> library result -> missing application invariant -> harmless synthetic action selected**.

## Directory, key-agreement, and keystore boundaries

| Boundary | Primary source | Safe validation pattern |
| --- | --- | --- |
| Certificate selector -> LDAP filter grammar | [GHSA-mf66-6236-xhfw](https://github.com/advisories/GHSA-mf66-6236-xhfw) / [CVE-2026-59652](https://github.com/bcgit/bc-java/wiki/CVE-2026-59652) | Point the legacy `jdk1.4` `LDAPStoreHelper` at a local fake LDAP recorder. Supply synthetic selector values containing `*`, `(`, `)`, NUL, and backslash and compare the emitted filter AST, not real directory results. |
| MTI/A0 peer public value -> valid DH group element | [GHSA-ghgq-7g74-28wp](https://github.com/advisories/GHSA-ghgq-7g74-28wp) / [CVE-2026-59650](https://github.com/bcgit/bc-java/wiki/CVE-2026-59650) | Use a tiny test-only group or mocked exponentiation boundary to compare valid, identity, zero, negative, and out-of-range peer values. Prove whether validation occurs before exponentiation; do not derive or reuse real session keys. |
| Parsed BKS version -> required integrity strength | [GHSA-mwmr-38hj-q7gm](https://github.com/advisories/GHSA-mwmr-38hj-q7gm) / [CVE-2026-59651](https://github.com/bcgit/bc-java/wiki/CVE-2026-59651) | Generate a keystore containing only a canary key and compare modern BKS with the legacy version using a 16-bit integrity-MAC key. Record format/version acceptance separately from any application trust decision. |

LDAP metacharacters in a filter string, an unusual DH value, or an old keystore version are structural observations. Escalate only when the application reaches an unauthorized directory match, agreement success, trusted-key import, or another concrete synthetic sink.

## Oracle and downgrade checks

[GHSA-w983-hf44-gcww](https://github.com/advisories/GHSA-w983-hf44-gcww) / [CVE-2026-59640](https://github.com/bcgit/bc-java/wiki/CVE-2026-59640) reports an OpenPGP CFB quick-check oracle on symmetric/session-key paths. Validate it only in a local process:

1. Produce one small OpenPGP canary with a generated key or password.
2. Mutate the quick-check bytes and unrelated ciphertext positions in a bounded fixture set.
3. Compare return class, exception type, response length, and coarse repeated timing distributions.
4. Confirm whether an application exposes a stable remote distinction before claiming an oracle. Do not automate plaintext recovery or send probes to a shared service.

The BKS legacy-integrity issue is similarly a format downgrade, not proof of key recovery. A report should separate **weak format accepted** from **application imports and trusts attacker-controlled key material**.

## Evidence and reporting checklist

- [ ] Exact Bouncy Castle artifact coordinates, provider order, and affected/patched versions are recorded.
- [ ] Every fixture uses generated keys, certificates, names, content, and directory entries.
- [ ] One trust binding changes per test, with valid, invalid, empty, and patched controls.
- [ ] Library return values are separated from the application's authorization or import decision.
- [ ] Signer count, signer identity, authenticated content bytes, certificate ID, hostname, and validation clock are recorded where relevant.
- [ ] Authenticated-decryption evidence states whether pre-verification plaintext was actually consumed.
- [ ] Oracle evidence includes stable externally visible classes; local exception differences alone are not reported as remote plaintext recovery.
- [ ] No private keys, production mail, directory data, keystores, ciphertext, or decrypted content appears in evidence.
