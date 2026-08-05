---
title: AWS Nitro Enclave KMS Boundary Testing
---

# AWS Nitro Enclave KMS Boundary Testing

Use this workflow to test whether an AWS Nitro Enclave remains bound to the intended KMS key, IAM role, attested image, request context, and transport when its untrusted parent controls inputs and relays traffic.

The useful question is not simply whether KMS accepts an attestation document. It is whether every security-relevant value consumed after that check is bound to the same trusted context.

!!! warning "Authorized, non-production validation only"
    Run mutation tests in an owned AWS account or an explicitly approved lab. Use disposable customer-managed keys and synthetic plaintext. Do not decrypt production ciphertext, weaken a live key policy, capture real IAM credentials, or test replay/substitution against shared workloads.

## When to use this workflow

Apply it when an assessment includes:

- Nitro Enclaves that call KMS through a parent instance or `vsock` proxy
- enclave-sealed databases, signing services, wallets, or credential brokers
- key policies using `kms:RecipientAttestation:*` conditions
- envelope encryption whose encrypted data keys live outside the enclave
- an enclave image that accepts a key ID, alias, encryption context, IAM credential, algorithm, or ciphertext from its parent
- code using [`aws-nitro-enclaves-sdk-c`](https://github.com/aws/aws-nitro-enclaves-sdk-c)

## Required inputs

Obtain before testing:

- written authorization for the AWS account, region, VPC, parent instance, enclave image, and test keys
- the enclave image hash or reproducible build inputs
- KMS key ARNs, key policies, grants, and relevant IAM role policies
- the parent-to-enclave and enclave-to-KMS protocol description
- source or traces showing where `Recipient`, `KeyId`, encryption context, algorithms, and credentials originate
- a disposable KMS key and synthetic marker plaintext
- an owned relay or patched client that records requests without forwarding secrets

Treat the parent instance, external storage, relay, and all values supplied at runtime as attacker-controlled unless the design explicitly proves otherwise.

## Boundary model

Build a value-to-authority table before changing anything:

| Value | Expected authority | Typical unsafe authority | Validation question |
| --- | --- | --- | --- |
| `Recipient.AttestationDocument` | current enclave | parent replay cache | Is freshness enough, or is the attestation also bound to this operation and its parameters? |
| KMS `KeyId` | attested enclave configuration | parent argument or ciphertext metadata | Can the parent substitute an alias, account, region, or CMK? |
| KMS response `KeyId` | KMS, checked by enclave | ignored response field | Does the enclave reject a successful response from the wrong key? |
| encryption context | enclave protocol state | parent-controlled map | Can context and ciphertext be swapped together? |
| encrypted data key | authenticated external record | arbitrary parent storage | Is it bound to record identity, purpose, tenant, and version? |
| IAM credentials/role | expected parent identity, verified by enclave | any instance profile supplied by parent | Does the enclave verify the caller identity it is about to use? |
| PCR conditions | approved image and deployment identity | partial or wildcard policy | Are code, signer, and parent-role assumptions represented deliberately? |
| algorithm identifiers | attested protocol | request or response defaults | Are key type, wrapping algorithm, and content algorithm pinned and checked? |
| TLS trust roots | attested enclave image | parent CA bundle | Is TLS initiated and authenticated inside the enclave? |

The core bug pattern is **trusted attestation plus unbound request state**. A valid attestation does not automatically authenticate the operation name, `KeyId`, encryption context, ciphertext blob, or other fields around it.

## Phase 1: Inventory effective KMS authority

Use read-only AWS CLI calls with a least-privileged audit role. Replace every placeholder with an approved test value.

```bash
export AWS_PROFILE=nitro-audit-readonly
export AWS_REGION=us-east-1
export KEY_ID='arn:aws:kms:us-east-1:111122223333:key/TEST-KEY-ID'

aws sts get-caller-identity --output json > evidence/caller-identity.json
aws kms describe-key --key-id "$KEY_ID" --output json > evidence/key.json
aws kms get-key-policy \
  --key-id "$KEY_ID" \
  --policy-name default \
  --output text > evidence/key-policy.json
aws kms list-grants --key-id "$KEY_ID" --output json > evidence/grants.json
```

Record separately:

1. principals allowed to administer the key;
2. principals allowed to use `Decrypt`, `GenerateDataKey`, `GenerateDataKeyPair`, `DeriveSharedSecret`, `ReEncrypt`, or `Encrypt`;
3. attestation conditions and which PCRs they constrain;
4. VPC endpoint, account, region, and transport conditions;
5. whether a broad account-root delegation lets IAM policies grant access more widely than the policy appears to at first glance.

Do not infer effective denial from one policy statement. Evaluate key policy, IAM policy, grants, service control policy, permission boundary, and resource context together.

### PCR questions

Use the policy as an assertion map rather than a checklist:

- **PCR0**: is access bound to the exact enclave image?
- **PCR1/PCR2**: are kernel, boot, and application measurements relevant to this deployment also constrained?
- **PCR3**: is use bound to the expected parent EC2 IAM role?
- **PCR8**: if signer-based rollout is used, who controls the signing key and can they sign arbitrary images?

A policy that names a PCR is not automatically sufficient. Confirm the measured property is the one the application security model relies on.

## Phase 2: Trace request construction

Locate every KMS operation the enclave can invoke and identify the source of each field.

Useful source-review searches include:

```bash
rg -n --hidden \
  'Recipient|AttestationDocument|KeyId|EncryptionContext|CiphertextBlob|GenerateDataKey|Decrypt|ReEncrypt|GetCallerIdentity' \
  ./enclave-src ./parent-src

rg -n --hidden \
  'aws-nitro-enclaves-sdk-c|aws-nitro-enclaves-nsm-api|boto3|kms\.Client|vsock|proxy' \
  ./enclave-src ./parent-src
```

For each operation, capture a redacted request schema such as:

```json
{
  "operation": "Decrypt",
  "key_id_source": "attested constant",
  "ciphertext_source": "external record",
  "context_source": "enclave state",
  "recipient_source": "fresh enclave attestation",
  "response_checks": ["KeyId", "KeySpec", "KeyEncryptionAlgorithm"]
}
```

Flag fields that are:

- omitted because an SDK treats them as optional;
- accepted from the parent after enclave startup;
- derived only from mutable ciphertext metadata;
- checked before alias, ARN, account, region, or Unicode normalization;
- returned by KMS but not checked by the enclave;
- shared across tenants, records, protocol states, or purposes.

## Phase 3: Run a substitution matrix

Patch the parent relay or client adapter so it records the attempted mutation and blocks the final KMS call unless the case uses a disposable test key and synthetic data. This separates **reached the sink** from **changed a real cryptographic object**.

Use one baseline and one mutation at a time:

| Case | Mutation | Secure result |
| --- | --- | --- |
| CMK identity | expected full ARN → different disposable ARN | rejected before plaintext is accepted |
| key alias | full ARN → same-name alias in another approved test context | alias rejected or resolved identity compared to pinned ARN |
| response binding | mock success response with foreign `KeyId` | enclave rejects the response |
| ciphertext swap | record A encrypted data key → record B key | authenticated context mismatch |
| ciphertext + context swap | replace both with another synthetic record | enclave-owned record/tenant/purpose binding still rejects |
| operation change | replay fresh attestation around another supported operation | operation-specific state rejects or channel binding prevents mutation |
| IAM role | expected disposable role → second disposable role | enclave detects caller-identity mismatch |
| algorithm | expected identifier → another accepted identifier | rejected before unwrap/decrypt/use |
| time | reuse a captured synthetic attestation inside and outside the acceptance window | replay-sensitive protocol state rejects; do not treat expiry alone as request binding |
| transport | parent relay presents an owned test CA | enclave-side TLS verification rejects it |

Keep test ciphertexts and plaintexts visibly synthetic, for example `NITRO-KMS-CANARY-A` and `NITRO-KMS-CANARY-B`. Hash canaries in the report if the customer does not want plaintext stored in evidence.

### High-value exploit-path hypotheses

#### Parent-selected CMK

Preconditions:

1. the parent can influence `KeyId`, an alias, or ciphertext metadata;
2. the enclave does not pin the full expected CMK ARN;
3. the response key identity is not checked;
4. the substituted test key is usable by the supplied role.

Proof boundary: show the patched KMS adapter receives the foreign test ARN and that the enclave would accept the mocked response. Do not use a production key or recover non-canary plaintext.

#### Data-key or record substitution

Preconditions:

1. encrypted data keys or ciphertext records are mutable outside the enclave;
2. encryption context is absent, generic, or parent-controlled;
3. record identity, tenant, purpose, and version are not authenticated by enclave-owned state.

Proof boundary: swap only two synthetic records and record the accept/reject result. If swapping both ciphertext and context succeeds, show which trusted record binding was missing.

#### Fresh-attestation replay into altered requests

Preconditions:

1. the parent can observe or reuse a still-fresh attestation document;
2. the application assumes freshness binds the document to one operation;
3. operation parameters are mutable outside an enclave-authenticated channel.

Proof boundary: use a patched request recorder to show the same attestation can accompany two distinct synthetic request schemas. Do not repeatedly invoke KMS or attempt quota/cost abuse.

#### Parent-controlled TLS

Preconditions:

1. TLS terminates in the parent or a parent-supplied proxy;
2. the enclave does not authenticate KMS using an attested trust store;
3. request or response fields remain security-sensitive after attestation.

Proof boundary: present an owned test certificate to the isolated relay and capture whether the enclave attempts to continue. Never intercept production KMS traffic or install a CA on a shared host.

## Phase 4: Review SDK and parser choices

Trail of Bits states that it found parent-host-to-enclave vulnerabilities in [`aws-nitro-enclaves-sdk-c`](https://github.com/aws/aws-nitro-enclaves-sdk-c), but its August 5 article does not publish exploit details or CVE identifiers. Treat that as a source-review trigger, not as evidence that a deployment is exploitable.

During review:

- identify the exact SDK commit and local modifications;
- map every parent-controlled message through length, type, state, and ownership checks;
- fuzz the parser and `vsock` message boundary in a disposable enclave harness;
- use ASan/UBSan builds where supported;
- require a replayable crash or patched-sink trace before making an impact claim;
- compare the design with narrower components such as [`aws-nitro-enclaves-nsm-api`](https://github.com/aws/aws-nitro-enclaves-nsm-api) plus a separately reviewed KMS client.

Do not claim RCE, enclave escape, or key disclosure from the article alone.

## Phase 5: Verify end-to-end key-policy claims

Remote attestation proves measured enclave properties. It does not make the KMS key policy immutable.

If a client relies on the enclave using a particular KMS key, document:

- how the client learns the expected key ARN and enclave measurements;
- whether the client can verify the effective key policy or only a snapshot;
- who can call policy, grant, rotation, disable, or deletion operations;
- whether key replacement, alias movement, or multi-region behavior changes identity assumptions;
- what happens during eventual-consistency windows and partial failures.

Report mutable policy authority as a separate boundary from enclave code integrity. Do not overstate a remotely attested image as end-to-end proof of current KMS authorization.

## Evidence package

Capture:

- enclave image hash and build provenance;
- redacted key policy, grants, and IAM decision inputs;
- operation/field authority table;
- baseline-versus-mutation matrix;
- request and response schemas with secrets removed;
- patched-sink or mock-client traces;
- accepted and rejected `KeyId`, role, context, algorithm, replay, and TLS cases;
- exact SDK version or commit;
- a concise statement of what the proof did **not** do.

A strong finding states the broken binding directly:

> The enclave accepted a mocked `Decrypt` response associated with disposable CMK B after starting from a request intended for CMK A because the response `KeyId` was not compared with the attested expected ARN.

Avoid vague titles such as “KMS misconfiguration” when the evidence supports a specific authority mismatch.

## Stop conditions

Stop immediately if a test would require:

- decrypting customer or production ciphertext;
- using a non-disposable key or real application credential;
- changing a live key policy, grant, alias, role, VPC endpoint, or enclave image;
- replaying requests against a shared KMS quota;
- intercepting traffic from another workload;
- extracting keys, plaintext, or credentials from a real enclave.

A policy trace, synthetic two-record differential, patched request sink, or mocked response acceptance is sufficient evidence for this workflow.

## Sources

- Trail of Bits, [A few notes on AWS Nitro Enclaves: KMS integration](https://blog.trailofbits.com/2026/08/05/a-few-notes-on-aws-nitro-enclaves-kms-integration/)
- AWS KMS, [Cryptographic attestation support in KMS](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-attestation.html)
- AWS Nitro Enclaves, [Using cryptographic attestation with KMS](https://docs.aws.amazon.com/enclaves/latest/user/kms.html)
- AWS KMS, [Encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html)
- AWS KMS, [VPC endpoint policy conditions](https://docs.aws.amazon.com/kms/latest/developerguide/vpce-policy-condition.html)
