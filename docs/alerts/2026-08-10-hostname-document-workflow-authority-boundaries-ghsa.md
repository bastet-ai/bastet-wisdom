---
title: Hostname, document, and workflow authority boundary testing
---

# Hostname, document, and workflow authority boundary testing

A GitHub advisory wave on August 10 yields four reusable offensive review patterns:

1. a TLS verifier and the resolver can disagree about Unicode dot separators in the same hostname;
2. document APIs can mint privileged file URLs before authenticating and authorizing the selected document;
3. a caller-selected organization or event can reach an audit or workflow mutation without being bound to the session principal; and
4. a missing related object can accidentally satisfy an authorization branch instead of failing closed.

Source records:

- Node.js Unicode-dot TLS hostname mismatch: [GHSA-g57m-hr98-5m89](https://github.com/advisories/GHSA-g57m-hr98-5m89);
- OpenSign contract read, decline, signed-URL, and file-read boundaries: [GHSA-mgm4-2355-58g4](https://github.com/advisories/GHSA-mgm4-2355-58g4), [GHSA-fm8m-9x77-qjvw](https://github.com/advisories/GHSA-fm8m-9x77-qjvw), [GHSA-9g58-36q9-g7mq](https://github.com/advisories/GHSA-9g58-36q9-g7mq), and [GHSA-jppp-j33j-6m5q](https://github.com/advisories/GHSA-jppp-j33j-6m5q);
- Bitwarden organization audit-log write: [GHSA-m2wp-hqw2-j56m](https://github.com/advisories/GHSA-m2wp-hqw2-j56m);
- Attendize cross-organizer event-question write: [GHSA-6c35-rp78-p585](https://github.com/advisories/GHSA-6c35-rp78-p585); and
- CTI-Transmute retained history after the related conversion is deleted: [GHSA-9p5q-96wv-4xvh](https://github.com/advisories/GHSA-9p5q-96wv-4xvh).
- OpenSign unauthenticated contact/tenant reads, contact writes, caller-attributed audit events, and user-ID resolution: [GHSA-89m8-qpv9-7q8g](https://github.com/advisories/GHSA-89m8-qpv9-7q8g), [GHSA-5w47-3cxw-fxxf](https://github.com/advisories/GHSA-5w47-3cxw-fxxf), [GHSA-4vpg-x7mh-3947](https://github.com/advisories/GHSA-4vpg-x7mh-3947), [GHSA-7j6v-hchx-rmq3](https://github.com/advisories/GHSA-7j6v-hchx-rmq3), and [GHSA-8r4x-jw7g-pvfw](https://github.com/advisories/GHSA-8r4x-jw7g-pvfw); and
- Attendize cross-organizer attendee import/invite writes: [GHSA-pm9m-4jvw-f3q5](https://github.com/advisories/GHSA-pm9m-4jvw-f3q5) and [GHSA-rvg3-vfj6-mf9f](https://github.com/advisories/GHSA-rvg3-vfj6-mf9f).

The product-specific records were unreviewed when scanned. Confirm the exact package, deployment mode, route, role, version, and corrected behavior before reporting. Do not infer internet reachability or combine independent records into an unsupported exploit chain.

!!! warning "Authorized lab validation only"
    Use local TLS peers, disposable application deployments, fake accounts, synthetic contracts/events/history, inert signed-URL recorders, and patched read/write/mutation sinks. Never retrieve real contracts, personal data, audit records, credentials, or files; never decline a live document, alter an operational event, forge a retained audit record, or intercept shared TLS traffic.

## 1. Compare hostname identity at every parser and connector

The Node.js record describes a mismatch between Unicode dot-separator handling in TLS wildcard-depth verification and in the resolver/connector path. The durable question is: **does certificate-name authorization evaluate the same canonical hostname and label depth that the socket ultimately uses?**

Build an isolated harness with two owned DNS names, a local resolver, and two TLS servers using disposable certificate authorities. One server is the expected authority; the other is an explicitly denied no-content peer. Do not use a public suffix, real wildcard certificate, production proxy, or shared DNS.

For each input, capture rather than infer:

```text
raw hostname
-> URL/authority parser output
-> IDNA and Unicode normalization
-> label array and wildcard-depth decision
-> SNI value
-> resolver query and answer
-> socket peer
-> certificate SAN matched by the TLS verifier
```

Use an ordinary ASCII hostname as the baseline, then compare each Unicode dot-like separator individually, mixed separators, a trailing separator, repeated separators, and a punycode control. Generate the exact code points in the harness and preserve them as escaped values in evidence so fonts or copy/paste cannot hide the distinction.

Patch the final connector if possible so it records SNI, resolver output, peer tuple, and verifier result without sending application data. A bounded positive is **the verifier accepts a wildcard or label-depth relationship for one canonical identity while the resolver/connector selects the owned denied peer under a different label split**. A parser disagreement, accepted certificate, or DNS answer alone is insufficient.

Repeat byte-identical cases on the corrected runtime. Require the certificate verifier, SNI path, resolver, and final connector to use one canonical label model or reject the ambiguous hostname before connection.

## 2. Map document APIs as capability-minting operations

The four OpenSign records describe separate failures around contract reads, decline mutations, signed-file URL generation, and file access. Do not reduce them to one generic IDOR. Inventory every operation that turns a caller-controlled document, file, URL, or user identifier into stronger server authority:

| Operation | Caller-controlled selectors | Final authority to instrument | Safe positive |
| --- | --- | --- | --- |
| contract read | document ID and OTP-state branch | master-key record query and response serializer | foreign synthetic contract reaches a no-content serializer under an unauthorized principal |
| decline | document ID, reason, and attributed user | workflow-state mutation | denied mutation recorder receives a foreign contract or caller-selected attribution |
| signed URL | document ID and file selector | master-key token signer | signer recorder receives a synthetic foreign file after an invalid or unrelated document selector bypasses authentication |
| file read | caller-supplied file URL or object selector | token signer, storage client, and response relay | foreign synthetic file reaches a no-content read/relay recorder without a valid session and ownership decision |

Create two organizations, users A and B, one contract per user, and random marker-only files. Patch master-key queries, token signing, storage reads, serializers, and mutations so candidate requests stop before bytes or state changes.

For every route, compare anonymous, malformed-session, A/A, A/B, B/B, nonexistent-document, deleted-document, OTP-enabled, and OTP-disabled controls. Record the canonical principal, organization, document owner, file owner, authentication branch, authorization predicate, signer/query options, and sink decision.

A token string is not required as evidence. Prefer a signer trace showing the exact synthetic object and claims that would have been authorized, then deny token creation. Likewise, prove a decline issue at the mutation recorder; do not terminate even a disposable workflow merely to strengthen the report.

### August 11 follow-up: trace every Parse cloud function separately

The later OpenSign records expand the matrix beyond contracts. Inventory `getcontact`, `gettenant`, `updatecontacttour`, `triggerevent`, and `getUserId` as distinct capabilities; do not assume a shared `useMasterKey` wrapper applies object policy. Use two fake organizations, synthetic contacts, random addresses, and patched query, serializer, update, and audit-append sinks.

Compare anonymous, malformed-session, A/A, A/B, nonexistent, and deleted selectors. For `getUserId`, use only synthetic usernames and email addresses and stop at a recorder that returns no identifier. For `triggerevent`, vary document, viewer identity, and IP independently and deny the append. Bounded positives are **unauthenticated selector -> foreign synthetic object reaches denied serializer/update**, or **caller-attributed identity/network fields -> denied audit sink without a session/document binding**. Never return contact/tenant fields, map real accounts, update records, or create audit evidence.

## 3. Bind workflow and audit mutations to session-owned objects

The Bitwarden and Attendize records show two variants of the same authority drift:

- an authenticated caller supplies an organization in an audit-log collection body without proving membership in that organization; and
- an authenticated organizer supplies an event ID that is loaded outside the organizer's tenant scope, allowing a question object to be attached to another organizer's event.

Use organizations or tenants A and B with one marker object each. Interpose the final audit append, event-question insert, association attach, and notification/queue sinks. Build an operation matrix that varies:

- session principal and claimed organization/event;
- route, method, body, path, and query copies of the selector;
- current, backdated, future, malformed, duplicate, and server-generated timestamps for the audit path;
- create, list, update, and delete paths for the event-question lifecycle; and
- nonexistent, archived, and foreign parent objects.

A bounded audit positive is **user A session -> body selects organization B -> membership check is absent -> append recorder receives a backdated synthetic B event**. Do not persist the event. A bounded event positive is **organizer A -> event B selector -> unscoped parent lookup -> insert/attach recorder receives a question for B**. Capture the owner assigned to the child as well as the parent selected; that mismatch can explain why a victim cannot later remove the injected object.

Test the full lifecycle because create and delete paths may use different tenant scopes. Never use the mismatch to create durable false evidence, send notifications, block registration, or alter a live event.

The August 11 Attendize follow-ups add `postImportAttendee` and `postInviteAttendee`. Replay the same A/B event matrix through question creation, bulk import, and invite/order creation, but replace attendee/order inserts, totals, email, and queue dispatch with denied recorders. Preserve session organizer, requested event, event owner, parser/import row count, proposed attendee/order owner, and first sink. A bounded positive is **organizer A -> event B ID -> unscoped parent lookup -> denied attendee/order recorder selects B**. Do not import people, create financial records, or send invitations.

## 4. Treat missing related objects as deny cases

The CTI-Transmute history record describes a classic fail-open shape: authorization was evaluated only when the related conversion existed, so a deleted conversion left retained history reachable through its history identifier.

Generalize the check across history, revision, attachment, export, job, and tombstone APIs:

```text
parent exists and caller may read it       -> allow synthetic child
parent exists and caller may not read it   -> deny
parent is deleted/missing                  -> deny
child references malformed parent          -> deny
parent lookup errors or times out          -> deny
```

Create two users and synthetic conversions, record history IDs before deletion, and patch the history serializer. Exercise current, foreign, deleted-parent, nonexistent-parent, malformed-parent, and fixed-version controls. A bounded positive is **retained history ID -> parent lookup returns no object -> authorization branch falls through -> serializer selects the synthetic history marker**. Stop before returning input/output bodies.

Distinguish identifier knowledge from authorization. If the ID must be learned through another permission, document that prerequisite rather than claiming broad enumeration. Also distinguish an intentionally retained audit record with a dedicated access policy from an orphan whose missing parent silently bypasses the only policy check.

## Evidence and reporting checklist

- [ ] Exact runtime or product revision, route, deployment mode, and affected/corrected behavior are recorded.
- [ ] Raw hostname, code points, normalized labels, SNI, resolver answer, certificate SAN decision, and socket peer are separate fields.
- [ ] Authentication, object lookup, ownership/membership, capability signing, serialization, and mutation decisions are captured independently.
- [ ] Every object test includes own, foreign, nonexistent, deleted, malformed, and fixed controls where applicable.
- [ ] Token/file/document proofs stop at denied sign/read/serialize sinks and contain only random synthetic markers.
- [ ] Workflow and audit tests do not persist changes, send notifications, alter registrations, or manufacture operational evidence.
- [ ] Claims state the exact prerequisite and authority transition instead of asserting account takeover, data theft, or code execution that was not demonstrated.
