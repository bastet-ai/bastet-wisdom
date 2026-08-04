---
title: Ghost fetch, upload, import, and offer-state boundaries
---

# Ghost fetch, upload, import, and offer-state boundaries

Four Ghost advisories published on August 4 provide a reusable CMS test sequence: normalize the destination actually reached, derive a file's served representation from bytes rather than caller metadata, sanitize imported rich text at the final content boundary, and revalidate mutable business-object state when an offer is redeemed.

Primary sources:

- IPv4-mapped IPv6 SSRF-filter bypass [GHSA-wvp2-4qqp-4h3r / CVE-2026-53944](https://github.com/advisories/GHSA-wvp2-4qqp-4h3r);
- Admin API upload `Content-Type` spoofing on S3/GCS backends [GHSA-944x-pm95-3jpr / CVE-2026-53948](https://github.com/advisories/GHSA-944x-pm95-3jpr);
- Universal Import post-content XSS [GHSA-2gx6-7gx2-wwcf / CVE-2026-70588](https://github.com/advisories/GHSA-2gx6-7gx2-wwcf); and
- archived subscription-offer redemption [GHSA-4wx2-7gvj-qfq3 / CVE-2026-70589](https://github.com/advisories/GHSA-4wx2-7gvj-qfq3).

The SSRF and upload records list Ghost 6.21.1 as the first fixed release. The import and offer-state records list 6.54.1. Confirm the exact affected range in each advisory; do not infer that one patch level fixes all four paths.

!!! warning "Owned Ghost lab and inert canaries only"
    Use a disposable site, synthetic members/offers/posts, owned network listeners, and a test S3/GCS-compatible bucket on an isolated origin. Never target metadata or internal production services, upload executable content, run script, redeem a paid offer, or involve real members, billing instruments, staff sessions, or production media.

## 1. Compare policy address to transport address

The fetch issue accepted an IPv6 literal whose low 32 bits represented a private IPv4 destination. Build a destination matrix around one owned public listener and one lab-private canary:

- ordinary public IPv4 and IPv6 controls;
- direct private and loopback negatives;
- IPv4-mapped IPv6 forms of the same private canary;
- compressed, expanded, uppercase/lowercase, and parser-canonicalized IPv6 text; and
- redirects and DNS names only as separate controls—do not attribute a redirect or rebinding result to this literal-address bug.

Record raw host, URL-parser output, canonical IP object, embedded IPv4 value where defined, policy class, and final socket peer. A strong positive is **literal IPv6 passes the external-address filter -> transport recorder connects to the denied IPv4 canary**. The proof ends at an owned callback; never request cloud metadata or a real internal endpoint.

## 2. Trace upload metadata through object storage to browser interpretation

Use a benign file whose bytes are unmistakably non-HTML and contain only a random text marker. Submit it through the authorized Admin API while varying filename, declared multipart type, detected byte type, object metadata, download response `Content-Type`, `Content-Disposition`, storage backend, and media origin.

| Input/storage condition | Evidence to capture | Secure result |
| --- | --- | --- |
| declaration matches benign bytes | request and stored metadata | normal control |
| declaration claims active HTML for benign bytes | stored object headers and GET response | reject or serve inert type/download |
| S3/GCS-compatible backend | object metadata plus CDN/origin response | server-derived type wins |
| same-origin media | browser parser mode in a sessionless profile | no active document interpretation |
| isolated media origin | origin and response policy | no access to application origin |

Do not upload a script or handler. A bounded positive is **client-declared active type -> object metadata preserves it -> same-origin GET enters an HTML document parser**, demonstrated only with an inert visible marker. Separate upload acceptance, stored metadata, served headers, origin placement, and script capability; the first three do not alone prove cross-site scripting.

## 3. Treat universal import as a second parser boundary

Export a synthetic Ghost post, modify only one rich-text field with harmless structural markers, and re-import it into the disposable site. Exercise HTML cards, Markdown conversion, nested or malformed elements, encoded markup, attributes, links, media blocks, and content that passes through more than one serializer. Instrument each representation: archive member, importer model, stored post document, editor preview, and public render.

Use an inert custom element or disallowed attribute as the canary and disable script execution. The reportable transition is **import accepts a marker outside the supported content schema -> persisted post -> final renderer reparses it as an active DOM structure**. Do not use cookie/session access or publish to real subscribers. Compare an equivalent post created through the normal editor; import and editor paths should converge on the same sanitized stored representation.

## 4. Revalidate offer state at redemption time

Create a zero-value synthetic offer and one disposable member. Record offer identifiers but use a payment-provider stub that can never charge. Compare active, archived, expired, deleted, wrong-product/tier, already-redeemed, and caller-modified identifiers across offer preview, checkout/session creation, and final redemption.

The security decision belongs at the state-changing sink, not only when the offer link was issued or rendered. Capture member, offer ID, current server-side state, product/tier binding, requested benefit, and whether the no-op subscription mutation recorder ran. A bounded positive is **previously valid link or known ID -> offer archived -> final redemption still reaches the mutation recorder**. Do not claim price or privilege impact unless the synthetic fixture proves the exact benefit that would have been applied.

## Reporting boundaries

- Name the exact mismatch: canonical-address class, declared-versus-derived media type, importer-versus-renderer schema, or link-time-versus-redemption-time state.
- Include affected and corrected build results with identical fixtures.
- Keep each edge independent. An accepted upload is not XSS without active same-origin rendering; imported markup is not executable without a final active sink; an archived ID being readable is not redemption without a state mutation.
- Preserve only canary headers, IDs, state transitions, and DOM/parser decisions. Exclude content, tokens, member data, and provider secrets.