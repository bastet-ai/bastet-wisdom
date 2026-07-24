---
title: Markdown file inlining and Trix rich-text model boundaries from July 24 GHSA updates
---

# Markdown file inlining and Trix rich-text model boundaries from July 24 GHSA updates

Two July 24 advisories yield durable content-ingestion checks: a Markdown extension resolves attacker-controlled image paths before embedding server files, and a rich-text editor sanitizes pasted HTML before unsafe attributes cross into its internal document model and later return to HTML.

Sources:

- [GHSA-9xwg-3r6f-jcx2 / CVE-2026-61632: PyMdown Extensions `b64` path traversal](https://github.com/advisories/GHSA-9xwg-3r6f-jcx2)
- [GHSA-53g2-mvcc-q9x3: Trix HTMLParser attribute injection on paste](https://github.com/advisories/GHSA-53g2-mvcc-q9x3)
- [GHSA-53p3-c7vp-4mcc: related Trix drag-and-drop JSON deserialization path](https://github.com/advisories/GHSA-53p3-c7vp-4mcc)

!!! warning "Authorized validation only"
    Render only synthetic Markdown and rich text in disposable workers, editors, and viewer accounts. Use marker image files under a temp root and harmless URL/DOM markers. Do not read production image assets, keys disguised with image extensions, private uploads, or application files; do not steal cookies, tokens, drafts, or user content.

## PyMdown `b64` image-path confinement

`pymdownx.b64` converts eligible `<img src>` files into base64 data URIs. In versions through 10.21.3, the extension normalized a relative path joined to `base_path`, or accepted an absolute path, then opened the file without proving that its real path remained under `base_path`. The extension restricts reads to configured image extensions, so this is a bounded file-read primitive rather than unrestricted arbitrary file read. PyMdown Extensions 11.0.0 adds the confinement fix.

### Preconditions

Confirm all of the following:

- `pymdownx.b64` is actually enabled; the broader `pymdown-extensions` dependency or other extensions are insufficient;
- an attacker can control raw HTML `<img src>` input that reaches Markdown conversion;
- the renderer can access local files and returns or publishes the converted HTML;
- the target file has an allowed image extension such as `.png`, `.jpg`, `.jpeg`, `.gif`, or `.svg`; and
- no upstream HTML policy removes or rewrites the image before the extension resolves it.

### Disposable fixture

Create this layout under one temporary root:

```text
TEMP/
  docs/                 # configured base_path
    inside.png           # marker INSIDE
  sibling/
    outside.png          # marker OUTSIDE
  linked.png -> sibling/outside.png   # optional symlink control
```

Use real, benign one-pixel image files with distinct trailing marker bytes. Then render one case at a time:

| Case | `src` shape | Boundary under test |
| --- | --- | --- |
| baseline | `inside.png` | expected in-root conversion |
| parent traversal | `../sibling/outside.png` | lexical escape |
| absolute | full path to `outside.png` | `base_path` bypass |
| symlink | `linked.png` | canonical path escape |
| false prefix | sibling directory named like `docs-backup` | string-prefix vs path-component containment |
| patched | same cases on 11.0.0+ | fixed negative control |

Decode only the emitted data URI and compare it with the synthetic canary bytes. Capture the configured `base_path`, raw `src`, normalized and real paths, extension allowlist, output fragment, and version. A strong finding proves **untrusted image path -> Markdown build process opens an out-of-base synthetic image -> its bytes appear in rendered HTML**.

Do not infer exposure for this wiki merely because MkDocs uses PyMdown Extensions: the `b64` extension must be enabled. The current Skillz Wiki configuration does not list `pymdownx.b64`.

## Trix paste and document-model URL validation

In Trix before 2.1.18, crafted pasted HTML could create a mock attachment `<span>` with an empty `data-trix-attachment="{}"`. It bypassed attachment handling, while `data-trix-attributes` crossed into a plain string piece. `StringPiece.fromJSON` accepted an unsafe `href`, and serialized output could preserve a `javascript:` URL until a viewer clicked it. The related earlier advisory reaches the same model sink through crafted `application/x-trix-document` drag-and-drop JSON in environments using the fallback `Level0InputController`.

This is not simply “DOMPurify missed a URL.” The durable chain is:

1. paste or drag/drop input is parsed;
2. attachment classification changes how an element is modeled;
3. model attributes are accepted without URL-scheme validation;
4. serialized HTML recreates the link; and
5. application rendering and a user interaction determine execution.

### Two-channel editor harness

1. Create disposable author and viewer accounts in a test application using the same Trix and server-side sanitization configuration as the target.
2. For paste, use a minimal span with empty synthetic attachment metadata and a `data-trix-attributes` object whose `href` is a harmless marker scheme string. Use a click handler/instrumented navigation shim that records the attempted URL without executing JavaScript.
3. Capture the pasted DOM, Trix document JSON/model, serialized editor value, server-stored value, viewer DOM, and attempted navigation.
4. Test ordinary typed links and legitimate pasted links as controls. Repeat with Trix 2.1.18 or later.
5. Test the drag/drop channel only if the actual client uses `Level0InputController` or an equivalent fallback. Deliver a synthetic `application/x-trix-document` object through a local drag source and use the same instrumented navigation sink.
6. Compare applications with and without their normal server-side HTML sanitizer. Do not disable production sanitization or claim stored impact when the stored/viewer representation removes the unsafe URL.

A useful decision table is:

| Channel | Attachment/model path reached? | Unsafe scheme retained in serialized value? | Retained after server save? | Viewer navigation sink reached? |
| --- | --- | --- | --- | --- |
| paste | record | record | record | record harmless marker only |
| fallback drag/drop | record | record | record | record harmless marker only |
| patched paste | expected safe | expected no | expected no | expected no |
| server-sanitized save | may be yes in editor | may be yes before save | expected no | expected no |

Report **input channel -> attachment-classification/model deserialization bypass -> unsafe `href` retained -> serialized/stored viewer link**. State whether a click is required and whether server-side sanitization neutralizes the value. Do not call editor-only retention stored XSS unless the application persists and renders the unsafe URL to another security principal.

## Reporting notes

For PyMdown, include extension enablement, renderer identity, path representations, canonical path evidence, allowed extension, and marker-only output. For Trix, include browser/editor path, input channel, internal model representation, server sanitizer behavior, viewer context, interaction requirement, and patched negative control.

Keep the two findings conceptually separate: PyMdown is a **server-side content renderer to filesystem** boundary; Trix is an **input parser to rich-text model to later browser interpretation** boundary.