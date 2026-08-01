---
title: AI dataset, scheduler fetch, and stale-session boundaries
---

# AI dataset, scheduler fetch, and stale-session boundaries

An August 1 advisory wave yields three reusable operator workflows: trace an unauthenticated AI-workflow upload into a pickle-bearing dataset loader without executing a payload, test whether a scheduler trigger accepts a caller-selected executor authority, and verify whether logout actually revokes an already-issued session.

Primary sources:

- ComfyUI [GHSA-6p72-9j26-4rmx / CVE-2026-68771](https://github.com/advisories/GHSA-6p72-9j26-4rmx), including the [upstream `weights_only=True` patch](https://github.com/Comfy-Org/ComfyUI/pull/14543);
- xxl-job [GHSA-xw47-r6m7-qrhr / CVE-2026-52371](https://github.com/advisories/GHSA-xw47-r6m7-qrhr) and its [route-level reproduction](https://github.com/RichardKabuto/xxl-job-ssrf-poc); and
- FeehiCMS [GHSA-jhhh-39pj-vgq6 / CVE-2026-51953](https://github.com/advisories/GHSA-jhhh-39pj-vgq6) and the [session-reuse report](https://github.com/altamish1994/CVE_Published/blob/main/FeehiCMS/CVE-2026-51953.MD).

!!! warning "Recorder-only proofs"
    Use disposable instances, random marker files, an owned callback listener, synthetic users, and fake cookies. Do not deserialize attacker-defined objects, execute commands, target metadata or internal services, capture another user's session, or test logout reuse on a production account.

## Boundary map

| Surface | Caller-controlled value | Expected policy | Bounded positive |
| --- | --- | --- | --- |
| ComfyUI upload plus `LoadTrainingDataset` | upload filename/content, workflow graph, dataset folder | untrusted artifacts never reach an unrestricted object loader | an inert uploaded shard reaches a patched `torch.load` recorder with `weights_only` absent or false |
| xxl-job trigger | job ID and `addressList` | execution targets come from the stored executor configuration | an authenticated trigger causes one request to an owned listener selected only by `addressList` |
| FeehiCMS logout | previously issued `PHPSESSID` and identity cookie | logout revokes server-side authority, not only browser state | the exact pre-logout synthetic session still reaches a harmless authenticated route after logout |

## 1. ComfyUI upload-to-dataset-loader chain

The advisory describes a composed path in ComfyUI 0.23.0: unauthenticated `POST /upload/image` accepts a dataset shard, then `POST /prompt` queues a graph whose `LoadTrainingDataset` node opens that shard with `torch.load`. The upstream patch identifies this as the only ComfyUI `torch.load` call that did not explicitly pass `weights_only=True`; it changes that single call in `comfy_extras/nodes_dataset.py`.

Treat this as two independently proven edges:

1. **Placement:** can the upload route place an inert file at a name and directory later selected as a dataset shard?
2. **Loader reachability:** can an unauthenticated or low-trust graph make `LoadTrainingDataset` open that exact file, and with what deserialization policy?

Do not create a pickle with `__reduce__`, a command gadget, or any executable callback. Sink reachability is enough.

### Safe harness

1. Run the affected and corrected revisions in separate disposable containers with no secrets, host mounts, provider credentials, or outbound network.
2. Create a benign training shard using only tensors and ordinary dictionaries produced by the same ComfyUI/PyTorch version. Add a random, non-secret marker in a normal scalar field.
3. Monkey-patch or interpose `torch.load` before starting the application. The wrapper must record:
   - the canonical file path;
   - whether the input is a path or already-open file object;
   - positional and keyword arguments, especially `weights_only`; and
   - the node and request correlation ID.
4. After recording, either return a known-safe in-memory dataset object or raise `SKILLZ_DESERIALIZATION_BLOCKED`. Never invoke the original loader on tester-supplied bytes.
5. Establish controls:
   - upload disabled or authenticated;
   - a normal non-dataset upload;
   - a server-created dataset shard; and
   - an invalid workflow that does not reach the node.
6. Upload the inert shard through the real route and submit the smallest graph that selects its dataset folder. Preserve upload response, stored relative path, graph JSON, queue response, node trace, and recorder event.
7. Repeat on the corrected revision. Confirm `weights_only=True` reaches the real call site; do not infer the fix solely from the package version.

A strong result is **unauthenticated artifact placement and graph submission reach the affected loader with no restrictive deserialization flag, while the corrected revision passes `weights_only=True` for the same inert fixture**. Report endpoint exposure, file placement, graph authorization, and loader policy separately. The recorder proves the dangerous boundary without proving or attempting code execution.

### Adjacent audit heuristic

Search AI workflow, model, checkpoint, dataset, adapter, and cache nodes for loaders with different policy defaults. Compare every `torch.load`, `pickle.load`, `joblib.load`, and framework-specific checkpoint helper across:

- browser uploads versus server-created files;
- image, input, output, model, and temporary directories;
- direct node invocation versus queued workflows;
- optional/custom nodes versus core nodes; and
- explicit safe-load flags versus dependency-version defaults.

Do not call a loader safe merely because a newer dependency changed its default. Preserve the actual arguments at the application call site.

## 2. xxl-job trigger-time executor authority

The advisory and reproduction identify authenticated `POST /xxl-job-admin/jobinfo/trigger` in xxl-job 3.4.0. The request carries a job `id` plus `addressList`; changing `addressList` can steer the trigger toward a caller-selected HTTP authority. This is not just generic SSRF input discovery: it is a stored scheduler object whose execution target can be overridden at trigger time.

### Owned-listener matrix

1. Deploy xxl-job locally with one synthetic executor and one no-op job. Use a non-production operator account and replace all default credentials before testing.
2. Start two owned HTTP listeners on an isolated test network:
   - listener A represents the executor address stored in the job; and
   - listener B is a recorder-only alternate address.
3. Both listeners should log method, path, headers, and body length, return a static response, and perform no callback or command action.
4. Capture a legitimate trigger request, then replay a matrix that changes only `addressList`:

| Case | `addressList` value | Evidence |
| --- | --- | --- |
| stored-target control | omitted or empty | only listener A receives a request |
| alternate owned authority | listener B URL | whether B replaces or supplements A |
| malformed authority | syntactically invalid URL | rejection stage and any DNS/connect attempt |
| multi-address form | two owned listeners | parsing, ordering, and fan-out behavior |
| redirect response | B redirects to A | whether the HTTP client follows redirects |

5. Preserve the authenticated role, job ownership, stored executor configuration, raw form body, final authority, DNS/connect events, and response returned to the caller.
6. Test patched behavior when available. The negative control should either ignore caller-supplied authority or constrain it to executor addresses already authorized for that job.

Stop at an owned listener. Do not request cloud metadata, loopback administration, RFC1918 services, link-local addresses, or unrelated internal hosts. A DNS callback proves name resolution, not HTTP reachability; preserve the actual listener request when claiming a completed server-side fetch.

Useful report wording is **“An authenticated trigger overrides the synthetic job's stored executor with a caller-selected owned authority.”** State the required role and job visibility. Do not describe this as unauthenticated SSRF or internal compromise unless those separate preconditions are independently demonstrated.

## 3. FeehiCMS logout revocation differential

The FeehiCMS report says version 2.1.1 clears or abandons browser state without invalidating the corresponding server-side session. A pre-logout `PHPSESSID` plus identity cookie can therefore remain authoritative. The durable workflow applies to any logout, password-change, role-change, SSO unlink, or administrator revocation path.

### Two-client synthetic test

1. Create a disposable FeehiCMS user with no privileged content. Route mail to a local sink and use no real identity data.
2. Log in with client A. Clone the complete cookie jar into client B **using only the test account's cookies**.
3. From both clients, request one harmless authenticated identity/status route and confirm that the same synthetic user is returned.
4. Log out normally in client A. Record the logout request, redirects, every `Set-Cookie`, and any session-store delete or rotation event visible to the harness.
5. Without accepting new cookies or redirects in client B, replay the old cookie jar against the same harmless route.
6. Compare three controls:
   - client A after processing logout cookies;
   - client B with the exact pre-logout cookies; and
   - client C with a random nonexistent session ID.
7. Repeat for password change, explicit “log out all sessions,” and administrator revocation only if those features exist and are in scope. Keep each revocation action as a separate result.

A positive requires **the same pre-logout authority remains accepted after a completed logout**, not merely that a stale cookie remains in the browser. Preserve a hash or redacted prefix of the synthetic session ID rather than the full bearer value.

Avoid inflated claims. Reusing your own test session proves insufficient revocation. Account takeover additionally requires a separate session-acquisition path, which this workflow does not attempt. Similarly, a stale identity cookie that fails server-side authorization is not a valid finding.

## Evidence and reporting

Preserve:

- exact application, commit, dependency, and container versions;
- route authentication and role requirements;
- upload destination, canonical shard path, minimal graph, and loader arguments;
- scheduler job ownership, stored executor, supplied authority, final connected authority, and redirect behavior;
- logout request/response, cookie mutations, session-store events, and pre/post route decisions;
- affected-versus-corrected controls; and
- proof that all files, listeners, jobs, and users were synthetic and owned.

Prefer narrow titles:

- **“Unauthenticated ComfyUI upload and prompt routes reach `LoadTrainingDataset`'s unrestricted loader.”**
- **“xxl-job trigger `addressList` overrides the stored executor with an owned callback.”**
- **“FeehiCMS accepts the same synthetic session after logout.”**

Do not convert sink reachability into claims of command execution, internal-network access, secret disclosure, or account takeover without separate bounded evidence.
