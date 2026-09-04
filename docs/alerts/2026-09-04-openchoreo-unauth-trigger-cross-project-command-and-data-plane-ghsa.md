# OpenChoreo: unauth workflow trigger, cross-project command execution, and data-plane access boundaries (GHSA)

Source: hourly offensive-security scan, 2026-09-04 late GitHub advisory wave (OpenChoreo cluster, 4 advisories). Durable because OpenChoreo is a cloud/Choreography orchestration service and the cluster exposes the **multi-project, multi-plane trust boundaries** this wiki flags for control/data-plane systems: an unauthenticated build/workflow trigger, a cross-project command-execution/wirelog leak, unauthenticated data-plane access, and an authenticated OS-command-injection leg.

Primary entries: [GHSA-c5f6-2rm9-2w8g](https://github.com/advisories/GHSA-c5f6-2rm9-2w8g) / CVE-2026-73840 (unauthenticated build/workflow trigger via git-push hook), [GHSA-52gf-6rpq-fgmx](https://github.com/advisories/GHSA-52gf-6rpq-fgmx) / CVE-2026-73841 (cross-project command execution and wirelog view), [GHSA-qh9r-j7rp-4x2m](https://github.com/advisories/GHSA-qh9r-j7rp-4x2m) / CVE-2026-73843 (unauthenticated access to data-plane operations), and [GHSA-2mw5-23gm-pccq](https://github.com/advisories/GHSA-2mw5-23gm-pccq) / CVE-2026-73667 (authenticated OS command injection).

!!! warning "Authorized validation only"
    Keep proofs to a disposable multi-project OpenChoreo lab with synthetic projects, a git-push canary, and inert command markers. Use denied process/network/file sinks. Do not trigger real production workflows, read real wirelogs containing credentials, execute real commands, or reach cloud/data-plane internal services.

## Boundary map

| GHSA | Boundary | Defect | Reusable check |
| --- | --- | --- | --- |
| [GHSA-c5f6-2rm9-2w8g](https://github.com/advisories/GHSA-c5f6-2rm9-2w8g) | Git-push → build/workflow trigger | the trigger endpoint is unauthenticated, so a crafted push can start a build/workflow | Confirm the trigger route's auth requirement; in a lab, a push canary should be able to start a synthetic workflow only if unauth. |
| [GHSA-52gf-6rpq-fgmx](https://github.com/advisories/GHSA-52gf-6rpq-fgmx) | Cross-project command + wirelog | a principal in project A can reach command execution and view wirelogs in project B | In a two-project lab, attempt the command and the wirelog read across the boundary; record the decision. |
| [GHSA-qh9r-j7rp-4x2m](https://github.com/advisories/GHSA-qh9r-j7rp-4x2m) | Data-plane operations | data-plane routes are reachable without authentication | Enumerate data-plane routes; test anonymous reachability against the control-plane auth model. |
| [GHSA-2mw5-23gm-pccq](https://github.com/advisories/GHSA-2mw5-23gm-pccq) | Authenticated OS command injection | an authenticated input reaches the OS command builder unescaped | As a low-priv authenticated user, submit a command canary; confirm the parse/escape gap with a denied sink. |

The unifying pattern is the **control-plane vs. data-plane vs. project-scope** split: each route should be gated by (a) authentication, (b) plane, and (c) project scope. This cluster shows one or more of those three missing per route.

## Replayable validation boundaries

### Unauthenticated git-push trigger

1. In a lab, identify the git-push/webhook trigger route that starts builds/workflows.
2. Determine the **auth requirement** on that route (token, signed webhook, anonymous). A positive is that an anonymous or low-trust push can enqueue a synthetic build/workflow.
3. Use an inert trigger (a no-op workflow) and record the enqueue decision, not a real build. Do not start production or secret-consuming workflows.

### Cross-project command execution + wirelog leak

1. Set up two projects, A and B, with distinct principals.
2. As project A's principal, attempt (a) the command-execution operation against a B object and (b) the wirelog view for a B run. Record the authorization decision for each.
3. A positive is either crossing the project boundary. Keep the wirelog to a synthetic run (no real credentials); do not capture live secrets from a real wirelog.
4. Negative control: the same request against a same-project object (should be allowed) to prove the scope check exists at all.

### Unauthenticated data-plane access

1. Enumerate the data-plane routes (as opposed to control-plane admin routes).
2. Test anonymous reachability against each. Record which data-plane operations are reachable without auth.
3. A positive is a data-plane operation reachable anonymously that the control-plane model assumes is gated. Do not mutate real data; a read/decision marker is enough.

### Authenticated OS command injection

1. As a low-privilege authenticated user, identify an input that feeds the OS command builder (a build arg, a plugin arg, a template value).
2. Submit an inert canary with command metacharacters; instrument the command wrapper to log argv and any substitution. A positive is command substitution or extra shell tokens.
3. Use a denied process sink and an inert marker (nonce to a controlled log); do not run real commands.

## Durable operator value

1. **Test all three gates per route.** For orchestration/control-plane systems, the reusable audit is: is this route gated by **auth**, by **plane** (control vs. data), and by **project scope**? Most multi-tenant orchestrator bugs are one of these missing on one route.
2. **Webhook/git-push triggers are a classic unauth entry.** Build/CI/webhook triggers that accept anonymous or weakly-signed pushes are a durable recon target: find the trigger route, confirm its auth, and (in lab) prove an enqueue.
3. **Wirelogs are a credential-bearing read.** Cross-project wirelog access is high-impact because wirelogs often carry runtime secrets; treat the *boundary proof* (synthetic run, boundary decision) as the report and never capture live secret material.
4. **Authenticated command injection on an orchestrator = the data-plane trust is already in your hand.** If you're authenticated and can reach the command builder, the boundary proof is expected-vs-observed trust level, not a payload.

## Safety

- **Multi-project disposable lab.** Synthetic projects, inert command canaries, denied process/network/file sinks.
- **No real production workflows.** No secret-consuming or mutating builds.
- **No live wirelog secret capture.** Synthetic runs only.
- **No internal/data-plane service probing** beyond the boundary decision.

---

*Source: hourly offensive-security scan, 2026-09-04. All 4 OpenChoreo advisories tracked in the [source index](../notes/source-index.md).*
