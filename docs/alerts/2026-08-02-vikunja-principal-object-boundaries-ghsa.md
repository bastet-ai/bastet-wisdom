# Vikunja principal-type and cross-object authorization checks

Sources: hourly offensive-security scan, 2026-08-02 GitHub Security Advisory feed. Primary entries: [GHSA-9jrx-vmh8-c6xw](https://github.com/advisories/GHSA-9jrx-vmh8-c6xw) / CVE-2026-68581 and [GHSA-p4r4-8cxw-pjx7](https://github.com/advisories/GHSA-p4r4-8cxw-pjx7) / CVE-2026-68582.

These advisories expose two reusable API-testing patterns: numeric IDs from different principal namespaces colliding behind a generic authentication interface, and an authorized parent object being combined with an independently selected child object that is loaded before authorization.

!!! warning "Authorized validation only"
    Use a disposable Vikunja instance, synthetic users, private test projects, canary tasks, and throwaway share links. Never enumerate a public instance, access another customer's projects, retain API tokens, or delete a real user's credentials.

## Confirmed boundaries

| Advisory | Affected versions | Failed binding | Operator value |
| --- | --- | --- | --- |
| [GHSA-9jrx-vmh8-c6xw](https://github.com/advisories/GHSA-9jrx-vmh8-c6xw) | `0.22.0` through `2.3.0` | link-share IDs and user IDs occupy independent numeric sequences, but token-management routes consume a generic numeric principal ID without checking its type | Test every credential-management route with each accepted principal class, especially when IDs can collide. |
| [GHSA-p4r4-8cxw-pjx7](https://github.com/advisories/GHSA-p4r4-8cxw-pjx7) | `0.24.0` through `2.3.0` | task scope remains pinned to the shared project while the path-selected view is loaded from another project without a matching authorization check | Test parent/child route selectors independently and preserve response-shape/existence-oracle evidence. |

## Preconditions and inputs

- A disposable Vikunja deployment and a `2.4.0` patched control.
- Users A and B with synthetic profiles.
- Projects A and B, at least one view and kanban bucket in each, and marker-only tasks.
- One link share for project A. Additional shares may be created only in the lab to construct an intentional numeric-ID collision.
- An HTTP recorder that redacts JWTs and API-token values while preserving route, principal type, numeric ID, selected project/view, status, and response field names.

## Principal-type collision matrix

1. Record user B's numeric ID from the authorized lab user-search path. Do not enumerate unknown users or infer production ID ranges.
2. In project A, create disposable link shares until one share ID equals B's user ID. This sequencing step is acceptable only in the local fixture; do not generate shares against a production service.
3. Authenticate with the colliding link-share JWT and exercise the token route family in ascending impact order: list, create through a recorder/no-op sink, then delete through a recorder. Compare the same calls with user A, user B, a non-colliding share, and an expired share.
4. For token creation, request only a harmless profile/status scope and intercept persistence where possible. Positive evidence is that the resolved token owner is user B even though the authenticated principal is a link share.
5. For deletion, do not remove an actual token. A patched repository, database transaction rollback, or fake token-store recorder is sufficient to show which owner/token row would be selected.
6. Repeat on `2.4.0`, where link-share principals should be rejected from user API-token management regardless of numeric equality.

The report should prove **link-share principal with ID N -> generic principal resolver treats N as user N -> user-token operation selected**. ID equality alone is not an authorization bypass; include the route decision or intercepted side effect.

## Project/view selector matrix

Create project A as the shared project and project B as private to user B. Give each a view and bucket with unique non-sensitive markers.

| Share principal | Path project | Path view | Expected result | Evidence to capture |
| --- | --- | --- | --- | --- |
| share A | A | view A | allowed control | A task/bucket markers only |
| share A | A | view B | denied | status, response field names, no B marker beyond the canary needed for proof |
| share A | B | view B | denied | route and auth decision only |
| share A | A | unknown view | not found control | status/body-shape fingerprint |

1. Request `GET /api/v1/projects/{project}/views/{view}/tasks` for each row and record the path IDs, share-bound project, loaded view owner, and response schema.
2. Confirm task rows remain scoped to A. The advisory's distinct impact is foreign bucket metadata and the full synthetic `created_by` object, not cross-project task content.
3. Compare known foreign, unknown, and unauthorized view IDs to determine whether status or body shape creates an existence oracle. Keep the candidate set to the fixture's known IDs.
4. Repeat as users A and B and on `2.4.0`. A patched result should authorize the view against the same principal/project context before returning bucket or creator fields.

Report **share for project A -> path selects view from project B -> foreign synthetic bucket/creator fields returned**, and report the existence oracle separately as **known versus unknown view -> stable response differential**. Do not inflate the finding into arbitrary task disclosure when the task scope remains constrained.

## Evidence checklist

- [ ] Authenticated principal type and numeric ID are recorded separately.
- [ ] Parent project, child view, resolved owner, and output object types are shown.
- [ ] Token values and JWTs are redacted; only synthetic IDs and marker fields remain.
- [ ] Mutating token operations use a recorder, rollback, or disposable token.
- [ ] Non-colliding, unknown-ID, legitimate-user, and patched-version controls are included.
- [ ] Claims distinguish token-management authority, bucket metadata disclosure, and existence-oracle behavior.
