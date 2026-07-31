---
title: Dynatrace MCP transport, query, and workflow-template boundaries
---

# Dynatrace MCP transport, query, and workflow-template boundaries

Three reviewed July 31 advisories for `@dynatrace-oss/dynatrace-mcp-server` expose a reusable chain for testing privileged observability agents: an HTTP transport may dispatch tools without authenticating the caller; parameters advertised as identifiers may cross into DQL grammar; and approved workflow metadata may become persistent server-side template expressions.

Sources:

- [GHSA-p7w7-4929-vpj5](https://github.com/advisories/GHSA-p7w7-4929-vpj5) reports unauthenticated tool dispatch in HTTP mode through 1.8.7, fixed in 2.0.0;
- [GHSA-pqh8-p93p-2rx7](https://github.com/advisories/GHSA-pqh8-p93p-2rx7) reports DQL injection through identifier, timeframe, and Kubernetes-ID parameters before 2.1.1; and
- [GHSA-xrmj-5g4g-8987](https://github.com/advisories/GHSA-xrmj-5g4g-8987) reports persistent Jinja expression injection through notification-workflow fields before 2.0.0.

The first advisory distinguishes tools that dispatch directly from tools that stop at human approval. The DQL advisory also states that the affected tools are marked `readOnlyHint: true` and that an explicit arbitrary-DQL tool may already exist. Report the exact crossed boundary rather than inflating either condition into generic tenant compromise.

!!! warning "Synthetic tenant and recorder-only tools"
    Use a loopback or isolated lab MCP server, fake platform credentials, no-op tools, a DQL parser/recorder, synthetic event objects, and a disposable workflow tenant. Never query real logs, sessions, security events, or metrics; never create workflows in a production tenant; and never route workflow output through a real messaging connector.

## Boundary map

| Surface | Attacker-controlled input | Authority transition | Bounded positive |
| --- | --- | --- | --- |
| Streamable HTTP | request without credentials, plus `Host` and `Origin` | network reachability becomes tool authority under the server token | an inert in-memory tool increments its recorder without authentication |
| Read-oriented tool | entity name, timeframe, cluster ID, or Kubernetes entity ID | schema scalar becomes DQL string, expression, comment, or pipeline grammar | parser AST or mocked query sink differs from the documented tool contract |
| Workflow creator | team name, problem type, or channel | approved metadata becomes runtime Jinja in a persistent workflow | synthetic event marker is evaluated into a local recorder after approval |

Prove the edges independently. Unauthenticated JSON-RPC parsing is not tool execution. A metacharacter in generated DQL is not injection until query structure changes. A stored brace sequence is not template injection until the workflow engine evaluates it in a synthetic run.

## Preconditions

- written authorization for the MCP deployment and its disposable Dynatrace tenant;
- exact package version, launch arguments, bind address, and transport mode;
- fake credentials that cannot access production observability data;
- one inert tool whose only effect is incrementing an in-memory counter;
- an instrumented DQL builder or mocked execution adapter; and
- a workflow fixture with no external Slack, email, webhook, or ticketing connection.

Keep transport authentication, tool approval, upstream platform authorization, query construction, and workflow execution as separate evidence columns.

## HTTP transport authentication matrix

Start the server only in an isolated namespace or container. Bind to loopback unless a second owned test host is required. Call the same no-op tool across this matrix:

| Request | Authorization | `Host` / `Origin` | Expected secure result |
| --- | --- | --- | --- |
| negative control | absent | expected owned values | reject before dispatch |
| token control | invalid canary | expected owned values | reject before dispatch |
| positive control | valid lab token | expected owned values | increment recorder once |
| host/origin probe | valid lab token | foreign owned values | reject according to configured browser/host policy |
| browser-style negative | absent | foreign owned values | reject before dispatch |

Capture the HTTP status, JSON-RPC result or error, authentication middleware decision, selected tool, approval decision, and recorder count. The decisive vulnerable result is the unauthenticated request incrementing the inert tool recorder.

Do not use an arbitrary-query, notebook-write, event-send, or other tenant-facing tool as the proof. The advisory identifies an in-memory budget-reset operation as a non-upstream canary; an equivalent purpose-built recorder is preferable. Test approval-gated tools separately and record a blocked approval as blocked, not exploitable.

### Reachability notes

Record whether HTTP mode is enabled, whether the listener binds beyond loopback, and whether a reverse proxy adds authentication. Test the application directly and through the documented deployment path, but do not treat a proxy control as proof that the underlying transport authenticates callers. Conversely, do not claim remote exposure from a loopback-only lab result without separately establishing an authorized network path.

## DQL contract-confusion testing

The reusable question is not merely “can this token run DQL?” It is whether a narrowly described or auto-approved tool can produce a query outside its declared field, filter, time, or row-limit contract.

### Build a query-construction harness

Intercept the final DQL string before network execution and feed it to the same parser used by the target when available. Seed the harness with synthetic identifiers only:

```text
entity name: skillz-canary
cluster ID: 00000000-0000-0000-0000-000000000001
timeframe: 24h
fields: id, name, type
```

For each parameter class, compare:

1. a normal scalar;
2. a quote or delimiter canary expected to be rejected or encoded;
3. a comment-token canary;
4. a pipeline-separator canary; and
5. the same cases on the fixed release.

Use inert labels such as `SKILLZ_STAGE_MARKER` rather than field names that could expose secrets. Do not send a changed query to a live Grail backend.

### Evidence table

| Case | Schema says | Generated string | Parsed structure | Sink called |
| --- | --- | --- | --- | --- |
| control | identifier/timeframe | one literal or duration | expected filter and stages | mocked only |
| quote canary | same scalar type | encoded or rejected | unchanged | no unexpected call |
| grammar canary | same scalar type | must not add syntax | no new comment/expression/stage | no unexpected call |

A valid positive shows the caller-controlled scalar closing its intended literal or duration context and changing the parsed filter, selected fields, timeframe, or pipeline stages. Preserve a redacted AST diff or normalized query plan. Raw string concatenation alone is supporting evidence, not the sink-side proof.

### Scope the impact accurately

If the same principal already has an explicit arbitrary-DQL tool, describe the result as an approval or tool-contract bypass unless the injected path reaches data or authority unavailable to that tool. `readOnlyHint: true` does not itself prove that a specific client auto-approves the call; record the tested client's actual decision.

## Persistent workflow-template boundary

Test the workflow creator with a local evaluator or a throwaway tenant whose only event is:

```json
{"skillz_marker":"EVENT-ONLY-CANARY"}
```

Use a destination adapter that records rendered strings locally and cannot contact external services.

1. Create a baseline workflow with ordinary synthetic team, problem-type, and channel values.
2. Save the approval text, serialized workflow definition, persistence/visibility setting, and local recorder output.
3. Place a harmless template marker in one field at a time. The marker should only render `skillz_marker`; it must not enumerate environment, credential, tenant, or event fields.
4. Compare what the operator approved with the exact stored workflow representation.
5. Trigger one synthetic event manually and record whether the marker remains literal or is evaluated.
6. Delete the workflow and verify the recorder cannot fire again.
7. Repeat against the fixed release.

### Decision table

| Approval text | Stored value | Runtime value | Interpretation |
| --- | --- | --- | --- |
| ordinary literal | ordinary literal | ordinary literal | baseline |
| marker visible as literal | marker encoded/literal | marker literal | no template crossing |
| marker looks like harmless metadata | executable template syntax | synthetic event canary | approval-to-template boundary crossed |

The strongest evidence is the three-stage chain: caller value, stored workflow AST/definition, and evaluated synthetic output. Also record whether the workflow survives the MCP session and whether its default visibility is private or tenant-wide. Persistence is a distinct impact amplifier, not proof of data exfiltration.

## Combined-chain validation

Only chain findings that were independently confirmed in the same authorized configuration:

```text
network caller
  -> unauthenticated inert tool dispatch
  -> narrowly described read tool changes DQL structure
  -> approved workflow field persists as runtime template
```

Do not infer that unauthenticated HTTP can pass a human-approval gate. Do not substitute a real arbitrary-DQL call for the recorder proof. Do not configure a working external connector merely to demonstrate that the workflow engine rendered a synthetic marker.

## Evidence and reporting

Preserve:

- package version, commit or image digest, launch arguments, listener scope, and transport;
- reverse-proxy and application-layer authentication results separately;
- JSON-RPC request class, auth decision, approval decision, and inert recorder count;
- schema type, generated DQL, normalized parser/AST difference, and mocked sink event;
- approval text, stored workflow definition, runtime render, visibility, and deletion result; and
- vulnerable/fixed differential using the same fixtures.

Use narrow titles such as “HTTP MCP transport dispatches a no-op tool without caller authentication,” “read-only MCP parameter changes generated DQL pipeline structure,” or “approved notification metadata persists as runtime workflow template.” Do not report generic MCP RCE, observability compromise, or event exfiltration unless those stronger effects were separately and safely proven.