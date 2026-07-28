# Agent-guided fuzzing campaigns

**Date**: 2026-07-02; updated 2026-07-28

**Sources**: Trail of Bits, *Field reports from Patch the Planet* and *How we use /goal to find bugs in Patch the Planet*

**Status**: Durable offensive operator workflow

---

## Core lesson

Frontier coding agents can now build useful fuzzing campaigns without being handed every harness step. The operator value is not “ask an agent to fuzz it” — it is giving the agent a scoped target, hard validity rules, observable sanitizer output, and a replayable evidence standard.

Use this workflow for authorized source reviews where parser, compression, archive, media, protocol, model, or file-format code exposes attacker-controlled input.

---

## When to use it

Good targets:

- compression, archive, codec, image, document, model, chemistry, geospatial, and serialization libraries
- network protocol parsers and stateful stream decoders
- CLI tools that ingest untrusted files or package metadata
- compatibility layers with compile-time flags, alternate backends, or legacy parser modes
- codebases with existing unit tests but narrow or shallow fuzz coverage

Avoid using agent-generated fuzzing as evidence when:

- you cannot build the target reproducibly
- crashes require impossible API states or caller misuse
- the harness never reaches meaningful parser/state branches
- you cannot preserve corpus, build flags, sanitizer output, and minimized inputs for replay

---

## Campaign setup

Give the agent a narrow objective and force it to prove reachability.

```text
Goal: build an authorized fuzzing campaign for <target component>.
Find only bugs reachable through documented/public or attacker-controlled input paths.
Use ASan/UBSan or the strongest available equivalent.
Prefer existing edge-case tests and fixtures as seeds.
Explore alternate build variants and feature flags that change parser behavior.
Reject crashes caused by invalid harness states or impossible caller misuse.
Preserve every command, corpus seed, minimized reproducer, and sanitizer trace.
```

### Define success before choosing the path

For an autonomous run, write the goal as a testable completion contract rather than a recipe. Include:

- one vulnerability outcome and the exact threat model it must satisfy;
- attacker-controlled inputs and normal/default configurations that count;
- local control, privileges, configuration changes, or prior execution that must **not** be assumed;
- a duplicate-check requirement;
- the minimum safe proof and evidence bundle;
- an explicit statement that “no bug found,” a crash without reachability, and a known issue do not satisfy the goal;
- a stopping condition: one validated, previously unreported candidate.

Do not prescribe a new harness, a specific code path, or an exact root cause unless that is the experiment. “Use fuzzing” leaves the agent free to reuse a better existing harness. For variant analysis, a one-sentence vulnerability class can be more productive than handing the agent the complete original backtrace.

Have a separate agent draft and challenge the goal before the campaign:

```text
Read THREAT_MODEL.md and the repository's build/test guidance.
Draft one goal for finding one previously unreported <impact> issue reachable by
<remote/file/API attacker> under <normal configuration>.

List the shortcuts a future agent could use to satisfy the wording without finding
a valid vulnerability: impossible attacker control, test-only APIs, known issues,
unreplayed crashes, missing default reachability, or evidence-only claims.
Revise the goal to close those exits without prescribing the search path.
```

Treat source-reading and coverage metrics as campaign telemetry, not as substitutes for a vulnerability. If available, record which files or lines the agent actually inspected so a confident result cannot rest on a narrow code sample.

### One outcome per agent

Do not ask one session to maximize code coverage and find a vulnerability. Those are competing objectives.

1. Run a **surface-mapping session** that inventories the repository and ranks a small number of attacker-reachable areas.
2. Assign one independent vulnerability-finding session to each area.
3. Add one open-ended session for surfaces the partitioning may have missed.
4. Run coverage analysis separately and use its gaps to seed another round; do not redefine a vulnerability run as “done” because coverage increased.
5. For variant analysis, spawn one session per source issue or bug class rather than asking one session to process the entire history.

Each worker should receive the same threat model and report schema, but only one outcome. Keep run IDs, repository commits, inputs, and artifacts isolated so results can be replayed independently.

### Gate variant-analysis inputs and outputs

Historical critical bugs are useful seeds only after a gate confirms they represent a real security boundary for the current threat model. Route each seed to:

```text
skip        source issue is not security-relevant or is outside scope
no_variant  valid vulnerability class, but no distinct reachable variant reproduced
candidate   distinct behavior with a safe reproducer and plausible security impact
```

Pass candidates through two independent reviews: one for threat-model and impact validity, and another focused on clean-checkout PoC replay. Then perform a human duplicate search against local findings, upstream issues, pull requests, release notes, and advisories before submission. Model agreement is triage evidence, not confirmation.

For C/C++ targets, start with a matrix like:

```text
build: default + ASan + UBSan
build: strict parser flags + ASan + UBSan
build: legacy/compatibility flags + ASan + UBSan
entrypoints: public parse/decode/decompress APIs
seeds: unit-test fixtures, regression files, boundary cases, tiny valid samples
oracle: sanitizer crash, invariant assertion, differential parse result, timeout only when security-relevant
```

---

## Harness strategy

Tell the agent to build breadth first, then deepen where coverage moves.

1. **Inventory reachable entrypoints**
   - public API functions
   - CLI file-ingestion paths
   - streaming/state-machine APIs
   - compatibility wrappers and contrib modules

2. **Seed from real behavior**
   - existing unit tests
   - regression files
   - tiny valid files/messages
   - edge cases already documented by maintainers

3. **Vary the build**
   - sanitizer builds: ASan, UBSan, MSan where practical
   - strict/legacy feature flags
   - optional parser backends
   - platform-specific branches if the target is portable

4. **Measure reachability**
   - require coverage growth beyond argument validation
   - log functions and branches reached by each harness
   - discard harnesses that only exercise invalid setup paths

5. **Minimize and classify**
   - minimize crashers
   - replay under the exact build
   - determine whether a real caller can create the vulnerable state
   - separate parser bugs from harness bugs

---

## Validity rules for agent output

A finding is reportable only when the campaign can answer these questions:

- What attacker-controlled input reaches the failing code?
- Which public API, CLI command, service route, or file-ingestion path exercises it?
- Does the minimized input work from a clean checkout and documented build?
- Does the crash depend on an impossible caller state, null callback, internal-only API misuse, or test-only configuration?
- Is there a patched or negative-control build showing the behavior disappears?
- Are sanitizer traces, build flags, corpus seed, and reproducer small enough for a maintainer to replay?

If the agent cannot answer those, keep fuzzing but do not publish or report the crash as a vulnerability.

---

## Operator prompt pattern

Use a prompt like this inside a local lab or authorized code-review environment:

```text
You are auditing <repo> for reachable parser/memory-safety bugs.
Work only inside this checkout and temporary build directories.
Do not run network commands except package installs already required by the project.

Tasks:
1. Identify attacker-controlled parsing/decode/decompress entrypoints.
2. Build sanitizer-enabled variants and record exact commands.
3. Create fuzz harnesses for the top entrypoints.
4. Seed from existing tests and minimal valid files.
5. Run short smoke campaigns, then expand the most promising harnesses.
6. Minimize any crashers and prove replay from a clean build.
7. Reject findings that require impossible public API states.
8. Produce an evidence bundle with commands, flags, corpus seeds, minimized inputs, and sanitizer output.
```

For a goal-driven discovery run, keep the search path open while making the acceptance boundary strict:

```text
Audit <repo> at <commit> and find exactly one previously unreported <impact>
vulnerability reachable in normal/default use by <attacker model> through
<allowed attacker-controlled inputs>.

First create a concise threat model and rank attacker-reachable trust boundaries.
Do not assume control of local configuration, command-line arguments, environment,
plugins, source, credentials, administrator privileges, or prior code execution.
Reject candidates that need those preconditions.

Before accepting a candidate, search local findings and current upstream issues,
pull requests, releases, and advisories for duplicates. Produce a minimal inert or
sanitizer-backed proof, replay it from a clean checkout, and save the threat path,
commands, artifacts, negative controls, and exact result under <output directory>.
The following do not satisfy the goal: no finding, an untriaged crash, a known
issue, or an unreplayed hypothesis. Stop after one valid candidate.
```

---

## Evidence bundle

Capture these artifacts before reporting:

```text
repo commit / release
compiler and sanitizer versions
all build flags and feature flags
harness source files
seed corpus source and hashes
fuzzer command lines and runtime limits
coverage summary or reached-function list
minimized reproducer files
sanitizer trace
negative-control or patched-version result
reachability explanation from real input to failing code
```

Keep inputs synthetic and minimal. Do not include customer data, proprietary corpora, production crash dumps, credentials, model weights, private documents, or unrelated files from the target environment.

---

## Reporting heuristic

High-signal reports state what the agent proved and what it rejected:

- “Reachable through `tool parse <file>` with this minimized file.”
- “Reproduces under default and strict builds; fixed in patched commit.”
- “Not dependent on a null callback, mocked allocator, or invalid internal state.”
- “The harness reaches the same state using public streaming APIs.”

Low-signal reports to avoid:

- “The fuzzer crashed” without reachability.
- “ASan found a bug” without a clean reproducer.
- “The agent says this is exploitable” without a public input path.
- Crashes that require harness-only object layouts or impossible caller behavior.

---

## Safety boundaries

- Run campaigns only on code you own or are authorized to test.
- Keep fuzzing in disposable lab containers or worktrees.
- Do not fuzz production services or shared developer machines.
- Do not use live user files as seed corpora.
- Do not publish weaponized exploit chains before coordinated disclosure.

---

## References

- Trail of Bits: [Field reports from Patch the Planet](https://blog.trailofbits.com/2026/07/02/field-reports-from-patch-the-planet/)
- Trail of Bits: [How we use /goal to find bugs in Patch the Planet](https://blog.trailofbits.com/2026/07/28/how-we-use-goal-to-find-bugs-in-patch-the-planet/)
- Trail of Bits: [Introducing Patch the Planet](https://blog.trailofbits.com/2026/06/22/introducing-patch-the-planet/)
