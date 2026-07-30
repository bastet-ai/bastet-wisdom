---
title: Uniswap v4 hook boundary testing
---

# Uniswap v4 hook boundary testing

Use this workflow when an authorized review includes a Uniswap v4 hook, periphery contract, or application that relies on hook-managed accounting. The core question is not merely whether `PoolManager` settles every currency delta. It is whether application-specific authorization, pool identity, value accounting, callback timing, and external integrations remain correct while settlement succeeds.

[Trail of Bits' recurring-failure analysis](https://blog.trailofbits.com/2026/07/30/building-secure-uniswap-v4-hooks/) is the primary source for this method. The protocol reference points are [`PoolKey.sol`](https://github.com/Uniswap/v4-core/blob/main/src/types/PoolKey.sol), [`PoolManager.sol`](https://github.com/Uniswap/v4-core/blob/main/src/PoolManager.sol), [`Hooks.sol`](https://github.com/Uniswap/v4-core/blob/main/src/libraries/Hooks.sol), and Uniswap's [v4 Security Framework](https://developers.uniswap.org/docs/protocols/v4/security).

!!! warning "Local fork or disposable deployment only"
    Run adversarial swaps, liquidity changes, callbacks, token fixtures, and dependency failures only against locally deployed contracts or an explicitly authorized private test environment. Do not send transactions to public pools, manipulate live prices, use borrowed production liquidity, or attempt to extract value. Use synthetic tokens and marker-only balances.

## Required inputs

Collect before testing:

- exact hook source, compiler settings, deployment bytecode, and commit;
- configured `PoolManager`, accepted `PoolKey` values, and derived `PoolId` values;
- implemented callbacks and the permission bits encoded in the hook address;
- proxy implementation, admin, delay, and storage layout when upgradeable;
- every internal balance bucket, returned delta, fee input, oracle, reward path, and external call;
- supported token behaviors, decimals, and rounding rules;
- affected and fixed builds or commits for negative controls.

Create a trust-boundary map:

| Input or actor | Boundary to verify | Recorder evidence |
| --- | --- | --- |
| direct external caller | only the configured manager reaches callback logic | call/revert matrix |
| user-supplied `PoolKey` | full pool identity is bound, not merely token addresses | key, derived ID, result |
| amount, fee, and returned delta | accounting conserves value and matches balances | before/after ledger |
| hook address | permission bits match code and returned values | bit/function matrix |
| token or dependency | reentry, transfer semantics, and failure stay bounded | no-op call trace |
| nested callback | temporary state cannot cross pool or caller | callback trace and state diff |

## Harness setup

Use a pinned local checkout and synthetic fixtures. A minimal Foundry run pattern is:

```bash
forge build
forge test --match-contract HookBoundaryTest -vvv
forge test --match-test 'testFuzz_*' --fuzz-runs 10000
forge test --match-test 'invariant_*' --fuzz-runs 1000
```

Pin the compiler, dependencies, and test seed in retained evidence. Deploy:

1. the exact `PoolManager` generation expected by the hook;
2. one approved pool and one attacker-selected pool using disposable ERC-20s;
3. ordinary, fee-on-transfer, rebasing-simulator, callback-enabled, pausable, and reverting token stubs as applicable;
4. bounded oracle/reward/dependency stubs with success, stale, revert, and reentry modes;
5. a ledger recorder that tracks real balances, internal buckets, deltas, shares, and fees after every action.

Start every campaign with a clean snapshot. A positive test must alter only synthetic marker balances or counters.

## Campaign 1: callback and unlock-path authorization

Enumerate every external callback, `unlockCallback`, helper, router entrypoint, and internal action reachable from them.

For each path, replay calls from:

- the configured `PoolManager`;
- an unrelated contract;
- an externally owned test account;
- a malicious pool or router fixture;
- the manager during a nested operation.

Preserve selector, caller, supplied pool identity, reached internal action, and revert reason. A direct call that reaches value-moving logic is meaningful; a callable function that always fails before an effect is not.

## Campaign 2: malicious pool identity

Pool creation is permissionless unless the application adds a stronger constraint. Test whether the hook validates the complete `PoolKey` or derived `PoolId` on every user-controlled path.

Build a mutation table covering:

- `currency0` and `currency1` independently;
- fee tier and dynamic-fee flag;
- tick spacing;
- hook address and callback permissions;
- token order;
- an approved key paired with an unapproved derived ID.

Do not stop at initialization. Attempt marker-only deposit, swap, liquidity, fee, reward, and redemption paths through the synthetic pool. Record whether attacker-selected token callbacks or per-pool mapping slots influence a later approved-pool action.

## Campaign 3: accounting that settles but leaks value

`PoolManager` settlement is a necessary protocol invariant, not proof that hook accounting is correct. Maintain an independent ledger and assert at least:

```text
user output <= value charged under the documented price and fee model
round-trip ending inventory <= starting inventory + explicit rewards
internal assets and liabilities reconcile with observed token balances
LP principal, fees, and incentives remain in separate ownership buckets
```

Exercise:

- exact minimum and maximum amounts;
- zero, one-unit, and repeated tiny operations;
- rounding at decimal boundaries;
- price/tick extremes permitted by the fixture;
- fee minimum, maximum, and rate-of-change boundaries;
- exact-input versus exact-output paths;
- return deltas that consume all or part of the specified amount;
- repeated deposit/withdraw and swap/reverse-swap sequences;
- supported non-standard token behavior.

Use only bounded synthetic liquidity. Report the smallest marker imbalance and the exact sequence that reproduces it; do not optimize extraction.

## Campaign 4: callback phase and state freshness

Build a table for every decision that uses pre-swap, post-swap, pre-liquidity, or post-liquidity state. Verify that logic executes in the callback phase whose state it assumes.

Replay sequences such as:

1. collect or alter a fee with a minimal liquidity action;
2. execute the action that applies a penalty or reward;
3. compare the decision with a direct action from the same starting snapshot.

A differential proves a timing or stale-state boundary only when the two sequences begin with equivalent state and differ solely in the permitted intervening action.

## Campaign 5: address permission bits and upgrade drift

For each callback and return-delta permission, compare:

| Check | Expected match |
| --- | --- |
| encoded address bit | callback intended by design |
| implemented selector | function actually present in runtime code |
| declared hook permissions | encoded bits |
| returned delta | corresponding return-delta bit |
| proxy implementation | semantics allowed by the fixed address bits |

Test both missing and extra bits in disposable deployments. Distinguish a callback that is never invoked, a callback that reverts because code is missing, and a returned value that the manager ignores. If a proxy is used, repeat after an inert test upgrade and record whether semantics can drift while address bits remain fixed.

## Campaign 6: dependency and exit-path failure

Force each optional and required external dependency into success, revert, stale-data, pause, empty-balance, missing-token, and decimal-mismatch modes. Test swaps and liquidity exits separately.

Capture whether:

- optional reward or cleanup logic blocks a core exit;
- stale data is rejected rather than silently consumed;
- a documented exit-safe fallback is reachable;
- failure changes accounting before the transaction reverts;
- the same dependency behaves differently across callback phases.

Availability-only behavior may be lower value, but an inability to exit synthetic liquidity is durable evidence of an application-level trust boundary. Never reproduce it against live LP positions.

## Campaign 7: nested callbacks and shared scratch state

One hook can serve multiple pools, and external calls can initiate nested actions. Build an adversarial fixture that performs one bounded nested swap or liquidity action while an outer callback is live.

Vary:

- same pool versus another pool sharing the hook;
- same caller versus another test caller;
- nested swap versus liquidity change;
- success versus inner revert;
- state keyed globally, by `PoolId`, by caller, and by both.

Record the callback tree and storage diff. Look for outer operations consuming inner-operation state, stale temporary values surviving a revert, overlap guards that can be bypassed through another pool, or state that is not cleared after success.

## Evidence package

Retain:

- source commit, dependency lock, compiler, chain ID, and test seed;
- deployment addresses and a permission-bit decoding table;
- approved and mutated `PoolKey`/`PoolId` pairs;
- transaction traces with synthetic addresses labeled;
- independent before/after balance and liability ledgers;
- minimal reproducer and fixed-build negative control;
- explicit statement that no public pool or real asset was touched.

## Reporting boundaries

Separate these claims:

1. an unauthorized caller reaches a callback path;
2. an attacker-selected pool is accepted;
3. a sequence creates a synthetic accounting imbalance while settlement succeeds;
4. a permission mismatch changes invocation or delta handling;
5. a dependency failure blocks an exit;
6. nested execution corrupts cross-pool or cross-caller state; and
7. actual asset loss, which requires a separately proven reachable value path.

Do not infer theft from a revert, settlement from a passing unit test, or protocol-core compromise from an application hook bug. State the hook, pool identity, deployment assumptions, exact synthetic value delta, and authorization required.