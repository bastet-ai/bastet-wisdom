# Klever KLV token-minting via split-royalty integer overflow and marketplace TOCTOU — operator validation

**Date reviewed:** 2026-08-28
**Advisories:** [GHSA-cgc5-v3f2-8m2v / CVE-2026-54755](https://github.com/advisories/GHSA-cgc5-v3f2-8m2v) (critical), [GHSA-p7gw-2pcp-5pf8 / CVE-2026-54754](https://github.com/advisories/GHSA-p7gw-2pcp-5pf8) (critical). Both in `klever-io/klever-go` (the Klever node).

Two independent paths let an attacker **mint KLV (the native token) out of thin air** by transferring or selling their own throwaway asset. Both are durable because they expose a reusable settlement-validation boundary: **percentage/amount accumulation and payout that is not bounded per-entry and not re-checked at the time of value transfer.**

## Boundary 1 — split-royalty integer overflow enables unbounded minting (GHSA-cgc5-v3f2-8m2v / CVE-2026-54755)

KDA split-royalty percentages are validated by summing entries into a **`uint32` accumulator** and comparing the *sum* to `HundredPercent (10000)`, **with no per-entry upper bound**. Two entries whose percentages sum to just over `2^32` **wrap around** below `10000` and pass validation, while each stored value stays astronomically large (e.g. `0x80000000 = 2,147,483,648` ≈ 21,474,836%).

At payout, each split recipient is credited `pool × hugePct / 10000` — far more than the royalty pool — and the resulting negative remainder is silently discarded (`if royaltiesToPay <= 0 { return Ok }`). Because **fixed** royalties (and marketplace/ITO royalties) are denominated in **KLV**, the attacker mints KLV on demand by transferring or selling their own asset. Independent of, and not mitigated by, the existing `FixMarketBuyOverflow` guard.

Where to look:

- `core/process/kda/assetHelper.go`, `core/kapp/kda/create.go`, `core/kapp/kda/trigger.go`, `core/kapp/builtInFunctions/utils.go` — validation side (the `uint32` sum).
- `core/kapp/accounts/accounts.go` (transfer) and `core/kapp/market/market.go` (marketplace) — the payout/mint sites.

## Boundary 2 — marketplace settlement mints KLV when referral% + royalty% exceed the bid (GHSA-p7gw-2pcp-5pf8 / CVE-2026-54754)

On settlement (`MarketBuy` / `BuyItNow`, auction `Claim`), the buyer's payment is split three ways:

```
marketOwnerAmount = CurrentBid − referralAmount − royaltiesAmount
```

Referral and royalties are paid **unconditionally**; the seller remainder is paid **only when positive** (`computeMarketOwnerAmount` returns `Ok` and pays nothing when `<= 0`). When `referral% + royalty%` exceeds 100% of the bid, `marketOwnerAmount` goes negative and is silently skipped — the marketplace pays out **more KLV/sale currency than the buyer paid**, minting the difference.

The `royalty% + referral% <= 100%` ceiling **is** checked once, at listing time (`Sell`). But the two percentages are sourced **asymmetrically** at settlement:

- **referral %** is **snapshotted** into the order at `Sell` (`MarketOrderData.ReferralPercentage`);
- **royalty %** is **never snapshotted** — read **live** from the asset at buy time (`asset.Royalties.MarketPercentage`).

So the listing-time invariant is a **time-of-check/time-of-use** guarantee only: after a valid listing, the asset owner raises the royalty `MarketPercentage` via `AssetTransfer`/update, and the next settlement mints.

## Durable operator value

Both items are the same bug class in a DeFi/token context: **a sum-of-percentages or sum-of-amounts gate that does not bound the components and is not re-evaluated at the value-transfer moment.** Reusable across any settlement engine, fee router, royalty splitter, or dividend distributor:

1. **Check the accumulator type and per-entry bounds.** A `sum <= MAX` gate with unbounded inputs is an overflow/underflow probe. Test two entries that individually exceed the scale but sum into the valid range after wrap.
2. **Check snapshot vs live sourcing of each operand.** If one percentage is fixed at listing/creation and another is read live at payout, the listing-time invariant is TOCTOU. Find the field that is re-fetched between the invariant check and the credit.
3. **Check the negative-remainder / silent-skip path.** `if amount <= 0 { return Ok }` after an unconditional payout is the mint primitive — it converts a bad input into free value instead of reverting.
4. **Confirm the token is the native/guaranteed asset.** Minting the native token (KLV) is the high-impact case; verify the payout currency and that the pool cannot absorb the over-credit.

## Replayable validation path (lab / forked chain only)

- Preconditions: a forked or dev Klever chain (or an isolated testnet), a throwaway KDA asset, and a funded test account. No production chain, no real user assets, no real marketplace liquidity.
- **Overflow path:** create/transfer an asset with two split-royalty entries chosen so their `uint32` sum wraps below `10000` while each entry is huge. Trigger a royalty payout and record the credited amount vs. the pool; the positive is an over-credit in a synthetic recipient.
- **TOCTOU path:** list an asset with a valid combined ceiling, then raise the asset's live royalty `MarketPercentage` so referral + royalty exceed the bid; settle a `BuyItNow` and record the `marketOwnerAmount` going negative and the over-payout.
- Evidence to capture: the exact validator line (accumulator type, per-entry bounds), the two operand sources (snapshot vs live), the negative-remainder branch, and the over-credit amount vs. the pool on a forked chain.
- Stop at the over-credit on a forked/dev chain. Do not run this on mainnet, do not drain real pools, do not move real user funds, and do not attempt to extract native-token value on a live chain.

## Safe boundaries

- Forked or isolated dev/test chain only; no production Klever chain, no real marketplace liquidity, no real user assets.
- Throwaway assets and test accounts only; prove the over-credit in a synthetic recipient.
- Report the exact validator type/bounds, the snapshot-vs-live operand sourcing, the negative-remainder branch, and the measured over-credit — framed as a settlement-validation boundary, not a live-chain drain.

## Sources

- [GitHub Advisory Database: Klever GHSA-cgc5-v3f2-8m2v / CVE-2026-54755](https://github.com/advisories/GHSA-cgc5-v3f2-8m2v)
- [GitHub Advisory Database: Klever GHSA-p7gw-2pcp-5pf8 / CVE-2026-54754](https://github.com/advisories/GHSA-p7gw-2pcp-5pf8)
