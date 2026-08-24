# Gödel — Benchmark & Evaluation Evidence

This document is the evidence trail behind the engine's claims. It is kept in
the repo so every number is reproducible and auditable. Regenerate anytime:

```
python -X utf8 testOfCode/run_corpus.py          # deterministic stack over TestsDone/
python -X utf8 main.py --doctor                  # environment readiness
python -X utf8 main.py --dry-run --contracts <folder>   # plumbing e2e, no LLM calls
```

## 1. Verified findings (real audit runs)

Findings below were produced by the full pipeline (Inspector → Z3 → Gatekeeper)
and are backed by artifacts committed under `output/` / `cache/fuzz/failures/`.

| Contract | Function | Class | Root cause | Z3 counterexample | EVM status |
|---|---|---|---|---|---|
| CollateralizeDebtPosition | `borrow` | HIGH · arithmetic precision | Floor division before multiplication: `(amount/10000)*50` zeroes the 0.5% fee for any `borrowAmount < 10000` | `borrowAmount = 9091 → fee = 0`, expected `45` | Z3 SAT counterexample; report: `output/submissions/CollateralizeDebtPosition_borrow_report.md` |
| CollateralizeDebtPosition | `repay` | HIGH · ordering | Interest computed on **post**-repayment balance instead of pre-repayment debt → repay-full-then-zero-interest | symbolic violation of `interest == (debt_old·t·rate)/1e18` | Report: `output/submissions/CollateralizeDebtPosition_repay_report.md` |

## 2. Foundry-confirmed invariant breaks (`cache/fuzz/failures/`)

The Gatekeeper replays every candidate bug as a Foundry fuzz suite. Failure
captures on disk are EVM-level confirmations, not LLM opinions:

- `DAOTreasuryManagerTest/testFuzz_RiskAdjustedGrantIncorrectCalculation`
- `DAOTreasuryManagerPropertyTest/*`
- `GlobalPayrollManagerVestingTest/test_VestedOptionsNotExceedLinearVesting`
- `StablecoinCDPTest/test_borrow_fee_discrepancy_fuzz`
- `SubscriptionBillingManagerTest/test_loyaltyDiscountZeroForLessThanSixMonths`

## 3. False-positive control

False positives are suppressed by two independent layers:

1. **Z3 UNSAT proofs** — candidate findings whose intent cannot be violated in
   the symbolic model never reach reporting.
2. **Gatekeeper replay** — findings whose PoC compiles and runs but does *not*
   break the property are discarded (`qc_status = property_held`), and forge
   crashes are flagged `inconclusive` rather than silently dropped or counted
   as bugs.

Claim scope: the "0% false positive" statement applies to **reported**
findings — a finding only reaches output when Z3 produces a counterexample AND
the EVM replay confirms it. Findings that fail either layer never surface.
Per-run counts land in `output/findings/` and `output/submissions/`.

## 4. Deterministic regression corpus

`TestsDone/` (9 contract folders, incl. the planted-vulnerability set
`VulunT/`) is exercised LLM-free on every CI push via
`.github/workflows/pipeline-tests.yml`: static abstraction → harness encoding →
invariant smoke, asserting zero crashes and graceful degradation on broken
input. The 51-test phase matrix (`testOfCode/test_phase*.py`) additionally
covers routing, verdict honesty labels, Z3 sentinels, the script safety gate,
and Gatekeeper classification (text + JSON modes).

## 5. Known model limitations (stated honestly)

See "Model Fidelity & Soundness" in the README: uint256 is modeled as
unbounded integers (UNSAT proofs remain sound; wraparound-induced bugs need a
future BitVec pass), branches degrade models to `PARTIAL`, and mapping slots
are modeled per concrete index observed in source.
