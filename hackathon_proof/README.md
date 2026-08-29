# Gödel Live Audit Proof — Visor.sol (Code4rena benchmark)

**Date:** 2026-08-29 · **Model:** deepseek-v4-flash (thinking enabled) · **Run:** targeted live audit, no ground-truth leakage

## The confirmed finding

**[LOW] `Visor::_removeNft` — duplicate NFT records are not fully removed.**

`_removeNft` scans the `nfts[]` array, removes the FIRST entry matching
`(nftContract, tokenId)` via swap-and-pop, then `break`s. If the same
`(nftContract, tokenId)` pair was deposited twice, the second stale record
survives after the physical NFT has left the vault — the bookkeeping array
disagrees with actual holdings, breaking downstream lookups/withdrawals.

```solidity
if (nftContract == nftInfo.nftContract && tokenId == nftInfo.tokenId) {
    ... nfts.pop(); emit RemoveNftToken(nftContract, tokenId); break;  // <-- stops at first match
}
```

This is the same NFT-record-management vulnerability family as Code4rena
Visor findings H-02/H-03 — discovered by Gödel end-to-end without being
told what to look for.

## Verification chain (fully automated by the pipeline)

1. **Bug Hunter (LLM + RAG)** proposed the finding for `_removeNft`.
2. **Supervisor** approved it for formal analysis.
3. **Specifier** translated it to a Z3 state-transition property:
   "if `(nftContract, tokenId)` existed before the call, it must not exist after."
4. **Executor (Z3)** returned **SAT** with a concrete counterexample
   (`length=4`, duplicate `(0x4, 1)` records, one survives removal).
5. **Gatekeeper** generated a Foundry PoC, compiled it with the legacy
   forge-std-free harness on **solc 0.7.6** (Visor's pinned compiler), and
   the invariant test FAILED against the real contract — defect active.
6. **Fixer** produced the remediation (see `report.md`).

## Files

| File | What it is |
|---|---|
| `report.md` | Full audit report: detail, impact, PoC, fix |
| `proof.py` | The Z3 property script the pipeline generated |
| `PoC.t.sol` | The Foundry PoC the pipeline generated (legacy harness, solc 0.7.6) |
| `finding.json` | Machine-readable artifact incl. Z3 trace + forge JSON output |
| `isolated_slice.sol` | Deterministic function slice fed to the hunter |
| `z3_independent_rerun.txt` | Re-running `proof.py` after the audit: `BUG FOUND` |
| `forge_independent_rerun.txt` | Re-running the PoC against real Visor.sol: test FAILS (invariant broken) |

## Reproduce it yourself (zero LLM credits)

```bash
# 1. Z3 proof
python hackathon_proof/proof.py
# -> SANITY: sat
# -> BUG FOUND: duplicate NFT remains after _removeNft

# 2. Foundry PoC (needs the real Benchmarks/Visor/Visor.sol as src/Visor.sol
#    plus test/helpers/GodelLegacyTest.sol in a forge project, solc 0.7.6)
forge test --match-path test/PoC.t.sol
# -> [FAIL: EvmError: Revert] test_removeNft_invariant()
```

The PoC fails exactly because the safe invariant is violated: after
`transferERC721` moves the NFT out, `getNftIdByTokenIdAndAddr(0x4, 1)`
still resolves the stale duplicate instead of reverting `"Token not found"`.
