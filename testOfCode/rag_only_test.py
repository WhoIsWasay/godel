"""
testOfCode/rag_only_test.py
────────────────────────────
RAG-only test harness. Runs the full retrieval bridge
(domain.rag -> Infrastructure.postgres) over a battery of realistic
finding-like intents and reports Precision@K per query and as a mean.

Run:
    python testOfCode/rag_only_test.py

Requires: ParadeDB up on :5433, Ollama up with qwen3-embedding:8b.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.rag import run_rag_benchmark

# Realistic Isolator-finding shaped intents spanning multiple vuln classes.
TEST_FINDINGS = [
    # arithmetic / precision (lending pool: share-asset exchange rate)
    {
        "label": "lending_share_rate",
        "target_function": "withdraw",
        "intent": "Asset-to-share conversion rounds down using division before multiplication, "
                  "allowing a depositor with amount > 0 to burn 0 shares and extract assets. "
                  "Exchange rate scaling breaks when totalAssets is inflated relative to totalSupply.",
        "constraint": "assert(assets > 0 && totalSupply_old > 0 => sharesToBurn > 0)",
    },
    # reentrancy (CEI violation)
    {
        "label": "reentrancy_withdraw",
        "target_function": "withdraw",
        "intent": "External token transfer is executed before the user balance and total supply "
                  "state updates, allowing a reentrancy attack to drain the contract via repeated "
                  "withdraw calls before balances are deducted.",
        "constraint": "assert(balance_new == balance_old - amount)",
    },
    # access control
    {
        "label": "access_control_admin",
        "target_function": "setFee",
        "intent": "Critical administrative function is callable by any caller because the "
                  "onlyOwner modifier is missing, allowing an attacker to change protocol fees "
                  "and steal funds.",
        "constraint": "assert(msg.sender == owner)",
    },
    # oracle manipulation / flash loan
    {
        "label": "oracle_flash_loan",
        "target_function": "liquidate",
        "intent": "The function reads a spot oracle price once and uses it directly in the "
                  "collateral valuation with no staleness check, so a flash loan can manipulate "
                  "the price to force a healthy position to appear liquidatable.",
        "constraint": "assert(healthFactor_new >= 1e18)",
    },
    # state management / stale state
    {
        "label": "stale_reward_state",
        "target_function": "claimRewards",
        "intent": "Reward calculation uses the accumulated rate before the user's reward debt "
                  "is synced, allowing a user to claim the same rewards twice or receive "
                  "retroactive rewards from a default zero mapping.",
        "constraint": "assert(rewardPerToken_new == rewardPerToken_old + (timeDelta * rate) / totalSupply_old)",
    },
    # first-depositor share inflation
    {
        "label": "first_depositor_inflation",
        "target_function": "deposit",
        "intent": "The initial depositor combines a minimal asset deposit with a direct token "
                  "donation to inflate totalAssets while keeping shares minimal, causing all "
                  "subsequent depositors to receive zero shares and lose their assets.",
        "constraint": "assert(sharesToMint > 0 for amount > 0)",
    },
    # token accounting / unchecked return
    {
        "label": "unchecked_transfer_return",
        "target_function": "swap",
        "intent": "The ERC20 transfer return value is never checked, so a failed transfer "
                  "silently leaves balances unchanged while the contract continues execution "
                  "and emits a success event.",
        "constraint": "assert(transferSucceeded == true)",
    },
    # denial of service / unbounded loop
    {
        "label": "unbounded_loop_dos",
        "target_function": "claimAll",
        "intent": "An unbounded loop iterates over a dynamic array of user entries, causing "
                  "the function to exceed the block gas limit and making claims permanently "
                  "impossible (denial of service).",
        "constraint": "assert(gasUsed <= blockGasLimit)",
    },
    # proxy storage collision
    {
        "label": "proxy_storage_collision",
        "target_function": "initialize",
        "intent": "The implementation contract storage layout collides with the proxy's "
                  "EIP-1967 admin slot during delegatecall, allowing an attacker to overwrite "
                  "the owner slot and take control of the proxy.",
        "constraint": "assert(owner_slot unchanged)",
    },
    # front running / slippage
    {
        "label": "front_running_slippage",
        "target_function": "swap",
        "intent": "The swap function has no slippage protection or deadline, so an attacker can "
                  "sandwich the user's transaction and extract value via price manipulation "
                  "between the two legs of the AMM swap.",
        "constraint": "assert(priceImpact <= maxSlippage)",
    },
]


def main():
    print("\n" + "=" * 72)
    print("GÖDEL RAG-ONLY TEST HARNESS")
    print("=" * 72)
    print("NOTE: Precision@K uses the diagnostic relevance proxy (vuln_class match\n"
          "      or Jaccard word-overlap with the finding intent) — no human labels.\n")

    summary = run_rag_benchmark(TEST_FINDINGS, final_top_k=5, top_k_per_query=10)

    print("\nPER-QUERY BREAKDOWN:")
    print(f"  {'Label':<26} {'P@1':>6} {'P@3':>6} {'P@5':>6}  elapsed(s)")
    for row in summary["per_query"]:
        p = row["precisions"]
        print(f"  {row['label']:<26} {p[1]:>6.2f} {p[3]:>6.2f} {p[5]:>6.2f}  {row['elapsed']:>7.1f}")

    print("\n" + "=" * 72)
    print("AGGREGATE")
    print(f"  Mean P@1: {summary.get('mean_p@1'):.4f}")
    print(f"  Mean P@3: {summary.get('mean_p@3'):.4f}")
    print(f"  Mean P@5: {summary.get('mean_p@5'):.4f}")
    print(f"  Total elapsed: {summary.get('elapsed_total'):.1f}s")
    print("=" * 72)


if __name__ == "__main__":
    main()
