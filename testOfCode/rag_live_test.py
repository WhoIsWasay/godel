"""Live RAG quality test: 4 realistic findings through the full stack."""
import sys
sys.path.insert(0, ".")
from domain.rag import retrieve_findings_for_specifier

FINDINGS = [
    {"label": "CDP borrow fee precision",
     "target_function": "borrow(uint256)",
     "intent": "Origination fee computed as (amount / 10000) * 50 suffers division-before-multiplication "
               "precision collapse; small borrow amounts produce zero fee and rounding leaks value.",
     "constraint": "fee rounds to zero for amount < 200",
     "relevant_code": "uint256 originationFee = (borrowAmount / 10000) * 50;"},
    {"label": "vault deposit reentrancy",
     "target_function": "depositCollateral(uint256)",
     "intent": "External token transfer before state update allows reentrant callback to "
               "deposit again with stale shares accounting, inflating vaultShares.",
     "constraint": "state updated after external call violates CEI",
     "relevant_code": "require(collateralToken.transferFrom(msg.sender, address(this), amount));"},
    {"label": "oracle price manipulation",
     "target_function": "redeem(uint256)",
     "intent": "Spot price read from AMM pool enables flash-loan oracle manipulation; "
               "attacker skews reserve ratio then redeems at inflated valuation.",
     "constraint": "no TWAP or chainlink fallback",
     "relevant_code": "uint256 price = getReserves()[0] * 1e18 / getReserves()[1];"},
    {"label": "access control gap",
     "target_function": "setFee(uint256)",
     "intent": "Admin setter lacks onlyOwner modifier so any caller can raise fees to 100% "
               "and drain users through privileged parameter update.",
     "constraint": "missing access control on critical setter",
     "relevant_code": "function setFee(uint256 f) external { fee = f; }"},
]

print("=" * 78)
for f in FINDINGS:
    formatted, diag = retrieve_findings_for_specifier(f, final_top_k=5)
    prec = diag.get("precisions", {})
    print(f"\n### {f['label']}")
    print(f"  elapsed={diag.get('elapsed')}s  n={diag.get('n_retrieved')}  "
          f"P@1={prec.get(1, {}).get('p_at_k')}  P@3={prec.get(3, {}).get('p_at_k')}  "
          f"P@5={prec.get(5, {}).get('p_at_k')}")
    for i, r in enumerate(formatted[:3], 1):
        title = (r['title_normalized'] or '')[:70]
        print(f"   {i}. [{r.get('vuln_class','?')}/{r.get('severity','?')}] "
              f"rerank={r.get('rerank_score') if r.get('rerank_score') is not None else '—'} {title}")
print("\nDONE")
