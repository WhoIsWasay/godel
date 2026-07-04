from domain.extractor import OutputExtractor

# 1. Test Z3 Variable Slicing
z3_mock_trace = """
BUG FOUND:
[Z3] Counterexample found! 
Model dimensions:
  amount = 13
  interestRate = 8
  totalShares -> 1
  totalAssets = 2
"""
z3_vars = OutputExtractor.parse_z3_counterexample(z3_mock_trace)
print("--- Z3 Parsed Variables ---")
print(z3_vars)  # Expected: {'amount': 13, 'interestRate': 8, 'totalShares': 1, 'totalAssets': 2}

# 2. Test Slither Parsing
slither_mock_json = """
{
  "success": true,
  "results": {
    "detectors": [
      {
        "check": "reentrancy-eth",
        "impact": "High",
        "description": "Reentrancy in LendingPool.withdraw(uint256) causes state changes after external call",
        "first_markdown_element": "lendingPool.sol#L27-L35"
      }
    ]
  }
}
"""
slither_facts = OutputExtractor.parse_slither_json(slither_mock_json, "withdraw")
print("\n--- Slither Parsed Facts ---")
print(slither_facts)