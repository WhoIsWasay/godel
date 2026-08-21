# StablecoinCDP Specification

## Protocol Purpose
The `StablecoinCDP` contract is a decentralized lending module. Users deposit a collateral token in exchange for vault shares, allowing them to borrow a stablecoin. Borrowing incurs a flat origination fee and continuous time-weighted interest. Users must repay their debt with interest before redeeming their shares for the underlying collateral.

## Core Invariants
A formal verification tool must mathematically verify the following invariants within the isolated scope of their respective functions:

1. **Fee Proportionality Invariant:** In `borrow`, the `originationFee` added to the user's debt must exactly equal `0.5%` (or 50 basis points) of the `borrowAmount` for any valid input, without truncation nullifying the fee.
2. **Interest Accrual Fidelity:** In `repay`, the `interest` charged must be mathematically derived from the *pre-repayment* principal debt balance over the elapsed time, ensuring users pay for the capital they held during that period.
3. **Anti-Arbitrage / Value Conservation:** In `redeemExactCollateral`, a user extracting a non-zero amount of `collateralRequested` must always burn a mathematically non-zero amount of `sharesToBurn`. `collateralRequested > 0 \implies sharesToBurn > 0`.
4. **Deposit Overflow Safety:** In `depositCollateral`, the global and local balance additions must never overflow the `uint256` maximum limit.

## Expected Function Behaviors
- `depositCollateral`: Safely increases user shares and total collateral tracking.
- `borrow`: Calculates a 0.5% fee, adds it to the principal debt, and initializes the interest timer.
- `repay`: Subtracts the repaid principal and calculates time-weighted interest owed.
- `redeemExactCollateral`: Translates a requested collateral amount into the required shares to burn, deducting them from the user and the global state.

## Out of Scope Assumptions
- External ERC20 token behavior is out of scope.
- Pricing oracle mechanics (collateralization ratios are intentionally abstracted away to focus purely on the vault arithmetic).
