Protocol Purpose
The IdleYieldSource is a PoolTogether V3 yield source adapter that deposits underlying ERC20 tokens into the Idle Finance protocol to generate yield. Users deposit assets and receive internal shares proportional to their contribution. The yield source mints/burns internal ERC20 shares to track each user's claim on the pooled Idle tokens.

Core Invariants
Share/Asset Exchange Rate: Converting tokens to shares and shares to tokens must preserve value proportionally. The exchange rate is determined by the Idle token price (tokenPriceWithFee). Under normal conditions, redeeming shares must return at least as many underlying tokens as the share's proportional value.

Zero-Share Prevention: A user depositing a nonzero amount of tokens must always receive a nonzero number of shares. The share minting formula must never round to zero for positive deposits.

Redeem Correctness: When a user redeems, the amount passed to the Idle protocol's redeemIdleToken() must be denominated in Idle shares, not in underlying token amounts. The user must receive the correct proportional amount of underlying assets.

Expected Function Behaviors
supplyTokenTo: Accepts underlying tokens from the user, computes the equivalent Idle share amount via _tokenToShares(), deposits tokens into Idle Finance, and mints internal shares to the specified recipient address.

redeemToken: Accepts a redeem amount denominated in underlying tokens, converts it to Idle shares via _tokenToShares(), burns the corresponding internal shares from the user, redeems Idle shares from the Idle protocol, and transfers the underlying tokens back to the user. The parameter passed to redeemIdleToken() must be the share amount, not the token amount.

sponsor: Allows anyone to deposit tokens without receiving shares, distributing value proportionally among existing shareholders.

Out of Scope Assumptions
Oracle Risks: The Idle token price (tokenPriceWithFee) is treated as an honest external oracle. No validation of price manipulation is in scope.

Asset Specifics: The underlying token behaves as a standard, fully compliant ERC20 token with no fee-on-transfer, rebasing, or transfer hooks.

Access Control: Owner and asset manager roles function correctly; only the transferERC20 access control is in scope.

Known Audit Findings (Code4rena June 2021)
H-01 (redeemToken): Passes redeemedShare (Idle shares) instead of redeemAmount (underlying tokens) to redeemIdleToken(). Since tokenPriceWithFee > ONE_IDLE_TOKEN, shares < tokens, so users receive fewer underlying tokens than entitled. CONFIRMED + PATCHED.

H-05 (supplyTokenTo): Division (tokens * ONE_IDLE_TOKEN) / _price() can yield 0 when _price() > tokens * ONE_IDLE_TOKEN (common when totalUnderlyingAssets has accrued yield). Users deposit but receive 0 shares. CONFIRMED + PATCHED.
