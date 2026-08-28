Protocol Purpose
The YearnV2YieldSource is a PoolTogether V3 yield source adapter that deposits underlying ERC20 tokens into a Yearn V2 Vault to generate yield. Users deposit assets and receive internal shares (ERC20Upgradeable) proportional to their contribution. The yield source handles deposit/withdrawal flows between the PoolTogether prize pool and the Yearn vault.

Core Invariants
Share/Asset Exchange Rate: Converting tokens to shares and back must preserve proportional value. The exchange rate is determined by the Yearn vault's pricePerShare. A user redeeming their full share balance must receive at least as many tokens as they originally deposited (minus accepted losses).

Withdrawal Correctness: The _withdrawFromVault function must return the actual amount of tokens received from the vault withdrawal. The computation must correctly measure the balance delta (tokens received = currentBalance - previousBalance, NOT previousBalance - currentBalance).

SafeApproval Correctness: When depositing into the vault, the token allowance must be correctly managed. If a prior partial deposit left a nonzero allowance, subsequent deposits must not revert due to safeApprove's nonzero-to-nonzero check.

Expected Function Behaviors
supplyTokenTo: Computes shares via _tokenToShares(), mints internal shares to the user, transfers tokens from the user, and deposits the full balance into the Yearn vault.

redeemToken: Computes shares to burn via _tokenToShares(), withdraws the requested amount from the Yearn vault via _withdrawFromVault(), burns internal shares, and transfers underlying tokens to the user. The _withdrawFromVault function must return the correct balance delta.

sponsor: Deposits tokens without minting shares, distributing value among existing shareholders.

_depositInVault: Deposits the contract's full token balance into the Yearn vault. Must handle the case where a prior partial deposit left a nonzero allowance.

_withdrawFromVault: Converts token amount to Yearn vault shares, withdraws from the vault, and returns the actual balance delta. The return value must equal currentBalance - previousBalance (the increase in token balance after withdrawal).

Out of Scope Assumptions
Oracle Risks: The Yearn vault's pricePerShare is treated as an honest external oracle.

Asset Specifics: The underlying token behaves as a standard ERC20. The Yearn vault is a standard v0.3.5+ vault.

Access Control: Owner role functions correctly.

Known Audit Findings (Code4rena June 2021)
H-02 (_withdrawFromVault): Computes previousBalance - currentBalance, but after vault.withdraw() the balance INCREASES (tokens received), so this subtraction underflows. All withdrawals revert; user funds permanently locked. CONFIRMED + PATCHED.

M-01 (_depositInVault): safeApprove() reverts when changing a nonzero allowance to another nonzero value. If a prior deposit was partial (vault cap reached), residual nonzero allowance blocks all future deposits. CONFIRMED + PATCHED.
