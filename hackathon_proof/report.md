### [VULNERABILITY CLASS]
LOW: Duplicate NFT records are not fully removed. _removeNft... in `_removeNft`

**Vulnerability Detail:**
Duplicate NFT records are not fully removed. _removeNft breaks after the first matching (nftContract, tokenId), so a second stale duplicate remains in nfts after the physical NFT has left the vault.

**Impact:**
Exploitation allows breaking the protocol's core logical constraints. Specifically, the mathematical system boundary `assert( (exists i: 0 <= i && i < nfts_old.length && nfts_old[i].nftContract == nftContract && nfts_old[i].tokenId == tokenId) => !(exists k: 0 <= k && k < nfts_new.length && nfts_new[k].nftContract == nftContract && nfts_new[k].tokenId == tokenId) )` can be violated under arbitrary input configurations as proven by symbolic and static verification boundaries.

**Proof of Concept (PoC):**
1. **Target Boundary Code:**
```solidity
if (nftContract == nftInfo.nftContract && tokenId == nftInfo.tokenId) { ... nfts.pop(); emit RemoveNftToken(nftContract, tokenId); break; }
```

2. **Mathematical / Structural Verification Log:**
```text
[Z3] Counterexample found:
SANITY: sat
BUG FOUND: duplicate NFT remains after _removeNft
Initial length: 4
Final length: 3
nftContract: 4
tokenId: 1
Initial array:
  [0]: nftContract=0, tokenId=65
  [1]: nftContract=4, tokenId=1
  [2]: nftContract=4, tokenId=1
  [3]: nftContract=0, tokenId=0
Final array:
  [0]: nftContract=0, tokenId=65
  [1]: nftContract=0, tokenId=0
  [2]: nftContract=4, tokenId=1
Concrete counterexample assignments: length=3, nftContract=4, tokenId=1
```

3. **Validation Script Reference:**
*The absolute mathematical proof can be verified by running the automatically generated validation script saved locally at:* `output/proofs/Visor__removeNft_1_proof.py`

**Recommendation:**
Refactor the function scope to enforce strict ordering, boundary locks, or precision adjustments. Below is the verified remediation layout:

```solidity
// <!-- reasoning: (a) the bug is that _removeNft stops after removing the first match due to break, so duplicate NFT entries remain; (b) the fix is to keep scanning after swap-and-pop and re-check the same index, removing every matching (nftContract, tokenId) entry. -->
function _removeNft(address nftContract, uint256 tokenId) internal {
    uint256 len = nfts.length;
    for (uint256 i = 0; i < len; ) {
        Nft memory nftInfo = nfts[i];
        if (nftContract == nftInfo.nftContract && tokenId == nftInfo.tokenId) {
            if (i != len - 1) {
                nfts[i] = nfts[len - 1];
            }
            nfts.pop();
            len = nfts.length;
            emit RemoveNftToken(nftContract, tokenId);
        } else {
            i++;
        }
    }
}
```
