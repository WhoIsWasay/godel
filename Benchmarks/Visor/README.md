# Visor

Visor is a vault for isolated storage of staking tokens. The vault is owned
via ERC721 ownership (the holder of the NFT whose tokenId equals the vault's
address controls it).

Delegates (staking programs) may lock/unlock ERC20 balances inside the vault
only with EIP-712 permissions signed by the owner; the owner can rage-quit
any lock. The vault additionally supports:

- ERC20 / ETH withdrawal by owner, plus owner-approved delegated transfers
- ERC721 custody (tracked via `onERC721Received`) with owner-or-approved transfers
- Time-locked ERC20 and ERC721 deposits redeemable by the recipient after expiry

Solidity 0.7.6.
