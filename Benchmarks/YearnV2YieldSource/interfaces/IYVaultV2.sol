// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";

interface IYVaultV2 is IERC20Upgradeable {
    function token() external view returns (address);
    function deposit() external returns (uint256);
    function withdraw(uint256 maxShares) external returns (uint256);
    function withdraw(uint256 maxShares, address recipient, uint256 maxLoss) external returns (uint256);
    function pricePerShare() external view returns (uint256);
    function decimals() external view returns (uint256);
    function apiVersion() external view returns (string memory);
    function activation() external view returns (uint256);
}
