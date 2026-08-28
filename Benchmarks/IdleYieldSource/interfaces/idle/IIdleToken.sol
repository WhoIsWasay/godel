// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";

interface IIdleToken is IERC20Upgradeable {
    function token() external view returns (address);
    function tokenPriceWithFee(address user) external view returns (uint256);
    function mintIdleToken(uint256 amount, bool skipWholeAmount, address referral) external returns (uint256);
    function redeemIdleToken(uint256 amount) external returns (uint256);
}
