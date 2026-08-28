// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

interface IProtocolYieldSource {
    function depositToken() external view returns (address);
    function balanceOfToken(address addr) external view returns (uint256);
    function supplyTokenTo(uint256 amount, address to) external;
    function redeemToken(uint256 amount) external returns (uint256);
    function sponsor(uint256 amount) external;
    function transferERC20(address erc20Token, address to, uint256 amount) external;
}
