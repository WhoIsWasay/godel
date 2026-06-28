// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RugToken {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        balances[to] += amount;
        totalSupply += amount;
    }

    function drain(address to) external {
        require(msg.sender == owner, "Not owner");
        uint256 amount = balances[address(this)];
        balances[address(this)] = 0;
        balances[to] += amount;
    }
}