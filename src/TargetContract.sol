// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IOracle {
    function getPrice() external view returns (uint256);
}

contract LendingPool {
    address public owner;
    IOracle public oracle;
    
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public shares;
    
    uint256 public totalShares;
    uint256 public totalAssets;
    uint256 public interestRate;
    
    constructor(address _oracle) {
        owner = msg.sender;
        oracle = IOracle(_oracle);
        interestRate = 5;
    }

    // VULNERABILITY 1: Reentrancy — state updated after external call
    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "Insufficient shares");
        uint256 assets = (amount * totalAssets) / totalShares;
        (bool success,) = msg.sender.call{value: assets}("");
        require(success);
        shares[msg.sender] -= amount;
        totalShares -= amount;
        totalAssets -= assets;
    }

    // VULNERABILITY 2: Oracle manipulation — price used directly for liquidation
    function liquidate(address user) external {
        uint256 price = oracle.getPrice();
        uint256 collateralValue = collateral[user] * price;
        require(collateralValue < debt[user], "Not liquidatable");
        collateral[user] = 0;
        debt[user] = 0;
    }

    // VULNERABILITY 3: Integer precision loss — division before multiplication
    function calculateInterest(uint256 amount) public view returns (uint256) {
        return amount / 100 * interestRate;
    }

    // VULNERABILITY 4: Access control — anyone can set interest rate
    function setInterestRate(uint256 rate) external {
        interestRate = rate;
    }

    // VULNERABILITY 5: Share inflation — first depositor can manipulate ratio
    function deposit(uint256 amount) external payable {
        uint256 sharesToMint;
        if (totalShares == 0) {
            sharesToMint = amount;
        } else {
            sharesToMint = (amount * totalShares) / totalAssets;
        }
        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;
        totalAssets += amount;
    }

    function setOwner(address newOwner) external {
        require(msg.sender == owner);
        owner = newOwner;
    }
}