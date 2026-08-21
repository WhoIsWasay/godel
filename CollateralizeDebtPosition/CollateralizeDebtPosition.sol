// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract StablecoinCDP {
    IERC20 public immutable collateralToken;
    IERC20 public immutable stablecoin;

    uint256 public totalCollateral;
    uint256 public totalSupply; 

    mapping(address => uint256) public vaultShares;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public lastInterestTime;

    uint256 public constant INTEREST_RATE_PER_SEC = 1585489599; 

    event Deposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount, uint256 fee);
    event Repaid(address indexed user, uint256 amount, uint256 interest);
    event Redeemed(address indexed user, uint256 collateralAmount, uint256 sharesBurned);

    constructor(address _collateralToken, address _stablecoin) {
        require(_collateralToken != address(0) && _stablecoin != address(0), "Invalid tokens");
        collateralToken = IERC20(_collateralToken);
        stablecoin = IERC20(_stablecoin);
    }

    function depositCollateral(uint256 amount) external {
        require(amount > 0, "Cannot deposit 0");

        unchecked {
            uint256 newTotal = totalCollateral + amount;
            require(newTotal >= totalCollateral, "Global overflow");
            totalCollateral = newTotal;

            uint256 newBalance = vaultShares[msg.sender] + amount;
            require(newBalance >= vaultShares[msg.sender], "Local overflow");
            vaultShares[msg.sender] = newBalance;
            totalSupply += amount;
        }

        require(collateralToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        emit Deposited(msg.sender, amount);
    }

    function borrow(uint256 borrowAmount) external {
        require(borrowAmount > 0, "Cannot borrow 0");
        require(vaultShares[msg.sender] > 0, "No collateral");

        uint256 originationFee = (borrowAmount / 10000) * 50; 
        
        debt[msg.sender] += (borrowAmount + originationFee);
        
        if (lastInterestTime[msg.sender] == 0) {
            lastInterestTime[msg.sender] = block.timestamp;
        }

        require(stablecoin.transfer(msg.sender, borrowAmount), "Transfer failed");
        emit Borrowed(msg.sender, borrowAmount, originationFee);
    }

    function repay(uint256 repayAmount) external {
        require(repayAmount > 0, "Cannot repay 0");
        require(debt[msg.sender] >= repayAmount, "Repaying more than owed");

        uint256 timeElapsed = block.timestamp - lastInterestTime[msg.sender];
        
        debt[msg.sender] -= repayAmount;
        
        uint256 interest = (debt[msg.sender] * timeElapsed * INTEREST_RATE_PER_SEC) / 1e18;
        
        lastInterestTime[msg.sender] = block.timestamp;

        require(stablecoin.transferFrom(msg.sender, address(this), repayAmount + interest), "Transfer failed");
        emit Repaid(msg.sender, repayAmount, interest);
    }

    function redeemExactCollateral(uint256 collateralRequested) external {
        require(collateralRequested > 0, "Cannot redeem 0");
        require(totalCollateral >= collateralRequested, "Insufficient pool collateral");
        require(debt[msg.sender] == 0, "Must clear debt first");

        uint256 sharesToBurn = (collateralRequested * totalSupply) / totalCollateral;
        
        require(vaultShares[msg.sender] >= sharesToBurn, "Insufficient shares");

        vaultShares[msg.sender] -= sharesToBurn;
        totalSupply -= sharesToBurn;
        totalCollateral -= collateralRequested;

        require(collateralToken.transfer(msg.sender, collateralRequested), "Transfer failed");
        emit Redeemed(msg.sender, collateralRequested, sharesToBurn);
    }
}