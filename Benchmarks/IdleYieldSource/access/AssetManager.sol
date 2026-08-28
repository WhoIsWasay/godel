// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

abstract contract AssetManager is OwnableUpgradeable {
    address public assetManager;

    modifier onlyOwnerOrAssetManager() {
        require(msg.sender == owner() || msg.sender == assetManager, "AssetManager: caller is not owner or asset manager");
        _;
    }

    function setAssetManager(address _assetManager) external onlyOwner {
        assetManager = _assetManager;
    }
}
