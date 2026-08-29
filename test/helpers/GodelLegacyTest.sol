// SPDX-License-Identifier: MIT
// Godel legacy verification harness.
//
// forge-std requires solc >= 0.8.13, so targets pinned below it (0.6.x /
// 0.7.x era contracts) cannot use forge-std-based PoC suites. This file is
// the drop-in replacement the verifier is instructed to import in legacy
// mode: a minimal cheatcode interface bound to Foundry's cheatcode address
// plus revert-based assertions. No imports, no forge-std dependency, compiles
// under pragma 0.6.0 through 0.8.x.
//
// Semantics match the modern harness: a FAILING test (revert) proves the
// vulnerability; a passing test means the property held.
pragma solidity >=0.6.0 <0.9.0;

interface GodelVm {
    function prank(address) external;
    function prank(address, address) external;
    function startPrank(address) external;
    function startPrank(address, address) external;
    function stopPrank() external;
    function deal(address who, uint256 newBalance) external;
    function warp(uint256) external;
    function roll(uint256) external;
    function fee(uint256) external;
    function label(address addr, string memory lbl) external;
    function expectRevert() external;
    function expectRevert(bytes4 revertData) external;
    function expectRevert(bytes memory revertData) external;
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData) external;
    function store(address target, bytes32 slot, bytes32 value) external;
    function load(address target, bytes32 slot) external returns (bytes32);
    function etch(address target, bytes memory newRuntimeBytecode) external;
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

contract GodelLegacyTest {
    address internal constant VM_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
    GodelVm internal constant vm = GodelVm(VM_ADDRESS);

    // dstest-style trace logging: forge prints these at -vv and above.
    event log(string);

    function fail(string memory reason) internal pure {
        revert(reason);
    }

    /* ---- booleans ---- */

    function assertTrue(bool condition) internal pure {
        require(condition, "GodelLegacyTest: expected true");
    }

    function assertTrue(bool condition, string memory reason) internal pure {
        require(condition, reason);
    }

    function assertFalse(bool condition) internal pure {
        require(!condition, "GodelLegacyTest: expected false");
    }

    function assertFalse(bool condition, string memory reason) internal pure {
        require(!condition, reason);
    }

    /* ---- equality ---- */

    function assertEq(uint256 a, uint256 b) internal pure {
        require(a == b, "GodelLegacyTest: assertEq(uint256) failed");
    }

    function assertEq(uint256 a, uint256 b, string memory reason) internal pure {
        require(a == b, reason);
    }

    function assertEq(int256 a, int256 b) internal pure {
        require(a == b, "GodelLegacyTest: assertEq(int256) failed");
    }

    function assertEq(address a, address b) internal pure {
        require(a == b, "GodelLegacyTest: assertEq(address) failed");
    }

    function assertEq(address a, address b, string memory reason) internal pure {
        require(a == b, reason);
    }

    function assertEq(bytes32 a, bytes32 b) internal pure {
        require(a == b, "GodelLegacyTest: assertEq(bytes32) failed");
    }

    function assertEq(bool a, bool b) internal pure {
        require(a == b, "GodelLegacyTest: assertEq(bool) failed");
    }

    function assertEq(string memory a, string memory b) internal pure {
        require(
            keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b)),
            "GodelLegacyTest: assertEq(string) failed"
        );
    }

    function assertEq(bytes memory a, bytes memory b) internal pure {
        require(
            keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b)),
            "GodelLegacyTest: assertEq(bytes) failed"
        );
    }

    function assertNotEq(bytes32 a, bytes32 b) internal pure {
        require(a != b, "GodelLegacyTest: assertNotEq failed");
    }

    /* ---- ordering (uint256) ---- */

    function assertGt(uint256 a, uint256 b) internal pure {
        require(a > b, "GodelLegacyTest: assertGt failed");
    }

    function assertGe(uint256 a, uint256 b) internal pure {
        require(a >= b, "GodelLegacyTest: assertGe failed");
    }

    function assertLt(uint256 a, uint256 b) internal pure {
        require(a < b, "GodelLegacyTest: assertLt failed");
    }

    function assertLe(uint256 a, uint256 b) internal pure {
        require(a <= b, "GodelLegacyTest: assertLe failed");
    }

    function assertLe(uint256 a, uint256 b, string memory reason) internal pure {
        require(a <= b, reason);
    }
}
