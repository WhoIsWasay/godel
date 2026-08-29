// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.7.6;
pragma abicoder v2;

import "test/helpers/GodelLegacyTest.sol";
import "src/Visor_0545d3.sol";

// reasoning: We exercise the internal Visor._removeNft() path through the public
// transferERC721() entrypoint. The property under test is that after removing an
// NFT record for (nftContract=0x4, tokenId=1), no record with that exact pair
// remains in the nfts[] array. The solver trace gives length=3, nftContract=4,
// tokenId=1; we seed three NFT records, two of which are duplicates of
// (0x4,1). _removeNft() only deletes the first match and leaves the duplicate
// behind, so a subsequent lookup for (0x4,1) succeeds instead of reverting,
// failing the safe-invariant assertion.

contract PropertyTest is GodelLegacyTest {
    Visor private visor;
    address private constant NFT = address(uint160(0x4));

    // Visor.initialize() sets its NFT controller address to msg.sender. Since this
    // test deploys and initializes Visor, the controller is this test contract.
    // Implementing ownerOf here lets Visor.owner() resolve to this contract.
    function ownerOf(uint256) external view returns (address) {
        return address(this);
    }

    function setUp() public {
        visor = new Visor();
        visor.initialize();
    }

    function test_removeNft_invariant() public {
        // Build nfts[] with length=3:
        //   index 0: (0x4, 1)
        //   index 1: (0x4, 1)  <-- duplicate
        //   index 2: (0x4, 2)
        vm.prank(NFT);
        visor.onERC721Received(NFT, address(this), 1, "");
        vm.prank(NFT);
        visor.onERC721Received(NFT, address(this), 1, "");
        vm.prank(NFT);
        visor.onERC721Received(NFT, address(this), 2, "");

        // Confirm the solver counterexample precondition: exactly three records.
        visor.getNftById(2);
        vm.expectRevert(bytes("ID overflow"));
        visor.getNftById(3);

        // Calls _removeNft(0x4, 1) internally. The duplicate entry survives.
        visor.transferERC721(address(uint160(0xBEEF)), NFT, 1);

        // Safe invariant: after removal, no (0x4, 1) record may remain.
        // A correct implementation must revert with "Token not found".
        vm.expectRevert(bytes("Token not found"));
        visor.getNftIdByTokenIdAndAddr(NFT, 1);
    }
}