// SPDX-License-Identifier: GPLv3
pragma solidity ^0.8.13;

import "solmate/tokens/ERC721.sol";

// A barren NFT contract
contract NFT is ERC721
{

    constructor(string memory _name, string memory _symbol) ERC721(_name, _symbol) {}

    function tokenURI(uint256 id) override public view virtual returns (string memory)
    {
	return "";
    }

    // Free NFTs for all
    function mint(address to, uint256 id) public
    {
	_mint(to, id);
    }
}
