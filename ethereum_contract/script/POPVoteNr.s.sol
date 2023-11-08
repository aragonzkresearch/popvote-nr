// SPDX-License-Identifier: GPLv3
pragma solidity ^0.8.13;

import {IRegistry} from "@aztec/core/interfaces/messagebridge/IRegistry.sol";
import "forge-std/Script.sol";
import "../src/POPVoteNr.sol";

contract POPVoteNrScript is Script {
    function setUp() public {}

    function run() external {
	uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
	
	vm.startBroadcast(deployerPrivateKey);

	NFT nft = new NFT("NFTest", "NFT");
	ZKRegistry zk_registry = new ZKRegistry();
	POPVoteNr popvote_nr = new POPVoteNr(nft, zk_registry);
	

	vm.stopBroadcast();

	console.log("NFT contract address: %s", address(nft));
	console.log("ZKRegistry contract address: %s", address(zk_registry));
	console.log("POPVoteNr contract address: %s", address(popvote_nr));
    }
}

contract POPVoteNrInitScript is Script {
    function setUp() public {}

    function run() external {
	uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
	
	vm.startBroadcast(deployerPrivateKey);

	address popvote_address = vm.envAddress("PORTAL_ADDRESS");
	bytes32 l2_contract_address = vm.envBytes32("L2_CONTRACT_ADDRESS");
	address registry_address = vm.envAddress("REGISTRY_ADDRESS");

	IRegistry registry = IRegistry(registry_address);

	POPVoteNr popvote_nr = POPVoteNr(popvote_address);

	popvote_nr.initialise(registry, l2_contract_address);

	vm.stopBroadcast();

    }
}
