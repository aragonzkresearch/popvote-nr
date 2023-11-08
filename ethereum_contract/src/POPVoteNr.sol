// SPDX-License-Identifier: GNU GPLv3
pragma solidity ^0.8.13;
import {IRegistry} from "@aztec/core/interfaces/messagebridge/IRegistry.sol";
import {IInbox} from "@aztec/core/interfaces/messagebridge/IInbox.sol";
import {DataStructures} from "@aztec/core/libraries/DataStructures.sol";
import {Hash} from "@aztec/core/libraries/Hash.sol";
import "./NFT.sol";
import "./ZKRegistry.sol";

contract POPVoteNr
{

    IRegistry public registry;
    bytes32 public l2_popvote_address;

    ZKRegistry public zk_registry;
    NFT public nft_contract;

    bool initialised_p = false;

    event process_creation(bytes32 key, uint256 indexed process_id);
    struct VotingProcess
    {
	/// IPFS CID of vote proposal
	bytes32 ipfs_hash;
	/// The block number at which the census is taken
	uint64 census_block;
	/// The time at which the voting process begins
	uint64 start_time;
	/// The hash of the census block
        bytes32 block_hash;
        /// Duration of voting process
        uint64 duration;
	/* /// ZK Registry contract storage root at census block */
	/* bytes32 zk_registry_storage_root; */
	/* /// Nouns token contract storage root at census block */
	/* bytes32 nft_contract_storage_root; */
	/// TLCS round number
	uint64 tlcs_round_number;
        /// TLCS public key used to encrypt the votes for later decryption
        uint256[2] tlcs_public_key;
	/// Tally indicator
	bool tallied_p;
	/// Results of the vote
        uint256[3] results;
    }
	
    mapping(uint256 => VotingProcess) public voting_process;
    
    uint256 num_processes = 0;

    // Contract constructor
    constructor(NFT _nft_contract, ZKRegistry _zk_registry)
	{
	    nft_contract = _nft_contract;
	    zk_registry = _zk_registry;
	}

    // Initialiser for L2 addresses
    function initialise(IRegistry _registry, bytes32 _l2_popvote_address) public
    {
	require(!initialised_p, "Contract has already been initialised.");
	registry = _registry;
	l2_popvote_address = _l2_popvote_address;

	initialised_p = true;
    }

    function hash_process(uint256 process_id, VotingProcess memory vp) public pure returns (bytes32)
    {
	// Hash the data
	bytes memory content = abi.encodePacked(process_id, vp.ipfs_hash, vp.start_time, vp.census_block, vp.block_hash, vp.duration, vp.tlcs_round_number, vp.tlcs_public_key);
	return Hash.sha256ToField(content);	
    }

    function hash_results(uint256 process_id, VotingProcess memory vp, uint256 num_voters, uint256[3] calldata results) public pure returns (bytes32)
    {
	bytes memory content = abi.encodePacked(hash_process(process_id, vp), num_voters, results);
	return Hash.sha256ToField(content);
    }
    
    function submit_process(bytes32 ipfs_hash, uint64 census_block, uint64 start_time, uint64 duration, uint64 tlcs_round_number, uint256[2] calldata tlcs_public_key, bytes32 secret_hash, uint32 deadline) external payable returns (bytes32)
    {
	// Sanity checks
	require(start_time >= block.timestamp, "Voting time cannot start in the past.");
	require(block.number - census_block < 256, "The census block cannot be more than 256 blocks in the past.");

	// Set up inbox
	IInbox inbox = registry.getInbox();
	DataStructures.L2Actor memory actor = DataStructures.L2Actor(l2_popvote_address, 1);

	// Hash the data
	VotingProcess memory vp = VotingProcess({
	    ipfs_hash: ipfs_hash,
	    census_block: uint64(census_block),
	    start_time: start_time,
	    block_hash: blockhash(census_block),
	    duration: duration,
	    tlcs_round_number: tlcs_round_number,
	    tlcs_public_key: tlcs_public_key,
	    tallied_p: false,
	    results: [uint256(0),uint256(0),uint256(0)]
	    });

	bytes32 content_hash = hash_process(num_processes, vp);

	// Send data to L2
	bytes32 key = inbox.sendL2Message(actor, deadline, content_hash, secret_hash);

	// Save data here
	voting_process[num_processes] = vp;

	// Fish the process number out of the event log
	emit process_creation(key, num_processes);

	// Increment number of processes
	num_processes++;
	
	return key;
    }

    function publish_results(uint256 process_id, uint256 num_voters, uint256[3] calldata results) external returns (bytes32)
    {

	require(!voting_process[process_id].tallied_p, "The results have already been published.");
	
	// Compute result hash
	bytes32 content_hash = hash_results(process_id, voting_process[process_id], num_voters, results);

	// Consume message passed from L2
	DataStructures.L2ToL1Msg memory message = DataStructures.L2ToL1Msg({
	    sender: DataStructures.L2Actor(l2_popvote_address, 1),
	    recipient: DataStructures.L1Actor(address(this), block.chainid),
	    content: content_hash
	    });

	bytes32 entry_key = registry.getOutbox().consume(message);

	// Store results
	voting_process[process_id].results = results;
	voting_process[process_id].tallied_p = true;

	return entry_key;
    }

    function view_results(uint256 process_id) public view returns (uint256[3] memory)
    {
	return voting_process[process_id].results;
    }
    
}
