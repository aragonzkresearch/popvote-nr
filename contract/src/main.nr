// TODO: Add serialisation methods to types such as TrieProof.
mod aux;
mod consts;
mod types;
mod hash_proof;
mod voter_proof;

contract POPVote
{
    // Aztec dependencies
    use dep::aztec::{
        context::{PrivateContext, PublicContext, Context},
        hash::sha256_to_field,
        state_vars::{map::Map, public_state::PublicState},
        types::type_serialization::{
            field_serialization::{FieldSerializationMethods, FIELD_SERIALIZED_LEN},
            bool_serialization::{BoolSerializationMethods, BOOL_SERIALIZED_LEN},
        },
        selector::compute_selector,
    };

    // stdlib dependencies
    use dep::std::ec::tecurve::affine::Point;
    use dep::std::ec::consts::te::baby_jubjub;
    
    // Trie proof dependency
    use dep::noir_trie_proofs::TrieProof;

    // Crate dependencies
    use crate::aux::{hash_process_content, hash_results};
    use crate::consts::{DEPTH8_PROOF_SIZE, MAX_BLOCK_HEADER_SIZE, MAX_PROOF_SIZE, MAX_ACCOUNT_STATE_SIZE};
    use crate::hash_proof::check_storage_against_block;
    use crate::types::ballot::{Ballot, BALLOT_SERIALIZED_LEN, BallotSerializationMethods};
    use crate::types::outcome::{Outcome, OUTCOME_SERIALIZED_LEN, OutcomeSerializationMethods};
    use crate::types::voting_process::{VotingProcess, VOTING_PROCESS_SERIALIZED_LEN, VotingProcessSerializationMethods, fields_to_b32, b32_to_fields};
    use crate::voter_proof::{Signature, verify_vote, VoteProverInput};

    struct Storage
    {
        /// Addresses of L1 NFT and registry contracts:
        nft_contract_address: PublicState<Field, FIELD_SERIALIZED_LEN>,
        zk_registry_address: PublicState<Field, FIELD_SERIALIZED_LEN>,
        /// Voting processes including specifiers, total number of voters and results
        voting_process: Map<PublicState<VotingProcess, VOTING_PROCESS_SERIALIZED_LEN>>,
        /// Nullifiers
        nullifier: Map<PublicState<bool, BOOL_SERIALIZED_LEN>>,
        /// Ballots
        vote: Map<Map<PublicState<Ballot, BALLOT_SERIALIZED_LEN>>>,
        /// Number of voters
        num_voters: Map<PublicState<Field, FIELD_SERIALIZED_LEN>>,
        /// Results
        outcome: Map<PublicState<Outcome, OUTCOME_SERIALIZED_LEN>>
    }

    impl Storage
    {
        fn init(context: Context) -> Self
        {
            Storage
            {
                nft_contract_address: PublicState::new(context, 1, FieldSerializationMethods),
                zk_registry_address: PublicState::new(context, 2, FieldSerializationMethods),
                voting_process: Map::new(
                    context,
                    3,
                    |context, slot| { PublicState::new(context, slot, VotingProcessSerializationMethods) }
                ),
                nullifier: Map::new(
                    context,
                    4,
                    |context, slot| { PublicState::new(context, slot, BoolSerializationMethods) }
                ),
                vote: Map::new(
                    context,
                    5,
                    |context, slot|
                    {
                        Map::new(context, slot, |c, s|
                                 {
                                     PublicState::new(c, s, BallotSerializationMethods)
                                 }
                        )
                    }
                ),
                num_voters: Map::new(context, 6, |c,s|
                                     {
                                         PublicState::new(c, s, FieldSerializationMethods)
                                     }),
                outcome: Map::new(context, 7, |c,s|
                                  {
                                      PublicState::new(c, s, OutcomeSerializationMethods)
                                  })

            }
        }
    }

    #[aztec(public)]
    internal fn _initialise(nft_contract_address: Field, zk_registry_address: Field)
    {
        storage.nft_contract_address.write(nft_contract_address);
        storage.zk_registry_address.write(zk_registry_address);
    }
    
    #[aztec(private)]
    fn constructor(nft_contract_address: Field, zk_registry_address: Field)
    {
        let selector = compute_selector("_initialise(Field,Field)");
        context.call_public_function(context.this_address(), selector, [nft_contract_address, zk_registry_address]);        
    }

    /// Function checking whether voting process is ongoing
    #[aztec(public)]
    internal fn _voting_period_check(process_id: Field)
    {
        let vp = storage.voting_process.at(process_id).read();

        assert(vp.start_time + vp.duration < context.timestamp() as u64, "The voting period is over.");
    }

    #[aztec(public)]
    internal fn _voter_parameter_check(process_id: Field, nft0: Field, nft1: Field, zk0: Field, zk1: Field, tlcs_pk_x: Field, tlcs_pk_y: Field)
    {
        let vp = storage.voting_process.at(process_id).read();
        let nft_contract_storage_root = fields_to_b32([nft0, nft1]);
        let zk_registry_storage_root = fields_to_b32([zk0, zk1]);

        // Check storage roots
        for i in 0..32
        {
            assert(nft_contract_storage_root[i] == vp.nft_contract_storage_root[i]);
            assert(zk_registry_storage_root[i] == vp.zk_registry_storage_root[i]);
        }

        // Check TLCS public key
        assert(Point::new(tlcs_pk_x, tlcs_pk_y).eq(vp.tlcs_pk));
    }
    

    /// Function checking whether it is time to tally
    #[aztec(public)]
    internal fn _tally_check(process_id: Field)
    {
        let vp = storage.voting_process.at(process_id).read();

        assert(vp.start_time + vp.duration >= context.timestamp() as u64, "The voting period is not over.");
    }

    
    #[aztec(public)]
    internal fn _commit_nullifier_and_vote(process_id: Field, n: Field, a_x: Field, a_y: Field, b: Field)
    {
        // Commit nullifier
        storage.nullifier.at(n).write(true);

        // Commit vote
        let voter_number = storage.num_voters.at(process_id).read();
        storage.vote.at(process_id).at(voter_number).write(
            Ballot { a: Point::new(a_x, a_y), b }
        );

        // Increment number of voters
        storage.num_voters.at(process_id).write(voter_number + 1);
    }
    
    #[aztec(public)]
    fn create_process(
        // Data passed up from L1
        process_id: Field,
        ipfs_hash: [u8; 32],
        start_time: u64,
        census_block: u64,
        block_hash: [u8; 32],
        duration: u64,
        tlcs_round_number: u64,
        tlcs_pk: [Field; 2],
        // Data for state proof
        block_header: [u8; MAX_BLOCK_HEADER_SIZE],
        zk_registry_state_proof_key: [u8; 20],
        zk_registry_state_proof_path: [u8; MAX_PROOF_SIZE],
        zk_registry_state_proof_depth: Field,
        zk_registry_state_proof_value: [u8; MAX_ACCOUNT_STATE_SIZE],
        zk_registry_storage_root: [u8; 32],
        nft_state_proof_key: [u8; 20],
        nft_state_proof_path: [u8; MAX_PROOF_SIZE],
        nft_state_proof_depth: Field,
        nft_state_proof_value: [u8; MAX_ACCOUNT_STATE_SIZE],
        nft_contract_storage_root: [u8; 32],
        // Data for message passing
        msg_key: Field,
        secret: Field
    )
    {
        // Compute content hash
        let content_hash = hash_process_content(process_id, ipfs_hash, start_time, census_block, block_hash, duration, tlcs_round_number, tlcs_pk);

        // Consume L1 message
        context.consume_l1_to_l2_message(msg_key, content_hash, secret);

        // Check storage roots
        let zk_registry_state_proof = TrieProof
        {
            key: zk_registry_state_proof_key,
            proof: zk_registry_state_proof_path,
            depth: zk_registry_state_proof_depth,
            value: zk_registry_state_proof_value
        };

        let nft_state_proof = TrieProof
        {
            key: nft_state_proof_key,
            proof: nft_state_proof_path,
            depth: nft_state_proof_depth,
            value: nft_state_proof_value
        };

        // Read addresses from storage
        let zk_registry_address = storage.zk_registry_address.read();
        let nft_contract_address = storage.nft_contract_address.read();
        
        check_storage_against_block(
            block_hash, census_block, block_header,
            zk_registry_address,
            zk_registry_state_proof,
            zk_registry_storage_root,
            nft_contract_address,
            nft_state_proof,
            nft_contract_storage_root);

        // Commit data to storage
        storage.voting_process.at(process_id).write(
            VotingProcess
            {
                ipfs_hash, census_block, start_time,
                block_hash, duration, zk_registry_storage_root,
                nft_contract_storage_root, tlcs_round_number,
                tlcs_pk: Point { x: tlcs_pk[0], y: tlcs_pk[1] },
            }
        );
    }

    /// Vote submission
    #[aztec(private)]
    fn submit_vote(
        a: [Field; 2],
        b: Field, // Hash of k,v,id
        n: Field,
        process_id: Field,
        registry_storage_root: [u8; 32], // Storage hash of zkRegistry contract
        nft_storage_root: [u8; 32], // Storage hash of NFT contract
        tlcs_pk: [Field; 2],
        
        v: Field, // in {0,1,2}
        blinding_factor: Field,
        signed_id_r: [Field; 2],
        signed_id_s : Field,
        voter_address: Field,
        signed_v_r: [Field; 2],
        signed_v_s: Field,
        nft_id: [Field; 2],
        h_id: Field,
        k: [Field; 2],
        registered_pbk: [Field; 2],
        zk_registry_key_proof_key: [u8; 32],
        zk_registry_key_proof_path: [u8; DEPTH8_PROOF_SIZE],
        zk_registry_key_proof_depth: Field,
        zk_registry_key_proof_value: [u8; 32],
        nft_ownership_proof_key: [u8; 32],
        nft_ownership_proof_path: [u8; DEPTH8_PROOF_SIZE],
        nft_ownership_proof_depth: Field,
        nft_ownership_proof_value: [u8; 32],
    )
    {
        // Check whether we are still in the voting period
        let selector = compute_selector("_voting_period_check(Field)");
        let is_ongoing = context.call_public_function(context.this_address(), selector, [process_id]);
        
        let signed_id = Signature
        {
            r_b8: Point
            {
                x: signed_id_r[0],
                y: signed_id_r[1]
            },
            s: signed_id_s
        };
        
        let signed_v = Signature
        {
            r_b8: Point
            {
                x: signed_v_r[0],
                y: signed_v_r[1]
            },
            s: signed_v_s
        };
        
        let registry_key_proof = TrieProof
        {
            key: zk_registry_key_proof_key,
            proof: zk_registry_key_proof_path,
            depth: zk_registry_key_proof_depth,
            value: zk_registry_key_proof_value
        };

        let nft_ownership_proof = TrieProof
        {
            key: nft_ownership_proof_key,
            proof: nft_ownership_proof_path,
            depth: nft_ownership_proof_depth,
            value: nft_ownership_proof_value
        };
        
        // TODO: Change these
        let chain_id = [0, context.chain_id()];
        let contract_addr = context.this_address();
        
        // Check voter eligibility
        let vote = VoteProverInput {
            a: Point::new(a[0],a[1]),
            b,
            n,
            h_id,
            process_id,
            contract_addr,
            chain_id,
            registry_storage_root,
            nft_storage_root,
            tlcs_pk: Point::new(tlcs_pk[0], tlcs_pk[1]),
            v,
            blinding_factor,
            signed_id,
            voter_address,
            signed_v,
            nft_id,
            k: Point::new(k[0], k[1]),
            registered_pbk: Point::new(registered_pbk[0], registered_pbk[1]),
            registry_key_proof,
            nft_ownership_proof,
        };

        verify_vote(vote);

        // Check that parameters agree with those in contract
        let nft_storage_root_fields = b32_to_fields(nft_storage_root);
        let zk_registry_storage_root_fields = b32_to_fields(registry_storage_root);
        
        let selector = compute_selector("_voter_parameter_check(Field,Field,Field,Field,Field,Field,Field)");
        context.call_public_function(context.this_address(), selector, [process_id, nft_storage_root_fields[0], nft_storage_root_fields[1], zk_registry_storage_root_fields[0], tlcs_pk[0], tlcs_pk[1]]);        
        
        // Commit to public storage
        let selector = compute_selector("_commit_nullifier_and_vote(Field,Field,Field,Field,Field)");
        context.call_public_function(context.this_address(), selector, [process_id, n, a[0], a[1], b]);        
    }

    #[aztec(public)]
    fn tally(process_id: Field, tlcs_sk: Field)
    {
        // Check that the voting process is over
        let selector = compute_selector("_tally_check(Field)");
        context.call_public_function(context.this_address(), selector, [process_id]);        

        let stored_outcome = storage.outcome.at(process_id).read();

        // Only proceed if there are no results
        if((stored_outcome.no == 0) & (stored_outcome.yes == 0) & (stored_outcome.abstain == 0))
        {
            // Check TLCS key
            let tlcs_pk = storage.voting_process.at(process_id).read().tlcs_pk;
            let bjj_curve = baby_jubjub().curve;
            let b8 = baby_jubjub().base8;
            assert(bjj_curve.mul(tlcs_sk, b8).eq(tlcs_pk));
            
            // Decrypt votes
            let num_voters = storage.num_voters.at(process_id).read();
            let mut vs: [Field] = [];
            
            for i in 0..num_voters
            {
                let ballot = storage.vote.at(process_id).at(i).read();
                let v = ballot.decrypt(tlcs_sk, [0, context.chain_id()], context.this_address(), process_id);
                vs = vs.push_front(v);
            }

            // Compute results
            let mut outcome = Outcome { no: 0, yes: 0, abstain: 0 };

            for i in 0..num_voters
            {
                if vs[i] == 0
                {
                    outcome.no += 1;
                } else if vs[i] == 1
                {
                    outcome.yes += 1;
                } else
                {
                    outcome.abstain += 1;
                }
            }

            // Store results
            storage.outcome.at(process_id).write(outcome);

            // ...and publish them on L1.
            let vp = storage.voting_process.at(process_id).read();
            let result_hash = hash_results(process_id, vp.ipfs_hash, vp.start_time, vp.census_block, vp.block_hash, vp.duration, vp.tlcs_round_number, [vp.tlcs_pk.x, vp.tlcs_pk.y], num_voters, [outcome.no, outcome.yes, outcome.abstain]);

            context.message_portal(result_hash);
        }
    }    
}
