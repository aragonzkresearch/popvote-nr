use dep::std::hash::keccak256;

// EdDSA dependencies from stdlib
use dep::std::ec::tecurve::affine::Point;
use dep::std::eddsa::eddsa_poseidon_verify as eddsa_verify;
use dep::std::hash::poseidon::bn254;
use dep::std::ec::consts::te::baby_jubjub;

// Trie proof primitives
use dep::noir_trie_proofs::TrieProof;

global MAX_BITS: Field = 256; // Required for bit representation of BJJ associated field element

// Data types
struct Signature
{
    r_b8: Point,
    s: Field,
}

struct VoteProverInput<MAX_PROOF_SIZE>
{
    // Public inputs
    a: Point,
    b: Field, // Hash of k,v,id
    n: Field,
    process_id: Field,
    contract_addr: Field,
    chain_id: [Field; 2],
    registry_storage_root: [u8; 32], // Storage hash of zkRegistry contract
    nft_storage_root: [u8; 32], // Storage hash of NFT contract
    tlcs_pk: Point,
    
    // Private inputs
    v: Field, // in {0,1,2}
    blinding_factor: Field, // TODO: Formerly r: [u1; MAX_BITS]
    signed_id: Signature, //sigma
    voter_address: Field,
    signed_v: Signature, // tau
    nft_id: [Field; 2],
    h_id: Field,
    k: Point,

    registered_pbk: Point,
    registry_key_proof: TrieProof<32, MAX_PROOF_SIZE, 32>, // Proof of registration
    nft_ownership_proof: TrieProof<32, MAX_PROOF_SIZE, 32>, // Proof of NFT ownership
}

pub fn verify_vote<MAX_PROOF_SIZE>(vote: VoteProverInput<MAX_PROOF_SIZE>)
{
    let bjj_curve = baby_jubjub().curve;

    // Check signatures
    assert(eddsa_verify(vote.registered_pbk.x, vote.registered_pbk.y, vote.signed_id.s, vote.signed_id.r_b8.x, vote.signed_id.r_b8.y, vote.h_id));
    assert(eddsa_verify(vote.registered_pbk.x, vote.registered_pbk.y, vote.signed_v.s, vote.signed_v.r_b8.x, vote.signed_v.r_b8.y, bn254::hash_1([vote.v])));

    // Check ID hash
    assert(vote.h_id == bn254::hash_6([vote.nft_id[0], vote.nft_id[1], vote.chain_id[0], vote.chain_id[1], vote.process_id, vote.contract_addr]));

    // Check nullifier
    assert(vote.n == bn254::hash_3([vote.signed_id.r_b8.x, vote.signed_id.r_b8.y, vote.signed_id.s]));

    // Check vote encryption
    let b8 = baby_jubjub().base8;
    assert(bjj_curve.mul(vote.blinding_factor, b8).eq(vote.a));
    assert(vote.k.eq(bjj_curve.mul(vote.blinding_factor, vote.tlcs_pk))); // TODO
    assert(vote.b == bn254::hash_7([vote.k.x, vote.k.y, vote.v, vote.chain_id[0], vote.chain_id[1], vote.process_id, vote.contract_addr]));
    assert((vote.v == 0) | (vote.v == 1) | (vote.v == 2)); // Check validity of vote

    // Check registration by verifying x coordinate of public key
    let address_in_bytes = vote.voter_address.to_be_bytes(20);
    let calculated_registry_key = {
        let mut buf = [0; 64]; // Buffer
        // Compute storage slot of pk[address], which is keccak256(bytes32(address) ++ slot_number)
        let slot_number = 0;
        let slot_number_bytes = slot_number.to_be_bytes(32);
        
        for i in 0..20
        {
            buf[12 + i] = address_in_bytes[i];
        }

        for i in 0..32
        {
            buf[32 + i] = slot_number_bytes[i];
        }

        // Hash
        let out = keccak256(buf, 64);

        // Now compute the storage slot of pk[address][bjj_code], which is keccak256(uint256(bjj_code) ++ slot(pk[address])),
        // where bjj_code is some integer that stands for 'Baby Jubjub'.
        let bjj_code = 0; // Subject to change
        let bjj_code_bytes = bjj_code.to_be_bytes(32);

        // Populate buffer
        for i in 0..32
        {
            buf[i] = bjj_code_bytes[i];
            buf[32 + i] = out[i];
        }

        keccak256(buf, 64)
    };
    
    // Keys should match
    assert(calculated_registry_key == vote.registry_key_proof.key);

    // And value should be what we expect
    let pbk_x_bytes = vote.registered_pbk.x.to_be_bytes(32);
    for i in 0..32
    {
        assert(pbk_x_bytes[i] == vote.registry_key_proof.value[i]);
    }

    // Storage proof verification
    assert(vote.registry_key_proof.verify_storage_root(vote.registry_storage_root));

    // Check NFT ownership
    let calculated_nft_key = {
        let mut buf = [0; 64];
        // Compute storage slot of _ownerOf[nft_id], which is keccak256(bytes32(nft_id) ++ slot_number)
        let slot_number = 2;
        let slot_number_bytes = slot_number.to_be_bytes(32);

        let nft_id_bytes1 = vote.nft_id[0].to_be_bytes(16);
        let nft_id_bytes2 = vote.nft_id[1].to_be_bytes(16);
        
        for i in 0..16
        {
            buf[i] = nft_id_bytes1[i];
            buf[16 + i] = nft_id_bytes2[i];
        }

        for i in 0..32
        {
            buf[32 + i] = slot_number_bytes[i];
        }

        keccak256(buf, 64)
    };
    
    // Keys should match
    assert(calculated_nft_key == vote.nft_ownership_proof.key);

    // NFT ownership proof verification
    assert(vote.nft_ownership_proof.verify_storage_root(vote.nft_storage_root));


    // The value should be an address
    for i in 0..12
    {
        assert(vote.nft_ownership_proof.value[i] == 0);
    }

    // Take note of the owner
    let mut nft_owner: [u8; 20] = [0; 20];
    
    for i in 0..20
    {
        nft_owner[i] = vote.nft_ownership_proof.value[12 + i];
    }

    // Now check whether the owner's address is the voter's address
    let mut nft_owner_p = true;
    for i in 0..20 { nft_owner_p &= nft_owner[i] == address_in_bytes[i]; }
    assert(nft_owner_p);
}

fn u256_from_fields(x: [Field; 2]) -> [u8; 32] // Convert a pair of 128-bit field elements to a 32-byte array
{
    let mut out = [0; 32];
    
    let a = x[0].to_be_bytes(16);
    let b = x[1].to_be_bytes(16);

    for i in 0..16
    {
        out[i] = a[i];
        out[16 + i] = b[i];
    }

    out
}
