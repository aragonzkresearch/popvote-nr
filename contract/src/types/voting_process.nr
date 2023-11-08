use dep::std::ec::tecurve::affine::Point;
use dep::aztec::types::type_serialization::TypeSerializationInterface;

type B32 = [u8; 32];

/// Type for voting processes
struct VotingProcess
{
    /// IPFS CID of proposal
    ipfs_hash: B32,
    /// Ethereum block number of census
    census_block: u64,
    /// Time at which voting begins (UNIX time)
    start_time: u64,
    /// Block hash of census block
    block_hash: B32,
    /// Duration of voting period in seconds
    duration: u64,
    /// Storage root of ZK registry contract on L1
    zk_registry_storage_root: B32,
    /// Storage root of NFT contract on L1
    nft_contract_storage_root: B32,
    /// Timelock service round number and public key
    tlcs_round_number: u64,
    tlcs_pk: Point,
}

/// Serialisation boilerplate
global VOTING_PROCESS_SERIALIZED_LEN: Field = 14;

pub fn deserialize_voting_process(fs: [Field; VOTING_PROCESS_SERIALIZED_LEN]) -> VotingProcess
{
    VotingProcess
    {
        ipfs_hash: fields_to_b32([fs[0], fs[1]]),
        census_block: fs[2] as u64,
        start_time: fs[3] as u64,
        block_hash: fields_to_b32([fs[4], fs[5]]),
        duration: fs[6] as u64,
        zk_registry_storage_root: fields_to_b32([fs[7], fs[8]]),
        nft_contract_storage_root: fields_to_b32([fs[9], fs[10]]),
        tlcs_round_number: fs[11] as u64,
        tlcs_pk: Point { x: fs[12], y: fs[13] },
    }
}

fn serialize_voting_process(vp: VotingProcess) -> [Field; VOTING_PROCESS_SERIALIZED_LEN]
{
    let ipfs_hash = b32_to_fields(vp.ipfs_hash);
    let block_hash = b32_to_fields(vp.block_hash);
    let zk_registry_storage_root = b32_to_fields(vp.zk_registry_storage_root);
    let nft_contract_storage_root = b32_to_fields(vp.nft_contract_storage_root);

    [
        ipfs_hash[0], ipfs_hash[1],
        vp.census_block as Field,
        vp.start_time as Field,
        block_hash[0], block_hash[1],
        vp.duration as Field,
        zk_registry_storage_root[0], zk_registry_storage_root[1],
        nft_contract_storage_root[0], nft_contract_storage_root[1],
        vp.tlcs_round_number as Field,
        vp.tlcs_pk.x, vp.tlcs_pk.y,
    ]
}

global VotingProcessSerializationMethods: TypeSerializationInterface<VotingProcess, VOTING_PROCESS_SERIALIZED_LEN> = TypeSerializationInterface
{
    deserialize: deserialize_voting_process,
    serialize: serialize_voting_process
};

pub fn fields_to_b32(fs: [Field; 2]) -> B32
{
    let mut out = [0; 32];
    
    let a = fs[0].to_be_bytes(16);
    let b = fs[1].to_be_bytes(16);

    for i in 0..16
    {
        out[i] = a[i];
        out[16 + i] = b[i];
    }

    out
}

pub fn b32_to_fields(bs: B32) -> [Field; 2]
{
    let mut lower = 0;
    let mut upper = 0;

    for i in 0..16
    {
        lower = 8*lower + bs[16 + i] as Field;
        upper = 8*upper + bs[i] as Field;
    }

    [upper, lower]
}
