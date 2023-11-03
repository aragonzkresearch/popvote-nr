// Some auxiliary functions

use dep::aztec::hash::sha256_to_field;

pub fn hash_process_content(process_id: Field, ipfs_hash: [u8; 32], start_time: u64, census_block: u64, block_hash: [u8; 32], duration: u64, tlcs_round_number: u64, tlcs_pk: [Field; 2]) -> Field
{
    // Byte array for content
    let mut content = [0; 192];

    // Byte conversions
    let process_id_bytes = process_id.to_be_bytes(32);
    let start_time_bytes = (start_time as Field).to_be_bytes(8);
    let census_block_bytes = (census_block as Field).to_be_bytes(8);
    let duration_bytes = (duration as Field).to_be_bytes(8);
    let tlcs_round_number_bytes = (tlcs_round_number as Field).to_be_bytes(8);
    let tlcs_pk_x_bytes = tlcs_pk[0].to_be_bytes(32);
    let tlcs_pk_y_bytes = tlcs_pk[1].to_be_bytes(32);

    // Populate content array
    write_at(&mut content, process_id_bytes, 0, 32);
    write_at(&mut content, ipfs_hash.as_slice(), 32, 32);
    write_at(&mut content, start_time_bytes, 64, 8);
    write_at(&mut content, census_block_bytes, 72, 8);
    write_at(&mut content, block_hash.as_slice(), 80, 32);
    write_at(&mut content, duration_bytes, 112, 8);
    write_at(&mut content, tlcs_round_number_bytes, 120, 8);
    write_at(&mut content, tlcs_pk_x_bytes, 128, 32);
    write_at(&mut content, tlcs_pk_y_bytes, 160, 32);

    // Return hash
    sha256_to_field(content)
}

/// Result hasher including process identifiers
pub fn hash_results(process_id: Field, ipfs_hash: [u8; 32], start_time: u64, census_block: u64, block_hash: [u8; 32], duration: u64, tlcs_round_number: u64, tlcs_pk: [Field; 2], results: [Field; 3]) -> Field
{
    let process_hash_bytes = hash_process_content(process_id, ipfs_hash, start_time, census_block, block_hash, duration, tlcs_round_number, tlcs_pk).to_be_bytes(32);
    let results_no = results[0].to_be_bytes(32);
    let results_yes = results[1].to_be_bytes(32);
    let results_abstain = results[2].to_be_bytes(32);

    let mut msg = [0; 128];

    write_at(&mut msg, process_hash_bytes, 0, 32);
    write_at(&mut msg, results_no, 32, 32);
    write_at(&mut msg, results_yes, 64, 32);
    write_at(&mut msg, results_abstain, 96, 32);

    // Return hash
    sha256_to_field(msg)
}

// auxiliary function for writing to portion of a byte array
fn write_at<M>(arr: &mut [u8; M], input: [u8], i: u64, len: u64)
{
    assert(i + len <= M);
    for j in 0..len
    {
        arr[i + j] = input[j];
    }
}
