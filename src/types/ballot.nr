use dep::std::ec::consts::te::baby_jubjub;
use dep::std::ec::tecurve::affine::Point;
use dep::std::hash::poseidon::bn254;
use dep::aztec::types::type_serialization::TypeSerializationInterface;

/// Ballot type
struct Ballot
{
    a: Point, // randomly generated public key
    b: Field // encrypted vote
}

global BALLOT_SERIALIZED_LEN: Field = 3;

fn deserialize_ballot(fs: [Field; BALLOT_SERIALIZED_LEN]) -> Ballot
{
    Ballot { a: Point { x: fs[0], y: fs[1] }, b: fs[2] }
}

fn serialize_ballot(b: Ballot) -> [Field; BALLOT_SERIALIZED_LEN]
{
    [b.a.x, b.a.y, b.b]
}

global BallotSerializationMethods: TypeSerializationInterface<Ballot, BALLOT_SERIALIZED_LEN> = TypeSerializationInterface
{
    deserialize: deserialize_ballot,
    serialize: serialize_ballot
};

impl Ballot
{
    fn decrypt(self, sk: Field, chain_id: [Field; 2], contract_address: Field, process_id: Field) -> Field
    {
        let bjj_curve = baby_jubjub().curve;

        // Compute shared secret
        let k = bjj_curve.mul(sk, self.a);

        // Decrypt ballot by brute-force
        let mut v = 3;
        for i in 0..3
        {
            let b = bn254::hash_7([k.x, k.y, i, chain_id[0], chain_id[1], process_id, contract_address]);
            if b == self.b
            {
                v = i;
            }
        }
        
        assert(v != 3, "Could not decrypt vote.");
        
        v
    }
}
