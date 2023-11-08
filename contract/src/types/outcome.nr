use dep::std::ec::tecurve::affine::Point;
use dep::aztec::types::type_serialization::TypeSerializationInterface;

/// Outcome type
struct Outcome
{
    no: Field,
    yes: Field,
    abstain: Field
}

global OUTCOME_SERIALIZED_LEN: Field = 3;

fn deserialize_outcome(fs: [Field; OUTCOME_SERIALIZED_LEN]) -> Outcome
{
    Outcome { no: fs[0], yes: fs[1], abstain: fs[2] }
}

fn serialize_outcome(o: Outcome) -> [Field; OUTCOME_SERIALIZED_LEN]
{
    [o.no, o.yes, o.abstain]
}

global OutcomeSerializationMethods: TypeSerializationInterface<Outcome, OUTCOME_SERIALIZED_LEN> = TypeSerializationInterface
{
    deserialize: deserialize_outcome,
    serialize: serialize_outcome
};
