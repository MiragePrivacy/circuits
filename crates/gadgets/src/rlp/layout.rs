//! Witness-supplied layout decoder.
//!
//! The prover supplies each item's offset and length; the circuit verifies them
//! instead of deriving them. The saving is that a field the relation never
//! inspects costs one prefix read rather than a full walk past it.
//!
//! # Why this is not obviously safe
//!
//! Chain arithmetic alone (`offset[i] + total_len(i) == offset[i+1]`) does not
//! prevent forgery, because a prover picks every offset consistently. A layout
//! shifted twenty bytes earlier is just as self-consistent, and lands the
//! relation's "logs" field inside `logsBloom`, whose bytes the attacker
//! influences by choosing which events to emit.
//!
//! Soundness rests on the prefix read being *complete*: for each claimed item,
//! read the prefix byte at its claimed start, derive the length from it, and
//! enforce that the derivation equals the claim. The witness then supplies only
//! a hint that is fully checked, not an unverified fact.
//!
//! The five checks that make it sound, all of which the adversarial suite
//! exercises:
//!
//! 1. Derive each item's length from its own prefix byte and enforce equality
//!    with the claim.
//! 2. Enforce canonical form: no long form where short fits, no leading zeros,
//!    no `0x81 xx` for a byte below `0x80`.
//! 3. Pin both ends: the first child starts at the payload start, the last ends
//!    at the payload end.
//! 4. Enforce the exact child count.
//! 5. Enforce containment: no child reaches past its parent.
//!
//! Drop any one and forged proofs verify while valid ones still do, with no
//! symptom. Spec 2.1.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use super::{Item, RlpDecoder};

pub struct Layout;

impl<F: PrimeField> RlpDecoder<F> for Layout {
    fn decode_item(
        _buf: &[UInt8<F>],
        _at: &FpVar<F>,
        _active: &ark_r1cs_std::boolean::Boolean<F>,
    ) -> Result<Item<F>, SynthesisError> {
        // Not yet implemented. `decode_item` at a single offset has nothing to
        // hint: the cursor version already reads exactly one prefix and derives
        // from it. The saving only appears in `decode_list`, where the cursor
        // version must walk every child to find the next.
        unimplemented!("layout::decode_item: use Cursor; see decode_list")
    }

    fn decode_list(
        _buf: &[UInt8<F>],
        _at: &FpVar<F>,
        _n: usize,
        _active: &ark_r1cs_std::boolean::Boolean<F>,
    ) -> Result<Vec<Item<F>>, SynthesisError> {
        unimplemented!("layout::decode_list: not yet written")
    }
}
