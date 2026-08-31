//! Canonical construction of the common receipt-trie terminal leaf.
//!
//! After two branch levels consume a one-byte `RLP(transactionIndex)` key, the
//! remaining compact path is the empty leaf path `0x20`. For receipts between
//! 256 and 512 bytes the complete node has one fixed shape:
//!
//! ```text
//! f9 <body:u16> 20 b9 <receipt_len:u16> <receipt bytes>
//! ```
//!
//! Constructing those bytes from the already-bound receipt removes the generic
//! leaf decoder, path comparison, and witness-positioned value copy. This
//! module is intentionally a shape prototype; broader key/depth cases need
//! either additional finite shapes or the existing generic traversal.

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::SynthesisError;

use crate::bytes::byte_to_field;
use crate::keccak::sponge::Byte;
use crate::keccak::keccak256_var;

/// Constructs and hashes `RLP([empty_leaf_path, receipt])`.
///
/// `receipt` remains a normal left-aligned bounded buffer. The two allocated
/// length bytes are not hints: field equalities bind them to `receipt_len`.
pub fn hash_empty_path_leaf<F: PrimeField>(
    receipt: &[UInt8<F>],
    receipt_len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<[Byte<F>; 32], SynthesisError> {
    let cs = receipt_len.cs();
    let len_value = receipt_len.value().unwrap_or(F::zero());
    let mut len_bytes = len_value.into_bigint().to_bytes_le();
    len_bytes.resize(8, 0);
    let native_len = u64::from_le_bytes(len_bytes[..8].try_into().expect("eight bytes"));

    let receipt_hi = UInt8::new_witness(cs.clone(), || Ok((native_len >> 8) as u8))?;
    let receipt_low = UInt8::new_witness(cs.clone(), || Ok(native_len as u8))?;
    let body_len = native_len.saturating_add(4);
    let body_hi = UInt8::new_witness(cs.clone(), || Ok((body_len >> 8) as u8))?;
    let body_low = UInt8::new_witness(cs, || Ok(body_len as u8))?;

    let decode_u16 = |hi: &UInt8<F>, low: &UInt8<F>| -> Result<FpVar<F>, SynthesisError> {
        Ok(byte_to_field(hi)? * FpVar::constant(F::from(256u64)) + byte_to_field(low)?)
    };
    decode_u16(&receipt_hi, &receipt_low)?
        .conditional_enforce_equal(receipt_len, active)?;
    decode_u16(&body_hi, &body_low)?
        .conditional_enforce_equal(&(receipt_len + FpVar::constant(F::from(4u64))), active)?;

    // Long-form length-of-length is exactly two bytes. The leaf buffer's own
    // bounded hash enforces the upper end (receipt_len <= receipt.len()).
    let receipt_hi_ok = receipt_hi.is_eq(&UInt8::constant(1))?
        | receipt_hi.is_eq(&UInt8::constant(2))?;
    let body_hi_ok = body_hi.is_eq(&UInt8::constant(1))? | body_hi.is_eq(&UInt8::constant(2))?;
    receipt_hi_ok.conditional_enforce_equal(&Boolean::TRUE, active)?;
    body_hi_ok.conditional_enforce_equal(&Boolean::TRUE, active)?;

    let mut leaf = Vec::with_capacity(receipt.len() + 7);
    leaf.extend([
        UInt8::constant(0xf9),
        body_hi,
        body_low,
        UInt8::constant(0x20),
        UInt8::constant(0xb9),
        receipt_hi,
        receipt_low,
    ]);
    leaf.extend_from_slice(receipt);

    let leaf_len = receipt_len + FpVar::constant(F::from(7u64));
    keccak256_var(&leaf, &leaf_len, active)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::gr1cs::ConstraintSystem;

    use crate::bytes::alloc_bounded;

    fn native_leaf(receipt: &[u8]) -> Vec<u8> {
        assert!((256..=512).contains(&receipt.len()));
        let body = receipt.len() + 4;
        let mut out = vec![
            0xf9,
            (body >> 8) as u8,
            body as u8,
            0x20,
            0xb9,
            (receipt.len() >> 8) as u8,
            receipt.len() as u8,
        ];
        out.extend_from_slice(receipt);
        out
    }

    #[test]
    fn constructed_leaf_matches_native_rlp() {
        let receipt = vec![0x42; 428];
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &receipt, 512).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(receipt.len() as u64))).unwrap();
        let digest = hash_empty_path_leaf(&buf, &len, &Boolean::TRUE).unwrap();
        let got: Vec<u8> = digest
            .iter()
            .map(|bits| {
                bits.iter().enumerate().fold(0u8, |v, (i, b)| {
                    v | ((b.value().unwrap() as u8) << i)
                })
            })
            .collect();
        assert_eq!(got, mirage_encoding::keccak256(&native_leaf(&receipt)));
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn rejects_a_length_outside_the_shape() {
        let receipt = vec![0x42; 255];
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &receipt, 512).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(receipt.len() as u64))).unwrap();
        let _ = hash_empty_path_leaf(&buf, &len, &Boolean::TRUE).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cost() {
        let receipt = vec![0x42; 428];
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &receipt, 512).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(receipt.len() as u64))).unwrap();
        let before = cs.num_constraints();
        let _ = hash_empty_path_leaf(&buf, &len, &Boolean::TRUE).unwrap();
        println!("constructed empty-path leaf: {} constraints", cs.num_constraints() - before);
    }
}
