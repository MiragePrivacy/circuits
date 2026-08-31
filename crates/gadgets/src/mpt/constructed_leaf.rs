//! Canonical construction of a receipt-trie terminal leaf.
//!
//! The key is at most three bytes, so a terminal leaf has only seven possible
//! remaining-path lengths (zero through six nibbles). This module enumerates
//! those finite layouts, constructs the canonical hex-prefix path and RLP from
//! the already-bound key and receipt, and hashes the selected layout once.
//! There is no raw leaf witness to decode and no witness-positioned receipt to
//! copy out of it.

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::SynthesisError;

use crate::bytes::byte_to_field;
use crate::keccak::sponge::Byte;
use crate::keccak::keccak256_var;
use crate::mpt::path::nibble_at;

/// Constructs and hashes `RLP([HP(key[consumed..], leaf), receipt])`.
///
/// `receipt` and `key` remain normal left-aligned bounded buffers. Every RLP
/// length byte and every packed path byte is constrained to the source fields;
/// the native values used to allocate them are only witness generators.
pub fn hash_leaf_from_remainder<F: PrimeField>(
    receipt: &[UInt8<F>],
    receipt_len: &FpVar<F>,
    key: &[UInt8<F>],
    key_len: &FpVar<F>,
    consumed: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<[Byte<F>; 32], SynthesisError> {
    let cs = receipt_len.cs();
    let len_value = receipt_len.value().unwrap_or(F::zero());
    let mut len_bytes = len_value.into_bigint().to_bytes_le();
    len_bytes.resize(8, 0);
    let native_len = u64::from_le_bytes(len_bytes[..8].try_into().expect("eight bytes"));

    let receipt_hi = UInt8::new_witness(cs.clone(), || Ok((native_len >> 8) as u8))?;
    let receipt_low = UInt8::new_witness(cs.clone(), || Ok(native_len as u8))?;
    let decode_u16 = |hi: &UInt8<F>, low: &UInt8<F>| -> Result<FpVar<F>, SynthesisError> {
        Ok(byte_to_field(hi)? * FpVar::constant(F::from(256u64)) + byte_to_field(low)?)
    };
    decode_u16(&receipt_hi, &receipt_low)?
        .conditional_enforce_equal(receipt_len, active)?;
    receipt_hi
        .conditional_enforce_equal(&UInt8::constant(1), active)?;

    let total_nibbles = key_len * FpVar::constant(F::from(2u64));
    let remaining = &total_nibbles - consumed;
    let max_nibbles = key.len() * 2;
    let mut layouts = Vec::with_capacity(max_nibbles + 1);
    let mut any_layout = Boolean::FALSE;
    let mut path_item_len = FpVar::zero();
    for n in 0..=max_nibbles {
        let selected = remaining.is_eq(&FpVar::constant(F::from(n as u64)))?;
        any_layout |= selected.clone();
        let encoded_len = if n <= 1 { 1 } else { 2 + n / 2 };
        path_item_len = FpVar::conditionally_select(
            &selected,
            &FpVar::constant(F::from(encoded_len as u64)),
            &path_item_len,
        )?;
        layouts.push((selected, encoded_len, path_bytes(key, consumed, n, active)?));
    }
    any_layout.conditional_enforce_equal(&Boolean::TRUE, active)?;

    let body_len_var = receipt_len + &path_item_len + FpVar::constant(F::from(3u64));
    let native_body_len = fp_to_u64(body_len_var.value().unwrap_or(F::zero()));
    let body_hi = UInt8::new_witness(cs.clone(), || Ok((native_body_len >> 8) as u8))?;
    let body_low = UInt8::new_witness(cs, || Ok(native_body_len as u8))?;
    decode_u16(&body_hi, &body_low)?.conditional_enforce_equal(&body_len_var, active)?;
    body_hi.conditional_enforce_equal(&UInt8::constant(1), active)?;

    // Maximum layout: 3-byte outer header, 5-byte encoded path, 3-byte
    // receipt header, and the bounded receipt.
    let node_bound = receipt.len() + 11;
    let mut leaf = vec![UInt8::constant(0); node_bound];
    for (selected, encoded_len, path) in layouts {
        let mut candidate = vec![UInt8::constant(0); node_bound];
        candidate[0] = UInt8::constant(0xf9);
        candidate[1] = body_hi.clone();
        candidate[2] = body_low.clone();
        if path.len() == 1 {
            candidate[3] = path[0].clone();
        } else {
            candidate[3] = UInt8::constant(0x80 + path.len() as u8);
            candidate[4..4 + path.len()].clone_from_slice(&path);
        }
        let receipt_at = 3 + encoded_len;
        candidate[receipt_at] = UInt8::constant(0xb9);
        candidate[receipt_at + 1] = receipt_hi.clone();
        candidate[receipt_at + 2] = receipt_low.clone();
        candidate[receipt_at + 3..receipt_at + 3 + receipt.len()].clone_from_slice(receipt);
        for (out, byte) in leaf.iter_mut().zip(candidate.iter()) {
            *out = UInt8::conditionally_select(&selected, byte, out)?;
        }
    }

    let leaf_len = receipt_len + path_item_len + FpVar::constant(F::from(6u64));
    keccak256_var(&leaf, &leaf_len, active)
}

fn path_bytes<F: PrimeField>(
    key: &[UInt8<F>],
    consumed: &FpVar<F>,
    n: usize,
    active: &Boolean<F>,
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    let cs = consumed.cs();
    let mut expressions = Vec::with_capacity(1 + n / 2);
    if n % 2 == 0 {
        expressions.push(FpVar::constant(F::from(0x20u64)));
    } else {
        expressions.push(
            FpVar::constant(F::from(0x30u64)) + nibble_at(key, consumed)?,
        );
    }
    let mut j = n % 2;
    while j < n {
        let high = nibble_at(key, &(consumed + FpVar::constant(F::from(j as u64))))?;
        let low = nibble_at(
            key,
            &(consumed + FpVar::constant(F::from((j + 1) as u64))),
        )?;
        expressions.push(high * FpVar::constant(F::from(16u64)) + low);
        j += 2;
    }

    expressions
        .into_iter()
        .map(|expression| {
            let native = fp_to_u64(expression.value().unwrap_or(F::zero())) as u8;
            let byte = UInt8::new_witness(cs.clone(), || Ok(native))?;
            byte_to_field(&byte)?.conditional_enforce_equal(&expression, active)?;
            Ok(byte)
        })
        .collect()
}

fn fp_to_u64<F: PrimeField>(value: F) -> u64 {
    let bytes = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 8];
    let n = bytes.len().min(8);
    out[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::gr1cs::ConstraintSystem;

    use crate::bytes::alloc_bounded;

    fn native_leaf(receipt: &[u8], key: &[u8], consumed: usize) -> Vec<u8> {
        assert!((256..=448).contains(&receipt.len()));
        let nibbles: Vec<u8> = key
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .skip(consumed)
            .collect();
        let mut path = Vec::with_capacity(1 + nibbles.len() / 2);
        let mut at = 0;
        if nibbles.len() % 2 == 0 {
            path.push(0x20);
        } else {
            path.push(0x30 | nibbles[0]);
            at = 1;
        }
        while at < nibbles.len() {
            path.push(nibbles[at] << 4 | nibbles[at + 1]);
            at += 2;
        }
        let mut path_item = if path.len() == 1 {
            path
        } else {
            let mut item = vec![0x80 + path.len() as u8];
            item.extend(path);
            item
        };
        let body = path_item.len() + 3 + receipt.len();
        let mut out = vec![0xf9, (body >> 8) as u8, body as u8];
        out.append(&mut path_item);
        out.extend([0xb9, (receipt.len() >> 8) as u8, receipt.len() as u8]);
        out.extend_from_slice(receipt);
        out
    }

    #[test]
    fn every_remaining_path_layout_matches_native_rlp() {
        let receipt = vec![0x42; 428];
        let key = [0x12, 0x34, 0x56];
        for consumed in 0..=6 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let buf = alloc_bounded(cs.clone(), &receipt, 448).unwrap();
            let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(receipt.len() as u64))).unwrap();
            let key_buf = alloc_bounded(cs.clone(), &key, 3).unwrap();
            let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
            let consumed_var =
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(consumed as u64))).unwrap();
            let digest = hash_leaf_from_remainder(
                &buf,
                &len,
                &key_buf,
                &key_len,
                &consumed_var,
                &Boolean::TRUE,
            )
            .unwrap();
            let got: Vec<u8> = digest
                .iter()
                .map(|bits| {
                    bits.iter().enumerate().fold(0u8, |v, (i, b)| {
                        v | ((b.value().unwrap() as u8) << i)
                    })
                })
                .collect();
            assert_eq!(
                got,
                mirage_encoding::keccak256(&native_leaf(&receipt, &key, consumed)),
                "remaining path length {}",
                6 - consumed
            );
            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn rejects_a_length_outside_the_shape() {
        let receipt = vec![0x42; 255];
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &receipt, 448).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(receipt.len() as u64))).unwrap();
        let key = alloc_bounded(cs.clone(), &[0x12], 3).unwrap();
        let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap();
        let consumed = FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))).unwrap();
        let _ = hash_leaf_from_remainder(
            &buf,
            &len,
            &key,
            &key_len,
            &consumed,
            &Boolean::TRUE,
        )
        .unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn cost() {
        let receipt = vec![0x42; 428];
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &receipt, 448).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(receipt.len() as u64))).unwrap();
        let key = alloc_bounded(cs.clone(), &[0x12], 3).unwrap();
        let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap();
        let consumed = FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap();
        let before = cs.num_constraints();
        let _ = hash_leaf_from_remainder(
            &buf,
            &len,
            &key,
            &key_len,
            &consumed,
            &Boolean::TRUE,
        )
        .unwrap();
        println!("constructed finite-family leaf: {} constraints", cs.num_constraints() - before);
    }
}
