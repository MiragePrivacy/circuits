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
use crate::keccak::{keccak256_var_with, DirectPermutation, PermutationBackend};
use crate::mpt::path::nibble_at_with;

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
    hash_leaf_from_remainder_with(
        receipt,
        receipt_len,
        key,
        key_len,
        consumed,
        active,
        &mut DirectPermutation,
    )
}

pub fn hash_leaf_from_remainder_with<F: PrimeField, B: PermutationBackend<F>>(
    receipt: &[UInt8<F>],
    receipt_len: &FpVar<F>,
    key: &[UInt8<F>],
    key_len: &FpVar<F>,
    consumed: &FpVar<F>,
    active: &Boolean<F>,
    backend: &mut B,
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
    decode_u16(&receipt_hi, &receipt_low)?.conditional_enforce_equal(receipt_len, active)?;
    receipt_hi.conditional_enforce_equal(&UInt8::constant(1), active)?;

    // The leaf buffer is wider than the receipt buffer, so bounding `leaf_len`
    // alone permits a `receipt_len` that runs past the receipt's own bytes and
    // absorbs the leaf's constant padding. That commits to a receipt this
    // gadget never saw. The receipt relation happens to pin the length too, but
    // a hash gadget must not depend on its caller for the extent it hashes.
    crate::bytes::assert_at_most(receipt_len, receipt.len(), active)?;

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
        let layout_active = active.clone() & selected.clone();
        layouts.push((
            selected,
            encoded_len,
            path_bytes(key, consumed, n, &layout_active)?,
        ));
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
    keccak256_var_with(&leaf, &leaf_len, active, backend)
}

/// Construct a terminal leaf for an arbitrary bounded value (including short
/// signed transactions), without the receipt-only 256..511-byte assumption.
pub fn hash_value_leaf_from_remainder_with<F: PrimeField, B: PermutationBackend<F>>(
    value: &[UInt8<F>],
    value_len: &FpVar<F>,
    key: &[UInt8<F>],
    key_len: &FpVar<F>,
    consumed: &FpVar<F>,
    active: &Boolean<F>,
    backend: &mut B,
) -> Result<[Byte<F>; 32], SynthesisError> {
    crate::bytes::assert_at_most(key_len, key.len(), active)?;
    let (encoded_value, encoded_len) = encode_bounded_rlp(value, value_len, false, active)?;
    let remaining = key_len * FpVar::constant(F::from(2u64)) - consumed;
    let mut body = vec![UInt8::constant(0); encoded_value.len() + 2 + key.len()];
    let mut path_len = FpVar::zero();
    let mut any = Boolean::FALSE;
    for n in 0..=key.len() * 2 {
        let selected = remaining.is_eq(&FpVar::constant(F::from(n as u64)))?;
        any |= selected.clone();
        let path = path_bytes(key, consumed, n, &(active.clone() & selected.clone()))?;
        let mut prefix = Vec::new();
        if path.len() > 1 {
            prefix.push(UInt8::constant(0x80 + path.len() as u8));
        }
        prefix.extend(path);
        path_len = FpVar::conditionally_select(
            &selected,
            &FpVar::constant(F::from(prefix.len() as u64)),
            &path_len,
        )?;
        let mut candidate = vec![UInt8::constant(0); body.len()];
        candidate[..prefix.len()].clone_from_slice(&prefix);
        candidate[prefix.len()..prefix.len() + encoded_value.len()]
            .clone_from_slice(&encoded_value);
        for (out, byte) in body.iter_mut().zip(candidate.iter()) {
            *out = UInt8::conditionally_select(&selected, byte, out)?;
        }
    }
    any.conditional_enforce_equal(&Boolean::TRUE, active)?;
    let (leaf, leaf_len) = encode_bounded_rlp(&body, &(encoded_len + path_len), true, active)?;
    keccak256_var_with(&leaf, &leaf_len, active, backend)
}

/// Canonical string/list prefixes for buffers below 64 KiB. Payload padding
/// remains outside the returned length and therefore outside the hash.
fn encode_bounded_rlp<F: PrimeField>(
    bytes: &[UInt8<F>],
    len: &FpVar<F>,
    list: bool,
    active: &Boolean<F>,
) -> Result<(Vec<UInt8<F>>, FpVar<F>), SynthesisError> {
    use ark_r1cs_std::convert::ToBitsGadget;
    assert!(!bytes.is_empty() && bytes.len() < 65536);
    crate::bytes::assert_at_most(len, bytes.len(), active)?;
    let native = fp_to_u64(len.value().unwrap_or(F::zero()));
    let hi = UInt8::new_witness(len.cs(), || Ok((native >> 8) as u8))?;
    let low = UInt8::new_witness(len.cs(), || Ok(native as u8))?;
    (byte_to_field(&hi)? * FpVar::constant(F::from(256u64)) + byte_to_field(&low)?)
        .conditional_enforce_equal(len, active)?;
    let bare = if list {
        Boolean::FALSE
    } else {
        len.is_eq(&FpVar::one())? & !bytes[0].to_bits_le()?[7].clone()
    };
    let short = crate::bytes::le(len, &FpVar::constant(F::from(55u64)))?;
    let one_length_byte = hi.is_eq(&UInt8::constant(0))?;
    let selectors = [
        bare.clone(),
        short.clone() & !bare,
        !short.clone() & one_length_byte.clone(),
        !short & !one_length_byte,
    ];
    let base = if list { 0xc0u64 } else { 0x80u64 };
    let short_prefix = UInt8::new_witness(len.cs(), || Ok((base + native) as u8))?;
    byte_to_field(&short_prefix)?.conditional_enforce_equal(
        &(len + FpVar::constant(F::from(base))),
        &(active.clone() & selectors[1].clone()),
    )?;
    let prefixes = [
        vec![],
        vec![short_prefix],
        vec![UInt8::constant((base + 55 + 1) as u8), low.clone()],
        vec![UInt8::constant((base + 55 + 2) as u8), hi, low],
    ];
    let mut out = vec![UInt8::constant(0); bytes.len() + 3];
    let mut header_len = FpVar::zero();
    for (selected, prefix) in selectors.iter().zip(prefixes.iter()) {
        let mut candidate = vec![UInt8::constant(0); out.len()];
        candidate[..prefix.len()].clone_from_slice(prefix);
        candidate[prefix.len()..prefix.len() + bytes.len()].clone_from_slice(bytes);
        for (out, byte) in out.iter_mut().zip(candidate.iter()) {
            *out = UInt8::conditionally_select(selected, byte, out)?;
        }
        header_len += FpVar::from(selected.clone()) * FpVar::constant(F::from(prefix.len() as u64));
    }
    Ok((out, len + header_len))
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
        expressions
            .push(FpVar::constant(F::from(0x30u64)) + nibble_at_with(key, consumed, active)?);
    }
    let mut j = n % 2;
    while j < n {
        let high = nibble_at_with(
            key,
            &(consumed + FpVar::constant(F::from(j as u64))),
            active,
        )?;
        let low = nibble_at_with(
            key,
            &(consumed + FpVar::constant(F::from((j + 1) as u64))),
            active,
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
            let len =
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(receipt.len() as u64))).unwrap();
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
                    bits.iter()
                        .enumerate()
                        .fold(0u8, |v, (i, b)| v | ((b.value().unwrap() as u8) << i))
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
    fn general_encoding_handles_bare_bytes_and_rejects_oversized_length() {
        for byte in [0u8, 0x7f, 0x80, 0xff] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let buf = alloc_bounded(cs.clone(), &[byte], 8).unwrap();
            let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap();
            let (encoded, encoded_len) =
                encode_bounded_rlp(&buf, &len, false, &Boolean::TRUE).unwrap();
            let expected = if byte < 0x80 {
                vec![byte]
            } else {
                vec![0x81, byte]
            };
            assert_eq!(
                encoded_len.value().unwrap(),
                Fr::from(expected.len() as u64)
            );
            assert_eq!(
                encoded[..expected.len()]
                    .iter()
                    .map(|b| b.value().unwrap())
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(cs.is_satisfied().unwrap());
        }
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &[0x42; 8], 8).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(9u64))).unwrap();
        let _ = encode_bounded_rlp(&buf, &len, false, &Boolean::TRUE).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn general_value_leaf_matches_canonical_rlp_at_length_boundaries() {
        // Cover both value-prefix and outer-list-prefix transitions, for every
        // remaining path width. Compare with an independent native encoder.
        for len in [
            0usize, 1, 49, 50, 51, 52, 53, 54, 55, 56, 249, 250, 251, 252, 253, 254, 255, 256, 511,
            512,
        ] {
            for consumed in 0..=6 {
                let value = vec![if len == 1 { 0x80 } else { 0x42 }; len];
                let cs = ConstraintSystem::<Fr>::new_ref();
                let buf = alloc_bounded(cs.clone(), &value, 512).unwrap();
                let value_len =
                    FpVar::new_witness(cs.clone(), || Ok(Fr::from(len as u64))).unwrap();
                let key = alloc_bounded(cs.clone(), &[0x82, 0x10, 0x00], 3).unwrap();
                let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
                let offset =
                    FpVar::new_witness(cs.clone(), || Ok(Fr::from(consumed as u64))).unwrap();
                let digest = hash_value_leaf_from_remainder_with(
                    &buf,
                    &value_len,
                    &key,
                    &key_len,
                    &offset,
                    &Boolean::TRUE,
                    &mut DirectPermutation,
                )
                .unwrap();
                let got: Vec<u8> = digest
                    .iter()
                    .map(|bits| {
                        bits.iter()
                            .enumerate()
                            .fold(0, |v, (i, b)| v | ((b.value().unwrap() as u8) << i))
                    })
                    .collect();
                let leaf = crate::mpt::tests::leaf_node(&[8, 2, 1, 0, 0, 0][consumed..], &value);
                assert_eq!(
                    got,
                    mirage_encoding::keccak256(&leaf),
                    "length {len}, consumed {consumed}"
                );
                assert!(cs.is_satisfied().unwrap());
            }
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
        let _ = hash_leaf_from_remainder(&buf, &len, &key, &key_len, &consumed, &Boolean::TRUE)
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
        let _ = hash_leaf_from_remainder(&buf, &len, &key, &key_len, &consumed, &Boolean::TRUE)
            .unwrap();
        println!(
            "constructed finite-family leaf: {} constraints",
            cs.num_constraints() - before
        );
    }
}
