//! Canonical construction of a trie's terminal leaf.
//!
//! The key is at most three bytes, so a terminal leaf has only seven possible
//! remaining-path lengths (zero through six nibbles). The leaf is
//! `RLP([HP(key[consumed..], leaf), value])`: at most eleven bytes of framing
//! built from the key and the value's length, followed by the value itself.
//! There is no raw leaf witness to decode and no witness-positioned value to
//! copy out of it.
//!
//! The framing is assembled at field level from a few selectors, the value is
//! shifted right by the framing length in four stages, and the result is
//! decomposed to bits once for hashing.

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::GR1CSVar;
use ark_relations::gr1cs::SynthesisError;

use crate::bytes::{
    byte_to_field, field_to_byte, le_const, one_hot_in_range, shift_right, to_bits_bounded,
    to_fields,
};
use crate::keccak::sponge::Byte;
use crate::keccak::{keccak256_var_with, PermutationBackend};
use crate::mpt::levels::KeyNibbles;

/// Longest framing: a three-byte list header, a five-byte path item and a
/// three-byte string header.
const MAX_FRAMING: usize = 11;

fn constant<F: PrimeField>(v: u64) -> FpVar<F> {
    FpVar::constant(F::from(v))
}

fn fp_to_u64<F: PrimeField>(value: F) -> u64 {
    use ark_ff::BigInteger;
    let bytes = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 8];
    let n = bytes.len().min(8);
    out[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(out)
}

/// A canonical RLP length header for a payload below 64 KiB.
struct Header<F: PrimeField> {
    /// Up to three bytes, zero past `len`.
    bytes: Vec<FpVar<F>>,
    len: FpVar<F>,
    /// `width[k] = [len == k + 1]`, all zero for a bare byte.
    width: Vec<FpVar<F>>,
}

/// `base` is 0x80 for strings, 0xc0 for lists. `bare` marks a one-byte string
/// below 0x80, which is its own encoding.
fn header<F: PrimeField>(
    payload: &FpVar<F>,
    base: u64,
    bare: &Boolean<F>,
) -> Result<Header<F>, SynthesisError> {
    let cs = payload.cs();
    let native = payload.value().map(fp_to_u64).unwrap_or(0);
    let hi = UInt8::new_witness(cs.clone(), || Ok((native >> 8) as u8))?;
    let lo = UInt8::new_witness(cs, || Ok(native as u8))?;
    let (hi, lo) = (byte_to_field(&hi)?, byte_to_field(&lo)?);
    (&hi * constant::<F>(256) + &lo).enforce_equal(payload)?;

    let le55 = le_const(payload, 55, 16)?;
    let one_byte = hi.is_zero()?;
    let short = FpVar::from(le55.clone() & !bare.clone());
    let mid = FpVar::from(one_byte.clone() & !le55);
    let long = FpVar::from(!one_byte);
    Ok(Header {
        bytes: vec![
            &short * (payload + constant::<F>(base))
                + &mid * constant::<F>(base + 56)
                + &long * constant::<F>(base + 57),
            &mid * payload + &long * &hi,
            &long * &lo,
        ],
        len: &short + &mid * constant::<F>(2) + &long * constant::<F>(3),
        width: vec![short, mid, long],
    })
}

/// `out[k] = a[k] + b[k - len(a)]` for `k < n`, where `a` is zero past its
/// selected length and `widths[l] = [len(a) == l + 1]`.
fn concat<F: PrimeField>(
    a: &[FpVar<F>],
    widths: &[FpVar<F>],
    b: &[FpVar<F>],
    n: usize,
) -> Vec<FpVar<F>> {
    (0..n)
        .map(|k| {
            let mut out = a.get(k).cloned().unwrap_or_else(FpVar::zero);
            for (l, w) in widths.iter().enumerate() {
                if let Some(v) = k.checked_sub(l + 1).and_then(|at| b.get(at)) {
                    out += w * v;
                }
            }
            out
        })
        .collect()
}

/// Constructs and hashes `RLP([HP(key[consumed..], leaf), value])`.
///
/// `value` is a left-aligned bounded buffer; its tail past `value_len` must be
/// zero, which the leaf hash enforces. The remaining path is the key's
/// nibbles from `consumed` to `2 * key_len`, and must be at most the key
/// buffer's width.
pub fn hash_value_leaf_from_remainder_with<F: PrimeField, B: PermutationBackend<F>>(
    value: &[UInt8<F>],
    value_len: &FpVar<F>,
    keys: &KeyNibbles<F>,
    key_len: &FpVar<F>,
    consumed: &FpVar<F>,
    backend: &mut B,
) -> Result<[Byte<F>; 32], SynthesisError> {
    assert!(!value.is_empty() && value.len() < 1 << 16);
    // The value must end inside its buffer, or the leaf would absorb bytes
    // past it that no caller parses.
    to_bits_bounded(&(constant::<F>(value.len() as u64) - value_len), 16)?;
    // Nibble reads past the key buffer return zero, so the length they are
    // measured against must not exceed it.
    to_bits_bounded(&(constant::<F>(keys.len() as u64 / 2) - key_len), 8)?;

    let bare = value_len.is_eq(&FpVar::one())? & !value[0].to_bits_le()?[7].clone();
    let value_header = header(value_len, 0x80, &bare)?;

    // Path item: HP(remaining nibbles, leaf), bare when it is one byte. The
    // remainder being in range is what bounds `key_len` and `consumed`.
    let remaining = key_len * constant::<F>(2) - consumed;
    let remainder = one_hot_in_range(&remaining, keys.len() + 1, &Boolean::TRUE)?;
    let position = keys.position(consumed)?;
    let nibble: Vec<FpVar<F>> = (0..keys.len()).map(|t| keys.at(&position, t)).collect();
    let mut item = vec![FpVar::zero(); 2 + keys.len() / 2];
    let mut item_widths = vec![FpVar::zero(); item.len()];
    for (n, selected) in remainder.iter().enumerate() {
        let mut hp = vec![if n % 2 == 1 {
            &nibble[0] + constant::<F>(0x30)
        } else {
            constant(0x20)
        }];
        let mut t = n % 2;
        while t < n {
            hp.push(&nibble[t] * constant::<F>(16) + &nibble[t + 1]);
            t += 2;
        }
        if hp.len() > 1 {
            hp.insert(0, constant(0x80 + hp.len() as u64));
        }
        let s = FpVar::from(selected.clone());
        for (out, v) in item.iter_mut().zip(hp.iter()) {
            *out += &s * v;
        }
        item_widths[hp.len() - 1] += &s;
    }
    let item_len = item_widths
        .iter()
        .enumerate()
        .fold(FpVar::zero(), |acc, (l, w)| acc + w * constant::<F>(l as u64 + 1));

    let body = &item_len + &value_header.len + value_len;
    let list_header = header(&body, 0xc0, &Boolean::FALSE)?;

    let head_len = list_header.bytes.len() + item.len();
    let head = concat(&list_header.bytes, &list_header.width, &item, head_len);
    let mut head_widths = vec![FpVar::zero(); head_len];
    for (a, wa) in list_header.width.iter().enumerate() {
        for (b, wb) in item_widths.iter().enumerate() {
            head_widths[a + b + 1] += wa * wb;
        }
    }
    let framing = concat(&head, &head_widths, &value_header.bytes, MAX_FRAMING);
    let framing_len = list_header.len + item_len + value_header.len;

    let width = value.len() + MAX_FRAMING;
    let placed = shift_right(&to_fields(value)?, &framing_len, width, 4)?;
    let leaf = placed
        .iter()
        .enumerate()
        .map(|(i, v)| match framing.get(i) {
            Some(f) => field_to_byte(&(f + v)),
            None => field_to_byte(v),
        })
        .collect::<Result<Vec<_>, _>>()?;
    keccak256_var_with(&leaf, &(framing_len + value_len), backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::gr1cs::ConstraintSystem;

    use crate::bytes::alloc_bounded;
    use crate::keccak::DirectPermutation;
    use crate::mpt::tests::leaf_node;

    const KEY: [u8; 3] = [0x82, 0x10, 0x00];
    const KEY_NIBBLES: [u8; 6] = [8, 2, 1, 0, 0, 0];

    /// Builds the leaf gadget and returns its digest and satisfiability.
    fn run(value: &[u8], bound: usize, len: u64, key_len: u64, consumed: u64) -> ([u8; 32], bool) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), value, bound).unwrap();
        let value_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(len))).unwrap();
        let key = alloc_bounded(cs.clone(), &KEY, 3).unwrap();
        let keys = KeyNibbles::new(&key).unwrap();
        let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(key_len))).unwrap();
        let consumed = FpVar::new_witness(cs.clone(), || Ok(Fr::from(consumed))).unwrap();
        let digest = hash_value_leaf_from_remainder_with(
            &buf,
            &value_len,
            &keys,
            &key_len,
            &consumed,
            &mut DirectPermutation,
        )
        .unwrap();
        let got = core::array::from_fn(|i| {
            digest[i]
                .iter()
                .enumerate()
                .fold(0u8, |v, (b, bit)| v | ((bit.value().unwrap() as u8) << b))
        });
        (got, cs.is_satisfied().unwrap())
    }

    /// Covers both string-header and list-header transitions at every
    /// remaining path width, against an independent native encoder.
    #[test]
    fn matches_canonical_rlp_at_length_boundaries() {
        for len in [
            0usize, 1, 2, 49, 50, 51, 52, 53, 54, 55, 56, 245, 249, 250, 251, 252, 253, 254, 255,
            256, 396,
        ] {
            for consumed in 0..=6 {
                let value = vec![if len == 1 { 0x80 } else { 0x42 }; len];
                let (got, ok) = run(&value, 396, len as u64, 3, consumed as u64);
                let leaf = leaf_node(&KEY_NIBBLES[consumed..], &value);
                assert_eq!(
                    got,
                    mirage_encoding::keccak256(&leaf),
                    "length {len}, consumed {consumed}"
                );
                assert!(ok, "length {len}, consumed {consumed} unsatisfied");
            }
        }
    }

    #[test]
    fn a_single_low_byte_is_its_own_encoding() {
        for byte in [0x00u8, 0x7f, 0x80, 0xff] {
            let (got, ok) = run(&[byte], 8, 1, 3, 2);
            assert_eq!(got, mirage_encoding::keccak256(&leaf_node(&KEY_NIBBLES[2..], &[byte])));
            assert!(ok);
        }
    }

    #[test]
    fn rejects_a_value_past_its_buffer() {
        let (_, ok) = run(&[0x42; 8], 8, 9, 3, 0);
        assert!(!ok, "accepted a value length past the buffer");
    }

    #[test]
    fn rejects_a_key_length_past_its_buffer() {
        let (_, ok) = run(&[0x42; 8], 8, 8, 4, 6);
        assert!(!ok, "accepted a key length past the buffer");
    }

    #[test]
    fn rejects_a_remainder_past_the_key() {
        let (_, ok) = run(&[0x42; 8], 8, 8, 3, 7);
        assert!(!ok, "accepted a position past the key");
    }

    #[test]
    fn cost() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &[0x42; 300], 396).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(300u64))).unwrap();
        let key = alloc_bounded(cs.clone(), &KEY, 3).unwrap();
        let key_len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();
        let consumed = FpVar::new_witness(cs.clone(), || Ok(Fr::from(4u64))).unwrap();
        let before = cs.num_constraints();
        let keys = KeyNibbles::new(&key).unwrap();
        let _ = hash_value_leaf_from_remainder_with(
            &buf,
            &len,
            &keys,
            &key_len,
            &consumed,
            &mut DirectPermutation,
        )
        .unwrap();
        println!(
            "constructed leaf, 396 B value: {} constraints",
            cs.num_constraints() - before
        );
    }
}
