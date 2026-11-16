//! Block header parsing, spec 12.7.1.
//!
//! The Ethereum-mainnet post-Prague header is a 21-item RLP list:
//!
//! ```text
//! [parentHash, ommersHash, beneficiary, stateRoot, transactionsRoot,
//!  receiptsRoot, logsBloom, difficulty, number, gasLimit, gasUsed,
//!  timestamp, extraData, prevRandao, nonce, baseFeePerGas,
//!  withdrawalsRoot, blobGasUsed, excessBlobGas,
//!  parentBeaconBlockRoot, requestsHash]
//! ```
//!
//! The ERC-20 relation needs two fields: `receiptsRoot` at index 5, which the
//! MPT traversal authenticates against, and `number` at index 8, which the
//! timing assertions use. The native relation additionally reads
//! `transactionsRoot` at index 4 for its second trie. The ancestry chain in
//! [`crate::ancestry`] reads `parentHash` at index 0.
//!
//! # Why the field count is enforced
//!
//! A header with a different item count is a different fork's schema, and its
//! field positions differ. Reading index 5 of a 20-item header returns
//! `logsBloom` where `receiptsRoot` was expected, so the count check is what
//! makes the fixed indices meaningful. Spec 12.7.1: unknown future header
//! layouts fail closed.
//!
//! # Cost
//!
//! `decode_list(21)` is 21 `decode_item` calls at ~41.5k each over a bounded
//! buffer. The header bound therefore matters as much here as elsewhere: a
//! mainnet header is around 600 bytes, so `MAX_HEADER_BYTES = 1024` carries
//! meaningful unusable headroom.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use crate::bytes::{le, select_bytes, zero_like};
use crate::rlp::{cursor::Cursor, RlpDecoder};

/// Field indices in the frozen 21-field schema.
pub const IDX_PARENT_HASH: usize = 0;
pub const IDX_TRANSACTIONS_ROOT: usize = 4;
pub const IDX_RECEIPTS_ROOT: usize = 5;
pub const IDX_NUMBER: usize = 8;
pub const FIELD_COUNT: usize = 21;

/// The header fields step 2 consumes.
pub struct Header<F: PrimeField> {
    /// 32 bytes.
    pub parent_hash: Vec<UInt8<F>>,
    /// 32 bytes.
    pub receipts_root: Vec<UInt8<F>>,
    /// 32 bytes. The native relation's second trie hangs from this.
    pub transactions_root: Vec<UInt8<F>>,
    /// The block number, as a field element.
    pub number: FpVar<F>,
}

/// Parses a bounded header buffer.
///
/// Enforces the exact 21-item count, that the list spans the whole header, and
/// that the fixed-length fields have their consensus lengths. `decode_list`
/// supplies canonical-form and tiling checks.
pub fn parse<F: PrimeField>(
    header: &[UInt8<F>],
    header_len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<Header<F>, SynthesisError> {
    let zero = zero_like(header)?;

    // Exactly 21 items. A different count is a different fork's schema, and
    // every fixed index below would then read the wrong field.
    let items = Cursor::decode_list(header, &zero, FIELD_COUNT, active)?;

    // The list must span the whole header: no trailing bytes.
    let list = Cursor::decode_item(header, &zero, active)?;
    list.is_list
        .conditional_enforce_equal(&Boolean::TRUE, active)?;
    list.end().conditional_enforce_equal(header_len, active)?;

    // The three 32-byte hash fields this build reads.
    for idx in [IDX_PARENT_HASH, IDX_TRANSACTIONS_ROOT, IDX_RECEIPTS_ROOT] {
        items[idx]
            .payload_len
            .conditional_enforce_equal(&FpVar::constant(F::from(32u64)), active)?;
    }

    let parent_hash = select_bytes(header, &items[IDX_PARENT_HASH].offset, 32)?;
    let receipts_root = select_bytes(header, &items[IDX_RECEIPTS_ROOT].offset, 32)?;
    let transactions_root = select_bytes(header, &items[IDX_TRANSACTIONS_ROOT].offset, 32)?;

    // The block number is a canonical RLP integer below 2^64, so at most 8
    // payload bytes. The decoder rejects non-canonical encodings, so a short
    // field cannot carry leading zeros.
    let num_item = &items[IDX_NUMBER];
    let num_fits = le(&num_item.payload_len, &FpVar::constant(F::from(8u64)))?;
    num_fits.conditional_enforce_equal(&Boolean::TRUE, active)?;
    let number = big_endian_value(header, &num_item.offset, &num_item.payload_len, 8)?;

    Ok(Header {
        parent_hash,
        receipts_root,
        transactions_root,
        number,
    })
}

/// The byte ranges [`parse_authenticated_prefix`] reads. A buffer passed to it
/// may hold placeholders anywhere else.
pub const AUTHENTICATED_PREFIX_READS: [core::ops::Range<usize>; 2] = [0..192, 448..458];

/// Extracts the fields before the first variable-width header item using the
/// fixed post-Prague prefix layout.
///
/// This variant is sound only when the caller separately proves that
/// `keccak256(header)` is a canonical chain block hash. Consensus then supplies
/// the full-header validity that [`parse`] establishes syntactically. The
/// circuit still pins every fixed prefix through `difficulty` and canonically
/// decodes `number`; an unknown fork that changes this prefix fails closed.
pub fn parse_authenticated_prefix<F: PrimeField>(
    header: &[UInt8<F>],
    _header_len: &FpVar<F>,
    active: &Boolean<F>,
) -> Result<Header<F>, SynthesisError> {
    // Two-byte long-list length, followed by the fixed-width fields through
    // post-Merge difficulty. Payload length bytes remain variable.
    for (at, want) in [
        (0usize, 0xf9u8),
        (3, 0xa0),  // parentHash
        (36, 0xa0), // ommersHash
        (69, 0x94), // beneficiary
        (90, 0xa0), // stateRoot
        (123, 0xa0), // transactionsRoot
        (156, 0xa0), // receiptsRoot
        (189, 0xb9), // logsBloom, 256 bytes
        (190, 0x01),
        (191, 0x00),
        (448, 0x80), // post-Merge difficulty == 0
    ] {
        header[at].conditional_enforce_equal(&UInt8::constant(want), active)?;
    }

    let parent_hash = header[4..36].to_vec();
    let transactions_root = header[124..156].to_vec();
    let receipts_root = header[157..189].to_vec();

    // Number begins at a compile-time offset. Enumerating its at-most-eight
    // byte canonical integer forms is dramatically cheaper than walking the
    // other twenty RLP items to discover the same offset.
    let prefix = &header[449];
    let bits = {
        use ark_r1cs_std::convert::ToBitsGadget;
        prefix.to_bits_le()?
    };
    let bare = !bits[7].clone();
    let mut accepted = bare.clone();
    let mut number = crate::bytes::byte_to_field(prefix)?;

    for width in 1usize..=8 {
        let selected = prefix.is_eq(&UInt8::constant(0x80 + width as u8))?;
        accepted |= selected.clone();

        let mut value = FpVar::zero();
        for byte in &header[450..450 + width] {
            value = value * FpVar::constant(F::from(256u64))
                + crate::bytes::byte_to_field(byte)?;
        }
        number = FpVar::conditionally_select(&selected, &value, &number)?;

        // Minimal integer encoding, beyond ordinary canonical RLP: a one-byte
        // payload below 0x80 is bare, and a wider integer has no leading zero.
        if width == 1 {
            let first_bits = header[450].to_bits_le()?;
            first_bits[7].conditional_enforce_equal(&Boolean::TRUE, &(active.clone() & selected))?;
        } else {
            let first_is_zero = header[450].is_eq(&UInt8::constant(0))?;
            first_is_zero.conditional_enforce_equal(
                &Boolean::FALSE,
                &(active.clone() & selected),
            )?;
        }
    }
    accepted.conditional_enforce_equal(&Boolean::TRUE, active)?;

    Ok(Header {
        parent_hash,
        receipts_root,
        transactions_root,
        number,
    })
}

/// Reads up to `max` bytes at `offset` as a big-endian integer, honouring a
/// witnessed length.
///
/// Bytes past `len` contribute nothing, and the accumulator only shifts while
/// inside the field, so a 3-byte number reads the same whether the buffer holds
/// 3 bytes or 8.
fn big_endian_value<F: PrimeField>(
    buf: &[UInt8<F>],
    offset: &FpVar<F>,
    len: &FpVar<F>,
    max: usize,
) -> Result<FpVar<F>, SynthesisError> {
    use ark_r1cs_std::select::CondSelectGadget;

    let bytes = select_bytes(buf, offset, max)?;
    let mut acc = FpVar::zero();
    for (i, byte) in bytes.iter().enumerate() {
        let within = crate::bytes::lt(&FpVar::constant(F::from(i as u64)), len)?;
        let v = crate::bytes::byte_to_field(byte)?;
        let contrib = FpVar::conditionally_select(&within, &v, &FpVar::zero())?;
        let shifted =
            FpVar::conditionally_select(&within, &(&acc * FpVar::constant(F::from(256u64))), &acc)?;
        acc = shifted + contrib;
    }
    Ok(acc)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;

    use crate::bytes::alloc_bounded;

    const BOUND: usize = 1024;

    fn enc_str(p: &[u8]) -> Vec<u8> {
        if p.len() == 1 && p[0] < 0x80 {
            return p.to_vec();
        }
        let mut out = Vec::new();
        if p.len() < 56 {
            out.push(0x80 + p.len() as u8);
        } else {
            let lb = trim(&p.len().to_be_bytes());
            out.push(0xb7 + lb.len() as u8);
            out.extend_from_slice(&lb);
        }
        out.extend_from_slice(p);
        out
    }

    fn enc_list(c: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = c.concat();
        let mut out = Vec::new();
        if body.len() < 56 {
            out.push(0xc0 + body.len() as u8);
        } else {
            let lb = trim(&body.len().to_be_bytes());
            out.push(0xf7 + lb.len() as u8);
            out.extend_from_slice(&lb);
        }
        out.extend_from_slice(&body);
        out
    }

    fn trim(b: &[u8]) -> Vec<u8> {
        let first = b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1);
        b[first..].to_vec()
    }

    /// A 21-field header with recognisable roots and a given block number.
    pub fn header_fixture(receipts_root: &[u8; 32], number: u64) -> Vec<u8> {
        header_with_parent(&[0x01; 32], receipts_root, number)
    }

    /// [`header_fixture`] with a chosen `parentHash`.
    pub(crate) fn header_with_parent(
        parent_hash: &[u8; 32],
        receipts_root: &[u8; 32],
        number: u64,
    ) -> Vec<u8> {
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(FIELD_COUNT);
        fields.push(enc_str(parent_hash)); // parentHash
        fields.push(enc_str(&[0x02; 32])); // ommersHash
        fields.push(enc_str(&[0x03; 20])); // beneficiary
        fields.push(enc_str(&[0x04; 32])); // stateRoot
        fields.push(enc_str(&[0x05; 32])); // transactionsRoot
        fields.push(enc_str(receipts_root)); // receiptsRoot
        fields.push(enc_str(&[0u8; 256])); // logsBloom
        fields.push(enc_str(&[])); // difficulty
        fields.push(enc_str(&trim(&number.to_be_bytes()))); // number
        fields.push(enc_str(&[0x01, 0xc9, 0xc3, 0x80])); // gasLimit
        fields.push(enc_str(&[0x52, 0x08])); // gasUsed
        fields.push(enc_str(&[0x66, 0x00, 0x00, 0x00])); // timestamp
        fields.push(enc_str(&[])); // extraData
        fields.push(enc_str(&[0x06; 32])); // prevRandao
        fields.push(enc_str(&[0u8; 8])); // nonce
        fields.push(enc_str(&[0x07])); // baseFeePerGas
        fields.push(enc_str(&[0x08; 32])); // withdrawalsRoot
        fields.push(enc_str(&[])); // blobGasUsed
        fields.push(enc_str(&[])); // excessBlobGas
        fields.push(enc_str(&[0x09; 32])); // parentBeaconBlockRoot
        fields.push(enc_str(&[0x0a; 32])); // requestsHash
        assert_eq!(fields.len(), FIELD_COUNT);
        enc_list(&fields)
    }

    fn run(bytes: &[u8]) -> (bool, Option<Header<Fr>>) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), bytes, BOUND).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(bytes.len() as u64))).unwrap();
        match parse(&buf, &len, &Boolean::TRUE) {
            Err(_) => (false, None),
            Ok(h) => (cs.is_satisfied().unwrap_or(false), Some(h)),
        }
    }

    #[test]
    fn parses_a_canonical_header() {
        let root = [0xab; 32];
        let (ok, h) = run(&header_fixture(&root, 21_000_000));
        assert!(ok, "rejected a canonical 21-field header");
        let h = h.unwrap();

        let got: Vec<u8> = h.receipts_root.iter().map(|b| b.value().unwrap()).collect();
        assert_eq!(got, root.to_vec(), "receiptsRoot");
        assert_eq!(h.number.value().unwrap(), Fr::from(21_000_000u64), "number");
    }

    #[test]
    fn authenticated_prefix_matches_the_full_parser() {
        let root = [0xab; 32];
        let bytes = header_fixture(&root, 21_000_000);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &bytes, BOUND).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(bytes.len() as u64))).unwrap();
        let h = parse_authenticated_prefix(&buf, &len, &Boolean::TRUE).unwrap();
        assert_eq!(h.receipts_root.iter().map(|b| b.value().unwrap()).collect::<Vec<_>>(), root);
        assert_eq!(h.transactions_root.iter().map(|b| b.value().unwrap()).collect::<Vec<_>>(), bytes[124..156]);
        assert_eq!(h.number.value().unwrap(), Fr::from(21_000_000u64));
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn authenticated_prefix_rejects_a_shifted_schema() {
        let mut bytes = header_fixture(&[0xab; 32], 21_000_000);
        bytes[156] = 0x9f; // receiptsRoot is no longer a 32-byte string.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &bytes, BOUND).unwrap();
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(bytes.len() as u64))).unwrap();
        let _ = parse_authenticated_prefix(&buf, &len, &Boolean::TRUE).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn reads_small_and_large_block_numbers() {
        for n in [0u64, 1, 255, 256, 21_000_000, u32::MAX as u64] {
            let (ok, h) = run(&header_fixture(&[0xcd; 32], n));
            assert!(ok, "rejected header with number {n}");
            assert_eq!(
                h.unwrap().number.value().unwrap(),
                Fr::from(n),
                "number {n}"
            );
        }
    }

    /// **Forgery: a header with the wrong field count.**
    ///
    /// A different count is a different fork's schema, and every fixed index
    /// reads the wrong field. Spec 12.7.1 requires it fail closed.
    #[test]
    fn rejects_wrong_field_count() {
        let root = [0xab; 32];
        let full = header_fixture(&root, 100);

        // Rebuild with 20 fields by dropping the last.
        let mut fields: Vec<Vec<u8>> = Vec::new();
        for i in 0..FIELD_COUNT - 1 {
            let _ = i;
            fields.push(enc_str(&[0x11; 32]));
        }
        let short = enc_list(&fields);
        assert!(!run(&short).0, "accepted a 20-field header");

        // And 22.
        let mut fields: Vec<Vec<u8>> = Vec::new();
        for _ in 0..FIELD_COUNT + 1 {
            fields.push(enc_str(&[0x11; 32]));
        }
        let long = enc_list(&fields);
        assert!(!run(&long).0, "accepted a 22-field header");

        // The genuine one still parses, so the test is not vacuous.
        assert!(run(&full).0);
    }

    /// **Forgery: a receiptsRoot that is not 32 bytes.**
    ///
    /// A short root shifts every following field.
    #[test]
    fn rejects_short_receipts_root() {
        let mut fields: Vec<Vec<u8>> = Vec::new();
        for i in 0..FIELD_COUNT {
            if i == IDX_RECEIPTS_ROOT {
                fields.push(enc_str(&[0xab; 16]));
            } else {
                fields.push(enc_str(&[0x11; 32]));
            }
        }
        assert!(
            !run(&enc_list(&fields)).0,
            "accepted a 16-byte receiptsRoot"
        );
    }

    /// **Forgery: trailing bytes after the header list.**
    #[test]
    fn rejects_trailing_bytes() {
        let mut h = header_fixture(&[0xab; 32], 100);
        let real_len = h.len();
        h.extend_from_slice(&[0xde, 0xad]);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let buf = alloc_bounded(cs.clone(), &h, BOUND).unwrap();
        // Claim the longer length: the list no longer spans the header.
        let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(h.len() as u64))).unwrap();
        let _ = parse(&buf, &len, &Boolean::TRUE);
        assert!(
            !cs.is_satisfied().unwrap(),
            "accepted a header with trailing bytes"
        );
        let _ = real_len;
    }

    #[test]
    fn cost() {
        let h = header_fixture(&[0xab; 32], 21_000_000);
        for bound in [640usize, 1024] {
            if h.len() > bound {
                continue;
            }
            let cs = ConstraintSystem::<Fr>::new_ref();
            let buf = alloc_bounded(cs.clone(), &h, bound).unwrap();
            let len = FpVar::new_witness(cs.clone(), || Ok(Fr::from(h.len() as u64))).unwrap();
            let before = cs.num_constraints();
            let _ = parse(&buf, &len, &Boolean::TRUE).unwrap();
            println!(
                "header parse, {bound} byte bound: {} constraints (header is {} bytes)",
                cs.num_constraints() - before,
                h.len()
            );
        }
    }
}
