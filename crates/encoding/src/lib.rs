//! Byte-exact encoders for the commitment and statement preimages.
//!
//! This is the native reference implementation. It runs outside any circuit and
//! is the authority the in-circuit gadgets and the Solidity contract are both
//! checked against, via the deterministic vectors in `test/vectors/`.
//!
//! Spec sections 8.3 (intent commitment) and 10.2 (statement hash). Both
//! preimages are fixed-width and byte-exact: `abi.encodePacked` with the widths
//! listed below and nothing variable-length. A one-byte disagreement between
//! this crate, the circuit, and the contract surfaces only as "proof rejected",
//! with no indication of which side is wrong.
//!
//! Changing any encoding here is a new circuit version under spec Section 18.4.

pub mod commitment;
pub mod statement;
pub mod vectors;

use tiny_keccak::{Hasher, Keccak};

/// Protocol relation version, the leading byte of both preimages.
pub const RELATION_VERSION: u8 = 2;

/// Settlement asset kind, spec 8.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetKind {
    Native = 0,
    Erc20 = 1,
}

pub type Address = [u8; 20];
pub type Bytes32 = [u8; 32];

/// Keccak-256 over `input`.
///
/// The circuit gadget must agree with this on every vector. Note this is
/// Ethereum keccak256 (padding delimiter `0x01`), not NIST SHA3-256 (`0x06`) —
/// the distinction that makes most off-the-shelf gadgets unusable here.
pub fn keccak256(input: &[u8]) -> Bytes32 {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut out);
    out
}

/// Splits a 32-byte big-endian value into the high and low 128-bit limbs the
/// circuit uses.
///
/// Spec 8.1: one BN254 field element cannot represent every 256-bit value, so
/// arbitrary 256-bit inputs are carried as two range-constrained limbs and
/// never reduced modulo the field order.
pub fn split_limbs(value: &Bytes32) -> (u128, u128) {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&value[0..16]);
    lo.copy_from_slice(&value[16..32]);
    (u128::from_be_bytes(hi), u128::from_be_bytes(lo))
}

/// Rejoins two 128-bit limbs into the original 32 big-endian bytes.
pub fn join_limbs(hi: u128, lo: u128) -> Bytes32 {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&hi.to_be_bytes());
    out[16..32].copy_from_slice(&lo.to_be_bytes());
    out
}

/// Big-endian 32-byte encoding of a `u64`, left-padded.
///
/// Used for chain ID, which Solidity encodes as `uint256` even though the
/// circuit constrains it below 2^64.
pub fn u64_to_word(value: u64) -> Bytes32 {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_matches_known_vector() {
        // keccak256("") — the standard empty-input digest. If this fails, the
        // hasher is SHA3, not Ethereum keccak.
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn transfer_topic0_is_canonical() {
        assert_eq!(
            hex::encode(keccak256(b"Transfer(address,address,uint256)")),
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    #[test]
    fn limbs_round_trip() {
        let value = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4,
            0xc3, 0xd2, 0xe1, 0xf0,
        ];
        let (hi, lo) = split_limbs(&value);
        assert_eq!(join_limbs(hi, lo), value);
    }

    #[test]
    fn limbs_split_at_the_boundary() {
        // 2^128 exactly: hi = 1, lo = 0. The boundary case spec 19.1 requires.
        let mut value = [0u8; 32];
        value[15] = 1;
        assert_eq!(split_limbs(&value), (1, 0));

        // 2^128 - 1: hi = 0, lo = u128::MAX.
        let mut value = [0u8; 32];
        value[16..32].copy_from_slice(&[0xff; 16]);
        assert_eq!(split_limbs(&value), (0, u128::MAX));
    }
}
