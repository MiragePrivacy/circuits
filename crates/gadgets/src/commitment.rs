//! The intent commitment, spec 8.3.
//!
//! ```text
//! intentCommitment = keccak256(abi.encodePacked(
//!     uint8(2),                 // relation version
//!     instanceDomain,           // 32 bytes
//!     uint256(chainId),         // 32 bytes, left-padded
//!     predictedEscrow,          // 20 bytes
//!     requestId,                // 32 bytes
//!     uint32(rowIndex),         // 4 bytes
//!     uint8(assetKind),         // 1 byte
//!     settlementToken,          // 20 bytes, zero when native
//!     recipient,                // 20 bytes
//!     settlementAmount,         // 32 bytes
//!     salt                      // 32 bytes
//! ))
//! ```
//!
//! # Why this closes the relation
//!
//! Without it, the settlement token, recipient, and amount are free witnesses:
//! a prover supplies any triple and proves a Transfer matching it. That is the
//! difference between "some Transfer happened" and "the Transfer this escrow
//! committed to happened".
//!
//! The escrow stores only the commitment. The circuit opens it privately and
//! shows the opened values are the ones the receipt log carries, which is what
//! ties the two halves of the relation together.
//!
//! # The salt
//!
//! `salt` is what makes the commitment hiding. Without it an observer could
//! guess a plausible `(token, recipient, amount)` and check the guess against
//! the stored commitment — recipients and round amounts are drawn from small
//! spaces. Spec 8.2 requires it be CSPRNG-generated per row.
//!
//! # The escrow address
//!
//! Binding `predictedEscrow` is what stops a proof generated for one deployment
//! authorizing another. Two escrows committing the same settlement still
//! produce different commitments, so a proof is not portable between them.
//!
//! Note what this does *not* provide: it binds the proof to one escrow, but
//! does not stop a second escrow being deployed with an identical intent and
//! independently proven against the same on-chain Transfer. Spec 9 records why
//! that gap is unreachable under the stated constraints.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::gr1cs::SynthesisError;

use crate::keccak::sponge::to_bytes;
use crate::keccak::{keccak256_fixed_with, DirectPermutation, PermutationBackend};

/// Byte width of the spec 8.3 preimage.
pub const PREIMAGE_LEN: usize = 226;

/// Protocol relation version, the preimage's leading byte.
pub const RELATION_VERSION: u8 = 2;

/// Settlement asset kind, spec 8.3.
pub const ASSET_KIND_NATIVE: u8 = 0;
pub const ASSET_KIND_ERC20: u8 = 1;

/// The commitment's private opening.
pub struct Opening<F: PrimeField> {
    /// 32 bytes.
    pub instance_domain: Vec<UInt8<F>>,
    /// 32 bytes, left-padded chain ID.
    pub chain_id: Vec<UInt8<F>>,
    /// 20 bytes.
    pub escrow: Vec<UInt8<F>>,
    /// 32 bytes.
    pub request_id: Vec<UInt8<F>>,
    /// 4 bytes, big-endian.
    pub row_index: Vec<UInt8<F>>,
    /// 1 byte: 0 native, 1 ERC-20.
    pub asset_kind: UInt8<F>,
    /// 20 bytes. Must be zero when `asset_kind` is native.
    pub settlement_token: Vec<UInt8<F>>,
    /// 20 bytes.
    pub recipient: Vec<UInt8<F>>,
    /// 32 bytes, big-endian.
    pub settlement_amount: Vec<UInt8<F>>,
    /// 32 bytes.
    pub salt: Vec<UInt8<F>>,
}

impl<F: PrimeField> Opening<F> {
    /// The packed preimage, in spec 8.3 order.
    pub fn preimage(&self) -> Vec<UInt8<F>> {
        let parts: [(&Vec<UInt8<F>>, usize); 5] = [
            (&self.instance_domain, 32),
            (&self.chain_id, 32),
            (&self.escrow, 20),
            (&self.request_id, 32),
            (&self.row_index, 4),
        ];
        let tail: [(&Vec<UInt8<F>>, usize); 4] = [
            (&self.settlement_token, 20),
            (&self.recipient, 20),
            (&self.settlement_amount, 32),
            (&self.salt, 32),
        ];

        let mut out = Vec::with_capacity(PREIMAGE_LEN);
        out.push(UInt8::constant(RELATION_VERSION));
        for (bytes, width) in parts {
            assert_eq!(bytes.len(), width, "commitment field has the wrong width");
            out.extend_from_slice(bytes);
        }
        out.push(self.asset_kind.clone());
        for (bytes, width) in tail {
            assert_eq!(bytes.len(), width, "commitment field has the wrong width");
            out.extend_from_slice(bytes);
        }
        debug_assert_eq!(out.len(), PREIMAGE_LEN);
        out
    }
}

/// Opens the commitment and enforces the spec 12.3 intent assertions.
///
/// Enforced:
/// - the recomputed hash equals `commitment`
/// - `assetKind` is 0 or 1
/// - a native row carries an all-zero token; an ERC-20 row does not
/// - the recipient is nonzero
/// - the amount is greater than zero
///
/// The caller is responsible for using the opened token, recipient, and amount
/// as the intent the receipt relation checks against. Opening the commitment
/// and then checking the log against *different* values would defeat the whole
/// exercise.
pub fn open<F: PrimeField>(
    opening: &Opening<F>,
    commitment: &[UInt8<F>],
    active: &Boolean<F>,
) -> Result<(), SynthesisError> {
    open_with(opening, commitment, active, &mut DirectPermutation)
}

pub fn open_with<F: PrimeField, B: PermutationBackend<F>>(
    opening: &Opening<F>,
    commitment: &[UInt8<F>],
    active: &Boolean<F>,
    backend: &mut B,
) -> Result<(), SynthesisError> {
    assert_eq!(commitment.len(), 32, "commitment must be 32 bytes");

    let digest_bits = keccak256_fixed_with(&to_bytes(&opening.preimage())?, backend)?;
    for (bits, want) in digest_bits.iter().zip(commitment.iter()) {
        UInt8::from_bits_le(bits).conditional_enforce_equal(want, active)?;
    }

    // assetKind is 0 or 1.
    let is_native = opening
        .asset_kind
        .is_eq(&UInt8::constant(ASSET_KIND_NATIVE))?;
    let is_erc20 = opening
        .asset_kind
        .is_eq(&UInt8::constant(ASSET_KIND_ERC20))?;
    (is_native.clone() | is_erc20).conditional_enforce_equal(&Boolean::TRUE, active)?;

    // A native row's token must be exactly zero; an ERC-20 row's must not be.
    // Without the first, a native commitment could smuggle a token address
    // past a relation that only checks the asset kind.
    let zero = UInt8::constant(0);
    let mut token_is_zero = Boolean::TRUE;
    for byte in &opening.settlement_token {
        token_is_zero &= byte.is_eq(&zero)?;
    }
    token_is_zero.conditional_enforce_equal(&is_native, active)?;

    // The recipient is nonzero: a Transfer to the zero address is a burn, not
    // a settlement.
    let mut recipient_is_zero = Boolean::TRUE;
    for byte in &opening.recipient {
        recipient_is_zero &= byte.is_eq(&zero)?;
    }
    recipient_is_zero.conditional_enforce_equal(&Boolean::FALSE, active)?;

    // The amount is greater than zero.
    let mut amount_is_zero = Boolean::TRUE;
    for byte in &opening.settlement_amount {
        amount_is_zero &= byte.is_eq(&zero)?;
    }
    amount_is_zero.conditional_enforce_equal(&Boolean::FALSE, active)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::{ConstraintSystem, ConstraintSystemRef};

    use crate::bytes::alloc_bounded;
    use mirage_encoding::commitment::Intent as NativeIntent;
    use mirage_encoding::AssetKind;

    fn native_sample() -> NativeIntent {
        NativeIntent {
            instance_domain: [0x11; 32],
            chain_id: 1,
            escrow: [0x22; 20],
            request_id: [0x33; 32],
            row_index: 5,
            asset_kind: AssetKind::Erc20,
            settlement_token: [0x44; 20],
            recipient: [0x55; 20],
            settlement_amount: {
                let mut a = [0u8; 32];
                a[24..].copy_from_slice(&1_000_000u64.to_be_bytes());
                a
            },
            salt: [0x66; 32],
        }
    }

    fn alloc(cs: ConstraintSystemRef<Fr>, i: &NativeIntent) -> Opening<Fr> {
        let b = |v: &[u8], n: usize| alloc_bounded(cs.clone(), v, n).unwrap();
        Opening {
            instance_domain: b(&i.instance_domain, 32),
            chain_id: b(&mirage_encoding::u64_to_word(i.chain_id), 32),
            escrow: b(&i.escrow, 20),
            request_id: b(&i.request_id, 32),
            row_index: b(&i.row_index.to_be_bytes(), 4),
            asset_kind: b(&[i.asset_kind as u8], 1)[0].clone(),
            settlement_token: b(&i.settlement_token, 20),
            recipient: b(&i.recipient, 20),
            settlement_amount: b(&i.settlement_amount, 32),
            salt: b(&i.salt, 32),
        }
    }

    fn run(i: &NativeIntent, commitment: [u8; 32]) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let opening = alloc(cs.clone(), i);
        let c = alloc_bounded(cs.clone(), &commitment, 32).unwrap();
        match open(&opening, &c, &Boolean::TRUE) {
            Err(_) => false,
            Ok(()) => cs.is_satisfied().unwrap_or(false),
        }
    }

    /// The circuit must agree with the native encoder byte for byte.
    #[test]
    fn preimage_matches_the_native_encoder() {
        let i = native_sample();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let opening = alloc(cs.clone(), &i);
        let got: Vec<u8> = opening
            .preimage()
            .iter()
            .map(|b| b.value().unwrap())
            .collect();
        assert_eq!(got.len(), PREIMAGE_LEN);
        assert_eq!(got, i.preimage().to_vec(), "preimage bytes differ");
    }

    #[test]
    fn opens_a_genuine_commitment() {
        let i = native_sample();
        assert!(run(&i, i.commitment()), "rejected a genuine opening");
    }

    #[test]
    fn opens_a_native_commitment() {
        let mut i = native_sample();
        i.asset_kind = AssetKind::Native;
        i.settlement_token = [0u8; 20];
        assert!(run(&i, i.commitment()), "rejected a genuine native opening");
    }

    /// **Forgery: an opening that does not match the commitment.**
    ///
    /// The whole point. A prover who could supply any opening would prove a
    /// Transfer of its own choosing.
    #[test]
    fn rejects_a_mismatched_opening() {
        let i = native_sample();
        let mut wrong = i.commitment();
        wrong[0] ^= 0xff;
        assert!(
            !run(&i, wrong),
            "accepted an opening against a wrong commitment"
        );
    }

    /// **Forgery: swapping the recipient while keeping the commitment.**
    ///
    /// The concrete attack the gadget prevents: prove a Transfer to an address
    /// the escrow never committed to.
    #[test]
    fn rejects_a_substituted_recipient() {
        let i = native_sample();
        let commitment = i.commitment();
        let mut attacker = i.clone();
        attacker.recipient = [0xee; 20];
        assert!(
            !run(&attacker, commitment),
            "accepted a substituted recipient"
        );
    }

    /// **Forgery: a native row carrying a token address.**
    #[test]
    fn rejects_native_with_a_token() {
        let mut i = native_sample();
        i.asset_kind = AssetKind::Native;
        // Commitment computed over the inconsistent opening, so the hash
        // matches; only the intent assertion can catch it.
        assert!(
            !run(&i, i.commitment()),
            "accepted a native row with a token"
        );
    }

    /// **Forgery: an ERC-20 row with a zero token.**
    #[test]
    fn rejects_erc20_without_a_token() {
        let mut i = native_sample();
        i.settlement_token = [0u8; 20];
        assert!(
            !run(&i, i.commitment()),
            "accepted an ERC-20 row with no token"
        );
    }

    /// **Forgery: a zero recipient.**
    #[test]
    fn rejects_zero_recipient() {
        let mut i = native_sample();
        i.recipient = [0u8; 20];
        assert!(!run(&i, i.commitment()), "accepted a zero recipient");
    }

    /// **Forgery: a zero amount.**
    #[test]
    fn rejects_zero_amount() {
        let mut i = native_sample();
        i.settlement_amount = [0u8; 32];
        assert!(!run(&i, i.commitment()), "accepted a zero amount");
    }

    /// **Forgery: an out-of-range asset kind.**
    #[test]
    fn rejects_unknown_asset_kind() {
        let i = native_sample();
        let commitment = i.commitment();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut opening = alloc(cs.clone(), &i);
        opening.asset_kind = UInt8::constant(7);
        let c = alloc_bounded(cs.clone(), &commitment, 32).unwrap();
        let _ = open(&opening, &c, &Boolean::TRUE);
        assert!(!cs.is_satisfied().unwrap(), "accepted asset kind 7");
    }

    /// The escrow address binds the proof to one deployment.
    #[test]
    fn escrow_address_changes_the_commitment() {
        let a = native_sample();
        let mut b = native_sample();
        b.escrow = [0x23; 20];
        assert_ne!(a.commitment(), b.commitment());
        assert!(
            !run(&b, a.commitment()),
            "proof was portable between escrows"
        );
    }

    #[test]
    fn cost() {
        let i = native_sample();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let opening = alloc(cs.clone(), &i);
        let c = alloc_bounded(cs.clone(), &i.commitment(), 32).unwrap();
        let before = cs.num_constraints();
        open(&opening, &c, &Boolean::TRUE).unwrap();
        println!(
            "commitment open ({PREIMAGE_LEN} byte preimage): {} constraints",
            cs.num_constraints() - before
        );
    }
}
