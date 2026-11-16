//! Spec 8.3 commitment derivation for a collected Transfer.
//!
//! Only `settlementToken`, `recipient` and `settlementAmount` come from the
//! real log. The escrow-side fields — instance domain, request ID, escrow
//! address, salt, row index — do not exist for a historical transaction, so
//! they are derived from the transaction hash.
//!
//! That keeps every fixture reproducible from its hash alone while making each
//! commitment distinct, which is what exercises the commitment gadget. A fixed
//! placeholder would leave all 100 commitments differing only in the settlement
//! triple.

use crate::{hash, hex_str};
use serde::{Deserialize, Serialize};

/// The opening and the commitment it produces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub instance_domain: String,
    pub chain_id: u64,
    pub escrow: String,
    pub request_id: String,
    pub row_index: u32,
    pub asset_kind: u8,
    pub settlement_token: String,
    pub recipient: String,
    pub settlement_amount: String,
    pub salt: String,
    /// The packed preimage, emitted so a mismatch identifies whether the
    /// disagreement is in the packing or the hash.
    pub preimage: String,
    pub commitment: String,
}

/// Derives the commitment for one Transfer.
///
/// `amount` is the log's 32-byte data field, big-endian.
pub fn derive(
    tx_hash: &[u8; 32],
    token: &[u8; 20],
    recipient: &[u8; 20],
    amount: &[u8; 32],
) -> Intent {
    derive_kind(
        tx_hash,
        mirage_encoding::AssetKind::Erc20,
        token,
        recipient,
        amount,
    )
}

/// Derives the commitment for one native ETH settlement.
///
/// The token is all-zero, which spec 8.3 requires of a native row and
/// `commitment::open` enforces against the asset kind.
pub fn derive_native(tx_hash: &[u8; 32], recipient: &[u8; 20], amount: &[u8; 32]) -> Intent {
    derive_kind(
        tx_hash,
        mirage_encoding::AssetKind::Native,
        &[0u8; 20],
        recipient,
        amount,
    )
}

fn derive_kind(
    tx_hash: &[u8; 32],
    asset_kind: mirage_encoding::AssetKind,
    token: &[u8; 20],
    recipient: &[u8; 20],
    amount: &[u8; 32],
) -> Intent {
    let d = |tag: &[u8], n: usize| -> Vec<u8> {
        let mut input = tx_hash.to_vec();
        input.extend_from_slice(tag);
        hash(&input)[..n].to_vec()
    };

    let instance_domain = d(b"instance", 32);
    let request_id = d(b"request", 32);
    let salt = d(b"salt", 32);
    let escrow = d(b"escrow", 20);
    // Spread across the 1..32 rows a batch escrow supports.
    let row_index = (tx_hash[0] % 32) as u32;

    let mut preimage = Vec::with_capacity(mirage_encoding::commitment::PREIMAGE_LEN);
    preimage.push(mirage_encoding::RELATION_VERSION);
    preimage.extend_from_slice(&instance_domain);
    preimage.extend_from_slice(&mirage_encoding::u64_to_word(1)); // mainnet
    preimage.extend_from_slice(&escrow);
    preimage.extend_from_slice(&request_id);
    preimage.extend_from_slice(&row_index.to_be_bytes());
    preimage.push(asset_kind as u8);
    preimage.extend_from_slice(token);
    preimage.extend_from_slice(recipient);
    preimage.extend_from_slice(amount);
    preimage.extend_from_slice(&salt);
    debug_assert_eq!(preimage.len(), mirage_encoding::commitment::PREIMAGE_LEN);

    Intent {
        instance_domain: hex_str(&instance_domain),
        chain_id: 1,
        escrow: hex_str(&escrow),
        request_id: hex_str(&request_id),
        row_index,
        asset_kind: asset_kind as u8,
        settlement_token: hex_str(token),
        recipient: hex_str(recipient),
        settlement_amount: hex_str(amount),
        salt: hex_str(&salt),
        preimage: hex_str(&preimage),
        commitment: hex_str(&hash(&preimage)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_encoding::commitment::Intent as NativeIntent;
    use mirage_encoding::AssetKind;

    fn arr<const N: usize>(hexs: &str) -> [u8; N] {
        let b = crate::from_hex(hexs).unwrap();
        let mut out = [0u8; N];
        out.copy_from_slice(&b);
        out
    }

    /// The derived commitment must match `mirage-encoding`'s reference
    /// encoder, which is what the circuit is checked against.
    #[test]
    fn matches_the_reference_encoder() {
        let tx = [0x9a; 32];
        let token = [0x11; 20];
        let recipient = [0x22; 20];
        let mut amount = [0u8; 32];
        amount[24..].copy_from_slice(&1_000_000u64.to_be_bytes());

        let got = derive(&tx, &token, &recipient, &amount);

        let want = NativeIntent {
            instance_domain: arr(&got.instance_domain),
            chain_id: 1,
            escrow: arr(&got.escrow),
            request_id: arr(&got.request_id),
            row_index: got.row_index,
            asset_kind: AssetKind::Erc20,
            settlement_token: token,
            recipient,
            settlement_amount: amount,
            salt: arr(&got.salt),
        };

        assert_eq!(
            got.preimage,
            crate::hex_str(&want.preimage()),
            "preimage differs from the reference encoder"
        );
        assert_eq!(
            got.commitment,
            crate::hex_str(&want.commitment()),
            "commitment differs from the reference encoder"
        );
        assert!(want.validate().is_ok(), "derived intent fails spec 12.3");
    }

    /// The native variant must also match the reference encoder, with an
    /// all-zero token that `validate` accepts only because the kind is native.
    #[test]
    fn native_matches_the_reference_encoder() {
        let tx = [0x5c; 32];
        let recipient = [0x22; 20];
        let mut amount = [0u8; 32];
        amount[16..].copy_from_slice(&1_000_000_000_000_000_000u128.to_be_bytes());

        let got = derive_native(&tx, &recipient, &amount);
        assert_eq!(got.asset_kind, AssetKind::Native as u8);
        assert_eq!(got.settlement_token, crate::hex_str(&[0u8; 20]));

        let want = NativeIntent {
            instance_domain: arr(&got.instance_domain),
            chain_id: 1,
            escrow: arr(&got.escrow),
            request_id: arr(&got.request_id),
            row_index: got.row_index,
            asset_kind: AssetKind::Native,
            settlement_token: [0u8; 20],
            recipient,
            settlement_amount: amount,
            salt: arr(&got.salt),
        };

        assert_eq!(got.preimage, crate::hex_str(&want.preimage()));
        assert_eq!(got.commitment, crate::hex_str(&want.commitment()));
        assert!(want.validate().is_ok(), "derived intent fails spec 12.3");
    }

    /// The asset kind is part of the preimage, so the same settlement details
    /// under a different kind must not collide.
    #[test]
    fn native_and_erc20_commitments_differ() {
        let tx = [0x7d; 32];
        let recipient = [0x22; 20];
        let amount = [0x01; 32];

        let native = derive_native(&tx, &recipient, &amount);
        let erc20 = derive(&tx, &[0u8; 20], &recipient, &amount);
        assert_ne!(
            native.commitment, erc20.commitment,
            "asset kind must change the commitment"
        );
    }

    #[test]
    fn is_deterministic_and_distinct() {
        let token = [0x11; 20];
        let recipient = [0x22; 20];
        let amount = [0x01; 32];

        let a = derive(&[0xaa; 32], &token, &recipient, &amount);
        let again = derive(&[0xaa; 32], &token, &recipient, &amount);
        let b = derive(&[0xbb; 32], &token, &recipient, &amount);

        assert_eq!(a.commitment, again.commitment, "not reproducible");
        assert_ne!(
            a.commitment, b.commitment,
            "different transactions must give different commitments"
        );
        // The escrow-side fields must differ too, not just the hash.
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.escrow, b.escrow);
    }
}
