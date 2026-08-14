//! Intent commitment, spec section 8.3.
//!
//! ```text
//! intentCommitment = keccak256(abi.encodePacked(
//!     uint8(2),                 // relation version
//!     instanceDomain,           // 32 bytes
//!     uint256(chainId),         // 32 bytes, left-padded
//!     predictedEscrow,          // 20 bytes
//!     requestId,                // 32 bytes
//!     uint32(rowIndex),         // 4 bytes, big-endian
//!     uint8(assetKind),         // 1 byte
//!     settlementToken,          // 20 bytes, zero when native
//!     recipient,                // 20 bytes
//!     settlementAmount,         // 32 bytes, big-endian
//!     salt                      // 32 bytes
//! ))
//! ```
//!
//! Total preimage: 1 + 32 + 32 + 20 + 32 + 4 + 1 + 20 + 20 + 32 + 32 = 226 bytes.

use crate::{keccak256, Address, AssetKind, Bytes32, RELATION_VERSION};

/// Length of the packed preimage. Fixed: every field is fixed-width.
pub const PREIMAGE_LEN: usize = 226;

#[derive(Debug, Clone)]
pub struct Intent {
    pub instance_domain: Bytes32,
    pub chain_id: u64,
    pub escrow: Address,
    pub request_id: Bytes32,
    pub row_index: u32,
    pub asset_kind: AssetKind,
    /// Must be all-zero when `asset_kind` is Native, nonzero otherwise.
    pub settlement_token: Address,
    pub recipient: Address,
    /// Big-endian 32 bytes.
    pub settlement_amount: Bytes32,
    pub salt: Bytes32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IntentError {
    ZeroRecipient,
    ZeroAmount,
    /// Native rows must carry an all-zero token; ERC-20 rows must not.
    TokenKindMismatch,
}

impl Intent {
    /// Checks the private assertions spec 12.3 requires the circuit to enforce.
    ///
    /// Validating here as well is deliberate: it keeps invalid vectors out of
    /// the fixture set, so a circuit failure means a circuit bug rather than
    /// bad input.
    pub fn validate(&self) -> Result<(), IntentError> {
        if self.recipient == [0u8; 20] {
            return Err(IntentError::ZeroRecipient);
        }
        if self.settlement_amount == [0u8; 32] {
            return Err(IntentError::ZeroAmount);
        }
        let token_is_zero = self.settlement_token == [0u8; 20];
        match self.asset_kind {
            AssetKind::Native if !token_is_zero => Err(IntentError::TokenKindMismatch),
            AssetKind::Erc20 if token_is_zero => Err(IntentError::TokenKindMismatch),
            _ => Ok(()),
        }
    }

    /// The exact packed preimage bytes.
    ///
    /// Emitted into the vectors alongside the digest, so a mismatch identifies
    /// whether the disagreement is in the packing or the hash.
    pub fn preimage(&self) -> [u8; PREIMAGE_LEN] {
        let mut out = [0u8; PREIMAGE_LEN];
        let mut i = 0;

        let mut put = |src: &[u8], i: &mut usize| {
            out[*i..*i + src.len()].copy_from_slice(src);
            *i += src.len();
        };

        put(&[RELATION_VERSION], &mut i);
        put(&self.instance_domain, &mut i);
        put(&crate::u64_to_word(self.chain_id), &mut i);
        put(&self.escrow, &mut i);
        put(&self.request_id, &mut i);
        put(&self.row_index.to_be_bytes(), &mut i);
        put(&[self.asset_kind as u8], &mut i);
        put(&self.settlement_token, &mut i);
        put(&self.recipient, &mut i);
        put(&self.settlement_amount, &mut i);
        put(&self.salt, &mut i);

        debug_assert_eq!(i, PREIMAGE_LEN);
        out
    }

    pub fn commitment(&self) -> Bytes32 {
        keccak256(&self.preimage())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Intent {
        Intent {
            instance_domain: [0x11; 32],
            chain_id: 1,
            escrow: [0x22; 20],
            request_id: [0x33; 32],
            row_index: 0,
            asset_kind: AssetKind::Erc20,
            settlement_token: [0x44; 20],
            recipient: [0x55; 20],
            settlement_amount: {
                let mut a = [0u8; 32];
                a[31] = 1;
                a
            },
            salt: [0x66; 32],
        }
    }

    #[test]
    fn preimage_length_is_fixed() {
        assert_eq!(sample().preimage().len(), PREIMAGE_LEN);
    }

    #[test]
    fn version_byte_leads() {
        assert_eq!(sample().preimage()[0], RELATION_VERSION);
    }

    #[test]
    fn commitment_is_deterministic() {
        assert_eq!(sample().commitment(), sample().commitment());
    }

    #[test]
    fn row_index_changes_the_commitment() {
        let a = sample();
        let mut b = sample();
        b.row_index = 1;
        assert_ne!(a.commitment(), b.commitment());
    }

    #[test]
    fn escrow_address_changes_the_commitment() {
        // Spec 8.3: binding the escrow address is what stops a proof generated
        // for one deployment authorizing another.
        let a = sample();
        let mut b = sample();
        b.escrow = [0x23; 20];
        assert_ne!(a.commitment(), b.commitment());
    }

    #[test]
    fn validate_rejects_native_with_token() {
        let mut i = sample();
        i.asset_kind = AssetKind::Native;
        assert_eq!(i.validate(), Err(IntentError::TokenKindMismatch));
    }

    #[test]
    fn validate_rejects_erc20_without_token() {
        let mut i = sample();
        i.settlement_token = [0u8; 20];
        assert_eq!(i.validate(), Err(IntentError::TokenKindMismatch));
    }

    #[test]
    fn validate_rejects_zero_amount() {
        let mut i = sample();
        i.settlement_amount = [0u8; 32];
        assert_eq!(i.validate(), Err(IntentError::ZeroAmount));
    }

    #[test]
    fn validate_rejects_zero_recipient() {
        let mut i = sample();
        i.recipient = [0u8; 20];
        assert_eq!(i.validate(), Err(IntentError::ZeroRecipient));
    }
}
