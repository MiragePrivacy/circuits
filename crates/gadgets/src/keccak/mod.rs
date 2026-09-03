//! Keccak-256 gadget.
//!
//! Ported from ZoKrates `hashes/keccak/keccak.zok`, which is the only
//! Rust-adjacent reference with a correct Ethereum delimiter and a genuine
//! multi-block absorb loop.
//!
//! # Ethereum keccak256, not SHA3-256
//!
//! The two differ only in the padding delimiter: `0x01` for keccak, `0x06` for
//! SHA3. Everything else is shared. Getting it wrong yields a gadget that
//! correctly computes the wrong function, which is why every test here checks
//! against `mirage_encoding::keccak256` rather than against itself.
//!
//! # Do not port from `natharyan/arkworks-keccak`
//!
//! Its `Keccak256` mode appends a plain `1` bit rather than the `0x01` domain
//! separator, and its `keccak_gadget` calls `assert_eq!` on `.value()` inside
//! the constraint-generation path — a native panic during proving and a silent
//! no-op during setup, so it enforces nothing.
//!
//! # Cost, measured
//!
//! | Input | Blocks | Constraints | Per block |
//! |---|---|---|---|
//! | 100 B | 1 | 152,000 | 152,000 |
//! | 200 B | 2 | 306,688 | 153,344 |
//! | 400 B | 3 | 461,888 | 153,962 |
//!
//! `keccak_f1600` alone is 155,200. Run
//! `cargo test -p mirage-gadgets --release -- --nocapture cost` to reproduce.
//!
//! This confirms the ~150k figure that drove the backend evaluation in
//! FINDINGS.md (vocdoni 150,848; IACR ePrint 2023/681 measures 151,357;
//! bkomuves ~146,000) on our own implementation rather than by inheritance.
//!
//! The cost is structural to R1CS: theta and chi are bitwise over 1600 state
//! bits, and R1CS expresses only field multiplication and addition.
//! Lookup-based implementations reach ~300 rows per permutation but require a
//! proof system with lookup arguments, which Groth16 does not have.
//!
//! Consequence for the relation, at ~153k per block:
//!
//! | Component | Blocks | Constraints |
//! |---|---|---|
//! | Commitment preimage, 226 B | 2 | ~306k |
//! | Statement preimage, 285 B | 3 | ~460k |
//! | Receipt hash, bounded 2048 B | 16 | ~2.45M |
//! | MPT nodes, 16 deep | 16+ | ~2.45M+ |
//!
//! The two bounded items dominate and both are witnessed-length, so they pay
//! their maximum regardless of the real input size. Tightening spec 12.9's
//! bounds against measured mainnet receipts is the largest single lever
//! available.

mod permutation;
pub mod sponge;

pub use permutation::{keccak_f1600, DirectPermutation, PermutationBackend, State};
pub use sponge::{keccak256_fixed, keccak256_fixed_with, keccak256_var, keccak256_var_with};

/// Rate in bytes for keccak-256: 200 - 2*32.
pub const RATE: usize = 136;

/// Ethereum's padding delimiter. SHA3-256 uses 0x06.
pub const DELIM_KECCAK: u8 = 0x01;
