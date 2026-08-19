//! Proving a settlement, as a library.
//!
//! The binaries in `src/bin` measure and export; this is the path a node takes
//! to produce a proof the escrow will accept. It exists so the settlement
//! witness is assembled in exactly one place: the escrow computes the statement
//! from its own storage, so a node that reconstructs any bound field
//! differently produces a proof that fails on-chain with no indication of which
//! field disagreed.
//!
//! # Coordinates
//!
//! [`proof_points`] returns the eight field elements in the order the EVM
//! pairing precompile takes, which reverses arkworks' G2 serialization. Getting
//! that wrong yields a verifier that rejects every valid proof and reports only
//! `false`, so the conversion lives here rather than at each call site.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;

use mirage_relation::{Bounds, ReceiptCircuit, Witness};

/// A proving and verifying key pair for one circuit version.
pub struct Keys {
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
}

/// Runs the circuit-specific setup for `bounds`.
///
/// Spec 18.2 requires a multiparty Phase 2 for production; this is the toy
/// stand-in. The verifier is structurally identical either way, so sizes and
/// gas hold, but a key from here has no soundness provenance. `seed` is fixed
/// rather than drawn from entropy so a rebuild reproduces the same key.
pub fn setup(bounds: Bounds, seed: u64) -> Result<Keys, SettlementError> {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(ReceiptCircuit::setup(bounds), &mut rng)
        .map_err(|e| SettlementError::Setup(e.to_string()))?;
    Ok(Keys { pk, vk })
}

/// Proves that `witness` satisfies the relation, and checks the proof natively
/// before returning it.
///
/// The native check is not redundant with the escrow's. A proof that fails
/// on-chain after the node has already fronted the transfer is an executor
/// loss under spec 12.9, so the cheap check runs first and turns a
/// would-be-silent rejection into an error at the point of construction.
pub fn prove<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
    keys: &Keys,
    bounds: Bounds,
    witness: &Witness,
    rng: &mut R,
) -> Result<Settlement, SettlementError> {
    check_bounds(bounds, witness)?;
    let (hi, lo) = mirage_relation::public_signals(witness);
    let proof = Groth16::<Bn254>::prove(
        &keys.pk,
        ReceiptCircuit::prove(bounds, witness.clone()),
        rng,
    )
    .map_err(|e| SettlementError::Prove(e.to_string()))?;

    let pvk = PreparedVerifyingKey::from(keys.vk.clone());
    let ok = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[Fr::from(hi), Fr::from(lo)], &proof)
        .map_err(|e| SettlementError::Verify(e.to_string()))?;
    if !ok {
        return Err(SettlementError::SelfCheck);
    }

    Ok(Settlement {
        proof: proof_points(&proof),
        signals: [hi, lo],
    })
}

/// [`prove`] with a seeded RNG, for artifacts that must reproduce byte-exactly.
///
/// Not for production settlements: a fixed seed reuses proof randomness across
/// proofs, which Groth16's zero-knowledge property depends on being fresh.
pub fn prove_seeded(
    keys: &Keys,
    bounds: Bounds,
    witness: &Witness,
    seed: u64,
) -> Result<Settlement, SettlementError> {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
    prove(keys, bounds, witness, &mut rng)
}

/// A proof and the two public signals it is bound to, ready for `collect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    /// `[a.x, a.y, b.x1, b.x0, b.y1, b.y0, c.x, c.y]`, each big-endian.
    pub proof: [[u8; 32]; 8],
    /// The statement hash's two 128-bit limbs, high first.
    pub signals: [u128; 2],
}

/// The proof as the eight field elements the Solidity verifier expects.
///
/// Read off the affine coordinates rather than sliced out of a serialization,
/// which would require knowing arkworks' byte order and endianness. The one
/// remaining convention is G2 order: the precompile takes `(x.c1, x.c0, y.c1,
/// y.c0)`, confirmed against the generated verifier's assembly.
pub fn proof_points(proof: &Proof<Bn254>) -> [[u8; 32]; 8] {
    use ark_ff::PrimeField;
    use num_bigint::BigUint;

    let fq = |v: ark_bn254::Fq| -> [u8; 32] {
        let n: BigUint = v.into_bigint().into();
        let be = n.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - be.len()..].copy_from_slice(&be);
        out
    };

    [
        fq(proof.a.x),
        fq(proof.a.y),
        fq(proof.b.x.c1),
        fq(proof.b.x.c0),
        fq(proof.b.y.c1),
        fq(proof.b.y.c0),
        fq(proof.c.x),
        fq(proof.c.y),
    ]
}

/// What can go wrong producing a settlement proof.
#[derive(Debug)]
pub enum SettlementError {
    /// A proving key could not be read: wrong encoding, truncated, or not a
    /// key for this curve.
    KeyLoad(String),
    Setup(String),
    Prove(String),
    Verify(String),
    /// The proof did not verify against its own key. A bug rather than a bad
    /// witness: an unsatisfied witness fails in `Prove`.
    SelfCheck,
    /// A witness field exceeded a compiled bound, so no proof exists.
    Bounds(String),
}

impl std::fmt::Display for SettlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyLoad(e) => write!(f, "proving key could not be loaded: {e}"),
            Self::Setup(e) => write!(f, "groth16 setup failed: {e}"),
            Self::Prove(e) => write!(f, "proving failed: {e}"),
            Self::Verify(e) => write!(f, "verification errored: {e}"),
            Self::SelfCheck => write!(f, "the proof does not verify against its own key"),
            Self::Bounds(e) => write!(f, "witness exceeds a compiled bound: {e}"),
        }
    }
}

impl std::error::Error for SettlementError {}

/// Checks a witness against the compiled bounds before proving.
///
/// Proving allocates the full key and runs for tens of seconds, and
/// `alloc_bounded` panics rather than erroring when an input is too long. This
/// turns that into a diagnosable error naming the offending field.
pub fn check_bounds(bounds: Bounds, w: &Witness) -> Result<(), SettlementError> {
    let over = |what: &str, got: usize, max: usize| {
        Err(SettlementError::Bounds(format!(
            "{what} is {got} bytes, bound is {max}"
        )))
    };
    if w.header.len() > bounds.header_bytes {
        return over("header", w.header.len(), bounds.header_bytes);
    }
    if w.receipt.len() > bounds.receipt_bytes {
        return over("receipt", w.receipt.len(), bounds.receipt_bytes);
    }
    if w.key.len() > bounds.key_bytes {
        return over("trie key", w.key.len(), bounds.key_bytes);
    }
    if w.nodes.len() > bounds.depth {
        return over("trie depth", w.nodes.len(), bounds.depth);
    }
    if let Some(n) = w.nodes.iter().find(|n| n.len() > bounds.node_bytes) {
        return over("trie node", n.len(), bounds.node_bytes);
    }
    Ok(())
}

/// Loads a proving key produced by the trusted setup.
///
/// # Why this is not `setup`
///
/// [`setup`] runs `circuit_specific_setup`, where one party learns the toxic
/// waste and can forge a proof for any statement. Spec 18.2 requires the
/// production key come from a multiparty Phase 2 instead, so a node must load a
/// ceremony's output rather than derive its own. Keeping the two as separate
/// functions means a caller cannot reach for the unsound one by leaving an
/// argument off.
///
/// `compressed` must match how the ceremony serialized the key: the encodings
/// are not self-describing, and reading one as the other fails at a point curve
/// check rather than as a clean length error.
pub fn load_proving_key(
    bytes: &[u8],
    compressed: bool,
) -> Result<ProvingKey<Bn254>, SettlementError> {
    use ark_serialize::{CanonicalDeserialize, Compress, Validate};
    let mode = if compressed {
        Compress::Yes
    } else {
        Compress::No
    };
    // Validated rather than trusted: a malformed key is a wrong answer, not a
    // crash, and the check runs once per startup rather than per settlement.
    ProvingKey::<Bn254>::deserialize_with_mode(bytes, mode, Validate::Yes)
        .map_err(|e| SettlementError::KeyLoad(e.to_string()))
}

/// The verifying key implied by a proving key.
///
/// A node holds only the proving half, but the escrow embeds the verifying
/// half, and the two must come from the same setup. Deriving it here lets a
/// node check that before proving rather than discovering the mismatch as a
/// rejected proof.
pub fn verifying_key_of(pk: &ProvingKey<Bn254>) -> VerifyingKey<Bn254> {
    pk.vk.clone()
}

/// The verifying key's on-chain form: the constants the generated Solidity
/// verifier compiles in.
///
/// Ordered as the template emits them, so a node can compare against what it
/// reads from a deployed escrow. Any difference means the key and the contract
/// came from different setups, and every proof would be rejected.
pub fn verifying_key_constants(vk: &VerifyingKey<Bn254>) -> VerifyingKeyConstants {
    use ark_ff::PrimeField;
    use num_bigint::BigUint;

    let fq = |v: ark_bn254::Fq| -> [u8; 32] {
        let n: BigUint = v.into_bigint().into();
        let be = n.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - be.len()..].copy_from_slice(&be);
        out
    };

    VerifyingKeyConstants {
        alpha: [fq(vk.alpha_g1.x), fq(vk.alpha_g1.y)],
        beta: [
            fq(vk.beta_g2.x.c1),
            fq(vk.beta_g2.x.c0),
            fq(vk.beta_g2.y.c1),
            fq(vk.beta_g2.y.c0),
        ],
        gamma: [
            fq(vk.gamma_g2.x.c1),
            fq(vk.gamma_g2.x.c0),
            fq(vk.gamma_g2.y.c1),
            fq(vk.gamma_g2.y.c0),
        ],
        delta: [
            fq(vk.delta_g2.x.c1),
            fq(vk.delta_g2.x.c0),
            fq(vk.delta_g2.y.c1),
            fq(vk.delta_g2.y.c0),
        ],
        ic: vk.gamma_abc_g1.iter().map(|p| [fq(p.x), fq(p.y)]).collect(),
    }
}

/// A verifying key as the flat field elements the Solidity verifier holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKeyConstants {
    pub alpha: [[u8; 32]; 2],
    pub beta: [[u8; 32]; 4],
    pub gamma: [[u8; 32]; 4],
    pub delta: [[u8; 32]; 4],
    /// One point per public input, plus the constant term. Three entries for
    /// this relation's two signals.
    pub ic: Vec<[[u8; 32]; 2]>,
}
