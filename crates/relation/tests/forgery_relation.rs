//! Structural checks on the deployed relations at production size.
#[path = "../../../experiments/keccacheck-arkworks/tests/forgery_common.rs"]
mod common;

use ark_bn254::Fr;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisMode,
    R1CS_PREDICATE_LABEL,
};
use mirage_keccacheck_arkworks::batch::KeccacheckBatch;
use mirage_keccacheck_arkworks::verifier::proof_elements;
use mirage_relation::native::{self, KeccacheckNativeCircuit, NativeBounds};
use mirage_relation::{fixture, Bounds, KeccacheckReceiptCircuit};
use std::hash::{DefaultHasher, Hash, Hasher};

fn digest(cs: &ConstraintSystemRef<Fr>) -> (u64, usize, usize, usize, usize) {
    cs.finalize();
    let m = cs.to_matrices().unwrap();
    let m = &m[R1CS_PREDICATE_LABEL];
    let mut h = DefaultHasher::new();
    let mut entries = 0;
    for matrix in m {
        matrix.len().hash(&mut h);
        for row in matrix {
            row.len().hash(&mut h);
            entries += row.len();
            for (coeff, idx) in row {
                coeff.to_string().hash(&mut h);
                idx.hash(&mut h);
            }
        }
    }
    (
        h.finish(),
        m[0].len(),
        cs.num_instance_variables(),
        cs.num_witness_variables(),
        entries,
    )
}

#[test]
fn erc20_setup_matrices_equal_prove_matrices() {
    let setup = ConstraintSystem::<Fr>::new_ref();
    setup.set_mode(SynthesisMode::Setup);
    KeccacheckReceiptCircuit::setup(Bounds::default())
        .generate_constraints(setup.clone())
        .unwrap();
    let a = digest(&setup);
    drop(setup);
    let prove = ConstraintSystem::<Fr>::new_ref();
    KeccacheckReceiptCircuit::prove(Bounds::default(), fixture::genuine())
        .generate_constraints(prove.clone())
        .unwrap();
    let b = digest(&prove);
    println!("erc20 setup {a:?} prove {b:?}");
    assert_eq!(a, b);
}

#[test]
fn native_setup_matrices_equal_prove_matrices() {
    let setup = ConstraintSystem::<Fr>::new_ref();
    setup.set_mode(SynthesisMode::Setup);
    KeccacheckNativeCircuit::setup(NativeBounds::default())
        .generate_constraints(setup.clone())
        .unwrap();
    let a = digest(&setup);
    drop(setup);
    let prove = ConstraintSystem::<Fr>::new_ref();
    KeccacheckNativeCircuit::prove(NativeBounds::default(), native::fixture::genuine())
        .generate_constraints(prove.clone())
        .unwrap();
    let b = digest(&prove);
    println!("native setup {a:?} prove {b:?}");
    assert_eq!(a, b);
}

/// Everything not pinned by booleans-as-seeds and the GKR proof elements.
fn report_free(name: &str, cs: &ConstraintSystemRef<Fr>, before_finish: usize, proof_len: usize) {
    let r = common::extract(cs);
    let unsat = r.unsatisfied();
    assert!(
        unsat.is_empty(),
        "honest witness fails direct evaluation: {:?}",
        &unsat[..unsat.len().min(5)]
    );
    let entries: usize = r.a.iter().chain(&r.b).chain(&r.c).map(Vec::len).sum();
    println!(
        "{name}: constraints {} vars {} instance {} entries {}",
        r.a.len(),
        r.z.len(),
        r.num_instance,
        entries
    );
    let unused = r.unused();
    println!(
        "{name}: unused variables {} {:?}",
        unused.len(),
        &unused[..unused.len().min(40)]
    );

    let start = r.num_instance + before_finish;
    let mut seed = r.boolean_vars();
    for s in seed.iter_mut().skip(start).take(proof_len) {
        *s = true;
    }
    let seeded = seed.iter().filter(|x| **x).count();
    let known = r.propagate(seed);
    let occ = r.occurrences();
    let free: Vec<usize> = (0..r.z.len()).filter(|i| !known[*i]).collect();
    let multi: Vec<usize> = free.iter().copied().filter(|i| occ[*i] > 1).collect();
    let in_verifier = free.iter().filter(|i| **i >= start).count();
    println!(
        "{name}: seeded {seeded} free {} free-with-more-than-one-use {} free-in-verifier {in_verifier}",
        free.len(),
        multi.len()
    );
    // Rows touching each multi-use free variable, for classification.
    let mut rows: std::collections::HashMap<usize, Vec<usize>> = Default::default();
    let wanted: std::collections::HashSet<usize> = multi.iter().copied().take(4000).collect();
    for (k, (a, (b, c))) in r.a.iter().zip(r.b.iter().zip(r.c.iter())).enumerate() {
        for (_, i) in a.iter().chain(b).chain(c) {
            if wanted.contains(i) {
                rows.entry(*i).or_default().push(k);
            }
        }
    }
    for v in multi.iter().take(60) {
        let list = rows.get(v).cloned().unwrap_or_default();
        println!(
            "  free var {} value {} uses {} rows {:?}",
            v - r.num_instance,
            r.z[*v],
            occ[*v],
            &list[..list.len().min(6)]
        );
        for k in list.iter().take(2) {
            println!(
                "    row {k}: |A|={} |B|={} |C|={} a(z)={} b(z)={} c(z)={}",
                r.a[*k].len(),
                r.b[*k].len(),
                r.c[*k].len(),
                common::dot(&r.a[*k], &r.z),
                common::dot(&r.b[*k], &r.z),
                common::dot(&r.c[*k], &r.z)
            );
        }
    }
    // Single-use free variables other than is_neq multipliers.
    let single_nonzero_mult = free
        .iter()
        .filter(|i| occ[**i] == 1)
        .filter(|i| {
            !r.a.iter().zip(&r.b).any(|(a, b)| {
                (b.iter().any(|(_, x)| x == *i) && common::dot(a, &r.z) == Fr::from(0u64))
                    || (a.iter().any(|(_, x)| x == *i) && common::dot(b, &r.z) == Fr::from(0u64))
            })
        })
        .count();
    println!("{name}: single-use free vars not multiplied by a zero: {single_nonzero_mult}");
}

#[test]
fn erc20_free_witnesses() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = mirage_relation::ReceiptCircuit::prove(Bounds::default(), fixture::genuine());
    let mut batch = KeccacheckBatch::new(cs.clone());
    mirage_relation::generate_constraints_with_backend(circuit, cs.clone(), &mut batch).unwrap();
    let before = cs.num_witness_variables();
    let result = batch.finish().unwrap();
    println!(
        "erc20 recorded {} padded {}",
        result.recorded, result.padded
    );
    report_free("erc20", &cs, before, proof_elements(result.padded));
}

mod end_to_end {
    use super::*;
    use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, GR1CSVar};
    use ark_relations::gr1cs::SynthesisError;
    use gkr::reference::{keccak_round, ROUND_CONSTANTS};
    use mirage_gadgets::keccak::{PermutationBackend, State};
    use mirage_keccacheck_arkworks::verifier::{derive_r_native, verify_boolean_batch};
    use mirage_relation::fixture::keccak;

    /// `KeccacheckBatch`, except permutation `target` reports `force` in its
    /// first four lanes. Everything else follows the real backend.
    struct Evil {
        cs: ConstraintSystemRef<Fr>,
        inputs: Vec<State<Fr>>,
        outputs: Vec<State<Fr>>,
        words_in: Vec<[u64; 25]>,
        words_out: Vec<[u64; 25]>,
        target: usize,
        force: [u64; 4],
    }

    impl PermutationBackend<Fr> for Evil {
        fn permute(&mut self, state: State<Fr>) -> Result<State<Fr>, SynthesisError> {
            let mut input = [0u64; 25];
            for lane in 0..25 {
                for bit in 0..64 {
                    if state[lane][bit].value()? {
                        input[lane] |= 1 << bit;
                    }
                }
            }
            let mut claimed = input;
            ::keccak::f1600(&mut claimed);
            if self.words_in.len() == self.target {
                claimed[..4].copy_from_slice(&self.force);
            }
            let output: State<Fr> = core::array::from_fn(|lane| {
                core::array::from_fn(|bit| {
                    Boolean::new_witness(self.cs.clone(), || Ok((claimed[lane] >> bit) & 1 == 1))
                        .unwrap()
                })
            });
            self.words_in.push(input);
            self.words_out.push(claimed);
            self.inputs.push(state);
            self.outputs.push(output.clone());
            Ok(output)
        }
    }

    fn lane_major(states: &[[u64; 25]]) -> Vec<u64> {
        let n = states.len();
        let mut out = vec![0u64; 25 * n];
        for (i, s) in states.iter().enumerate() {
            for l in 0..25 {
                out[l * n + i] = s[l];
            }
        }
        out
    }

    fn constant_state(words: &[u64; 25]) -> State<Fr> {
        core::array::from_fn(|l| {
            core::array::from_fn(|b| Boolean::constant((words[l] >> b) & 1 == 1))
        })
    }

    /// Settles an intent for a payment that never happened, at production
    /// size: the receipt pays `A'`, the block's trie holds a receipt paying
    /// `A`, and the one lie is the leaf hash permutation's output. The
    /// Fiat-Shamir challenge is derived from the false statement and the proof
    /// follows the true layers. Only the batch verifier can object.
    #[test]
    fn fabricated_receipt_with_forged_leaf_hash() {
        let mut w = fixture::genuine();
        let true_leaf_hash = keccak(&w.nodes[1]);
        let leaf_len = w.nodes[1].len();

        // A payment of 999, where the block's receipt pays the fixture amount.
        let mut amount = [0u8; 32];
        amount[30..].copy_from_slice(&999u16.to_be_bytes());
        w.intent.settlement_amount = amount;
        w.statement.intent_commitment = mirage_encoding::commitment::Intent {
            instance_domain: w.intent.instance_domain,
            chain_id: w.intent.chain_id,
            escrow: w.intent.escrow,
            request_id: w.intent.request_id,
            row_index: w.intent.row_index,
            asset_kind: mirage_encoding::AssetKind::Erc20,
            settlement_token: w.intent.settlement_token,
            recipient: w.intent.recipient,
            settlement_amount: w.intent.settlement_amount,
            salt: w.intent.salt,
        }
        .commitment();
        let n = w.receipt.len();
        w.receipt[n - 32..].copy_from_slice(&amount);

        // Commitment 2, header slots 5 * 40, ancestors 3 + 5 * 4, then the leaf's final block.
        let target = 2 + 200 + 23 + leaf_len / 136;
        let force = core::array::from_fn(|i| {
            u64::from_le_bytes(true_leaf_hash[i * 8..i * 8 + 8].try_into().unwrap())
        });

        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut evil = Evil {
            cs: cs.clone(),
            inputs: vec![],
            outputs: vec![],
            words_in: vec![],
            words_out: vec![],
            target,
            force,
        };
        let circuit = mirage_relation::ReceiptCircuit::prove(Bounds::default(), w);
        mirage_relation::generate_constraints_with_backend(circuit, cs.clone(), &mut evil).unwrap();
        let relation_rows = cs.num_constraints();
        assert_eq!(evil.words_in.len(), 232);

        // Pad exactly as `finish` does.
        while evil.words_in.len() < 256 {
            let mut out = [0u64; 25];
            ::keccak::f1600(&mut out);
            evil.inputs.push(constant_state(&[0u64; 25]));
            evil.outputs.push(constant_state(&out));
            evil.words_in.push([0u64; 25]);
            evil.words_out.push(out);
        }
        let input = lane_major(&evil.words_in);
        let output = lane_major(&evil.words_out);
        let r = derive_r_native(&input, &output, 8);

        // True layers from the input states.
        let mut states = Vec::with_capacity(24);
        let mut cur = input.clone();
        for round in 0..24 {
            let s = keccak_round(&cur, round);
            cur = s.iota.clone();
            states.push(s);
        }
        assert_ne!(cur, output, "the statement must actually be false");
        let proof = common::prove_layers(&states, &ROUND_CONSTANTS, r);

        let bits = |list: &[State<Fr>]| -> Vec<Boolean<Fr>> {
            let mut out = Vec::new();
            for lane in 0..25 {
                for s in list {
                    out.extend(s[lane].iter().cloned());
                }
            }
            out
        };
        verify_boolean_batch(
            cs.clone(),
            &proof,
            &bits(&evil.inputs),
            &bits(&evil.outputs),
        )
        .unwrap();

        let r1cs = common::extract(&cs);
        let unsat = r1cs.unsatisfied();
        let in_relation = unsat.iter().filter(|k| **k < relation_rows).count();
        println!(
            "rows {} relation rows {} unsatisfied {} in-relation {} first {:?}",
            r1cs.a.len(),
            relation_rows,
            unsat.len(),
            in_relation,
            &unsat[..unsat.len().min(5)]
        );
        assert_eq!(in_relation, 0, "the relation should accept the forged hash");
        assert!(
            !unsat.is_empty(),
            "FORGERY: batch accepted a false statement"
        );
    }
}

#[test]
fn native_free_witnesses() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = native::NativeCircuit::prove(NativeBounds::default(), native::fixture::genuine());
    let mut batch = KeccacheckBatch::new(cs.clone());
    native::generate_constraints_with_backend(circuit, cs.clone(), &mut batch).unwrap();
    let before = cs.num_witness_variables();
    let result = batch.finish().unwrap();
    println!(
        "native recorded {} padded {}",
        result.recorded, result.padded
    );
    report_free("native", &cs, before, proof_elements(result.padded));
}
