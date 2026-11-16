//! Attempts on the Keccacheck verifier gadget at small batch sizes.
#[path = "forgery_common.rs"]
mod common;

use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean};
use ark_relations::gr1cs::ConstraintSystem;
use gkr::reference::{KeccakRoundState, RHO_OFFSETS, ROUND_CONSTANTS, keccak_round};
use mirage_keccacheck_arkworks::verifier::{
    Witness, derive_r_native, make_witness_from_data, verify_boolean_batch, verify_witness,
};

use common::prove_layers;

fn lane_major(data: &[u64], instances: usize) -> Vec<u64> {
    let mut out = vec![0u64; data.len()];
    for i in 0..instances {
        for s in 0..25 {
            out[s * instances + i] = data[i * 25 + s];
        }
    }
    out
}

fn seed_data(instances: usize, seed: u64) -> Vec<u64> {
    let mut x = seed.wrapping_mul(0x9e3779b97f4a7c15) | 1;
    (0..instances * 25)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        })
        .collect()
}

/// Each mutation turns one round into a consistent alternate function.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    None,
    /// `rc[round]` altered by a bit; the prover uses the altered constant.
    Rc {
        round: usize,
        bit: u32,
    },
    /// Same, on one instance only.
    RcInstance {
        round: usize,
        instance: usize,
        bit: u32,
    },
    /// A different rotation of one lane in rho.
    Rho {
        round: usize,
        lane: usize,
        extra: u32,
    },
    /// Swaps two lanes after pi.
    Pi {
        round: usize,
        x: usize,
        y: usize,
    },
    /// chi uses x+1 and x+3.
    Chi {
        round: usize,
    },
    /// One chi output bit flipped.
    ChiBit {
        round: usize,
        lane: usize,
        instance: usize,
        bit: u32,
    },
    /// d rotates by 2 instead of 1.
    ThetaRot {
        round: usize,
    },
    /// d bit flipped in one column.
    ThetaD {
        round: usize,
        col: usize,
        instance: usize,
        bit: u32,
    },
    /// c bit flipped in one column.
    ThetaC {
        round: usize,
        col: usize,
        instance: usize,
        bit: u32,
    },
    /// theta output flipped while c and d stay honest.
    ThetaOut {
        round: usize,
        lane: usize,
        instance: usize,
        bit: u32,
    },
    /// The round's input is not the previous round's output.
    Link {
        round: usize,
        lane: usize,
        instance: usize,
        bit: u32,
    },
}

fn chi_iota(s: &mut KeccakRoundState, pi: &[u64], instances: usize, round: usize, far: usize) {
    for i in 0..instances {
        for yy in 0..5 {
            let y = yy * 5;
            for x in 0..5 {
                s.pi_chi[(y + x) * instances + i] = pi[(y + x) * instances + i]
                    ^ (!pi[(y + (x + 1) % 5) * instances + i]
                        & pi[(y + (x + far) % 5) * instances + i]);
            }
        }
    }
    s.iota = s.pi_chi.clone();
    for i in 0..instances {
        s.iota[i] ^= ROUND_CONSTANTS[round];
    }
}

fn downstream_from_rho(
    s: &mut KeccakRoundState,
    instances: usize,
    round: usize,
    swap: Option<(usize, usize)>,
) {
    let mut pi = s.rho.clone();
    gkr::reference::apply_pi(&s.rho, &mut pi);
    if let Some((x, y)) = swap {
        for i in 0..instances {
            pi.swap(x * instances + i, y * instances + i);
        }
    }
    chi_iota(s, &pi, instances, round, 2);
}

fn downstream_from_theta(s: &mut KeccakRoundState, instances: usize, round: usize) {
    for i in 0..instances {
        for (x, off) in RHO_OFFSETS.iter().enumerate() {
            s.rho[x * instances + i] = s.theta[x * instances + i].rotate_left(*off);
        }
    }
    downstream_from_rho(s, instances, round, None);
}

fn rebuild_d_theta(s: &mut KeccakRoundState, instances: usize, rot: u32) {
    for i in 0..instances {
        for x in 0..5 {
            s.d[x * instances + i] = s.c[((x + 4) % 5) * instances + i]
                ^ s.c[((x + 1) % 5) * instances + i].rotate_left(rot);
            for y in 0..5 {
                s.theta[(y * 5 + x) * instances + i] =
                    s.a[(y * 5 + x) * instances + i] ^ s.d[x * instances + i];
            }
        }
    }
}

fn mutated_states(a_t: &[u64], m: Mutation) -> (Vec<KeccakRoundState>, [u64; 24]) {
    let instances = a_t.len() / 25;
    let mut rcs = ROUND_CONSTANTS;
    let mut states: Vec<KeccakRoundState> = Vec::with_capacity(24);
    let mut cur = a_t.to_vec();
    for round in 0..24 {
        if let Mutation::Link {
            round: r,
            lane,
            instance,
            bit,
        } = m
        {
            if r == round {
                cur[lane * instances + instance] ^= 1u64 << bit;
            }
        }
        let mut s = keccak_round(&cur, round);
        match m {
            Mutation::ThetaD {
                round: r,
                col,
                instance,
                bit,
            } if r == round => {
                s.d[col * instances + instance] ^= 1u64 << bit;
                for y in 0..5 {
                    s.theta[(y * 5 + col) * instances + instance] ^= 1u64 << bit;
                }
                downstream_from_theta(&mut s, instances, round);
            }
            Mutation::ThetaC {
                round: r,
                col,
                instance,
                bit,
            } if r == round => {
                s.c[col * instances + instance] ^= 1u64 << bit;
                rebuild_d_theta(&mut s, instances, 1);
                downstream_from_theta(&mut s, instances, round);
            }
            Mutation::ThetaRot { round: r } if r == round => {
                rebuild_d_theta(&mut s, instances, 2);
                downstream_from_theta(&mut s, instances, round);
            }
            Mutation::ThetaOut {
                round: r,
                lane,
                instance,
                bit,
            } if r == round => {
                s.theta[lane * instances + instance] ^= 1u64 << bit;
                downstream_from_theta(&mut s, instances, round);
            }
            Mutation::Rho {
                round: r,
                lane,
                extra,
            } if r == round => {
                for i in 0..instances {
                    s.rho[lane * instances + i] =
                        s.theta[lane * instances + i].rotate_left(RHO_OFFSETS[lane] + extra);
                }
                downstream_from_rho(&mut s, instances, round, None);
            }
            Mutation::Pi { round: r, x, y } if r == round => {
                downstream_from_rho(&mut s, instances, round, Some((x, y)));
            }
            Mutation::Chi { round: r } if r == round => {
                let mut pi = s.rho.clone();
                gkr::reference::apply_pi(&s.rho, &mut pi);
                chi_iota(&mut s, &pi, instances, round, 3);
            }
            Mutation::ChiBit {
                round: r,
                lane,
                instance,
                bit,
            } if r == round => {
                s.pi_chi[lane * instances + instance] ^= 1u64 << bit;
                s.iota[lane * instances + instance] ^= 1u64 << bit;
            }
            Mutation::Rc { round: r, bit } if r == round => {
                rcs[round] ^= 1u64 << bit;
                for i in 0..instances {
                    s.iota[i] ^= 1u64 << bit;
                }
            }
            Mutation::RcInstance {
                round: r,
                instance,
                bit,
            } if r == round => {
                s.iota[instance] ^= 1u64 << bit;
            }
            _ => {}
        }
        cur = s.iota.clone();
        states.push(s);
    }
    (states, rcs)
}

fn honest_output(input: &[u64], instances: usize) -> Vec<u64> {
    let mut output = vec![0u64; input.len()];
    for i in 0..instances {
        let mut st: [u64; 25] = core::array::from_fn(|l| input[l * instances + i]);
        keccak::f1600(&mut st);
        for l in 0..25 {
            output[l * instances + i] = st[l];
        }
    }
    output
}

/// Verifier verdict by direct A*B=C evaluation on the finalized matrices.
fn verdict(w: &Witness) -> (usize, usize) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    verify_witness(cs.clone(), w).unwrap();
    let r = common::extract(&cs);
    (r.unsatisfied().len(), r.a.len())
}

fn all_mutations(instances: usize) -> Vec<Mutation> {
    let mut v = Vec::new();
    for round in [0usize, 1, 11, 22, 23] {
        v.push(Mutation::Rc { round, bit: 63 });
        v.push(Mutation::Rc { round, bit: 5 });
        v.push(Mutation::RcInstance {
            round,
            instance: instances - 1,
            bit: 40,
        });
        for lane in [0usize, 1, 7, 13, 24] {
            v.push(Mutation::Rho {
                round,
                lane,
                extra: 1,
            });
            v.push(Mutation::ChiBit {
                round,
                lane,
                instance: instances - 1,
                bit: 63,
            });
            v.push(Mutation::ThetaOut {
                round,
                lane,
                instance: 0,
                bit: 0,
            });
            if round != 0 {
                v.push(Mutation::Link {
                    round,
                    lane,
                    instance: instances - 1,
                    bit: 17,
                });
            }
        }
        v.push(Mutation::Pi { round, x: 3, y: 17 });
        v.push(Mutation::Pi { round, x: 0, y: 1 });
        v.push(Mutation::Chi { round });
        v.push(Mutation::ThetaRot { round });
        for col in 0..5 {
            v.push(Mutation::ThetaD {
                round,
                col,
                instance: 0,
                bit: 31,
            });
            v.push(Mutation::ThetaC {
                round,
                col,
                instance: instances - 1,
                bit: 63,
            });
        }
    }
    v
}

/// Each case: a self-consistent alternate permutation with a Fiat-Shamir proof
/// derived from its own false statement. Acceptance of any is a forgery.
/// Needs upstream gkr with its prover self-checks removed, which panic on
/// inconsistent layers: apply docs/keccacheck-soundness/scripts/forgery/
/// gkr-no-asserts.patch to a copy and point a cargo `patch` at it.
#[test]
#[ignore = "needs patched gkr"]
fn alternate_functions_with_consistent_proofs() {
    let mut accepted = Vec::new();
    for instances in [4usize] {
        let data = seed_data(instances, 7 + instances as u64);
        let a_t = lane_major(&data, instances);
        // Control: unmutated layers through the same harness must verify.
        let (states, rcs) = mutated_states(&a_t, Mutation::None);
        let output = states[23].iota.clone();
        assert_eq!(output, honest_output(&a_t, instances));
        let r = derive_r_native(&a_t, &output, instances.ilog2() as usize);
        let proof = prove_layers(&states, &rcs, r);
        assert_eq!(
            verdict(&Witness {
                proof,
                input: a_t.clone(),
                output
            })
            .0,
            0,
            "control rejected"
        );

        for m in all_mutations(instances) {
            let (states, rcs) = mutated_states(&a_t, m);
            let output = states[23].iota.clone();
            let input = states[0].a.clone();
            let false_statement = output != honest_output(&input, instances);
            let r = derive_r_native(&input, &output, instances.ilog2() as usize);
            let proof = prove_layers(&states, &rcs, r);
            let (bad, total) = verdict(&Witness {
                proof,
                input,
                output,
            });
            println!("{instances} {m:?} false={false_statement} unsat={bad}/{total}");
            if bad == 0 && false_statement {
                accepted.push((instances, m));
            }
        }
    }
    assert!(accepted.is_empty(), "FORGERY: {accepted:?}");
}

/// True layers, but the statement claims a different output or input, with r
/// from the false statement.
#[test]
fn honest_layers_false_statement() {
    let instances = 4;
    let a_t = lane_major(&seed_data(instances, 5), instances);
    let (states, rcs) = mutated_states(&a_t, Mutation::None);
    for (name, flip_in, flip_out) in [
        ("output", false, true),
        ("input", true, false),
        ("both", true, true),
    ] {
        let (mut input, mut output) = (states[0].a.clone(), states[23].iota.clone());
        if flip_in {
            input[3 * instances + 1] ^= 1 << 9;
        }
        if flip_out {
            output[24 * instances + 3] ^= 1 << 63;
        }
        let r = derive_r_native(&input, &output, instances.ilog2() as usize);
        let proof = prove_layers(&states, &rcs, r);
        let (bad, total) = verdict(&Witness {
            proof,
            input,
            output,
        });
        println!("{name}: unsat={bad}/{total}");
        assert!(bad > 0, "FORGERY {name}");
    }
}

/// Every statement word, both sides, low and high bit, with the challenge
/// re-derived from the flipped statement so the proof stays transcript-consistent.
/// Catches any position the packing or the MLE checks fail to cover.
#[test]
fn every_statement_word_is_bound() {
    let instances = 4;
    let a_t = lane_major(&seed_data(instances, 21), instances);
    let (states, rcs) = mutated_states(&a_t, Mutation::None);
    let (input, output) = (states[0].a.clone(), states[23].iota.clone());
    let mut cases = Vec::new();
    for word in 0..input.len() {
        for bit in [0u32, 63] {
            for side in [false, true] {
                cases.push((word, bit, side));
            }
        }
    }
    let accepted = std::sync::Mutex::new(Vec::new());
    let (states, rcs, input, output, accepted_ref) = (&states, &rcs, &input, &output, &accepted);
    std::thread::scope(|scope| {
        for chunk in cases.chunks(cases.len().div_ceil(6)) {
            scope.spawn(move || {
                for &(word, bit, side) in chunk {
                    let (mut i, mut o) = (input.clone(), output.clone());
                    if side {
                        o[word] ^= 1u64 << bit;
                    } else {
                        i[word] ^= 1u64 << bit;
                    }
                    let r = derive_r_native(&i, &o, instances.ilog2() as usize);
                    let proof = prove_layers(states, rcs, r);
                    if verdict(&Witness {
                        proof,
                        input: i,
                        output: o,
                    })
                    .0 == 0
                    {
                        accepted_ref.lock().unwrap().push((word, bit, side));
                    }
                }
            });
        }
    });
    println!("statement flips tested: {}", cases.len());
    let accepted = accepted.into_inner().unwrap();
    assert!(accepted.is_empty(), "FORGERY: {accepted:?}");
}

/// A valid proof replayed against the same pairs reordered between instances.
#[test]
fn reordering_is_not_accepted() {
    let instances = 4;
    let w = make_witness_from_data(&seed_data(instances, 11));
    let (mut input, mut output) = (w.input.clone(), w.output.clone());
    for l in 0..25 {
        input.swap(l * instances, l * instances + 1);
        output.swap(l * instances, l * instances + 1);
    }
    assert!(
        verdict(&Witness {
            proof: w.proof.clone(),
            input,
            output
        })
        .0 > 0
    );
}

/// All-zero states, the most degenerate MLEs, with a false output.
#[test]
fn degenerate_statements() {
    for instances in [4usize] {
        let data = vec![0u64; 25 * instances];
        let w = make_witness_from_data(&data);
        assert_eq!(verdict(&w).0, 0);
        let input = w.input.clone();
        let mut output = w.output.clone();
        output.iter_mut().for_each(|x| *x ^= 1);
        let r = derive_r_native(&input, &output, instances.ilog2() as usize);
        let (states, rcs) = mutated_states(&lane_major(&data, instances), Mutation::None);
        let proof = prove_layers(&states, &rcs, r);
        assert!(
            verdict(&Witness {
                proof,
                input,
                output
            })
            .0 > 0
        );
    }
}

/// Random proof elements, with all intermediates computed by synthesis.
#[test]
fn random_proof_rejected() {
    let mut rng = ark_std::test_rng();
    let w = make_witness_from_data(&seed_data(4, 3));
    let proof = (0..w.proof.len()).map(|_| Fr::rand(&mut rng)).collect();
    assert!(
        verdict(&Witness {
            proof,
            input: w.input,
            output: w.output
        })
        .0 > 0
    );
}

/// Given statement bits and proof elements, every other variable the verifier
/// allocates must be functionally pinned by the constraints.
#[test]
fn verifier_has_no_free_witnesses() {
    for instances in [4usize, 8] {
        let w = make_witness_from_data(&seed_data(instances, 13));
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut bits = Vec::new();
        for words in [&w.input, &w.output] {
            let mut side = Vec::with_capacity(words.len() * 64);
            for word in words.iter() {
                for b in 0..64 {
                    side.push(
                        Boolean::new_witness(cs.clone(), || Ok((word >> b) & 1 == 1)).unwrap(),
                    );
                }
            }
            bits.push(side);
        }
        let n_bits = cs.num_witness_variables();
        let profile = verify_boolean_batch(cs.clone(), &w.proof, &bits[0], &bits[1]).unwrap();
        let r = common::extract(&cs);
        assert!(r.unsatisfied().is_empty());
        assert!(r.unused().is_empty(), "unused: {:?}", r.unused());
        // Seed: statement bits then proof elements, which are allocated first.
        let mut known = vec![false; r.z.len()];
        for k in known
            .iter_mut()
            .take(r.num_instance + n_bits + w.proof.len())
        {
            *k = true;
        }
        let known = r.propagate(known);
        let free: Vec<usize> = (0..r.z.len()).filter(|i| !known[*i]).collect();
        println!(
            "{instances}: vars {} constraints {} bits {} proof {} free {} profile total {}",
            r.z.len(),
            r.a.len(),
            n_bits,
            w.proof.len(),
            free.len(),
            profile.total
        );
        assert!(
            free.is_empty(),
            "free witnesses: {:?}",
            &free[..free.len().min(20)]
        );
        // Statement bits must reach constraints other than their own booleanity.
        let occ = r.occurrences();
        for i in r.num_instance..r.num_instance + n_bits {
            assert!(occ[i] >= 3, "bit var {i} occurs {} times", occ[i]);
        }
    }
}

/// Setup and proving synthesis produce identical matrices at the gadget level.
#[test]
fn setup_matches_prove_gadget() {
    use ark_relations::gr1cs::SynthesisMode;
    use mirage_gadgets::keccak::PermutationBackend;
    use mirage_keccacheck_arkworks::batch::KeccacheckBatch;
    for recorded in [1usize, 3, 4, 5] {
        let build = |prove: bool| {
            let cs = ConstraintSystem::<Fr>::new_ref();
            if !prove {
                cs.set_mode(SynthesisMode::Setup);
            }
            let mut batch = KeccacheckBatch::new(cs.clone());
            let mut state: mirage_gadgets::keccak::State<Fr> = core::array::from_fn(|l| {
                core::array::from_fn(|b| {
                    Boolean::new_witness(cs.clone(), || {
                        Ok(((l as u64 * 37 + 5) >> (b % 13)) & 1 == 1)
                    })
                    .unwrap()
                })
            });
            for _ in 0..recorded {
                state = batch.permute(state).unwrap();
            }
            batch.finish().unwrap();
            cs.finalize();
            cs.to_matrices().unwrap()
        };
        let (s, p) = (build(false), build(true));
        assert_eq!(s, p, "matrices differ at recorded={recorded}");
    }
}
