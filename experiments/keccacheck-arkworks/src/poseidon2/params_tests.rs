//! Pins the Poseidon2 instance: round counts, constants, linear layers and cost.

use super::*;
use ark_ff::{BigInt, BigInteger, Field, One, PrimeField, Zero};
use ark_r1cs_std::{GR1CSVar, alloc::AllocVar};
use ark_relations::gr1cs::ConstraintSystem;

const RF: usize = 8;
const RP: usize = 57;
const FIELD_BITS: u64 = 254;
const M4: [[u64; 4]; 4] = [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]];
const EXPECTED_DIAG: [u64; WIDTH] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 16, 17];

/// Grain LFSR of the Poseidon reference scripts, for a prime field and x^alpha.
struct Grain(Vec<bool>);

impl Grain {
    fn new(n: u64, t: u64, rf: u64, rp: u64) -> Self {
        let mut bits = Vec::with_capacity(80);
        for (value, len) in [(1, 2), (0, 4), (n, 12), (t, 12), (rf, 10), (rp, 10)] {
            bits.extend((0..len).rev().map(|k| (value >> k) & 1 == 1));
        }
        bits.resize(80, true);
        let mut grain = Self(bits);
        for _ in 0..160 {
            grain.step();
        }
        grain
    }

    fn step(&mut self) -> bool {
        let b = &self.0;
        let bit = b[62] ^ b[51] ^ b[38] ^ b[23] ^ b[13] ^ b[0];
        self.0.remove(0);
        self.0.push(bit);
        bit
    }

    fn output_bit(&mut self) -> bool {
        loop {
            let keep = self.step();
            let bit = self.step();
            if keep {
                return bit;
            }
        }
    }

    /// Next field element, rejecting values at or above the modulus.
    fn next_field(&mut self, n: usize) -> Fr {
        loop {
            let mut bits = vec![false; 256 - n];
            bits.extend((0..n).map(|_| self.output_bit()));
            if let Some(value) = Fr::from_bigint(BigInt::<4>::from_bits_be(&bits)) {
                return value;
            }
        }
    }
}

fn apply(layer: fn(&mut [FpVar<Fr>; WIDTH]), input: [Fr; WIDTH]) -> [Fr; WIDTH] {
    let mut state = input.map(FpVar::Constant);
    layer(&mut state);
    core::array::from_fn(|i| state[i].value().unwrap())
}

/// Reads a linear layer from its action on basis vectors, as rows.
fn extract(layer: fn(&mut [FpVar<Fr>; WIDTH])) -> [[Fr; WIDTH]; WIDTH] {
    let columns: [[Fr; WIDTH]; WIDTH] = core::array::from_fn(|j| {
        apply(
            layer,
            core::array::from_fn(|i| if i == j { Fr::one() } else { Fr::zero() }),
        )
    });
    core::array::from_fn(|i| core::array::from_fn(|j| columns[j][i]))
}

fn rank(mut rows: Vec<[Fr; WIDTH]>) -> usize {
    let mut rank = 0;
    for column in 0..WIDTH {
        let Some(pivot) = (rank..rows.len()).find(|&r| !rows[r][column].is_zero()) else {
            continue;
        };
        rows.swap(rank, pivot);
        let inverse = rows[rank][column].inverse().unwrap();
        for value in &mut rows[rank] {
            *value *= inverse;
        }
        let pivot_row = rows[rank];
        for (r, row) in rows.iter_mut().enumerate() {
            if r != rank && !row[column].is_zero() {
                let factor = row[column];
                for (value, pivot_value) in row.iter_mut().zip(pivot_row) {
                    *value -= factor * pivot_value;
                }
            }
        }
        rank += 1;
    }
    rank
}

fn row_times(row: &[Fr; WIDTH], matrix: &[[Fr; WIDTH]; WIDTH]) -> [Fr; WIDTH] {
    core::array::from_fn(|j| (0..WIDTH).map(|i| row[i] * matrix[i][j]).sum())
}

fn native_round_model(input: [Fr; WIDTH]) -> [Fr; WIDTH] {
    let external = extract(mat_full_16);
    let internal = extract(mat_partial_16);
    let times = |m: &[[Fr; WIDTH]; WIDTH], x: &[Fr; WIDTH]| -> [Fr; WIDTH] {
        core::array::from_fn(|i| (0..WIDTH).map(|j| m[i][j] * x[j]).sum())
    };
    let mut state = times(&external, &input);
    for rc in RC16.0.iter().chain(RC16.2.iter()).take(RF / 2) {
        state = core::array::from_fn(|i| (state[i] + rc[i]).pow([5u64]));
        state = times(&external, &state);
    }
    for rc in RC16.1 {
        state[0] = (state[0] + rc).pow([5u64]);
        state = times(&internal, &state);
    }
    for rc in RC16.2 {
        state = core::array::from_fn(|i| (state[i] + rc[i]).pow([5u64]));
        state = times(&external, &state);
    }
    state
}

#[test]
fn field_and_round_counts_are_pinned() {
    assert_eq!(Fr::MODULUS_BIT_SIZE as u64, FIELD_BITS);
    // x^5 is a permutation of the field only if 5 does not divide p - 1.
    let mut remainder = 0u64;
    for limb in Fr::MODULUS.0.iter().rev() {
        remainder = (((remainder as u128) << 64 | *limb as u128) % 5) as u64;
    }
    assert_ne!(remainder, 1);
    assert_eq!(RC16.0.len(), RF / 2);
    assert_eq!(RC16.1.len(), RP);
    assert_eq!(RC16.2.len(), RF / 2);
    assert_eq!((RATE, WIDTH), (10, 16));
}

#[test]
fn round_constants_regenerate_from_grain() {
    let mut grain = Grain::new(FIELD_BITS, WIDTH as u64, RF as u64, RP as u64);
    for rc in &RC16.0 {
        for value in rc {
            assert_eq!(grain.next_field(FIELD_BITS as usize), *value);
        }
    }
    for value in &RC16.1 {
        assert_eq!(grain.next_field(FIELD_BITS as usize), *value);
    }
    for rc in &RC16.2 {
        for value in rc {
            assert_eq!(grain.next_field(FIELD_BITS as usize), *value);
        }
    }
}

#[test]
fn external_matrix_is_two_circulant_tensor_m4() {
    let matrix = extract(mat_full_16);
    for (i, row) in matrix.iter().enumerate() {
        for (j, value) in row.iter().enumerate() {
            let scale = if i / 4 == j / 4 { 2 } else { 1 };
            assert_eq!(*value, Fr::from(scale * M4[i % 4][j % 4]), "entry {i},{j}");
        }
    }
    assert_eq!(rank(matrix.to_vec()), WIDTH);
}

#[test]
fn m4_is_mds() {
    let m = M4.map(|row| row.map(Fr::from));
    let det = |rows: &[usize], columns: &[usize]| -> Fr {
        let mut a: Vec<Vec<Fr>> = rows
            .iter()
            .map(|&r| columns.iter().map(|&c| m[r][c]).collect())
            .collect();
        let mut det = Fr::one();
        for k in 0..a.len() {
            let Some(pivot) = (k..a.len()).find(|&r| !a[r][k].is_zero()) else {
                return Fr::zero();
            };
            if pivot != k {
                a.swap(pivot, k);
                det = -det;
            }
            det *= a[k][k];
            let inverse = a[k][k].inverse().unwrap();
            for r in k + 1..a.len() {
                let factor = a[r][k] * inverse;
                for c in k..a.len() {
                    let sub = a[k][c];
                    a[r][c] -= factor * sub;
                }
            }
        }
        det
    };
    for size in 1..=4usize {
        let subsets: Vec<Vec<usize>> = (0u32..16)
            .filter(|mask| mask.count_ones() as usize == size)
            .map(|mask| (0..4).filter(|bit| mask >> bit & 1 == 1).collect())
            .collect();
        for rows in &subsets {
            for columns in &subsets {
                assert!(!det(rows, columns).is_zero(), "minor {rows:?} {columns:?}");
            }
        }
    }
}

#[test]
fn internal_matrix_is_ones_plus_pinned_diagonal() {
    let matrix = extract(mat_partial_16);
    for (i, row) in matrix.iter().enumerate() {
        for (j, value) in row.iter().enumerate() {
            let diagonal = if i == j { EXPECTED_DIAG[i] } else { 0 };
            assert_eq!(*value, Fr::from(diagonal + 1), "entry {i},{j}");
        }
    }
    assert_eq!(rank(matrix.to_vec()), WIDTH);
}

/// Without a full rank the S-box coordinate would admit an infinite subspace trail.
#[test]
fn internal_matrix_has_no_infinite_trail_from_the_sbox_coordinate() {
    let matrix = extract(mat_partial_16);
    let mut row: [Fr; WIDTH] =
        core::array::from_fn(|i| if i == 0 { Fr::one() } else { Fr::zero() });
    let mut rows = Vec::with_capacity(WIDTH);
    for _ in 0..WIDTH {
        rows.push(row);
        row = row_times(&row, &matrix);
    }
    assert_eq!(rank(rows), WIDTH);
}

#[test]
fn initial_linear_layer_and_round_order_are_as_modelled() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let input: [Fr; WIDTH] = core::array::from_fn(|i| Fr::from(i as u64 * 3 + 1));
    let mut state: [FpVar<Fr>; WIDTH] =
        core::array::from_fn(|i| FpVar::new_witness(cs.clone(), || Ok(input[i])).unwrap());
    permute_16(&mut state);
    let got: [Fr; WIDTH] = core::array::from_fn(|i| state[i].value().unwrap());
    assert_eq!(got, native_round_model(input));
}

#[test]
fn permutation_matches_reference_test_vector() {
    let input: [Fr; WIDTH] = core::array::from_fn(|i| Fr::from(i as u64));
    let mut state = input.map(FpVar::Constant);
    permute_16(&mut state);
    assert_eq!(
        state[0].value().unwrap(),
        MontFp!("7913381039332130239696391099451993335431181984785002668304949494341223775274")
    );
    assert_eq!(
        state[15].value().unwrap(),
        MontFp!("12353300117943495010938017401947409192192248445045039923330878007229549978485")
    );
}

#[test]
fn permutation_costs_555_constraints_on_witness_state() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let mut state: [FpVar<Fr>; WIDTH] = core::array::from_fn(|i| {
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(i as u64))).unwrap()
    });
    permute_16(&mut state);
    assert_eq!(cs.num_constraints(), 3 * (RF * WIDTH + RP));
    assert_eq!(cs.num_constraints(), 555);
}

/// Absorption positions decide how much of a block the prover controls.
#[test]
fn absorb_after_squeeze_starts_past_the_squeezed_positions() {
    let value = |k: u64| Fr::from(1000 + k);
    let mut sponge = SpongeVar::new();
    let mut model = INITIAL_STATE;
    let permute = |state: &mut [Fr; WIDTH]| {
        let mut vars = state.map(FpVar::Constant);
        permute_16(&mut vars);
        *state = core::array::from_fn(|i| vars[i].value().unwrap());
    };
    for k in 0..3 {
        sponge.absorb(&FpVar::Constant(value(k)));
        model[k as usize] += value(k);
    }
    permute(&mut model);
    assert_eq!(sponge.squeeze().value().unwrap(), model[0]);
    for k in 0..6 {
        sponge.absorb(&FpVar::Constant(value(k)));
        model[1 + k as usize] += value(k);
    }
    permute(&mut model);
    assert_eq!(sponge.squeeze().value().unwrap(), model[0]);
    assert_eq!(sponge.squeeze().value().unwrap(), model[1]);
    for k in 0..9 {
        sponge.absorb(&FpVar::Constant(value(k)));
        if k < 8 {
            model[2 + k as usize] += value(k);
        }
    }
    permute(&mut model);
    model[0] += value(8);
    permute(&mut model);
    assert_eq!(sponge.squeeze().value().unwrap(), model[0]);
}

#[test]
fn sponge_matches_native_transcript() {
    use ark_bn254_05::Fr as Fr05;
    let mut native = gkr::transcript::Sponge::new();
    let mut gadget = SpongeVar::new();
    for (step, reads) in [2usize, 6, 25, 3, 10, 0, 1].into_iter().enumerate() {
        for k in 0..reads {
            let v = (step * 100 + k) as u64;
            native.absorb(Fr05::from(v));
            gadget.absorb(&FpVar::Constant(Fr::from(v)));
        }
        for _ in 0..=step * 4 {
            assert_eq!(
                gadget.squeeze().value().unwrap().to_string(),
                native.squeeze().to_string()
            );
        }
    }
}
