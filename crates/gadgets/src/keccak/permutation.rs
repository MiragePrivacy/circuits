//! keccak-f[1600] permutation over boolean signals.
//!
//! The state is 25 lanes of 64 bits, held as `Boolean` throughout rather than
//! packed into field elements. That is deliberate:
//!
//! - **XOR is free.** For booleans `a` and `b`, `a XOR b = a + b - 2ab`, which
//!   arkworks emits as a linear combination when one side is constant and one
//!   constraint otherwise. Theta and chi are almost entirely XOR.
//! - **Rotation is free.** `rotl` is an index permutation on a bit array, so it
//!   emits no constraints at all.
//! - Packing to field elements and back would cost range checks on every
//!   round-trip and buy nothing, since no step needs field arithmetic.
//!
//! The only genuinely non-linear step is chi's `AND`, which is one constraint
//! per bit: 1600 per round, 38,400 across 24 rounds. Everything above that in
//! the measured ~150k per block comes from the boolean allocations and the
//! XOR chains.
//!
//! Bit ordering follows the spec: lane `i` holds bits in little-endian order,
//! matching the byte order the sponge feeds in. ZoKrates does the same job with
//! explicit `swap_u64` calls on entry and exit because it works on `u64`s; a
//! bit-array representation makes those byte swaps an indexing convention
//! instead, so they vanish.

use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_relations::gr1cs::SynthesisError;

/// 25 lanes of 64 bits.
pub type State<F> = [[Boolean<F>; 64]; 25];

/// Rotation offsets, indexed by the rho/pi step order.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane permutation for the rho/pi step.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Round constants, applied to lane 0 in iota.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Left-rotate a lane by `n`. Pure indexing: emits no constraints.
fn rotl<F: PrimeField>(lane: &[Boolean<F>; 64], n: u32) -> [Boolean<F>; 64] {
    let n = (n % 64) as usize;
    core::array::from_fn(|i| lane[(i + 64 - n) % 64].clone())
}

/// XOR two lanes bitwise.
fn xor_lane<F: PrimeField>(
    a: &[Boolean<F>; 64],
    b: &[Boolean<F>; 64],
) -> Result<[Boolean<F>; 64], SynthesisError> {
    let mut out = Vec::with_capacity(64);
    for i in 0..64 {
        out.push(a[i].clone() ^ &b[i]);
    }
    out.try_into().map_err(|_| SynthesisError::Unsatisfiable)
}

/// The keccak-f[1600] permutation, 24 rounds.
pub fn keccak_f1600<F: PrimeField>(mut st: State<F>) -> Result<State<F>, SynthesisError> {
    for rc in RC {
        // theta: column parities, then fold each into its column.
        let mut bc: Vec<[Boolean<F>; 64]> = Vec::with_capacity(5);
        for i in 0..5 {
            let mut acc = st[i].clone();
            for j in 1..5 {
                acc = xor_lane(&acc, &st[i + 5 * j])?;
            }
            bc.push(acc);
        }

        for i in 0..5 {
            let t = xor_lane(&bc[(i + 4) % 5], &rotl(&bc[(i + 1) % 5], 1))?;
            for j in 0..5 {
                st[(j * 5) + i] = xor_lane(&st[(j * 5) + i], &t)?;
            }
        }

        // rho and pi: rotate and permute lanes. Indexing only.
        let mut t = st[1].clone();
        for i in 0..24 {
            let j = PI[i];
            let tmp = st[j].clone();
            st[j] = rotl(&t, RHO[i]);
            t = tmp;
        }

        // chi: the only non-linear step. One AND constraint per bit.
        for i in 0..5 {
            let row: Vec<[Boolean<F>; 64]> = (0..5).map(|j| st[(i * 5) + j].clone()).collect();
            for j in 0..5 {
                let not_next: [Boolean<F>; 64] =
                    core::array::from_fn(|b| !row[(j + 1) % 5][b].clone());
                let mut anded = Vec::with_capacity(64);
                for b in 0..64 {
                    anded.push(not_next[b].clone() & &row[(j + 2) % 5][b]);
                }
                let anded: [Boolean<F>; 64] = anded
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?;
                st[(i * 5) + j] = xor_lane(&row[j], &anded)?;
            }
        }

        // iota: XOR the round constant into lane 0. Constant operand, so this
        // is a linear combination rather than a constraint.
        for (b, bit) in st[0].iter_mut().enumerate() {
            if (rc >> b) & 1 == 1 {
                *bit = !bit.clone();
            }
        }
    }

    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::GR1CSVar;
    use ark_relations::gr1cs::ConstraintSystem;

    /// Native keccak-f[1600], for differential testing.
    fn native_f1600(st: &mut [u64; 25]) {
        for rc in RC {
            let mut bc = [0u64; 5];
            for i in 0..5 {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }
            for i in 0..5 {
                let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
                for j in 0..5 {
                    st[(j * 5) + i] ^= t;
                }
            }
            let mut t = st[1];
            for i in 0..24 {
                let j = PI[i];
                let tmp = st[j];
                st[j] = t.rotate_left(RHO[i]);
                t = tmp;
            }
            for i in 0..5 {
                let mut row = [0u64; 5];
                row[..5].copy_from_slice(&st[i * 5..i * 5 + 5]);
                for j in 0..5 {
                    st[(i * 5) + j] = row[j] ^ ((!row[(j + 1) % 5]) & row[(j + 2) % 5]);
                }
            }
            st[0] ^= rc;
        }
    }

    fn alloc_state(
        cs: ark_relations::gr1cs::ConstraintSystemRef<Fr>,
        lanes: &[u64; 25],
    ) -> State<Fr> {
        core::array::from_fn(|i| {
            core::array::from_fn(|b| {
                Boolean::new_witness(cs.clone(), || Ok((lanes[i] >> b) & 1 == 1)).unwrap()
            })
        })
    }

    fn read_state(st: &State<Fr>) -> [u64; 25] {
        let mut out = [0u64; 25];
        for (i, lane) in st.iter().enumerate() {
            for (b, bit) in lane.iter().enumerate() {
                if bit.value().unwrap() {
                    out[i] |= 1 << b;
                }
            }
        }
        out
    }

    #[test]
    fn permutation_matches_native_on_zero_state() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let lanes = [0u64; 25];
        let out = keccak_f1600(alloc_state(cs.clone(), &lanes)).unwrap();

        let mut expected = lanes;
        native_f1600(&mut expected);

        assert_eq!(read_state(&out), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn permutation_matches_native_on_patterned_state() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let lanes: [u64; 25] = core::array::from_fn(|i| {
            (i as u64)
                .wrapping_mul(0x0123_4567_89ab_cdef)
                .rotate_left(i as u32)
        });
        let out = keccak_f1600(alloc_state(cs.clone(), &lanes)).unwrap();

        let mut expected = lanes;
        native_f1600(&mut expected);

        assert_eq!(read_state(&out), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn permutation_constraint_cost() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let before = cs.num_constraints();
        let _ = keccak_f1600(alloc_state(cs.clone(), &[0u64; 25])).unwrap();
        let cost = cs.num_constraints() - before;

        // Recorded so a regression shows up in review. The chi AND alone is
        // 1600 bits * 24 rounds = 38,400; the rest is XOR chains.
        println!("keccak-f[1600] constraints: {cost}");
        assert!(cost > 0, "permutation emitted no constraints");
    }
}
