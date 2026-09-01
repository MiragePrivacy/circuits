//! Direct bit-level R1CS Keccak control.
//!
//! This is the same Boolean construction used by Mirage: theta and chi use
//! ordinary Boolean XOR/AND constraints while rho and pi are wire permutations.

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

pub type StateVar<F> = [[Boolean<F>; 64]; 25];

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

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

fn rotl<F: PrimeField>(lane: &[Boolean<F>; 64], n: u32) -> [Boolean<F>; 64] {
    let n = (n % 64) as usize;
    core::array::from_fn(|i| lane[(i + 64 - n) % 64].clone())
}

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

pub fn keccak_f1600<F: PrimeField>(mut st: StateVar<F>) -> Result<StateVar<F>, SynthesisError> {
    for rc in RC {
        let mut bc = Vec::with_capacity(5);
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
                st[j * 5 + i] = xor_lane(&st[j * 5 + i], &t)?;
            }
        }

        let mut t = st[1].clone();
        for i in 0..24 {
            let j = PI[i];
            let tmp = st[j].clone();
            st[j] = rotl(&t, RHO[i]);
            t = tmp;
        }

        for i in 0..5 {
            let row: Vec<[Boolean<F>; 64]> = (0..5).map(|j| st[i * 5 + j].clone()).collect();
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
                st[i * 5 + j] = xor_lane(&row[j], &anded)?;
            }
        }

        for (b, bit) in st[0].iter_mut().enumerate() {
            if (rc >> b) & 1 == 1 {
                *bit = !bit.clone();
            }
        }
    }
    Ok(st)
}

pub fn synthesize_batch<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    inputs: &[[u64; 25]],
) -> Result<(), SynthesisError> {
    for input in inputs {
        let mut lanes = Vec::with_capacity(25);
        for word in input {
            let mut bits = Vec::with_capacity(64);
            for bit in 0..64 {
                bits.push(Boolean::new_witness(cs.clone(), || {
                    Ok((word >> bit) & 1 == 1)
                })?);
            }
            lanes.push(bits.try_into().map_err(|_| SynthesisError::Unsatisfiable)?);
        }
        let state: StateVar<F> = lanes
            .try_into()
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        let _ = keccak_f1600(state)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn direct_control_matches_mirage_cost() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        synthesize_batch(cs.clone(), &[[0u64; 25]]).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 155_200);
    }

    #[test]
    fn direct_control_matches_native_keccak() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut expected: [u64; 25] = core::array::from_fn(|i| i as u64);
        let state: StateVar<Fr> = core::array::from_fn(|lane| {
            core::array::from_fn(|bit| {
                Boolean::new_witness(cs.clone(), || Ok((expected[lane] >> bit) & 1 == 1)).unwrap()
            })
        });
        keccak::f1600(&mut expected);
        let output = keccak_f1600(state).unwrap();
        for lane in 0..25 {
            for (bit, output_bit) in output[lane].iter().enumerate() {
                assert_eq!(
                    output_bit.value().unwrap(),
                    (expected[lane] >> bit) & 1 == 1
                );
            }
        }
        assert!(cs.is_satisfied().unwrap());
    }
}
