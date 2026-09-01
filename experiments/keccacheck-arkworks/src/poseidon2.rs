//! Width-16 Poseidon2 transcript gadget matching Keccacheck commit `15f00e3`.

use crate::poseidon2_constants::RC16;
use ark_bn254::Fr;
use ark_ff::MontFp;
use ark_r1cs_std::fields::fp::FpVar;

pub const RATE: usize = 10;
const WIDTH: usize = 16;

pub const INITIAL_STATE: [Fr; WIDTH] = [
    MontFp!("314159265358979323846264338327950288419716939937510582097494"),
    MontFp!("45923078164062862089986280348253421170679821480865132823066470"),
    MontFp!("93844609550582231725359408128481117450284102701938521105559644"),
    MontFp!("62294895493038196442881097566593344612847564823378678316527120"),
    MontFp!("19091456485669234603486104543266482133936072602491412737245870"),
    MontFp!("06606315588174881520920962829254091715364367892590360011330530"),
    MontFp!("54882046652138414695194151160943305727036575959195309218611738"),
    MontFp!("19326117931051185480744623799627495673518857527248912279381830"),
    MontFp!("11949129833673362440656643086021394946395224737190702179860943"),
    MontFp!("70277053921717629317675238467481846766940513200056812714526356"),
    MontFp!("08277857713427577896091736371787214684409012249534301465495853"),
    MontFp!("71050792279689258923542019956112129021960864034418159813629774"),
    MontFp!("77130996051870721134999999837297804995105973173281609631859502"),
    MontFp!("44594553469083026425223082533446850352619311881710100031378387"),
    MontFp!("52886587533208381420617177669147303598253490428755468731159562"),
    MontFp!("86388235378759375195778185778053217122680661300192787661119590"),
];

fn sbox(x: &FpVar<Fr>) -> FpVar<Fr> {
    let x2 = x * x;
    let x4 = &x2 * &x2;
    x4 * x
}

fn mat_full_4(state: &mut [FpVar<Fr>]) {
    let t0 = &state[0] + &state[1];
    let t1 = &state[2] + &state[3];
    let t2 = &state[1] + &state[1] + &t1;
    let t3 = &state[3] + &state[3] + &t0;
    let t4 = &t1 + &t1 + &t1 + &t1 + &t3;
    let t5 = &t0 + &t0 + &t0 + &t0 + &t2;
    let t6 = &t3 + &t5;
    let t7 = &t2 + &t4;
    state.clone_from_slice(&[t6, t5, t7, t4]);
}

fn mat_full_16(state: &mut [FpVar<Fr>; WIDTH]) {
    let mut sum: [FpVar<Fr>; 4] = core::array::from_fn(|_| FpVar::Constant(Fr::from(0u64)));
    for chunk in state.chunks_exact_mut(4) {
        mat_full_4(chunk);
        for j in 0..4 {
            sum[j] += &chunk[j];
        }
    }
    for chunk in state.chunks_exact_mut(4) {
        for j in 0..4 {
            chunk[j] += &sum[j];
        }
    }
}

fn mat_partial_16(state: &mut [FpVar<Fr>; WIDTH]) {
    let sum = state
        .iter()
        .cloned()
        .fold(FpVar::Constant(Fr::from(0u64)), |acc, x| acc + x);
    const DIAG: [u64; WIDTH] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 16, 17];
    for i in 0..WIDTH {
        state[i] = &state[i] * Fr::from(DIAG[i]) + &sum;
    }
}

pub fn permute_16(state: &mut [FpVar<Fr>; WIDTH]) {
    mat_full_16(state);
    for rc in RC16.0 {
        for i in 0..WIDTH {
            state[i] += rc[i];
            state[i] = sbox(&state[i]);
        }
        mat_full_16(state);
    }
    for rc in RC16.1 {
        state[0] += rc;
        state[0] = sbox(&state[0]);
        mat_partial_16(state);
    }
    for rc in RC16.2 {
        for i in 0..WIDTH {
            state[i] += rc[i];
            state[i] = sbox(&state[i]);
        }
        mat_full_16(state);
    }
}

#[derive(Clone)]
pub struct SpongeVar {
    state: [FpVar<Fr>; WIDTH],
    idx: usize,
    dirty: bool,
}

impl SpongeVar {
    pub fn new() -> Self {
        Self {
            state: INITIAL_STATE.map(FpVar::Constant),
            idx: 0,
            dirty: true,
        }
    }

    pub fn absorb(&mut self, value: &FpVar<Fr>) {
        if self.idx < RATE {
            self.state[self.idx] += value;
            self.idx += 1;
        } else {
            permute_16(&mut self.state);
            self.state[0] += value;
            self.idx = 1;
        }
        self.dirty = true;
    }

    pub fn squeeze(&mut self) -> FpVar<Fr> {
        if self.dirty || self.idx >= RATE {
            permute_16(&mut self.state);
            self.idx = 0;
            self.dirty = false;
        }
        let out = self.state[self.idx].clone();
        self.idx += 1;
        out
    }
}

impl Default for SpongeVar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn permutation_matches_upstream_native() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let input: [Fr; 16] = core::array::from_fn(|i| Fr::from(i as u64));
        let mut expected = input;
        gkr::poseidon::permute_16(&mut expected);
        let mut state: [FpVar<Fr>; 16] =
            core::array::from_fn(|i| FpVar::new_witness(cs.clone(), || Ok(input[i])).unwrap());
        permute_16(&mut state);
        let got: Vec<Fr> = state.iter().map(|x| x.value().unwrap()).collect();
        assert_eq!(got, expected);
        assert!(cs.is_satisfied().unwrap());
    }
}
