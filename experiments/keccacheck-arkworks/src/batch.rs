//! Deferred Keccak-f backend for integration with Mirage's sponge gadgets.

use crate::verifier::{
    MIN_INSTANCES, VerificationProfile, make_witness_from_data, proof_elements,
    verify_boolean_batch,
};
use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, boolean::Boolean};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use mirage_gadgets::keccak::{PermutationBackend, State};

pub struct BatchResult {
    pub recorded: usize,
    pub padded: usize,
    pub profile: VerificationProfile,
}

pub struct KeccacheckBatch {
    cs: ConstraintSystemRef<Fr>,
    inputs: Vec<State<Fr>>,
    outputs: Vec<State<Fr>>,
    native_inputs: Option<Vec<[u64; 25]>>,
}

impl KeccacheckBatch {
    pub fn new(cs: ConstraintSystemRef<Fr>) -> Self {
        Self {
            cs,
            inputs: Vec::new(),
            outputs: Vec::new(),
            native_inputs: Some(Vec::new()),
        }
    }

    pub fn finish(mut self) -> Result<BatchResult, SynthesisError> {
        let recorded = self.inputs.len();
        assert!(recorded > 0, "cannot prove an empty Keccak batch");
        let padded = recorded.next_power_of_two().max(MIN_INSTANCES);
        while self.inputs.len() < padded {
            let input_words = [0u64; 25];
            let mut output_words = input_words;
            keccak::f1600(&mut output_words);
            self.inputs.push(constant_state(&input_words));
            self.outputs.push(constant_state(&output_words));
            if let Some(native) = &mut self.native_inputs {
                native.push(input_words);
            }
        }

        let proof = match &self.native_inputs {
            Some(native) => {
                let data = native
                    .iter()
                    .flat_map(|state| state.iter().copied())
                    .collect::<Vec<_>>();
                make_witness_from_data(&data).proof
            }
            None => vec![Fr::zero(); proof_elements(padded)],
        };
        let input_bits = transpose_states(&self.inputs);
        let output_bits = transpose_states(&self.outputs);
        let profile = verify_boolean_batch(self.cs, &proof, &input_bits, &output_bits)?;
        Ok(BatchResult {
            recorded,
            padded,
            profile,
        })
    }
}

impl PermutationBackend<Fr> for KeccacheckBatch {
    fn permute(&mut self, state: State<Fr>) -> Result<State<Fr>, SynthesisError> {
        let native_input = state_words(&state);
        let native_output = native_input.map(|mut words| {
            keccak::f1600(&mut words);
            words
        });
        if let Some(inputs) = &mut self.native_inputs {
            match native_input {
                Some(words) => inputs.push(words),
                None => self.native_inputs = None,
            }
        }

        let mut lanes = Vec::with_capacity(25);
        for lane in 0..25 {
            let mut bits = Vec::with_capacity(64);
            for bit in 0..64 {
                bits.push(Boolean::new_witness(self.cs.clone(), || {
                    native_output
                        .map(|words| (words[lane] >> bit) & 1 == 1)
                        .ok_or(SynthesisError::AssignmentMissing)
                })?);
            }
            lanes.push(bits.try_into().map_err(|_| SynthesisError::Unsatisfiable)?);
        }
        let output: State<Fr> = lanes
            .try_into()
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        self.inputs.push(state);
        self.outputs.push(output.clone());
        Ok(output)
    }
}

fn state_words(state: &State<Fr>) -> Option<[u64; 25]> {
    let mut words = [0u64; 25];
    for lane in 0..25 {
        for bit in 0..64 {
            if state[lane][bit].value().ok()? {
                words[lane] |= 1u64 << bit;
            }
        }
    }
    Some(words)
}

fn constant_state(words: &[u64; 25]) -> State<Fr> {
    core::array::from_fn(|lane| {
        core::array::from_fn(|bit| Boolean::constant((words[lane] >> bit) & 1 == 1))
    })
}

fn transpose_states(states: &[State<Fr>]) -> Vec<Boolean<Fr>> {
    let mut bits = Vec::with_capacity(states.len() * 25 * 64);
    for lane in 0..25 {
        for state in states {
            bits.extend(state[lane].iter().cloned());
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::ConstraintSystem;

    fn witness_state(cs: ConstraintSystemRef<Fr>, seed: u64) -> State<Fr> {
        core::array::from_fn(|lane| {
            let word = seed.wrapping_add(lane as u64);
            core::array::from_fn(|bit| {
                Boolean::new_witness(cs.clone(), || Ok((word >> bit) & 1 == 1)).unwrap()
            })
        })
    }

    /// Flips allocated bits after synthesis.
    ///
    /// Symbolic linear combinations cache their values when created. The system
    /// is finalized (inlining every combination into witness terms) and the
    /// cache dropped, so each constraint re-evaluates from the edited witness.
    fn flip(cs: &ConstraintSystemRef<Fr>, bits: &[Boolean<Fr>]) {
        cs.finalize();
        let mut inner = cs.borrow_mut().unwrap();
        for bit in bits {
            let Boolean::Var(bit) = bit else {
                panic!("expected an allocated bit");
            };
            let value = &mut inner.assignments.witness_assignment[bit.variable().index().unwrap()];
            *value = Fr::from(1u64) - *value;
        }
        inner.assignments.lc_assignment.clear();
    }

    #[test]
    fn caller_owned_states_are_verified_and_padding_is_constant() {
        let cs = ConstraintSystem::new_ref();
        let mut batch = KeccacheckBatch::new(cs.clone());
        for seed in [7, 11, 19] {
            let _ = batch.permute(witness_state(cs.clone(), seed)).unwrap();
        }
        let result = batch.finish().unwrap();
        assert_eq!(result.recorded, 3);
        assert_eq!(result.padded, 4);
        assert!(cs.is_satisfied().unwrap());
    }

    /// A singleton GKR batch derives no output challenge, so one recorded
    /// permutation is padded up to `MIN_INSTANCES`.
    #[test]
    fn a_single_permutation_is_padded_and_verifies() {
        let cs = ConstraintSystem::new_ref();
        let mut batch = KeccacheckBatch::new(cs.clone());
        let _ = batch.permute(witness_state(cs.clone(), 7)).unwrap();
        let result = batch.finish().unwrap();
        assert_eq!(result.recorded, 1);
        assert_eq!(result.padded, MIN_INSTANCES);
        assert!(
            cs.is_satisfied().unwrap(),
            "genuine single-permutation batch rejected"
        );
    }

    #[test]
    fn a_single_permutation_batch_rejects_a_forged_output() {
        let cs = ConstraintSystem::new_ref();
        let mut batch = KeccacheckBatch::new(cs.clone());
        let output = batch.permute(witness_state(cs.clone(), 7)).unwrap();
        let _ = batch.finish().unwrap();
        assert!(cs.is_satisfied().unwrap());
        flip(&cs, &output[0][..1]);
        assert!(
            !cs.is_satisfied().unwrap(),
            "batch accepted an output bit that is not keccak-f(input)"
        );
    }

    #[test]
    fn a_single_permutation_batch_rejects_a_forged_input() {
        let cs = ConstraintSystem::new_ref();
        let mut batch = KeccacheckBatch::new(cs.clone());
        let input = witness_state(cs.clone(), 7);
        let _ = batch.permute(input.clone()).unwrap();
        let _ = batch.finish().unwrap();
        assert!(cs.is_satisfied().unwrap());
        flip(&cs, &input[3][..1]);
        assert!(
            !cs.is_satisfied().unwrap(),
            "batch accepted an input bit that does not map to its output"
        );
    }
}
