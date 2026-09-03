use ark_bn254::Fr;
use ark_relations::gr1cs::ConstraintSystem;
use mirage_keccacheck_arkworks::verifier::{make_witness, verify_witness_profile};
use std::{env, process::ExitCode, time::Instant};

const DIRECT_CONSTRAINTS_PER_PERMUTATION: usize = 155_200;

fn usage() {
    eprintln!("usage: mirage-keccacheck-arkworks compare [power-of-two instances ...]");
}

fn compare(instances: usize) -> Result<(), String> {
    if !instances.is_power_of_two() {
        return Err(format!("instance count {instances} is not a power of two"));
    }

    let started = Instant::now();
    let witness = make_witness(instances);
    let prove_ms = started.elapsed().as_millis();

    let cs = ConstraintSystem::<Fr>::new_ref();
    let started = Instant::now();
    let profile =
        verify_witness_profile(cs.clone(), &witness).map_err(|error| error.to_string())?;
    let synth_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let satisfied = cs.is_satisfied().map_err(|error| error.to_string())?;
    let check_ms = started.elapsed().as_millis();
    if !satisfied {
        return Err(format!(
            "valid {instances}-instance proof was not satisfied"
        ));
    }

    let gkr_constraints = cs.num_constraints();
    let direct_constraints = DIRECT_CONSTRAINTS_PER_PERMUTATION * instances;
    println!(
        "{instances},{},{},{gkr_constraints},{direct_constraints},{:.3},{},{},{},{},{},{prove_ms},{synth_ms},{check_ms}",
        witness.proof.len(),
        witness.proof.len() * 32,
        direct_constraints as f64 / gkr_constraints as f64,
        profile.allocation,
        profile.output_binding,
        profile.output_reduction,
        profile.rounds,
        profile.input_binding,
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("compare") {
        usage();
        return Err("missing compare command".to_owned());
    }
    let instances = args
        .map(|arg| arg.parse::<usize>().map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let instances = if instances.is_empty() {
        vec![1, 2, 8]
    } else {
        instances
    };
    println!(
        "instances,proof_elements,proof_bytes,gkr_constraints,direct_constraints,direct_over_gkr,allocation_constraints,output_binding_constraints,output_reduction_constraints,round_constraints,input_binding_constraints,native_prove_ms,synthesize_ms,check_ms"
    );
    for count in instances {
        compare(count)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
