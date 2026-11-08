use ark_relations::gr1cs::ConstraintSystem;
use mirage_keccacheck_arkworks::verifier::{make_witness_from_data, verify_witness};

fn main() {
    let log_h: usize = std::env::args().nth(1).unwrap().parse().unwrap();
    let h = 1usize << log_h;
    let mut x = 0x9E3779B97F4A7C15u64;
    let data: Vec<u64> = (0..25 * h)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        })
        .collect();
    let w = make_witness_from_data(&data);
    let cs = ConstraintSystem::new_ref();
    verify_witness(cs.clone(), &w).unwrap();
    println!("gadget_satisfied {}", cs.is_satisfied().unwrap());
    let join = |v: Vec<String>| v.join(" ");
    println!("input {}", join(w.input.iter().map(|v| v.to_string()).collect()));
    println!("output {}", join(w.output.iter().map(|v| v.to_string()).collect()));
    println!("proof {}", join(w.proof.iter().map(|v| v.to_string()).collect()));
}
