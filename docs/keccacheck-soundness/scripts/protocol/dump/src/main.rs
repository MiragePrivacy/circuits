// Runs the pinned native prover and replays its Fiat-Shamir transcript along an
// externally supplied R/G schedule, printing every value.
use ark_bn254::Fr;
use gkr::transcript::{Sponge, Verifier};
use std::io::Write;

fn derive_r(input: &[u64], output: &[u64], log: usize) -> Vec<Fr> {
    let word = Fr::from(1u128 << 64);
    let tag = u128::from_le_bytes(*b"mirage/kcck/stmt");
    let mut s = Sponge::new();
    s.absorb(Fr::from(tag));
    s.absorb(Fr::from(1u64 << log));
    for chunk in input.chunks(3).chain(output.chunks(3)) {
        s.absorb(chunk.iter().rev().fold(Fr::from(0u64), |a, v| a * word + Fr::from(*v)));
    }
    (0..log).map(|_| s.squeeze()).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let log: usize = a[1].parse().unwrap();
    let schedule = std::fs::read_to_string(&a[2]).unwrap();
    let mut out = std::io::BufWriter::new(std::fs::File::create(&a[3]).unwrap());
    let h = 1usize << log;
    let mut x = 0x0123456789abcdefu64 ^ (log as u64);
    let mut data = vec![0u64; h * 25];
    for v in data.iter_mut() {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17; *v = x;
    }
    let mut input = vec![0u64; h * 25];
    let mut output = vec![0u64; h * 25];
    for j in 0..h {
        let mut s: [u64; 25] = core::array::from_fn(|l| data[j * 25 + l]);
        for l in 0..25 { input[l * h + j] = s[l]; }
        keccak::f1600(&mut s);
        for l in 0..25 { output[l * h + j] = s[l]; }
    }
    let r = derive_r(&input, &output, log);
    let (proof, pi, po) = gkr::keccacheck_og::prover::prove(&data, r.clone());
    assert_eq!(pi, input);
    assert_eq!(po, output);
    let mut v = Verifier::new(&proof);
    for c in &r { v.absorb(*c); }
    let mut chal: Vec<Fr> = r.clone();
    let mut read: Vec<Fr> = vec![];
    for (i, op) in schedule.trim().chars().enumerate() {
        match op {
            'R' => read.push(v.read()),
            'G' => { if i >= log { chal.push(v.generate()); } }
            _ => panic!(),
        }
    }
    assert!(v.remaining().is_empty(), "schedule left proof elements unread");
    writeln!(out, "{}", input.iter().map(u64::to_string).collect::<Vec<_>>().join(" ")).unwrap();
    writeln!(out, "{}", output.iter().map(u64::to_string).collect::<Vec<_>>().join(" ")).unwrap();
    writeln!(out, "{}", read.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(" ")).unwrap();
    writeln!(out, "{}", chal.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(" ")).unwrap();
}
