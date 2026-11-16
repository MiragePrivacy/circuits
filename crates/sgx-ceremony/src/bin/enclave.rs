#[cfg(not(target_env = "sgx"))]
fn main() {
    eprintln!("ceremony-enclave requires real SGX; no host setup fallback exists");
    std::process::exit(1);
}

#[cfg(target_env = "sgx")]
fn main() -> anyhow::Result<()> {
    use anyhow::{ensure, Context};
    use mirage_sgx_ceremony::*;
    use std::net::TcpStream;

    ensure!(
        !sgx_isa::Report::for_self()
            .attributes
            .flags
            .contains(sgx_isa::AttributesFlags::DEBUG),
        "debug enclaves cannot run a ceremony"
    );
    rayon::ThreadPoolBuilder::new()
        .num_threads(16)
        .build_global()?;
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 3, "expected host address and circuit ID");
    let inputs: Inputs = serde_json::from_slice(INPUTS)?;
    ensure!(inputs.version == 1, "unsupported input version");
    let circuit = inputs
        .circuits
        .iter()
        .find(|c| c.circuit == args[2])
        .context("unpinned circuit")?;
    let mut stream = TcpStream::connect(&args[1])?;
    let started = std::time::Instant::now();
    let stage = |name| {
        eprintln!(
            "{}: {name} at {:.1}s",
            circuit.circuit,
            started.elapsed().as_secs_f64()
        )
    };
    stage("receiving genesis");
    let bytes = read_frame(&mut stream, MAX_KEY)?;
    ensure!(
        bytes.len() == circuit.genesis_bytes && hash(&bytes) == circuit.genesis_sha256,
        "genesis does not match measured inputs"
    );
    stage("validating genesis");
    let mut key = read_key(&bytes)?;
    drop(bytes);
    stage("contributing");
    // OsRng uses the Fortanix enclave entropy implementation, not host files.
    contribute(&mut key, &mut ark_std::rand::rngs::OsRng)?;
    let vk = mirage_prover::serialize_verifying_key(&key.vk)?;
    stage("streaming proving key");
    let proving_key_sha256 = write_key_frame(&mut stream, &key)?;
    drop(key);
    let manifest = serde_json::to_vec(&Output {
        version: 1,
        mode: "beta-tee".into(),
        inputs_sha256: hash(INPUTS),
        circuit: circuit.circuit.clone(),
        proving_key_sha256,
        verifying_key_sha256: hash(&vk),
    })?;
    write_frame(&mut stream, &vk)?;
    write_frame(&mut stream, &manifest)?;
    stage("requesting attestation");
    let ti = read_frame(&mut stream, 512)?;
    let ti = sgx_isa::Targetinfo::try_copy_from(&ti).context("invalid target info")?;
    let report = sgx_isa::Report::for_target(&ti, &report_data(&manifest));
    ensure!(
        !report
            .attributes
            .flags
            .contains(sgx_isa::AttributesFlags::DEBUG),
        "debug enclaves cannot attest a ceremony"
    );
    write_frame(&mut stream, report.as_ref())?;
    Ok(())
}
