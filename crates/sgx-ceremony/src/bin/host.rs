use anyhow::{bail, ensure, Context, Result};
use mirage_sgx_ceremony::*;
use std::{
    fs,
    net::TcpListener,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

const TCB_POLICY: &str = "beta-nomad-advisories-v1";

fn verify_tcb_policy(
    platform: dcap_qvl::tcb_info::TcbStatus,
    qe: dcap_qvl::tcb_info::TcbStatus,
    advisories: &[String],
) -> Result<()> {
    use dcap_qvl::tcb_info::TcbStatus;
    for (name, status) in [("platform", platform), ("QE", qe)] {
        ensure!(
            matches!(
                status,
                TcbStatus::UpToDate
                    | TcbStatus::SWHardeningNeeded
                    | TcbStatus::ConfigurationNeeded
                    | TcbStatus::ConfigurationAndSWHardeningNeeded
            ),
            "rejected {name} TCB status: {status}"
        );
    }
    for advisory in advisories {
        ensure!(
            matches!(advisory.as_str(), "INTEL-SA-00289" | "INTEL-SA-00615"),
            "advisory outside beta policy: {advisory}"
        );
    }
    Ok(())
}

fn verify_evidence(
    quote: &[u8],
    collateral: &dcap_qvl::QuoteCollateralV3,
    manifest: &[u8],
    measurement: &str,
) -> Result<()> {
    let verified = dcap_qvl::verify::verify(quote, collateral, now()?)?;
    verify_tcb_policy(
        verified.platform_status.status,
        verified.qe_status.status,
        &verified.advisory_ids,
    )?;
    eprintln!(
        "TCB accepted under {TCB_POLICY}: {}; advisories: {:?}",
        verified.status, verified.advisory_ids
    );
    let report = verified.report.as_sgx().context("expected SGX quote")?;
    verify_identity(
        report.attributes[0],
        &report.mr_enclave,
        &report.report_data,
        manifest,
        measurement,
    )?;
    Ok(())
}

fn verify_identity(
    flags: u8,
    found: &[u8; 32],
    data: &[u8; 64],
    manifest: &[u8],
    measurement: &str,
) -> Result<()> {
    ensure!(flags & 2 == 0, "debug quote rejected");
    ensure!(hex::encode(found) == measurement, "unexpected MRENCLAVE");
    ensure!(
        *data == report_data(manifest),
        "quote does not bind output manifest"
    );
    Ok(())
}

fn verify_files(
    root: &Path,
    inputs_bytes: &[u8],
    circuit: &Circuit,
    measurement: &str,
) -> Result<()> {
    let started = std::time::Instant::now();
    let dir = root.join(&circuit.circuit);
    eprintln!("{}: checking output hashes and quote", circuit.circuit);
    let manifest = fs::read(dir.join("output.json"))?;
    let pk = fs::read(dir.join("final.pk"))?;
    let vk = fs::read(dir.join("final.vk"))?;
    verify_manifest(inputs_bytes, &circuit.circuit, &manifest, &pk, &vk)?;
    let quote = fs::read(dir.join("quote.bin"))?;
    let collateral = serde_json::from_slice(&fs::read(dir.join("collateral.json"))?)?;
    verify_evidence(&quote, &collateral, &manifest, measurement)?;
    eprintln!(
        "{}: quote accepted after {:.1}s; checking key update",
        circuit.circuit,
        started.elapsed().as_secs_f64()
    );
    let genesis = fs::read(
        root.join("inputs")
            .join(&circuit.circuit)
            .join("genesis.pk"),
    )?;
    ensure!(
        genesis.len() == circuit.genesis_bytes && hash(&genesis) == circuit.genesis_sha256,
        "genesis mismatch"
    );
    let before = read_key(&genesis)?;
    drop(genesis);
    let after = read_key(&pk)?;
    drop(pk);
    ensure!(
        mirage_prover::serialize_verifying_key(&after.vk)? == vk,
        "VK does not match PK"
    );
    verify_update(&before, &after, &mut ark_std::rand::rngs::OsRng)?;
    eprintln!(
        "{}: key update checked after {:.1}s; generating fixture proof",
        circuit.circuit,
        started.elapsed().as_secs_f64()
    );
    use taceo_groth16_sol::{askama::Template, SolidityVerifierConfig, SolidityVerifierContext};
    drop(before);
    let verifier = SolidityVerifierContext {
        vk: after.vk.clone(),
        config: SolidityVerifierConfig::default(),
    }
    .render()?;
    let verifier_path = dir.join("Verifier.sol");
    if verifier_path.exists() {
        ensure!(
            fs::read_to_string(verifier_path)? == verifier,
            "verifier source mismatch"
        );
    } else {
        fs::write(verifier_path, verifier)?;
    }
    let keys = mirage_prover::Keys {
        vk: after.vk.clone(),
        pk: after,
    };
    let proof = if circuit.circuit == "native-keccacheck" {
        mirage_prover::native::prove_keccacheck(
            &keys,
            mirage_relation::native::NativeBounds::default(),
            &mirage_relation::native::fixture::genuine(),
            &mut ark_std::rand::rngs::OsRng,
        )?
    } else {
        mirage_prover::prove_keccacheck(
            &keys,
            mirage_relation::Bounds::default(),
            &mirage_relation::fixture::genuine(),
            &mut ark_std::rand::rngs::OsRng,
        )?
    };
    fs::write(
        dir.join("proof.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "proof": proof.proof.map(|word| format!("0x{}", hex::encode(word))),
            "publicSignals": proof.signals.map(|signal| format!("0x{signal:032x}")),
        }))?,
    )?;
    Ok(())
}

fn run(
    root: &Path,
    inputs: &[u8],
    circuit: &Circuit,
    image: &Path,
    signature: &Path,
    measurement: &str,
) -> Result<()> {
    let dir = root.join(&circuit.circuit);
    fs::create_dir(&dir).context("output exists; use a new ceremony directory for a new run")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?.to_string();
    let image = image.to_owned();
    let signature = signature.to_owned();
    let id = circuit.circuit.clone();
    let runner = std::thread::spawn(move || -> Result<()> {
        let mut device = sgxs_loaders::isgx::Device::new()?
            .einittoken_provider(aesm_client::AesmClient::new())
            .build();
        let mut platform = enclave_runner_sgx::EnclaveBuilder::new(&image);
        platform.signature(signature)?;
        let mut builder =
            enclave_runner::EnclaveBuilder::<_, enclave_runner::Command>::new(platform);
        builder.arg(&address).arg(&id);
        builder.build(&mut device)?.run()?;
        Ok(())
    });
    let start = std::time::Instant::now();
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if runner.is_finished() {
                    runner
                        .join()
                        .map_err(|_| anyhow::anyhow!("enclave runner panicked"))??;
                    bail!("enclave exited before connecting");
                }
                ensure!(
                    start.elapsed() < Duration::from_secs(60),
                    "enclave connection timed out"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.into()),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(7200)))?;
    stream.set_write_timeout(Some(Duration::from_secs(7200)))?;
    let genesis = fs::read(
        root.join("inputs")
            .join(&circuit.circuit)
            .join("genesis.pk"),
    )?;
    ensure!(
        genesis.len() == circuit.genesis_bytes && hash(&genesis) == circuit.genesis_sha256,
        "genesis mismatch"
    );
    write_frame(&mut stream, &genesis)?;
    drop(genesis);
    for (file, limit) in [
        ("final.pk", MAX_KEY),
        ("final.vk", 1 << 20),
        ("output.json", 1 << 20),
    ] {
        fs::write(dir.join(file), read_frame(&mut stream, limit)?)?;
    }
    let aesm = aesm_client::AesmClient::new();
    let ids: Vec<_> = aesm
        .get_supported_att_key_ids()?
        .into_iter()
        .filter(|id| id.get(154..158) == Some(&2u32.to_le_bytes()))
        .collect();
    ensure!(ids.len() == 1, "expected one ECDSA attestation key");
    let quote_info = aesm.init_quote_ex(ids[0].clone())?;
    write_frame(&mut stream, quote_info.target_info())?;
    let report = read_frame(&mut stream, 432)?;
    ensure!(
        sgx_isa::Report::try_copy_from(&report).is_some(),
        "invalid report"
    );
    let quote = aesm
        .get_quote_ex(ids[0].clone(), report, None, vec![0; 16])?
        .quote()
        .to_vec();
    runner
        .join()
        .map_err(|_| anyhow::anyhow!("enclave runner panicked"))??;
    let collateral = tokio::runtime::Runtime::new()?.block_on(async {
        dcap_qvl::collateral::CollateralClient::with_default_http(
            dcap_qvl::collateral::INTEL_PCS_URL,
        )?
        .fetch(&quote)
        .await
    })?;
    fs::write(dir.join("quote.bin"), quote)?;
    fs::write(
        dir.join("collateral.json"),
        serde_json::to_vec_pretty(&collateral)?,
    )?;
    verify_files(root, inputs, circuit, measurement)?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() >= 4,
        "usage: ceremony-host run|resume ROOT MRENCLAVE IMAGE SIG | verify ROOT MRENCLAVE"
    );
    ensure!(
        hex::decode(&args[3])?.len() == 32,
        "expected 32-byte measurement"
    );
    let root = Path::new(&args[2]);
    let marker = root.join("verified.json");
    if marker.exists() {
        fs::remove_file(marker)?;
    }
    let bytes = fs::read(root.join("inputs.json"))?;
    let inputs: Inputs = serde_json::from_slice(&bytes)?;
    ensure!(
        inputs.version == 1 && inputs.circuits.len() == 2,
        "expected v1 two-circuit manifest"
    );
    for circuit in &inputs.circuits {
        ensure!(
            matches!(
                circuit.circuit.as_str(),
                "native-keccacheck" | "erc20-keccacheck"
            ),
            "unknown circuit"
        );
    }
    ensure!(
        inputs.circuits[0].circuit != inputs.circuits[1].circuit,
        "duplicate circuit"
    );
    for circuit in &inputs.circuits {
        match args[1].as_str() {
            "run" | "resume" => {
                ensure!(args.len() == 6, "run/resume requires IMAGE SIG");
                if args[1] == "resume" && root.join(&circuit.circuit).exists() {
                    verify_files(root, &bytes, circuit, &args[3])?;
                } else {
                    run(
                        root,
                        &bytes,
                        circuit,
                        Path::new(&args[4]),
                        Path::new(&args[5]),
                        &args[3],
                    )?;
                }
            }
            "verify" => verify_files(root, &bytes, circuit, &args[3])?,
            _ => bail!("unknown command"),
        }
        println!("Verified {}", circuit.circuit);
    }
    fs::write(
        root.join("verified.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"inputs_sha256": hash(&bytes), "mrenclave": args[3], "verified_at": now()?, "tcb_policy": TCB_POLICY}),
        )?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beta_policy_rejects_stale_qe_platform_and_unknown_advisories() {
        use dcap_qvl::tcb_info::TcbStatus::*;
        for status in [
            UpToDate,
            ConfigurationNeeded,
            SWHardeningNeeded,
            ConfigurationAndSWHardeningNeeded,
        ] {
            verify_tcb_policy(
                status,
                UpToDate,
                &["INTEL-SA-00289".into(), "INTEL-SA-00615".into()],
            )
            .unwrap();
        }
        for status in [OutOfDate, OutOfDateConfigurationNeeded, Revoked] {
            assert!(verify_tcb_policy(status, UpToDate, &[]).is_err());
            assert!(verify_tcb_policy(UpToDate, status, &[]).is_err());
        }
        assert!(verify_tcb_policy(UpToDate, UpToDate, &["INTEL-SA-UNKNOWN".into()]).is_err());
    }

    #[test]
    fn quote_identity_rejects_debug_wrong_measurement_and_manifest() {
        let measurement = [7; 32];
        let expected = hex::encode(measurement);
        let data = report_data(b"manifest");
        verify_identity(0, &measurement, &data, b"manifest", &expected).unwrap();
        assert!(verify_identity(2, &measurement, &data, b"manifest", &expected).is_err());
        assert!(verify_identity(0, &[8; 32], &data, b"manifest", &expected).is_err());
        assert!(verify_identity(0, &measurement, &data, b"other", &expected).is_err());
    }
}
