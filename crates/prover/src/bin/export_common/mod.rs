use std::path::PathBuf;

pub fn output_dir() -> PathBuf {
    std::env::var_os("MIRAGE_EXPORT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts"))
}

pub fn ceremony_keys() -> Option<mirage_prover::Keys> {
    let path = std::env::var_os("MIRAGE_EXPORT_PROVING_KEY")?;
    eprintln!(
        "loading ceremony proving key from {}",
        PathBuf::from(&path).display()
    );
    let pk =
        mirage_prover::load_proving_key(&std::fs::read(path).expect("read ceremony key"), false)
            .expect("validated ceremony key");
    let vk = mirage_prover::verifying_key_of(&pk);
    Some(mirage_prover::Keys { pk, vk })
}
