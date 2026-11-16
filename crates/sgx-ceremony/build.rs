fn main() {
    println!("cargo:rerun-if-env-changed=CEREMONY_INPUTS");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("inputs.json");
    if let Some(path) = std::env::var_os("CEREMONY_INPUTS") {
        println!(
            "cargo:rerun-if-changed={}",
            std::path::Path::new(&path).display()
        );
        std::fs::copy(path, output).expect("read ceremony inputs");
    } else {
        assert_ne!(
            std::env::var("CARGO_CFG_TARGET_ENV").unwrap(),
            "sgx",
            "CEREMONY_INPUTS is required for SGX builds"
        );
        std::fs::write(output, b"null").unwrap();
    }
}
