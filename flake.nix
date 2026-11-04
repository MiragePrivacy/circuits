{
  description = "Mirage settlement circuits";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.rust-overlay.url = "github:oxalica/rust-overlay";
  inputs.rust-overlay.inputs.nixpkgs.follows = "nixpkgs";

  outputs =
    inputs:
    let
      system = "x86_64-linux";
      pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [ (import inputs.rust-overlay) ];
      };
    in
    {
      devShells.${system} = {
        sgx = pkgs.mkShell {
          packages = with pkgs; [
            (rust-bin.nightly."2026-07-19".default.override {
              targets = [ "x86_64-fortanix-unknown-sgx" ];
            })
            fortanix-sgx-tools
            sgxs-tools
            openssl
            pkg-config
            protobuf
            python3
          ];
        };
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            gcc
            jq
            python3
            openssl
            pkg-config
            protobuf
          ];

          # ark-ff's asm feature needs these. Measured at 9-26% end-to-end
          # (see FINDINGS.md); the widely quoted 30-70% is a field-op
          # microbenchmark figure, not end-to-end proving.
          #
          # Note for the eventual enclave build: CPUID traps inside SGX, so
          # feature detection must be pinned at compile time rather than probed.
          # ADX and BMI2 are general-purpose integer instructions with no
          # extended xsave state, so they should be available in-enclave unlike
          # AVX, which is gated by XFRM attributes. That is architectural
          # reasoning, not a documented guarantee -- probe before relying on it.
          shellHook = ''
            export RUSTFLAGS="-C target-feature=+bmi2,+adx"
          '';
      };
      };
    };
}
