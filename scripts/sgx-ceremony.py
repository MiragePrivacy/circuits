#!/usr/bin/env python3
"""Prepare and build a fresh beta ceremony from the current circuit revision."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
PTAU = {21: "9aef0573cef4ded9c4a75f148709056bf989f80dad96876aadeb6f1c6d062391f07a394a9e756d16f7eb233198d5b69407cca44594c763ab4a5b67ae73254678",
        22: "0d64f63dba1a6f11139df765cb690da69d9b2f469a1ddd0de5e4aa628abb28f787f04c6a5fb84a235ec5ea7f41d0548746653ecab0559add658a83502d1cb21b"}
CIRCUITS = ("native-keccacheck", "erc20-keccacheck")


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def digest(path, algorithm="sha256"):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def revision():
    if run("git", "status", "--porcelain", "--untracked-files=normal", capture_output=True).stdout:
        raise SystemExit("Commit source changes before preparing or building a release ceremony")
    return run("git", "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()


def prepare(args):
    rev = revision()
    if not args.id.strip():
        raise SystemExit("A nonempty ceremony ID is required")
    ptau = args.ptau.resolve()
    ptau_hash = digest(ptau, "blake2b")
    if ptau_hash not in PTAU.values():
        raise SystemExit("Expected a published Hermez power-21 or power-22 transcript")
    out = args.directory.resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, CEREMONY_SOURCE_REV=rev)
    run("nix", "develop", "-c", "cargo", "build", "--locked", "--release", "-p", "mirage-prover", "--bin", "ceremony", env=env)
    records = []
    for circuit in CIRCUITS:
        directory = out / "inputs" / circuit
        run(str(ROOT / "target/release/ceremony"), "export", str(directory), str(ptau), env=dict(env, CEREMONY_CIRCUIT=circuit))
        metadata = json.loads((directory / "circuit.json").read_text())
        key = directory / "genesis.pk"
        if key.stat().st_size > 2 << 30:
            raise SystemExit("Genesis exceeds the enclave transport limit")
        records.append(dict(circuit=circuit, r1cs_digest=metadata["r1cs_digest"], genesis_sha256=digest(key), genesis_bytes=key.stat().st_size))
    manifest = dict(version=1, ceremony_id=args.id, source_revision=rev, ptau_blake2b=ptau_hash, circuits=records)
    (out / "inputs.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")


def build(args):
    rev = revision()
    out = args.directory.resolve()
    inputs = out / "inputs.json"
    if json.loads(inputs.read_text())["source_revision"] != rev:
        raise SystemExit("Source revision changed; prepare a new ceremony")
    build_dir = out / "build"
    build_dir.mkdir(exist_ok=False)
    env = dict(os.environ, CEREMONY_INPUTS=str(inputs), FORTANIX_SGX_LVI_MITIGATION="1", RUSTFLAGS="-C target-feature=+bmi2,+adx")
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    run("nix", "develop", ".#sgx", "-c", "cargo", "build", "--release", "--locked", "--target", "x86_64-fortanix-unknown-sgx", "-p", "mirage-sgx-ceremony", "--bin", "ceremony-enclave", env=env)
    binary = ROOT / "target/x86_64-fortanix-unknown-sgx/release/ceremony-enclave"
    run("nix", "develop", ".#sgx", "-c", "ftxsgx-elf2sgxs", "--threads", "32", "--stack-size", "0x200000", "--heap-size", "0x400000000", str(binary))
    image = build_dir / "ceremony.sgxs"
    image.write_bytes(Path(str(binary) + ".sgxs").read_bytes())
    signature = build_dir / "ceremony.sig"
    run("nix", "develop", ".#sgx", "-c", "sgxs-sign", "--key", str(args.signing_key.resolve()), str(image), str(signature), "--attributes", "0x4/0", "--xfrm", "7/0", "--isvprodid", "1", "--isvsvn", "1")
    # SIGSTRUCT's ENCLAVEHASH is the measured SGXS image digest.
    sig = signature.read_bytes()
    if len(sig) != 1808:
        raise SystemExit("Unexpected SIGSTRUCT length")
    if int.from_bytes(sig[928:936], "little") & 2 or not int.from_bytes(sig[944:952], "little") & 2:
        raise SystemExit("Signature must prohibit DEBUG enclaves")
    measurement = sig[960:992].hex()
    (build_dir / "mrenclave.txt").write_text(measurement + "\n")
    (build_dir / "build.json").write_text(json.dumps(dict(source_revision=rev, inputs_sha256=digest(inputs), image_sha256=digest(image), signature_sha256=digest(signature), mrenclave=measurement), indent=2) + "\n")
    run("nix", "develop", "-c", "cargo", "build", "--locked", "--release", "-p", "mirage-sgx-ceremony", "--features", "host", "--bin", "ceremony-host")
    print(f"Built {image}; expected MRENCLAVE {measurement}")


parser = argparse.ArgumentParser(description=__doc__)
commands = parser.add_subparsers(dest="command", required=True)
p = commands.add_parser("prepare")
p.add_argument("directory", type=Path)
p.add_argument("ptau", type=Path)
p.add_argument("--id", required=True)
p.set_defaults(func=prepare)
p = commands.add_parser("build")
p.add_argument("directory", type=Path)
p.add_argument("--signing-key", type=Path, required=True)
p.set_defaults(func=build)
args = parser.parse_args()
args.func(args)
