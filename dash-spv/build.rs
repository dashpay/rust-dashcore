use std::path::PathBuf;
use std::process::Command;

use serde::Deserialize;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

#[derive(Deserialize)]
struct Checkpoint {
    height: u32,
    headers: Vec<Header>,
}

#[derive(Deserialize)]
struct Header {
    version: i32,
    prev_blockhash: String,
    merkle_root: String,
    time: u32,
    bits: u32,
    nonce: u32,
}

/// Hashes are displayed byte-reversed, as in block explorers.
fn hash_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len(), 64, "hash {hex} is not 32 bytes");
    let mut bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hash must be hex"))
        .collect();
    bytes.reverse();
    bytes
}

/// Encodes `checkpoints/<network>.json` into the consensus format the crate embeds.
fn encode_checkpoints(network: &str) {
    let json = format!("checkpoints/{network}.json");
    println!("cargo:rerun-if-changed={json}");

    let checkpoints: Vec<Checkpoint> =
        serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();

    let mut bytes = Vec::new();
    for checkpoint in checkpoints {
        bytes.extend(checkpoint.height.to_le_bytes());
        for header in checkpoint.headers {
            bytes.extend(header.version.to_le_bytes());
            bytes.extend(hash_bytes(&header.prev_blockhash));
            bytes.extend(hash_bytes(&header.merkle_root));
            bytes.extend(header.time.to_le_bytes());
            bytes.extend(header.bits.to_le_bytes());
            bytes.extend(header.nonce.to_le_bytes());
        }
    }

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out.join(format!("{network}.checkpoints")), bytes).unwrap();
}

fn main() {
    encode_checkpoints("mainnet");
    encode_checkpoints("testnet");

    let hash = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_default();
    let tagged = git(&["describe", "--exact-match", "--tags", "--match", "v*", "HEAD"]).is_some();

    println!("cargo:rustc-env=DASH_SPV_GIT_HASH={hash}");
    println!("cargo:rustc-env=DASH_SPV_GIT_TAGGED={tagged}");

    println!("cargo:rerun-if-changed=build.rs");
    // Watching these git files keeps the hash current, and also keeps the
    // `git_dirty!` macro correct on commit: a commit moves a watched ref, which
    // reruns this script and forces the crate (and the macro) to recompile.
    // Narrowing this set would let the dirty flag go stale across a commit.
    //
    // `.git/HEAD` only changes when switching branches, not when committing on
    // the current one, so also watch the symbolic target's ref file.
    if let Some(head_ref) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        if let Some(p) = git(&["rev-parse", "--git-path", &head_ref]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    for path in ["HEAD", "index", "packed-refs"] {
        if let Some(p) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
}
