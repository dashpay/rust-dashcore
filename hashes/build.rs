use std::env;

// Rust has no `cfg` for the opt-level, and unoptimized SIMD SipHash is slower than scalar.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(hashes_unoptimized)");
    println!("cargo::rerun-if-changed=build.rs");
    if opt_level().as_deref() == Some("0") {
        println!("cargo::rustc-cfg=hashes_unoptimized");
    }
}

/// Returns the opt-level rustc compiles this crate at. `RUSTFLAGS` come after the profile's
/// flags on the rustc command line, so their last opt-level wins over `OPT_LEVEL`.
fn opt_level() -> Option<String> {
    let flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let mut level = env::var("OPT_LEVEL").ok();
    let mut codegen = false;
    for flag in flags.split('\x1f') {
        let option = if codegen {
            Some(flag)
        } else {
            flag.strip_prefix("-C").or_else(|| flag.strip_prefix("--codegen="))
        };
        codegen = flag == "-C" || flag == "--codegen";
        if flag == "-O" {
            level = Some("3".into());
        } else if let Some(value) = option.and_then(|o| o.strip_prefix("opt-level=")) {
            level = Some(value.into());
        }
    }
    level
}
