use std::env;

// Rust has no `cfg` for the opt-level, and unoptimized SIMD SipHash is slower than scalar.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(hashes_unoptimized)");
    println!("cargo::rerun-if-changed=build.rs");
    if env::var("OPT_LEVEL").as_deref() == Ok("0") {
        println!("cargo::rustc-cfg=hashes_unoptimized");
    }
}
