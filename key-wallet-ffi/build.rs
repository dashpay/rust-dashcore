// Build script for key-wallet-ffi

use std::env;
use std::path::PathBuf;

fn main() {
    // Add platform-specific linking flags
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    match target_os.as_str() {
        "ios" => {
            println!("cargo:rustc-link-lib=framework=Security");
        }
        "macos" => {
            println!("cargo:rustc-link-lib=framework=Security");
        }
        _ => {}
    }

    // Generate C header file
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_path = PathBuf::from(&crate_dir);

    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");

    if let Err(e) = ffi_header_gen::generate_header(&crate_path, "key_wallet_ffi.h") {
        println!("cargo:warning=Failed to generate C header: {}", e);
    }
}
