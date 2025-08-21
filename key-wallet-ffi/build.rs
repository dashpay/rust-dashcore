// Build script for key-wallet-ffi
// Generates C header file using cbindgen

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

    // Generate C header file using cbindgen
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_path = PathBuf::from(&crate_dir).join("include/key_wallet_ffi.h");

    // Create include directory if it doesn't exist
    std::fs::create_dir_all(output_path.parent().unwrap()).ok();

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(cbindgen::Config::from_file("cbindgen.toml").unwrap_or_default())
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(&output_path);
            println!("cargo:warning=Generated C header at {:?}", output_path);
        }
        Err(e) => {
            println!("cargo:warning=Failed to generate C header: {}", e);
        }
    }
}
