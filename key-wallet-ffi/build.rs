// Build script for key-wallet-ffi
// No longer uses uniffi - just standard FFI compilation

fn main() {
    // Add any necessary build configuration here
    // For example, linking flags for different platforms

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    match target_os.as_str() {
        "ios" => {
            println!("cargo:rustc-link-lib=framework=Security");
        }
        "macos" => {
            println!("cargo:rustc-link-lib=framework=Security");
        }
        _ => {}
    }
}
