use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_path = PathBuf::from(&crate_dir).join("include");

    std::fs::create_dir_all(&output_path).unwrap();

    // Ensure the build script reruns when header-relevant files change
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");

    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("cbindgen config missing or invalid: cbindgen.toml");

    match cbindgen::Builder::new().with_crate(&crate_dir).with_config(config).generate() {
        Ok(bindings) => {
            bindings.write_to_file(output_path.join("dash_spv_ffi.h"));
            println!("cargo:warning=Generated C header at {:?}", output_path);
        }
        Err(e) => {
            // Fail the build to avoid shipping stale headers
            panic!("Failed to generate C header via cbindgen: {}", e);
        }
    }
}
