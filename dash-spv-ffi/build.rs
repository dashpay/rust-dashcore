use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_path = PathBuf::from(&crate_dir);

    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");

    if let Err(e) = ffi_header_gen::generate_header(&crate_path, "dash_spv_ffi.h") {
        panic!("{}", e);
    }
}
