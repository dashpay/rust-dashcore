use std::{env, fs, path::Path};

fn main() {
    if std::env::var("CARGO_FEATURE_FFI").is_ok() {
        generate_bindings();
    }

    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .expect("Failed to run rustc --version");
    assert!(output.status.success(), "Failed to get rust version");
    let stdout = String::from_utf8(output.stdout).expect("rustc produced non-UTF-8 output");
    let version_prefix = "rustc ";
    if !stdout.starts_with(version_prefix) {
        panic!("unexpected rustc output: {}", stdout);
    }

    let version = &stdout[version_prefix.len()..];
    let end = version.find(&[' ', '-'] as &[_]).unwrap_or(version.len());
    let version = &version[..end];
    let mut version_components = version.split('.');
    let major = version_components.next().unwrap();
    assert_eq!(major, "1", "Unexpected Rust version");
    let minor = version_components
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .expect("invalid Rust minor version");

    for activate_version in &[53, 60] {
        if minor >= *activate_version {
            println!("cargo:rustc-cfg=rust_v_1_{}", activate_version);
        }
    }
}

fn generate_bindings() {
    let crate_name = env::var("CARGO_PKG_NAME").unwrap();
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();

    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/");

    let target_dir = Path::new(&out_dir)
        .ancestors()
        .nth(3) // This line moves up to the target/<PROFILE> directory
        .expect("Failed to find target dir");

    let include_dir = target_dir.join("include").join(&crate_name);

    fs::create_dir_all(&include_dir).unwrap();

    let output_path = include_dir.join(format!("{}.h", &crate_name));

    let config_path = Path::new(&crate_dir).join("cbindgen.toml");
    let config = cbindgen::Config::from_file(&config_path).expect("Failed to read cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&output_path);
}
