use std::path::Path;

use cbindgen::Config;

/// Generates a C header file for the given crate directory.
///
/// Loads `cbindgen.toml` from `crate_dir`, runs cbindgen, and writes the
/// header to `<crate_dir>/include/<header_name>`.
pub fn generate_header(crate_dir: &Path, header_name: &str) -> Result<(), String> {
    let config_path = crate_dir.join("cbindgen.toml");
    let output_dir = crate_dir.join("include");
    let output_path = output_dir.join(header_name);

    std::fs::create_dir_all(&output_dir)
        .map_err(|e| format!("failed to create {}: {}", output_dir.display(), e))?;

    let config = Config::from_file(&config_path)
        .map_err(|e| format!("failed to load {}: {}", config_path.display(), e))?;

    let bindings = cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .map_err(|e| format!("failed to generate header for {}: {}", crate_dir.display(), e))?;

    bindings.write_to_file(&output_path);
    Ok(())
}
