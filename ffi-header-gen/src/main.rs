use std::path::PathBuf;
use std::process;

use ffi_header_gen::generate_header;

struct FfiCrate {
    dir: &'static str,
    header: &'static str,
}

const FFI_CRATES: &[FfiCrate] = &[
    FfiCrate {
        dir: "key-wallet-ffi",
        header: "key_wallet_ffi.h",
    },
    FfiCrate {
        dir: "dash-spv-ffi",
        header: "dash_spv_ffi.h",
    },
];

fn main() {
    let repo_root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("failed to get current directory"));

    let mut failed = false;

    for ffi in FFI_CRATES {
        let crate_dir = repo_root.join(ffi.dir);
        match generate_header(&crate_dir, ffi.header) {
            Ok(()) => {
                eprintln!("generated {}", crate_dir.join("include").join(ffi.header).display())
            }
            Err(e) => {
                eprintln!("{}", e);
                failed = true;
            }
        }
    }

    if failed {
        process::exit(1);
    }
}
