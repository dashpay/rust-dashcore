//! Compile-time git repository state, exposed as procedural macros.

use proc_macro::TokenStream;
use std::env;
use std::process::Command;

/// Expands to a `bool` literal: whether the repository containing the invoking
/// crate has uncommitted tracked changes, evaluated at compile time.
///
/// Unlike a build-script environment variable, a macro is expanded as part of
/// compiling the invoking crate, so this re-evaluates whenever that crate is
/// recompiled. An unstaged edit that triggers a rebuild is therefore reflected
/// without staging or committing first, which a `rerun-if-changed` set on a
/// build script cannot capture for the unbounded working tree.
///
/// Any failure to determine the state (git absent, not a repository, or a
/// packaged source tree with no `.git`) expands to `false` rather than guessing.
#[proc_macro]
pub fn git_dirty(_input: TokenStream) -> TokenStream {
    let dirty = env::var("CARGO_MANIFEST_DIR")
        .ok()
        .and_then(|dir| {
            Command::new("git")
                .args(["-C", &dir, "status", "--porcelain", "--untracked-files=no"])
                .output()
                .ok()
        })
        .filter(|out| out.status.success())
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false);

    let literal = if dirty {
        "true"
    } else {
        "false"
    };
    literal.parse().expect("bool literal is valid tokens")
}
