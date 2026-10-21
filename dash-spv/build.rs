use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn main() {
    let hash = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_default();
    let tagged = git(&["describe", "--exact-match", "--tags", "--match", "v*", "HEAD"]).is_some();

    println!("cargo:rustc-env=DASH_SPV_GIT_HASH={hash}");
    println!("cargo:rustc-env=DASH_SPV_GIT_TAGGED={tagged}");

    println!("cargo:rerun-if-changed=build.rs");
    // Watching these git files keeps the hash current, and also keeps the
    // `git_dirty!` macro correct on commit: a commit moves a watched ref, which
    // reruns this script and forces the crate (and the macro) to recompile.
    // Narrowing this set would let the dirty flag go stale across a commit.
    //
    // `.git/HEAD` only changes when switching branches, not when committing on
    // the current one, so also watch the symbolic target's ref file.
    if let Some(head_ref) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        if let Some(p) = git(&["rev-parse", "--git-path", &head_ref]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    for path in ["HEAD", "index", "packed-refs"] {
        if let Some(p) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
}
