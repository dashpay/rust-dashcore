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
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let tagged = git(&["describe", "--exact-match", "--tags", "--match", "v*", "HEAD"]).is_some();

    println!("cargo:rustc-env=DASH_SPV_GIT_HASH={hash}");
    println!("cargo:rustc-env=DASH_SPV_GIT_DIRTY={dirty}");
    println!("cargo:rustc-env=DASH_SPV_GIT_TAGGED={tagged}");

    println!("cargo:rerun-if-changed=build.rs");
    for path in ["HEAD", "index", "packed-refs"] {
        if let Some(p) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
}
