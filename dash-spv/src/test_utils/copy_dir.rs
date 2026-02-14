//! Recursive directory copy utility.

use std::fs;
use std::path::Path;

/// Recursively copy a directory and all its contents.
pub fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("failed to create destination dir");
    for entry in fs::read_dir(src).expect("failed to read source dir") {
        let entry = entry.expect("failed to read dir entry");
        let dst_path = dst.join(entry.file_name());
        if entry.file_type().expect("failed to get file type").is_dir() {
            copy_dir(&entry.path(), &dst_path);
        } else {
            fs::copy(entry.path(), dst_path).expect("failed to copy file");
        }
    }
}
