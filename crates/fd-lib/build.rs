use std::env;
use std::fs;
use std::path::PathBuf;

fn copy_tree(source: &std::path::Path, target: &std::path::Path) {
    fs::create_dir_all(target).expect("failed to create fd source directory in OUT_DIR");
    for entry in fs::read_dir(source).expect("failed to read fd source directory") {
        let entry = entry.expect("failed to inspect fd source entry");
        let kind = entry.file_type().expect("failed to inspect fd source type");
        let dest = target.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &dest);
        } else if entry.file_name() != "main.rs" {
            fs::copy(entry.path(), dest).expect("failed to copy fd source to OUT_DIR");
        }
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest_dir.join("../../.upstreams/fd/src/main.rs");
    let src = fs::read_to_string(&source).expect("failed to read fd main.rs — run `cargo x init`");
    let patched = src.replacen("\nfn main()", "\npub fn main()", 1);
    assert_ne!(src, patched, "fd main function was not found");

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("fd-src");
    if out.exists() {
        fs::remove_dir_all(&out).expect("failed to reset fd source directory in OUT_DIR");
    }
    copy_tree(source.parent().unwrap(), &out);
    fs::write(out.join("main.rs"), patched).expect("failed to write patched fd main.rs to OUT_DIR");
    println!("cargo::rerun-if-changed={}", source.parent().unwrap().display());
}
