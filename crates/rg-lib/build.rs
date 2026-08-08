use std::env;
use std::fs;
use std::path::PathBuf;

fn copy_tree(source: &std::path::Path, target: &std::path::Path) {
    fs::create_dir_all(target).expect("failed to create rg source directory in OUT_DIR");
    for entry in fs::read_dir(source).expect("failed to read rg source directory") {
        let entry = entry.expect("failed to inspect rg source entry");
        let kind = entry.file_type().expect("failed to inspect rg source type");
        let dest = target.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &dest);
        } else if entry.file_name() != "main.rs" {
            fs::copy(entry.path(), dest).expect("failed to copy rg source to OUT_DIR");
        }
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest_dir.join("../../.upstreams/ripgrep/crates/core/main.rs");
    let src = fs::read_to_string(&source).expect("failed to read rg main.rs — run `cargo x init`");

    let mut patched = String::with_capacity(src.len());
    let mut in_block_doc = false;

    for line in src.lines() {
        // Upstream inner docs are invalid once main.rs is included as a module.
        if !in_block_doc && line.starts_with("/*!") {
            in_block_doc = true;
            continue;
        }
        if in_block_doc {
            if line.contains("*/") {
                in_block_doc = false;
            }
            continue;
        }
        if line.starts_with("//!") {
            continue;
        }
        patched.push_str(line);
        patched.push('\n');
    }

    let entrypoint = patched.replacen("\nfn main()", "\npub fn main()", 1);
    assert_ne!(patched, entrypoint, "rg main function was not found");

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("rg-src");
    if out.exists() {
        fs::remove_dir_all(&out).expect("failed to reset rg source directory in OUT_DIR");
    }
    copy_tree(source.parent().unwrap(), &out);
    fs::write(out.join("main.rs"), entrypoint).expect("failed to write patched rg main.rs to OUT_DIR");
    println!("cargo::rerun-if-changed={}", source.parent().unwrap().display());
}
