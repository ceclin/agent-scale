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

fn replace_once(source: String, from: &str, to: &str, description: &str) -> String {
    let patched = source.replacen(from, to, 1);
    assert_ne!(source, patched, "{description} was not found");
    patched
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest_dir.join("../../.upstreams/fd/src/main.rs");
    let src = fs::read_to_string(&source).expect("failed to read fd main.rs — run `cargo x init`");
    let patched = replace_once(src, "\nfn main()", "\npub fn main()", "fd main function");

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("fd-src");
    if out.exists() {
        fs::remove_dir_all(&out).expect("failed to reset fd source directory in OUT_DIR");
    }
    copy_tree(source.parent().unwrap(), &out);
    fs::write(out.join("main.rs"), patched).expect("failed to write patched fd main.rs to OUT_DIR");

    // Android's libc omits the reentrant account lookup symbols used by nix.
    // Keep numeric --owner filters available there without changing fd's
    // behavior on platforms that can resolve user and group names.
    let owner_path = out.join("filter/owner.rs");
    let owner = fs::read_to_string(&owner_path).expect("failed to read copied fd owner filter");
    let owner = replace_once(
        owner,
        "use nix::unistd::{Group, User};",
        "#[cfg(not(target_os = \"android\"))]\nuse nix::unistd::{Group, User};",
        "fd account lookup import",
    );
    let owner = replace_once(
        owner,
        "            } else {\n                User::from_name(s)?\n                    .map(|user| user.uid.as_raw())\n                    .ok_or_else(|| anyhow!(\"'{}' is not a recognized user name\", s))\n            }",
        "            } else {\n                #[cfg(target_os = \"android\")]\n                return Err(anyhow!(\"Android owner filters require a numeric user ID\"));\n                #[cfg(not(target_os = \"android\"))]\n                return User::from_name(s)?\n                    .map(|user| user.uid.as_raw())\n                    .ok_or_else(|| anyhow!(\"'{}' is not a recognized user name\", s));\n            }",
        "fd user-name lookup",
    );
    let patched_owner = replace_once(
        owner,
        "            } else {\n                Group::from_name(s)?\n                    .map(|group| group.gid.as_raw())\n                    .ok_or_else(|| anyhow!(\"'{}' is not a recognized group name\", s))\n            }",
        "            } else {\n                #[cfg(target_os = \"android\")]\n                return Err(anyhow!(\"Android owner filters require a numeric group ID\"));\n                #[cfg(not(target_os = \"android\"))]\n                return Group::from_name(s)?\n                    .map(|group| group.gid.as_raw())\n                    .ok_or_else(|| anyhow!(\"'{}' is not a recognized group name\", s));\n            }",
        "fd group-name lookup",
    );
    fs::write(owner_path, patched_owner).expect("failed to patch copied fd owner filter");
    println!("cargo::rerun-if-changed={}", source.parent().unwrap().display());
}
