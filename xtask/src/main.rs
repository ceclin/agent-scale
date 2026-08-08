// Copyright 2026 agent-scale contributors
// SPDX-License-Identifier: Apache-2.0

//! Repository task runner used by developers and CI.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Output};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

const CARGO_DENY_PACKAGE: &str = "cargo-deny@0.20.2";
const TAPLO_PACKAGE: &str = "taplo-cli@0.10.0";
const TYPOS_PACKAGE: &str = "typos-cli@1.49.0";

#[derive(Debug, Parser)]
#[command(about = "Run agent-scale repository tasks")]
struct Command {
    #[command(subcommand)]
    task: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Build all workspace targets without changing Cargo.lock.
    Build,
    /// Run the complete end-to-end suite.
    E2e,
    /// Initialize the pinned fd and ripgrep source checkouts.
    Init,
    /// Run formatting, lint, docs, metadata, spelling, and dependency checks.
    Lint,
    /// Build cross-platform edge artifacts for a release.
    Dist,
    /// Run all workspace tests.
    Test,
    /// Cross-compile edge artifacts with the fast development profile.
    Zigbuild {
        /// Targets to build; defaults to all supported edge targets.
        targets: Vec<String>,
    },
}

fn workspace() -> &'static Path {
    Path::new(env!("AGENT_SCALE_WORKSPACE_DIR"))
}

fn command(program: impl AsRef<OsStr>) -> ProcessCommand {
    let mut command = ProcessCommand::new(program);
    command.current_dir(workspace());
    command
}

fn run(mut command: ProcessCommand) -> Result<()> {
    println!("{command:?}");
    let status = command.status().context("start repository command")?;
    if !status.success() {
        bail!("repository command failed with {status}");
    }
    Ok(())
}

fn capture(mut command: ProcessCommand) -> Result<Output> {
    println!("{command:?}");
    command.output().context("start repository command")
}

fn stdout(command: ProcessCommand) -> Result<String> {
    let output = capture(command)?;
    if !output.status.success() {
        bail!(
            "repository command failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("repository command returned non-UTF-8 output")
}

fn git(directory: &Path) -> ProcessCommand {
    let mut git = command("git");
    git.arg("-C").arg(directory);
    git
}

fn init_upstream(root: &Path, name: &str, repository: &str, revision: &str) -> Result<()> {
    if !matches!(name, "fd" | "ripgrep") {
        bail!("unsupported upstream name: {name}");
    }

    let destination = root.join(name);
    let mut probe = git(&destination);
    probe.args(["rev-parse", "--git-dir"]);
    if !capture(probe)?.status.success() {
        if destination.exists() && (!destination.is_dir() || fs::read_dir(&destination)?.next().is_some()) {
            bail!("refusing to replace non-git directory {}", destination.display());
        }
        fs::create_dir_all(&destination).with_context(|| format!("create {}", destination.display()))?;

        let mut init = git(&destination);
        init.args(["init", "--quiet"]);
        run(init)?;
        let mut remote = git(&destination);
        remote.args(["remote", "add", "origin", repository]);
        run(remote)?;
    }

    let mut origin = git(&destination);
    origin.args(["remote", "get-url", "origin"]);
    let actual_repository = stdout(origin)?;
    if actual_repository.trim() != repository {
        bail!(
            "unexpected origin for {}: {}; expected: {repository}",
            destination.display(),
            actual_repository.trim()
        );
    }

    let mut status = git(&destination);
    status.args(["status", "--porcelain"]);
    if !stdout(status)?.is_empty() {
        bail!(
            "refusing to overwrite local changes in {}; stash or remove the disposable upstream checkout, then retry",
            destination.display()
        );
    }

    let mut head = git(&destination);
    head.args(["rev-parse", "HEAD"]);
    let current_revision = capture(head)?;
    if !current_revision.status.success() || String::from_utf8_lossy(&current_revision.stdout).trim() != revision {
        let mut fetch = git(&destination);
        fetch.args(["fetch", "--depth", "1", "origin", revision]);
        run(fetch)?;

        let mut checkout = git(&destination);
        checkout.args(["-c", "advice.detachedHead=false", "checkout", "--detach", revision]);
        run(checkout)?;
    }

    let mut head = git(&destination);
    head.args(["rev-parse", "HEAD"]);
    let actual_revision = stdout(head)?;
    if actual_revision.trim() != revision {
        bail!(
            "unexpected revision for {}: {}; expected: {revision}",
            destination.display(),
            actual_revision.trim()
        );
    }
    println!("initialized {name} at {revision}");
    Ok(())
}

fn init_upstreams() -> Result<()> {
    let configured_root = std::env::var_os("AGENT_SCALE_UPSTREAM_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".upstreams"));
    let root = if configured_root.is_absolute() {
        configured_root
    } else {
        workspace().join(configured_root)
    };
    let lock_path = workspace().join("scripts/upstreams.lock");
    let lock = fs::read_to_string(&lock_path).with_context(|| format!("read {}", lock_path.display()))?;

    for (index, line) in lock.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(name), Some(repository), Some(revision), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            bail!("invalid upstream lock entry at line {}", index + 1);
        };
        init_upstream(&root, name, repository, revision)?;
    }
    Ok(())
}

fn ensure(binary: &str, package: &str) -> Result<()> {
    if which::which(binary).is_err() {
        let mut install = command("cargo");
        install.args(["install", "--locked", package]);
        run(install)?;
    }
    Ok(())
}

fn lint() -> Result<()> {
    let mut fmt = command("cargo");
    fmt.args(["fmt", "--all", "--", "--check"]);
    run(fmt)?;

    let mut clippy = command("cargo");
    clippy.args([
        "clippy",
        "--workspace",
        "--exclude",
        "fd-lib",
        "--exclude",
        "rg-lib",
        "--all-features",
        "--all-targets",
        "--no-deps",
        "--",
        "-D",
        "warnings",
    ]);
    run(clippy)?;

    let mut wrappers = command("cargo");
    wrappers.args(["check", "--locked", "-p", "fd-lib", "-p", "rg-lib"]);
    run(wrappers)?;

    let mut docs = command("cargo");
    docs.env("RUSTDOCFLAGS", "-D warnings").args([
        "doc",
        "--workspace",
        "--exclude",
        "fd-lib",
        "--exclude",
        "rg-lib",
        "--all-features",
        "--no-deps",
    ]);
    run(docs)?;

    let mut sync = command("./scripts/sync-deps.py");
    sync.arg("--check");
    run(sync)?;

    let mut licenses = command("./scripts/generate-licenses.sh");
    licenses.arg("--check");
    run(licenses)?;

    ensure("taplo", TAPLO_PACKAGE)?;
    let mut taplo = command("taplo");
    taplo.args(["format", "--check"]);
    run(taplo)?;

    ensure("typos", TYPOS_PACKAGE)?;
    run(command("typos"))?;

    ensure("cargo-deny", CARGO_DENY_PACKAGE)?;
    let mut deny = command("cargo");
    deny.args(["deny", "check"]);
    run(deny)
}

fn main() -> Result<()> {
    let task = Command::parse().task;
    if !matches!(task, Task::Init) {
        init_upstreams()?;
    }
    match task {
        Task::Build => {
            let mut build = command("cargo");
            build.args(["build", "--workspace", "--all-targets", "--locked"]);
            run(build)
        }
        Task::E2e => {
            for script in [
                "./scripts/e2e-2b.sh",
                "./scripts/e2e-private-relay.sh",
                "./scripts/e2e-control.sh",
            ] {
                run(command(script))?;
            }
            Ok(())
        }
        Task::Init => init_upstreams(),
        Task::Lint => lint(),
        Task::Dist => {
            let mut dist = command("./scripts/zigbuild.sh");
            dist.env("PROFILE", "dist");
            run(dist)
        }
        Task::Test => {
            let mut test = command("cargo");
            test.args(["test", "--workspace", "--all-targets", "--locked"]);
            run(test)
        }
        Task::Zigbuild { targets } => {
            let mut zigbuild = command("./scripts/zigbuild.sh");
            zigbuild.env("PROFILE", "release").args(targets);
            run(zigbuild)
        }
    }
}
