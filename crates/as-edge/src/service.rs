//! Current-user service installation for the edge runtime.

use anyhow::Result;

use super::who_dir;

#[cfg(target_os = "linux")]
pub(super) fn install(who: &str) -> Result<()> {
    linux_install(who)
}
#[cfg(target_os = "windows")]
pub(super) fn install(who: &str) -> Result<()> {
    windows_install(who)
}
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(super) fn install(_who: &str) -> Result<()> {
    anyhow::bail!("service installation is supported on Linux and Windows")
}

#[cfg(target_os = "linux")]
pub(super) fn status(who: &str) -> Result<()> {
    who_dir(who)?;
    let status = std::process::Command::new("systemctl")
        .args(["--user", "status", &unit_name(who), "--no-pager"])
        .status()?;
    anyhow::ensure!(status.success(), "systemd user service is not running");
    Ok(())
}
#[cfg(target_os = "windows")]
pub(super) fn status(who: &str) -> Result<()> {
    who_dir(who)?;
    let status = std::process::Command::new("schtasks.exe")
        .args(["/Query", "/TN", &task_name(who)])
        .status()?;
    anyhow::ensure!(status.success(), "scheduled task is not installed");
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(super) fn status(_who: &str) -> Result<()> {
    anyhow::bail!("service status is supported on Linux and Windows")
}

#[cfg(target_os = "linux")]
pub(super) fn uninstall(who: &str) -> Result<()> {
    who_dir(who)?;
    let unit = unit_name(who);
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", &unit])
        .status();
    let path = unit_dir()?.join(&unit);
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    println!("uninstalled service '{who}' (identity and enrollment were preserved)");
    Ok(())
}
#[cfg(target_os = "windows")]
pub(super) fn uninstall(who: &str) -> Result<()> {
    who_dir(who)?;
    let status = std::process::Command::new("schtasks.exe")
        .args(["/Delete", "/TN", &task_name(who), "/F"])
        .status()?;
    anyhow::ensure!(status.success(), "failed to delete scheduled task");
    println!("uninstalled service '{who}' (identity and enrollment were preserved)");
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(super) fn uninstall(_who: &str) -> Result<()> {
    anyhow::bail!("service uninstall is supported on Linux and Windows")
}

#[cfg(target_os = "linux")]
fn linux_install(who: &str) -> Result<()> {
    use anyhow::Context;
    use tracing::warn;

    let bin_dir = std::env::home_dir().context("no home directory")?.join(".local/bin");
    std::fs::create_dir_all(&bin_dir)?;
    let installed = bin_dir.join("as-edge");
    let current = std::env::current_exe()?;
    if current != installed {
        std::fs::copy(&current, &installed).with_context(|| format!("copy binary to {}", installed.display()))?;
    }
    let unit_dir = unit_dir()?;
    std::fs::create_dir_all(&unit_dir)?;
    let unit = unit_name(who);
    let contents = format!(
        "[Unit]\nDescription=agent-scale edge {who}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart={} run {}\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n",
        systemd_quote(&installed.to_string_lossy()),
        systemd_quote(who)
    );
    std::fs::write(unit_dir.join(&unit), contents)?;
    let reload = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()?;
    anyhow::ensure!(reload.success(), "systemctl --user daemon-reload failed");
    let start = std::process::Command::new("systemctl")
        .args(["--user", "enable", "--now", &unit])
        .status()?;
    anyhow::ensure!(start.success(), "systemctl --user enable --now failed");
    let lingering = std::process::Command::new("loginctl")
        .args([
            "show-user",
            &std::env::var("USER").unwrap_or_default(),
            "-p",
            "Linger",
            "--value",
        ])
        .output()
        .ok();
    if lingering
        .as_ref()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() != "yes")
        .unwrap_or(true)
    {
        warn!("user lingering is not enabled; the edge starts after login but may stop after logout");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unit_dir() -> Result<std::path::PathBuf> {
    use anyhow::Context;

    Ok(std::env::home_dir()
        .context("no home directory")?
        .join(".config/systemd/user"))
}

#[cfg(target_os = "linux")]
fn unit_name(who: &str) -> String {
    format!("agent-scale-edge-{who}.service")
}

#[cfg(target_os = "linux")]
fn systemd_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(target_os = "windows")]
fn windows_install(who: &str) -> Result<()> {
    use anyhow::Context;

    let local = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is not set")?;
    let bin_dir = std::path::PathBuf::from(local).join("AgentScale/bin");
    std::fs::create_dir_all(&bin_dir)?;
    let installed = bin_dir.join("as-edge.exe");
    let current = std::env::current_exe()?;
    if current != installed {
        std::fs::copy(current, &installed)?;
    }
    let command = format!("\"{}\" run {}", installed.display(), who);
    let task = task_name(who);
    let create = std::process::Command::new("schtasks.exe")
        .args([
            "/Create", "/SC", "ONLOGON", "/RL", "LIMITED", "/TN", &task, "/TR", &command, "/F",
        ])
        .status()?;
    anyhow::ensure!(create.success(), "failed to create scheduled task");
    let start = std::process::Command::new("schtasks.exe")
        .args(["/Run", "/TN", &task])
        .status()?;
    anyhow::ensure!(start.success(), "failed to start scheduled task");
    Ok(())
}

#[cfg(target_os = "windows")]
fn task_name(who: &str) -> String {
    format!("AgentScale\\{who}")
}
