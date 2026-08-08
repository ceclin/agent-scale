//! Uses current-user service managers so installing an Edge never requires
//! Administrator, root, or machine-wide credentials.

use anyhow::Result;

use super::who_dir;

#[cfg(target_os = "linux")]
pub(super) fn install(who: &str) -> Result<()> {
    linux_install(who)
}
#[cfg(target_os = "macos")]
pub(super) fn install(who: &str) -> Result<()> {
    macos_install(who)
}
#[cfg(target_os = "windows")]
pub(super) fn install(who: &str) -> Result<()> {
    windows_install(who)
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn install(_who: &str) -> Result<()> {
    anyhow::bail!("service installation is supported on Linux, macOS, and Windows")
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
#[cfg(target_os = "macos")]
pub(super) fn status(who: &str) -> Result<()> {
    who_dir(who)?;
    let status = std::process::Command::new("launchctl")
        .args(["print", &launch_agent_target(who)?])
        .status()?;
    anyhow::ensure!(status.success(), "LaunchAgent is not running");
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
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn status(_who: &str) -> Result<()> {
    anyhow::bail!("service status is supported on Linux, macOS, and Windows")
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
#[cfg(target_os = "macos")]
pub(super) fn uninstall(who: &str) -> Result<()> {
    who_dir(who)?;
    let path = launch_agent_path(who)?;
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &launch_agent_target(who)?])
        .status();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
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
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn uninstall(_who: &str) -> Result<()> {
    anyhow::bail!("service uninstall is supported on Linux, macOS, and Windows")
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

#[cfg(target_os = "macos")]
fn macos_install(who: &str) -> Result<()> {
    use anyhow::Context;

    let home = std::env::home_dir().context("no home directory")?;
    let bin_dir = home.join("Library/Application Support/AgentScale/bin");
    std::fs::create_dir_all(&bin_dir)?;
    let installed = bin_dir.join("as-edge");
    let current = std::env::current_exe()?;
    if current != installed {
        std::fs::copy(&current, &installed).with_context(|| format!("copy binary to {}", installed.display()))?;
    }

    let state_dir = who_dir(who)?;
    std::fs::create_dir_all(&state_dir)?;
    let path = launch_agent_path(who)?;
    std::fs::create_dir_all(path.parent().context("LaunchAgent path has no parent")?)?;
    let label = launch_agent_label(who);
    let contents = launch_agent_plist(
        &label,
        &installed,
        who,
        &state_dir.join("service.stdout.log"),
        &state_dir.join("service.stderr.log"),
    );

    let target = launch_agent_target(who)?;
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &target])
        .status();
    std::fs::write(&path, contents)?;
    let domain = launch_agent_domain()?;
    let start = std::process::Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(&path)
        .status()?;
    anyhow::ensure!(start.success(), "launchctl bootstrap failed");
    let kickstart = std::process::Command::new("launchctl")
        .args(["kickstart", "-k", &target])
        .status()?;
    anyhow::ensure!(kickstart.success(), "launchctl kickstart failed");
    Ok(())
}

#[cfg(target_os = "macos")]
fn launch_agent_domain() -> Result<String> {
    use anyhow::Context;

    let output = std::process::Command::new("id")
        .arg("-u")
        .output()
        .context("run id -u")?;
    anyhow::ensure!(output.status.success(), "id -u failed");
    let uid = String::from_utf8(output.stdout).context("id -u returned non-UTF-8 output")?;
    let uid = uid.trim();
    anyhow::ensure!(
        !uid.is_empty() && uid.bytes().all(|byte| byte.is_ascii_digit()),
        "id -u returned an invalid uid"
    );
    Ok(format!("gui/{uid}"))
}

#[cfg(target_os = "macos")]
fn launch_agent_target(who: &str) -> Result<String> {
    Ok(format!("{}/{}", launch_agent_domain()?, launch_agent_label(who)))
}

#[cfg(target_os = "macos")]
fn launch_agent_path(who: &str) -> Result<std::path::PathBuf> {
    use anyhow::Context;

    Ok(std::env::home_dir()
        .context("no home directory")?
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", launch_agent_label(who))))
}

#[cfg(target_os = "macos")]
fn launch_agent_label(who: &str) -> String {
    let encoded = who
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("io.github.ceclin.agent-scale.edge.{encoded}")
}

#[cfg(target_os = "macos")]
fn launch_agent_plist(
    label: &str,
    installed: &std::path::Path,
    who: &str,
    stdout: &std::path::Path,
    stderr: &std::path::Path,
) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n    <string>run</string>\n    <string>{}</string>\n  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n  <key>ProcessType</key>\n  <string>Background</string>\n  <key>StandardOutPath</key>\n  <string>{}</string>\n  <key>StandardErrorPath</key>\n  <string>{}</string>\n</dict>\n</plist>\n",
        xml_text(label),
        xml_text(&installed.to_string_lossy()),
        xml_text(who),
        xml_text(&stdout.to_string_lossy()),
        xml_text(&stderr.to_string_lossy()),
    )
}

#[cfg(target_os = "macos")]
fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
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
