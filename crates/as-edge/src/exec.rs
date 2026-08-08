use protocol::ExecParams;
use tokio::process::Command;

const BUILTIN_COMMANDS: &[&str] = &["fd", "rg"];

/// Use this marker when re-execing a built-in; unlike `argv[0]` tricks it works
/// consistently on Unix and Windows without temporary links.
pub const BUILTIN_ENV: &str = "AS_EDGE_BUILTIN";

pub fn build_command(params: &ExecParams) -> Command {
    if !BUILTIN_COMMANDS.contains(&params.command.as_str()) {
        return Command::new(&params.command);
    }

    let exe = std::env::current_exe().unwrap();
    let mut cmd = Command::new(exe);
    cmd.env(BUILTIN_ENV, &params.command);
    cmd
}
