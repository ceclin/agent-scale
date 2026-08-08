use protocol::ExecParams;
use tokio::process::Command;

const BUILTIN_COMMANDS: &[&str] = &["fd", "rg"];

/// Env var the edge sets on a built-in (fd/rg) child to signal which CLI to run.
/// Portable: avoids `argv[0]` tricks (Unix `arg0`, a Windows temp-hardlink shim)
/// and their staleness. See `main()`'s dispatch.
pub const BUILTIN_ENV: &str = "AS_EDGE_BUILTIN";

pub fn build_command(params: &ExecParams) -> Command {
    if !BUILTIN_COMMANDS.contains(&params.command.as_str()) {
        return Command::new(&params.command);
    }

    // Built-in fd/rg: re-exec ourselves and signal the dispatch via env var, so
    // `main()` routes into the right CLI. fd/rg read their flags from argv[1..]
    // (set by the caller); argv[0] is irrelevant to their parsing.
    let exe = std::env::current_exe().unwrap();
    let mut cmd = Command::new(exe);
    cmd.env(BUILTIN_ENV, &params.command);
    cmd
}
