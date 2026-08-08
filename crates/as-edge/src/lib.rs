//! Edge-agent library: command execution + the iroh edge transport and MCP
//! bridge used by the `as-edge` binary.

pub mod exec;
pub mod iroh_edge;
pub mod mcp_http;
pub mod mcp_registry;
mod runtime;
