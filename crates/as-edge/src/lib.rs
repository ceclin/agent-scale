//! Exposes the agent runtime separately from CLI dispatch so built-ins can
//! re-exec the same binary without coupling to argument parsing.

pub mod exec;
pub mod iroh_edge;
pub mod mcp_http;
pub mod mcp_registry;
mod proxy;
mod runtime;
