//! A shared schema keeps Center and Edge framing changes compile-time coupled.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What the edge is asked to do on a single bi-stream (START frame payload).
#[derive(Debug, Serialize, Deserialize)]
pub enum EdgeReq {
    /// Run a command, streaming STDOUT/STDERR/EXIT frames.
    Exec(ExecParams),
    /// Add a local (on-edge) file to the blob store; reply with its hash so the
    /// center can fetch it. (download direction)
    PrepareDownload { path: String },
    /// Fetch a blob from the center and write it to `path`. (upload direction)
    ReceiveUpload {
        hash: String,
        center_id: String,
        center_relay: String,
        path: String,
    },
    /// Read the edge-owned MCP registry.
    McpList,
    /// Add or update one edge-owned MCP definition.
    McpUpsert { name: String, transport: McpTransport },
    /// Remove one edge-owned MCP definition.
    McpRemove { name: String },
    /// Connect to a named MCP server and bridge its bytes in T_DATA frames.
    McpConnect { name: String },
}

/// How the edge reaches a local MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpTransport {
    /// Spawn a child process and pipe its stdio.
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        cwd: Option<String>,
    },
    /// MCP Streamable HTTP endpoint (single URL, POST + optional SSE).
    Http { url: String },
    /// Legacy MCP HTTP+SSE endpoint (GET sse stream + POST messages).
    Sse { url: String },
}

/// Snapshot of the MCP definitions persisted by one edge identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpCatalog {
    pub revision: u64,
    #[serde(default)]
    pub servers: BTreeMap<String, McpTransport>,
}

/// A stable error returned by the remote process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteError {
    pub code: String,
    pub message: String,
}

impl RemoteError {
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: "internal".into(),
            message: message.into(),
        }
    }
}

/// Typed result envelope used in RESULT frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum RpcResult<T> {
    Ok(T),
    Error(RemoteError),
}

/// Successful values for upload and download operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransferResult {
    DownloadReady { hash: String },
    Stored { bytes: u64 },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecParams {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_transport_is_tagged() {
        let t = McpTransport::Http {
            url: "http://127.0.0.1:8888/mcp".into(),
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"kind\":\"http\""), "got {json}");
        let parsed: McpTransport = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, McpTransport::Http { .. }));
    }

    #[test]
    fn rpc_results_are_unambiguous() {
        let value = RpcResult::Ok(TransferResult::Stored { bytes: 42 });
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<RpcResult<TransferResult>>(&json).unwrap(), value);

        let error: RpcResult<()> = RpcResult::Error(RemoteError::internal("failed"));
        assert!(matches!(
            serde_json::from_str::<RpcResult<()>>(&serde_json::to_string(&error).unwrap()).unwrap(),
            RpcResult::Error(RemoteError { code, .. }) if code == "internal"
        ));
    }
}
