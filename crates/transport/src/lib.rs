//! Reusing one framing contract across local IPC and iroh keeps the daemon a
//! byte-forwarder instead of a second protocol translation layer.
//!
//! Use `[tag: u8][len: u32 LE][payload: len bytes]` on both transports.
//!   START  payload = JSON (ExecParams on the iroh side; {edge, params} on the
//!          unix side)
//!   STDOUT payload = raw stdout bytes
//!   STDERR payload = raw stderr bytes
//!   EXIT   payload = i32 LE exit code
//!
//! Framing is provided twice (concrete) rather than via an async trait, to keep
//! the futures `Send` for `tokio::spawn` without async-fn-in-trait gymnastics.

use anyhow::{Context, Result};
use iroh::endpoint::{RelayMode, presets};
use iroh::{Endpoint, RelayMap, RelayUrl, SecretKey};

/// ALPN for the agent-scale RPC protocol.
pub const ALPN: &[u8] = b"agent-scale/rpc/3";

/// Valid tags in the center/edge and client/daemon frame protocols.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameTag {
    Start = 0,
    Stdout = 1,
    Stderr = 2,
    Exit = 3,
    Result = 4,
    Data = 5,
}

impl TryFrom<u8> for FrameTag {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Start),
            1 => Ok(Self::Stdout),
            2 => Ok(Self::Stderr),
            3 => Ok(Self::Exit),
            4 => Ok(Self::Result),
            5 => Ok(Self::Data),
            _ => anyhow::bail!("unknown frame tag {value}"),
        }
    }
}

impl std::fmt::Display for FrameTag {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", *self as u8)
    }
}

/// One validated protocol frame.
#[derive(Debug, Eq, PartialEq)]
pub struct Frame {
    pub tag: FrameTag,
    pub payload: Vec<u8>,
}

pub const T_START: FrameTag = FrameTag::Start;
pub const T_STDOUT: FrameTag = FrameTag::Stdout;
pub const T_STDERR: FrameTag = FrameTag::Stderr;
pub const T_EXIT: FrameTag = FrameTag::Exit;
pub const T_RESULT: FrameTag = FrameTag::Result;
pub const T_DATA: FrameTag = FrameTag::Data;

pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Relay URLs operated by n0 and bundled with the current iroh release.
///
/// Keeping this behind iroh's `RelayMode::Default` avoids baking relay hostnames
/// into agent-scale while giving standalone nodes a zero-config path.
pub fn default_relay_urls() -> Vec<RelayUrl> {
    RelayMode::Default.relay_map().urls()
}

/// Parse an explicit relay list, or return iroh's official relay set when the
/// list is empty. Supplying any custom URL replaces the defaults entirely.
pub fn relay_urls_or_default(values: &[String]) -> Result<Vec<RelayUrl>> {
    if values.is_empty() {
        return Ok(default_relay_urls());
    }
    values
        .iter()
        .map(|value| {
            value
                .parse::<RelayUrl>()
                .map_err(|error| anyhow::anyhow!("invalid relay {value}: {error}"))
        })
        .collect()
}

/// Construct the exact Relay/QAD settings distributed in a signed Control map.
pub fn managed_relay_config(url: RelayUrl, qad_port: Option<u16>) -> iroh::RelayConfig {
    iroh::RelayConfig::new(url, qad_port.map(iroh_relay::RelayQuicConfig::new))
}

/// Build a relay-only-capable endpoint: minimal preset (ring crypto provider,
/// no discovery), custom relays, given identity + ALPNs. Direct paths are left
/// enabled — iroh will hole-punch when it can and fall back to the relay.
pub async fn build_endpoint(secret_key: SecretKey, relay_urls: &[RelayUrl], alpns: Vec<Vec<u8>>) -> Result<Endpoint> {
    let relays = relay_urls
        .iter()
        .cloned()
        .map(iroh::RelayConfig::from)
        .collect::<Vec<_>>();
    build_endpoint_with_config(secret_key, relays, None, alpns).await
}

/// Build an endpoint from an explicit relay configuration. Managed mode uses
/// this to install Control-signed QAD ports and its private Relay CA.
pub async fn build_endpoint_with_config(
    secret_key: SecretKey,
    relays: Vec<iroh::RelayConfig>,
    relay_ca_der: Option<Vec<u8>>,
    alpns: Vec<Vec<u8>>,
) -> Result<Endpoint> {
    // reqwest (shared with iroh, for net-report probes + our MCP-HTTP bridge)
    // builds rustls bring-your-own-provider, so install `ring` as the process
    // default once. Idempotent — a no-op if iroh already installed one.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let relay_count = relays.len();
    let map = RelayMap::from_iter(relays);
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .relay_mode(RelayMode::Custom(map))
        .alpns(alpns);
    if let Some(ca_der) = relay_ca_der {
        anyhow::ensure!(!ca_der.is_empty(), "managed Relay CA certificate is empty");
        builder = builder.ca_tls_config(
            iroh_relay::tls::CaTlsConfig::embedded()
                .with_extra_roots([rustls::pki_types::CertificateDer::from(ca_der)]),
        );
    }
    let ep = builder.bind().await?;
    // A freshly enrolled control-managed node may legitimately receive an
    // empty relay map until the first relay finishes enrollment. Waiting for
    // `online()` with no relay configured never completes, which would prevent
    // the control watcher from installing the first relay.
    if relay_count != 0 {
        ep.online().await;
    }
    Ok(ep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn managed_relay_uses_the_control_qad_port() {
        let url: RelayUrl = "https://relay.example.com".parse().unwrap();
        let enabled = managed_relay_config(url.clone(), Some(4433));
        assert_eq!(enabled.quic.as_ref().map(|quic| quic.port), Some(4433));
        let disabled = managed_relay_config(url, None);
        assert!(disabled.quic.is_none());
    }

    #[test]
    fn official_relay_preset_is_available() {
        let relays = default_relay_urls();
        assert!(!relays.is_empty());
        assert!(relays.iter().all(|relay| relay.as_str().starts_with("https://")));
    }

    #[test]
    fn custom_relays_replace_the_official_set() {
        let relays = relay_urls_or_default(&["https://relay.example.com".into()]).unwrap();
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].to_string(), "https://relay.example.com/");
    }

    #[test]
    fn headers_reject_oversized_payloads() {
        assert!(header(T_DATA, MAX_FRAME + 1).is_err());
    }

    #[tokio::test]
    async fn io_wire_distinguishes_clean_eof_from_truncation() {
        let (writer, mut reader) = tokio::io::duplex(16);
        drop(writer);
        assert!(io_wire::read_frame(&mut reader).await.unwrap().is_none());

        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&[T_START as u8, 0]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(io_wire::read_frame(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn io_wire_rejects_unknown_tags() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&[99, 0, 0, 0, 0]).await.unwrap();
        assert!(io_wire::read_frame(&mut reader).await.is_err());
    }
}

fn header(tag: FrameTag, len: usize) -> Result<[u8; 5]> {
    anyhow::ensure!(len <= MAX_FRAME, "frame too large: {len}");
    let len = u32::try_from(len).context("frame length exceeds u32")?;
    let value = len.to_le_bytes();
    Ok([tag as u8, value[0], value[1], value[2], value[3]])
}

fn split_header(header: [u8; 5]) -> Result<(FrameTag, usize)> {
    let tag = FrameTag::try_from(header[0])?;
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    anyhow::ensure!(len <= MAX_FRAME, "frame too large: {len}");
    Ok((tag, len))
}

/// Framing over iroh QUIC streams (center <-> edge).
pub mod iroh_wire {
    use super::*;
    use iroh::endpoint::{RecvStream, SendStream};

    pub async fn write_frame(s: &mut SendStream, tag: FrameTag, payload: &[u8]) -> Result<()> {
        s.write_all(&header(tag, payload.len())?)
            .await
            .map_err(|e| anyhow::anyhow!("write header: {e}"))?;
        s.write_all(payload)
            .await
            .map_err(|e| anyhow::anyhow!("write payload: {e}"))?;
        Ok(())
    }

    /// Returns `Ok(None)` on a clean end-of-stream.
    pub async fn read_frame(r: &mut RecvStream) -> Result<Option<Frame>> {
        let mut hdr = [0u8; 5];
        let Some(first) = r
            .read_chunk(1)
            .await
            .map_err(|error| anyhow::anyhow!("read frame tag: {error}"))?
        else {
            return Ok(None);
        };
        hdr[0] = first[0];
        r.read_exact(&mut hdr[1..])
            .await
            .map_err(|error| anyhow::anyhow!("read frame header: {error}"))?;
        let (tag, n) = split_header(hdr)?;
        let mut buf = vec![0u8; n];
        r.read_exact(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read payload: {e}"))?;
        Ok(Some(Frame { tag, payload: buf }))
    }
}

/// iroh-blobs helpers: a disk-backed store (bounded memory) and a streaming
/// fetch that writes straight to a file (never buffers the whole blob).
pub mod blobs {
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};
    use bao_tree::io::BaoContentItem;
    use futures_util::StreamExt;
    use iroh::{Endpoint, EndpointAddr};
    use iroh_blobs::Hash;
    use iroh_blobs::get::request::GetBlobItem;
    use iroh_blobs::store::fs::FsStore;
    use tokio::io::AsyncWriteExt;

    /// Open (or create) a filesystem-backed blob store at `dir`.
    pub async fn open_store(dir: impl AsRef<Path>) -> Result<FsStore> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        FsStore::load(dir)
            .await
            .map_err(|e| anyhow::anyhow!("open blob store {}: {e}", dir.display()))
    }

    /// Stream a blob from `addr` to `dest`, bounded memory (chunk-sized).
    /// Returns the number of bytes written. Content is BLAKE3-verified per chunk.
    pub async fn fetch_to_file(endpoint: &Endpoint, addr: EndpointAddr, hash: Hash, dest: &str) -> Result<u64> {
        let conn = endpoint
            .connect(addr, iroh_blobs::ALPN)
            .await
            .map_err(|e| anyhow::anyhow!("connect blobs: {e}"))?;
        let mut stream = iroh_blobs::get::request::get_blob(conn, hash);
        let destination = PathBuf::from(dest);
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let temp_parent = parent.to_owned();
        let temp = tokio::task::spawn_blocking(move || tempfile::NamedTempFile::new_in(temp_parent))
            .await
            .context("join temporary download creator")?
            .with_context(|| format!("create temporary download beside {dest}"))?;
        let mut file = tokio::fs::File::from_std(temp.as_file().try_clone()?);
        let mut total = 0u64;
        let mut completed = false;
        while let Some(item) = stream.next().await {
            match item {
                GetBlobItem::Item(BaoContentItem::Leaf(leaf)) => {
                    file.write_all(&leaf.data).await?;
                    total += leaf.data.len() as u64;
                }
                GetBlobItem::Item(BaoContentItem::Parent(_)) => {}
                GetBlobItem::Done(_) => {
                    completed = true;
                    break;
                }
                GetBlobItem::Error(e) => anyhow::bail!("get_blob: {e}"),
            }
        }
        anyhow::ensure!(completed, "blob stream ended before verification completed");
        file.flush().await.context("flush downloaded file")?;
        file.sync_all().await.context("sync downloaded file")?;
        drop(file);
        tokio::task::spawn_blocking(move || install_download(temp, &destination))
            .await
            .context("join download installer")??;
        Ok(total)
    }

    fn install_download(temp: tempfile::NamedTempFile, destination: &Path) -> Result<()> {
        temp.persist(destination)
            .map_err(|error| error.error)
            .with_context(|| format!("replace {}", destination.display()))?;
        #[cfg(unix)]
        {
            let parent = destination
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::File::open(parent)
                .with_context(|| format!("open directory {}", parent.display()))?
                .sync_all()
                .with_context(|| format!("sync directory {}", parent.display()))?;
        }
        Ok(())
    }
}

/// Framing over any Tokio byte stream (client <-> daemon local IPC).
pub mod io_wire {
    use super::*;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, tag: FrameTag, payload: &[u8]) -> Result<()> {
        w.write_all(&header(tag, payload.len())?).await?;
        w.write_all(payload).await?;
        w.flush().await?;
        Ok(())
    }

    /// Returns `Ok(None)` on a clean end-of-stream.
    pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>> {
        let mut hdr = [0u8; 5];
        match r.read(&mut hdr[..1]).await {
            Ok(0) => return Ok(None),
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) => return Err(error).context("read frame tag"),
        }
        r.read_exact(&mut hdr[1..]).await.context("read frame header")?;
        let (tag, n) = split_header(hdr)?;
        let mut buf = vec![0u8; n];
        r.read_exact(&mut buf).await.context("read frame payload")?;
        Ok(Some(Frame { tag, payload: buf }))
    }
}
