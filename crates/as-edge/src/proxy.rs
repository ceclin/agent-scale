use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::{RecvStream, SendStream};
use protocol::{ProxyConnectResult, ProxyDatagram, ProxyTarget, RemoteError, RpcResult};
use scale_transport::{Frame, T_DATA, T_RESULT, decode_proxy_datagram, encode_proxy_datagram, iroh_wire};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::{TcpStream, UdpSocket};

pub async fn serve_tcp(
    mut send: SendStream,
    mut recv: RecvStream,
    target: ProxyTarget,
    connect_timeout_secs: u64,
) -> Result<()> {
    let result = connect_tcp(&target, connect_timeout_secs).await;
    let mut socket = match result {
        Ok(socket) => socket,
        Err(error) => {
            let response: RpcResult<ProxyConnectResult> = RpcResult::Error(error);
            iroh_wire::write_frame(&mut send, T_RESULT, &serde_json::to_vec(&response)?).await?;
            let _ = send.finish();
            return Ok(());
        }
    };
    socket.set_nodelay(true)?;
    let response = RpcResult::Ok(ProxyConnectResult {
        bound_addr: socket.local_addr()?.to_string(),
    });
    iroh_wire::write_frame(&mut send, T_RESULT, &serde_json::to_vec(&response)?).await?;

    let (mut socket_read, mut socket_write) = socket.split();
    let client_to_target = async {
        copy(&mut recv, &mut socket_write).await?;
        socket_write.shutdown().await
    };
    let target_to_client = async {
        copy(&mut socket_read, &mut send).await?;
        send.finish().map_err(io::Error::other)
    };
    tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}

async fn connect_tcp(target: &ProxyTarget, timeout_secs: u64) -> Result<TcpStream, RemoteError> {
    if target.host.is_empty() || target.port == 0 {
        return Err(RemoteError {
            code: "invalid_target".into(),
            message: "proxy target requires a host and non-zero port".into(),
        });
    }
    if timeout_secs == 0 {
        return Err(RemoteError {
            code: "invalid_timeout".into(),
            message: "proxy connect timeout must be non-zero".into(),
        });
    }
    match tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    {
        Ok(Ok(socket)) => Ok(socket),
        Ok(Err(error)) => Err(network_error(error)),
        Err(_) => Err(RemoteError {
            code: "timeout".into(),
            message: format!("connection to {}:{} timed out", target.host, target.port),
        }),
    }
}

pub async fn serve_udp(mut send: SendStream, mut recv: RecvStream, resolve_timeout_secs: u64) -> Result<()> {
    anyhow::ensure!(resolve_timeout_secs != 0, "proxy resolve timeout must be non-zero");
    let ipv4 = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let ipv6 = UdpSocket::bind("[::]:0").await.ok().map(Arc::new);
    let response: RpcResult<()> = RpcResult::Ok(());
    iroh_wire::write_frame(&mut send, T_RESULT, &serde_json::to_vec(&response)?).await?;

    let mut ipv4_buf = vec![0; scale_transport::MAX_UDP_PAYLOAD];
    let mut ipv6_buf = vec![0; scale_transport::MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            frame = iroh_wire::read_frame(&mut recv) => match frame? {
                Some(Frame { tag: T_DATA, payload }) => {
                    let datagram = decode_proxy_datagram(&payload)?;
                    send_udp(&ipv4, ipv6.as_deref(), datagram, resolve_timeout_secs).await?;
                }
                Some(frame) => anyhow::bail!("unexpected UDP proxy frame tag {}", frame.tag),
                None => break,
            },
            received = ipv4.recv_from(&mut ipv4_buf) => {
                let (len, source) = received?;
                write_udp_response(&mut send, source, &ipv4_buf[..len]).await?;
            },
            received = recv_optional(ipv6.as_deref(), &mut ipv6_buf) => {
                let (len, source) = received?;
                write_udp_response(&mut send, source, &ipv6_buf[..len]).await?;
            },
        }
    }
    let _ = send.finish();
    Ok(())
}

async fn send_udp(
    ipv4: &UdpSocket,
    ipv6: Option<&UdpSocket>,
    datagram: ProxyDatagram,
    timeout_secs: u64,
) -> Result<()> {
    let addrs = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        tokio::net::lookup_host((datagram.target.host.as_str(), datagram.target.port)),
    )
    .await
    .context("proxy target resolution timed out")??;

    let mut last_error = None;
    for addr in addrs {
        let socket = match addr {
            SocketAddr::V4(_) => ipv4,
            SocketAddr::V6(_) => match ipv6 {
                Some(socket) => socket,
                None => continue,
            },
        };
        match socket.send_to(&datagram.payload, addr).await {
            Ok(_) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("proxy target did not resolve to a supported address")))
}

async fn recv_optional(socket: Option<&UdpSocket>, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

async fn write_udp_response(send: &mut SendStream, source: SocketAddr, payload: &[u8]) -> Result<()> {
    let datagram = ProxyDatagram {
        target: ProxyTarget {
            host: source.ip().to_string(),
            port: source.port(),
        },
        payload: payload.to_vec(),
    };
    iroh_wire::write_frame(send, T_DATA, &encode_proxy_datagram(&datagram)?).await
}

fn network_error(error: io::Error) -> RemoteError {
    let code = match error.kind() {
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::TimedOut => "timeout",
        io::ErrorKind::NotFound => "host_unreachable",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        _ => "network_error",
    };
    RemoteError {
        code: code.into(),
        message: error.to_string(),
    }
}
