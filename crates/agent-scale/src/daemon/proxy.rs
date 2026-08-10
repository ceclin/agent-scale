use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command, new_udp_header, parse_udp_request};
use iroh::endpoint::{RecvStream, SendStream};
use protocol::{EdgeReq, ProxyConnectResult, ProxyDatagram, ProxyTarget, RemoteError, RpcResult};
use scale_transport::{Frame, T_DATA, T_RESULT, T_START, decode_proxy_datagram, encode_proxy_datagram, iroh_wire};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tracing::warn;

use super::{Ctx, get_conn};
use crate::common::{ProxyAdmin, ProxyAdminResult, ProxyInfo, ProxyKind, ProxySpec};

#[derive(Clone, Default)]
pub(super) struct ProxyManager {
    running: Arc<Mutex<HashMap<String, RunningProxy>>>,
}

struct RunningProxy {
    info: ProxyInfo,
    cancel: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl ProxyManager {
    pub async fn handle(&self, ctx: Ctx, command: ProxyAdmin) -> Result<ProxyAdminResult> {
        match command {
            ProxyAdmin::Start(spec) => self.start(ctx, spec).await.map(ProxyAdminResult::Started),
            ProxyAdmin::Stop { name } => {
                self.stop(&name).await?;
                Ok(ProxyAdminResult::Stopped)
            }
            ProxyAdmin::List => Ok(ProxyAdminResult::List(self.list().await)),
        }
    }

    async fn start(&self, ctx: Ctx, spec: ProxySpec) -> Result<ProxyInfo> {
        anyhow::ensure!(!spec.name.trim().is_empty(), "proxy name cannot be empty");
        anyhow::ensure!(spec.connect_timeout_secs != 0, "proxy connect timeout must be non-zero");
        anyhow::ensure!(
            ctx.edges.lock().await.contains_key(&spec.edge),
            "unknown edge '{}'",
            spec.edge
        );
        let listener = TcpListener::bind(spec.listen)
            .await
            .with_context(|| format!("bind proxy listener {}", spec.listen))?;
        let listen = listener.local_addr()?;
        let info = ProxyInfo {
            name: spec.name.clone(),
            edge: spec.edge.clone(),
            listen,
            kind: spec.kind.clone(),
        };

        let mut running = self.running.lock().await;
        anyhow::ensure!(
            !running.contains_key(&spec.name),
            "proxy '{}' already exists",
            spec.name
        );
        anyhow::ensure!(
            running.values().all(|proxy| proxy.info.listen != listen),
            "another proxy already listens on {listen}"
        );
        let (cancel, cancelled) = oneshot::channel();
        let task_info = info.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = serve_listener(listener, ctx, spec, cancelled).await {
                warn!("proxy '{}': {error:#}", task_info.name);
            }
        });
        running.insert(
            info.name.clone(),
            RunningProxy {
                info: info.clone(),
                cancel,
                task,
            },
        );
        Ok(info)
    }

    async fn stop(&self, name: &str) -> Result<()> {
        let proxy = self
            .running
            .lock()
            .await
            .remove(name)
            .with_context(|| format!("unknown proxy '{name}'"))?;
        let _ = proxy.cancel.send(());
        let _ = proxy.task.await;
        Ok(())
    }

    async fn list(&self) -> Vec<ProxyInfo> {
        let mut proxies = self
            .running
            .lock()
            .await
            .values()
            .map(|proxy| proxy.info.clone())
            .collect::<Vec<_>>();
        proxies.sort_by(|left, right| left.name.cmp(&right.name));
        proxies
    }

    pub async fn len(&self) -> usize {
        self.running.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.running.lock().await.is_empty()
    }

    pub async fn shutdown(&self) {
        let proxies = self
            .running
            .lock()
            .await
            .drain()
            .map(|(_, proxy)| proxy)
            .collect::<Vec<_>>();
        let mut tasks = Vec::with_capacity(proxies.len());
        for proxy in proxies {
            let _ = proxy.cancel.send(());
            tasks.push(proxy.task);
        }
        for task in tasks {
            let _ = task.await;
        }
    }
}

async fn serve_listener(
    listener: TcpListener,
    ctx: Ctx,
    spec: ProxySpec,
    mut cancelled: oneshot::Receiver<()>,
) -> Result<()> {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut cancelled => break,
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let ctx = ctx.clone();
                let spec = spec.clone();
                sessions.spawn(async move {
                    let result = match &spec.kind {
                        ProxyKind::Tcp { target } => tunnel_tcp(
                            &ctx,
                            &spec.edge,
                            target.clone(),
                            spec.connect_timeout_secs,
                            socket,
                        )
                        .await,
                        ProxyKind::Socks5 => serve_socks5(
                            &ctx,
                            &spec.edge,
                            spec.connect_timeout_secs,
                            socket,
                        )
                        .await,
                    };
                    if let Err(error) = result {
                        warn!("proxy '{}' connection: {error:#}", spec.name);
                    }
                });
            }
            Some(result) = sessions.join_next(), if !sessions.is_empty() => {
                if let Err(error) = result {
                    warn!("proxy session task: {error}");
                }
            }
        }
    }
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    Ok(())
}

async fn tunnel_tcp(
    ctx: &Ctx,
    edge_name: &str,
    target: ProxyTarget,
    connect_timeout_secs: u64,
    socket: TcpStream,
) -> Result<()> {
    let (send, recv, _) = open_tcp_tunnel(ctx, edge_name, target, connect_timeout_secs)
        .await
        .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?;
    bridge_tcp(socket, send, recv).await
}

async fn open_tcp_tunnel(
    ctx: &Ctx,
    edge_name: &str,
    target: ProxyTarget,
    connect_timeout_secs: u64,
) -> std::result::Result<(SendStream, RecvStream, SocketAddr), RemoteError> {
    let edge = ctx
        .edges
        .lock()
        .await
        .get(edge_name)
        .cloned()
        .ok_or_else(|| remote_internal(anyhow::anyhow!("edge '{edge_name}' is no longer configured")))?;
    let connection = get_conn(ctx, &edge).await.map_err(remote_internal)?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| remote_internal(anyhow::anyhow!("open_bi: {error}")))?;
    iroh_wire::write_frame(
        &mut send,
        T_START,
        &serde_json::to_vec(&EdgeReq::ProxyTcpConnect {
            target,
            connect_timeout_secs,
        })
        .map_err(remote_internal)?,
    )
    .await
    .map_err(remote_internal)?;
    match iroh_wire::read_frame(&mut recv).await.map_err(remote_internal)? {
        Some(Frame { tag: T_RESULT, payload }) => {
            match serde_json::from_slice::<RpcResult<ProxyConnectResult>>(&payload).map_err(remote_internal)? {
                RpcResult::Ok(result) => {
                    let bound = result
                        .bound_addr
                        .parse()
                        .map_err(|error| remote_internal(anyhow::anyhow!("invalid Edge bound address: {error}")))?;
                    Ok((send, recv, bound))
                }
                RpcResult::Error(error) => Err(error),
            }
        }
        Some(frame) => Err(remote_internal(anyhow::anyhow!(
            "unexpected edge proxy frame tag {}",
            frame.tag
        ))),
        None => Err(remote_internal(anyhow::anyhow!("edge closed during proxy startup"))),
    }
}

async fn bridge_tcp(mut socket: TcpStream, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    socket.set_nodelay(true)?;
    let (mut socket_read, mut socket_write) = socket.split();
    let local_to_edge = async {
        copy(&mut socket_read, &mut send).await?;
        send.finish().map_err(io::Error::other)
    };
    let edge_to_local = async {
        copy(&mut recv, &mut socket_write).await?;
        socket_write.shutdown().await
    };
    tokio::try_join!(local_to_edge, edge_to_local)?;
    Ok(())
}

async fn serve_socks5(ctx: &Ctx, edge_name: &str, timeout_secs: u64, socket: TcpStream) -> Result<()> {
    let peer_ip = socket.peer_addr()?.ip();
    let local_ip = socket.local_addr()?.ip();
    let (protocol, command, target) = Socks5ServerProtocol::accept_no_auth(socket)
        .await?
        .read_command()
        .await?;
    match command {
        Socks5Command::TCPConnect => {
            let target = proxy_target(target);
            match open_tcp_tunnel(ctx, edge_name, target, timeout_secs).await {
                Ok((send, recv, bound)) => {
                    let socket = protocol.reply_success(bound).await?;
                    bridge_tcp(socket, send, recv).await
                }
                Err(error) => {
                    protocol.reply_error(&socks_reply(&error.code)).await?;
                    Ok(())
                }
            }
        }
        Socks5Command::UDPAssociate => {
            let (send, recv) = match open_udp_tunnel(ctx, edge_name, timeout_secs).await {
                Ok(streams) => streams,
                Err(error) => {
                    protocol.reply_error(&socks_reply(&error.code)).await?;
                    return Ok(());
                }
            };
            let udp = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
            let bound = udp.local_addr()?;
            let control = protocol.reply_success(bound).await?;
            serve_socks_udp(control, udp, peer_ip, send, recv).await
        }
        Socks5Command::TCPBind => {
            protocol.reply_error(&ReplyError::CommandNotSupported).await?;
            Ok(())
        }
    }
}

async fn open_udp_tunnel(
    ctx: &Ctx,
    edge_name: &str,
    timeout_secs: u64,
) -> std::result::Result<(SendStream, RecvStream), RemoteError> {
    let edge = ctx
        .edges
        .lock()
        .await
        .get(edge_name)
        .cloned()
        .ok_or_else(|| remote_internal(anyhow::anyhow!("edge '{edge_name}' is no longer configured")))?;
    let connection = get_conn(ctx, &edge).await.map_err(remote_internal)?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| remote_internal(anyhow::anyhow!("open_bi: {error}")))?;
    let request = EdgeReq::ProxyUdpAssociate {
        resolve_timeout_secs: timeout_secs,
    };
    iroh_wire::write_frame(
        &mut send,
        T_START,
        &serde_json::to_vec(&request).map_err(remote_internal)?,
    )
    .await
    .map_err(remote_internal)?;
    match iroh_wire::read_frame(&mut recv).await.map_err(remote_internal)? {
        Some(Frame { tag: T_RESULT, payload }) => {
            match serde_json::from_slice::<RpcResult<()>>(&payload).map_err(remote_internal)? {
                RpcResult::Ok(()) => Ok((send, recv)),
                RpcResult::Error(error) => Err(error),
            }
        }
        Some(frame) => Err(remote_internal(anyhow::anyhow!(
            "unexpected Edge UDP proxy frame tag {}",
            frame.tag
        ))),
        None => Err(remote_internal(anyhow::anyhow!("Edge closed during UDP proxy startup"))),
    }
}

async fn serve_socks_udp(
    mut control: TcpStream,
    udp: UdpSocket,
    client_ip: IpAddr,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let mut client_addr = None;
    let mut control_byte = [0u8; 1];
    let mut packet = vec![0u8; u16::MAX as usize];
    loop {
        tokio::select! {
            read = control.read(&mut control_byte) => match read {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
            received = udp.recv_from(&mut packet) => {
                let (len, source) = received?;
                if source.ip() != client_ip || client_addr.is_some_and(|known| known != source) {
                    continue;
                }
                client_addr.get_or_insert(source);
                let (fragment, target, payload) = match parse_udp_request(&packet[..len]).await {
                    Ok(parsed) => parsed,
                    Err(_) => continue,
                };
                if fragment != 0 {
                    continue;
                }
                let datagram = ProxyDatagram {
                    target: proxy_target(target),
                    payload: payload.to_vec(),
                };
                iroh_wire::write_frame(&mut send, T_DATA, &encode_proxy_datagram(&datagram)?).await?;
            },
            frame = iroh_wire::read_frame(&mut recv) => match frame? {
                Some(Frame { tag: T_DATA, payload }) => {
                    let Some(client_addr) = client_addr else { continue };
                    let datagram = decode_proxy_datagram(&payload)?;
                    let source_ip = datagram.target.host.parse::<IpAddr>()?;
                    let source = SocketAddr::new(source_ip, datagram.target.port);
                    let mut response = new_udp_header(source)?;
                    response.extend_from_slice(&datagram.payload);
                    udp.send_to(&response, client_addr).await?;
                }
                Some(frame) => anyhow::bail!("unexpected Edge UDP proxy frame tag {}", frame.tag),
                None => break,
            },
        }
    }
    let _ = send.finish();
    Ok(())
}

fn proxy_target(target: TargetAddr) -> ProxyTarget {
    match target {
        TargetAddr::Ip(address) => ProxyTarget {
            host: address.ip().to_string(),
            port: address.port(),
        },
        TargetAddr::Domain(host, port) => ProxyTarget { host, port },
    }
}

fn socks_reply(code: &str) -> ReplyError {
    match code {
        "connection_refused" => ReplyError::ConnectionRefused,
        "network_unreachable" => ReplyError::NetworkUnreachable,
        "host_unreachable" => ReplyError::HostUnreachable,
        "timeout" => ReplyError::ConnectionTimeout,
        "invalid_target" => ReplyError::AddressTypeNotSupported,
        _ => ReplyError::GeneralFailure,
    }
}

fn remote_internal(error: impl Into<anyhow::Error>) -> RemoteError {
    RemoteError::internal(format!("{:#}", error.into()))
}
