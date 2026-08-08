//! Authenticated-user-local byte stream used by the CLI and background daemon.
//!
//! Unix uses a private Unix-domain socket. Windows uses a byte-mode named pipe:
//! Tokio rejects remote clients by default, the first instance is exclusive,
//! and clients request duplex access so the default Windows pipe DACL only
//! admits the creator, administrators, and LocalSystem.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::common;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type Stream = Box<dyn AsyncStream>;
pub type ReadHalf = tokio::io::ReadHalf<Stream>;
pub type WriteHalf = tokio::io::WriteHalf<Stream>;

pub struct Listener(platform::Listener);

impl Listener {
    pub fn bind() -> io::Result<Self> {
        platform::Listener::bind(&common::local_endpoint()).map(Self)
    }

    pub async fn accept(&mut self) -> io::Result<Stream> {
        self.0.accept().await
    }
}

pub async fn connect() -> io::Result<Stream> {
    platform::connect(&common::local_endpoint()).await
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use tokio::net::UnixListener;

    use super::Stream;

    pub struct Listener {
        inner: UnixListener,
        path: PathBuf,
    }

    impl Listener {
        pub fn bind(endpoint: &str) -> io::Result<Self> {
            let path = PathBuf::from(endpoint);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let inner = UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self { inner, path })
        }

        pub async fn accept(&mut self) -> io::Result<Stream> {
            let (stream, _) = self.inner.accept().await?;
            Ok(Box::new(stream))
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    pub async fn connect(endpoint: &str) -> io::Result<Stream> {
        Ok(Box::new(tokio::net::UnixStream::connect(endpoint).await?))
    }
}

#[cfg(windows)]
mod platform {
    use std::io;
    use std::time::Duration;

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

    use super::Stream;

    const ERROR_PIPE_BUSY: i32 = 231;

    pub struct Listener {
        endpoint: String,
        next: Option<NamedPipeServer>,
    }

    impl Listener {
        pub fn bind(endpoint: &str) -> io::Result<Self> {
            let next = create_server(endpoint, true)?;
            Ok(Self {
                endpoint: endpoint.to_owned(),
                next: Some(next),
            })
        }

        pub async fn accept(&mut self) -> io::Result<Stream> {
            if self.next.is_none() {
                self.next = Some(create_server(&self.endpoint, false)?);
            }
            let connected = self.next.take().expect("named pipe instance initialized");
            connected.connect().await?;
            // Publish the next instance before handing this one to its task, so
            // concurrent CLI invocations do not observe an avoidable busy pipe.
            self.next = Some(create_server(&self.endpoint, false)?);
            Ok(Box::new(connected))
        }
    }

    fn create_server(endpoint: &str, first: bool) -> io::Result<NamedPipeServer> {
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first);
        options.create(endpoint)
    }

    pub async fn connect(endpoint: &str) -> io::Result<Stream> {
        for attempt in 0..50 {
            match ClientOptions::new().open(endpoint) {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < 49 => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("named-pipe retry loop always returns")
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("agent-scale Center supports Unix and Windows hosts");

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    static NEXT_ENDPOINT: AtomicU64 = AtomicU64::new(0);

    fn test_endpoint() -> String {
        let id = NEXT_ENDPOINT.fetch_add(1, Ordering::Relaxed);
        #[cfg(unix)]
        {
            std::env::temp_dir()
                .join(format!("agent-scale-ipc-{}-{id}.sock", std::process::id()))
                .to_string_lossy()
                .into_owned()
        }
        #[cfg(windows)]
        {
            format!(r"\\.\pipe\agent-scale-test-{}-{id}", std::process::id())
        }
    }

    #[tokio::test]
    async fn local_stream_round_trip() {
        let endpoint = test_endpoint();
        let mut listener = platform::Listener::bind(&endpoint).unwrap();
        let client = platform::connect(&endpoint);
        let server = listener.accept();
        let (client, server) = tokio::join!(client, server);
        let mut client = client.unwrap();
        let mut server = server.unwrap();

        client.write_all(b"ping").await.unwrap();
        let mut request = [0; 4];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");

        server.write_all(b"pong").await.unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
    }
}
