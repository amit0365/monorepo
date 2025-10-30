// Proof-of-concept implementation of buffered tokio runtime
// This demonstrates how BufReader/BufWriter would be integrated

use crate::Error;
use commonware_utils::StableBuf;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt as _, AsyncWriteExt as _, BufReader, BufWriter},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    time::timeout,
};
use tracing::warn;

/// Default buffer sizes for BufReader/BufWriter
const DEFAULT_READ_BUFFER_SIZE: usize = 8192;  // 8KB
const DEFAULT_WRITE_BUFFER_SIZE: usize = 8192; // 8KB

/// Implementation of [crate::Sink] with buffering for the [tokio] runtime.
pub struct BufferedSink {
    write_timeout: Duration,
    writer: BufWriter<OwnedWriteHalf>,
}

impl BufferedSink {
    /// Create a new buffered sink with specified buffer size
    pub fn new(sink: OwnedWriteHalf, write_timeout: Duration, buffer_size: usize) -> Self {
        Self {
            write_timeout,
            writer: BufWriter::with_capacity(buffer_size, sink),
        }
    }
}

impl crate::Sink for BufferedSink {
    async fn send(&mut self, msg: impl Into<StableBuf> + Send) -> Result<(), Error> {
        // Write to buffer (may not actually send yet)
        timeout(
            self.write_timeout,
            self.writer.write_all(msg.into().as_ref()),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::SendFailed)?;

        // Flush to ensure data is actually sent
        // This is important for latency-sensitive applications
        timeout(self.write_timeout, self.writer.flush())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::SendFailed)?;

        Ok(())
    }
}

/// Implementation of [crate::Stream] with buffering for the [tokio] runtime.
pub struct BufferedStream {
    read_timeout: Duration,
    reader: BufReader<OwnedReadHalf>,
}

impl BufferedStream {
    /// Create a new buffered stream with specified buffer size
    pub fn new(stream: OwnedReadHalf, read_timeout: Duration, buffer_size: usize) -> Self {
        Self {
            read_timeout,
            reader: BufReader::with_capacity(buffer_size, stream),
        }
    }

    /// Read a single byte efficiently (useful for varint decoding)
    pub async fn read_byte(&mut self) -> Result<u8, Error> {
        let mut byte = [0u8; 1];
        timeout(self.read_timeout, self.reader.read_exact(&mut byte))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::RecvFailed)?;
        Ok(byte[0])
    }

    /// Peek at buffered data without consuming (useful for protocol detection)
    pub async fn peek(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        // Fill buffer if needed
        let available = timeout(self.read_timeout, self.reader.fill_buf())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::RecvFailed)?;

        // Return up to n bytes without consuming
        let peek_len = available.len().min(n);
        Ok(available[..peek_len].to_vec())
    }
}

impl crate::Stream for BufferedStream {
    async fn recv(&mut self, buf: impl Into<StableBuf> + Send) -> Result<StableBuf, Error> {
        let mut buf = buf.into();
        if buf.is_empty() {
            return Ok(buf);
        }

        // BufReader will handle buffering efficiently
        timeout(self.read_timeout, self.reader.read_exact(buf.as_mut()))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::RecvFailed)?;

        Ok(buf)
    }
}

/// Enhanced configuration for buffered tokio network
#[derive(Clone, Debug)]
pub struct BufferedConfig {
    /// Whether or not to disable Nagle's algorithm.
    tcp_nodelay: Option<bool>,
    /// Read timeout for connections
    read_timeout: Duration,
    /// Write timeout for connections
    write_timeout: Duration,
    /// Size of read buffer (bytes)
    read_buffer_size: usize,
    /// Size of write buffer (bytes)
    write_buffer_size: usize,
}

impl BufferedConfig {
    pub fn new() -> Self {
        Self::default()
    }

    // Builder methods
    pub fn with_tcp_nodelay(mut self, tcp_nodelay: Option<bool>) -> Self {
        self.tcp_nodelay = tcp_nodelay;
        self
    }

    pub fn with_read_timeout(mut self, read_timeout: Duration) -> Self {
        self.read_timeout = read_timeout;
        self
    }

    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    pub fn with_read_buffer_size(mut self, size: usize) -> Self {
        self.read_buffer_size = size;
        self
    }

    pub fn with_write_buffer_size(mut self, size: usize) -> Self {
        self.write_buffer_size = size;
        self
    }
}

impl Default for BufferedConfig {
    fn default() -> Self {
        Self {
            tcp_nodelay: Some(true), // Default to low latency
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            read_buffer_size: DEFAULT_READ_BUFFER_SIZE,
            write_buffer_size: DEFAULT_WRITE_BUFFER_SIZE,
        }
    }
}

/// Buffered [crate::Network] implementation using tokio
pub struct BufferedNetwork {
    cfg: BufferedConfig,
}

impl From<BufferedConfig> for BufferedNetwork {
    fn from(cfg: BufferedConfig) -> Self {
        Self { cfg }
    }
}

impl Default for BufferedNetwork {
    fn default() -> Self {
        Self::from(BufferedConfig::default())
    }
}

impl crate::Network for BufferedNetwork {
    type Listener = BufferedListener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        TcpListener::bind(socket)
            .await
            .map_err(|_| Error::BindFailed)
            .map(|listener| BufferedListener {
                cfg: self.cfg.clone(),
                listener,
            })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), crate::Error> {
        // Create TCP connection
        let stream = TcpStream::connect(socket)
            .await
            .map_err(|_| Error::ConnectionFailed)?;

        // Configure TCP options
        if let Some(tcp_nodelay) = self.cfg.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Split and wrap in buffers
        let (read_half, write_half) = stream.into_split();
        Ok((
            BufferedSink::new(
                write_half,
                self.cfg.write_timeout,
                self.cfg.write_buffer_size,
            ),
            BufferedStream::new(
                read_half,
                self.cfg.read_timeout,
                self.cfg.read_buffer_size,
            ),
        ))
    }
}

/// Buffered implementation of [crate::Listener]
pub struct BufferedListener {
    cfg: BufferedConfig,
    listener: TcpListener,
}

impl crate::Listener for BufferedListener {
    type Sink = BufferedSink;
    type Stream = BufferedStream;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        // Accept connection
        let (stream, addr) = self.listener.accept().await.map_err(|_| Error::Closed)?;

        // Configure TCP options
        if let Some(tcp_nodelay) = self.cfg.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Split and wrap in buffers
        let (read_half, write_half) = stream.into_split();
        Ok((
            addr,
            BufferedSink::new(
                write_half,
                self.cfg.write_timeout,
                self.cfg.write_buffer_size,
            ),
            BufferedStream::new(
                read_half,
                self.cfg.read_timeout,
                self.cfg.read_buffer_size,
            ),
        ))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network as _;

    #[tokio::test]
    async fn test_buffered_network_basic() {
        // Create network with custom buffer sizes
        let config = BufferedConfig::new()
            .with_read_buffer_size(4096)
            .with_write_buffer_size(4096);

        let network = BufferedNetwork::from(config);

        // Bind to a random port
        let listener = network.bind("127.0.0.1:0".parse().unwrap()).await;
        assert!(listener.is_ok());

        let mut listener = listener.unwrap();
        let addr = listener.local_addr().unwrap();

        // Test connection
        tokio::spawn(async move {
            let (mut sink, mut stream) = network
                .dial(addr)
                .await
                .expect("Failed to connect");

            // Send message
            sink.send(b"Hello, World!".to_vec())
                .await
                .expect("Failed to send");

            // Receive echo
            let msg = stream
                .recv(vec![0u8; 13])
                .await
                .expect("Failed to receive");

            assert_eq!(msg.as_ref(), b"Hello, World!");
        });

        // Accept connection and echo
        let (_, mut sink, mut stream) = listener
            .accept()
            .await
            .expect("Failed to accept");

        let msg = stream
            .recv(vec![0u8; 13])
            .await
            .expect("Failed to receive");

        sink.send(msg)
            .await
            .expect("Failed to send");
    }

    #[tokio::test]
    async fn test_buffered_stream_read_byte() {
        let config = BufferedConfig::default();
        let network = BufferedNetwork::from(config);

        // Setup connection
        let listener = network
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let addr = listener.local_addr().unwrap();

        // Test byte-by-byte reading (useful for varint)
        tokio::spawn(async move {
            let (mut sink, _) = network.dial(addr).await.unwrap();

            // Send bytes one at a time
            for i in 0u8..10 {
                sink.send(vec![i]).await.unwrap();
            }
        });

        let mut listener = listener;
        let (_, _, mut stream) = listener.accept().await.unwrap();

        // Read bytes one at a time
        for i in 0u8..10 {
            let byte = stream.read_byte().await.unwrap();
            assert_eq!(byte, i);
        }
    }
}