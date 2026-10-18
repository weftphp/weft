//! A blocking request/response client for length-prefixed protocols, for scripts and tools
//! that talk to a server without running an event loop.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::address::{SocketAddress, UnixName};
use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, Result};
use crate::protocol::framing::{Decoder, LengthPrefixed};

enum Transport {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Transport {
    fn io(&mut self) -> &mut dyn ReadWrite {
        match self {
            Transport::Tcp(s) => s,
            Transport::Unix(s) => s,
        }
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// See the [module documentation](self).
pub struct Stream {
    transport: Transport,
    codec: LengthPrefixed,
    buffer: ByteBuffer,
}

impl Stream {
    /// Connects to `addr`; every read and write gives up after `timeout`.
    pub fn connect(
        addr: &SocketAddress,
        codec: LengthPrefixed,
        timeout: Duration,
    ) -> Result<Stream> {
        codec.validate()?;
        let transport = match addr {
            SocketAddress::Inet(inet) => {
                let s = TcpStream::connect_timeout(inet, timeout)?;
                s.set_nodelay(true)?;
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))?;
                Transport::Tcp(s)
            }
            SocketAddress::Unix(UnixName::Path(path)) => {
                let s = UnixStream::connect(path)?;
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))?;
                Transport::Unix(s)
            }
            SocketAddress::Unix(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidArgument,
                    "only path-based Unix sockets are supported",
                ));
            }
        };
        Ok(Stream {
            transport,
            codec,
            buffer: ByteBuffer::new(),
        })
    }

    /// Sends one framed message.
    pub fn send(&mut self, body: &[u8]) -> Result<()> {
        let frame = self.codec.encode(body)?;
        self.transport.io().write_all(&frame)?;
        Ok(())
    }

    /// Receives one framed message.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let mut chunk = [0u8; 16 * 1024];
        loop {
            if let Some(message) = self.codec.decode(&mut self.buffer)? {
                return Ok(message);
            }
            let n = self.transport.io().read(&mut chunk)?;
            if n == 0 {
                return Err(Error::new(ErrorKind::Closed, "server closed the stream"));
            }
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }

    /// Sends `body` and waits for the reply.
    pub fn request(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        self.send(body)?;
        self.recv()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::framing::Width;
    use std::net::TcpListener;

    #[test]
    fn request_reply_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = SocketAddress::from(listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut codec = LengthPrefixed::simple(Width::U32, 1024);
            let mut buf = ByteBuffer::new();
            let mut chunk = [0u8; 64];
            for _ in 0..2 {
                let msg = loop {
                    if let Some(m) = codec.decode(&mut buf).unwrap() {
                        break m;
                    }
                    let n = s.read(&mut chunk).unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                };
                let mut reply = msg;
                reply.reverse();
                s.write_all(&codec.encode(&reply).unwrap()).unwrap();
            }
        });
        let mut stream = Stream::connect(
            &addr,
            LengthPrefixed::simple(Width::U32, 1024),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(stream.request(b"abc").unwrap(), b"cba");
        assert_eq!(stream.request(b"").unwrap(), b"");
        server.join().unwrap();
        assert_eq!(stream.recv().unwrap_err().kind(), ErrorKind::Closed);
    }
}
