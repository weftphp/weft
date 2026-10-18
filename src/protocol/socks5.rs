//! The client side of SOCKS version 5 (RFC 1928) with username/password authentication
//! (RFC 1929), as a sans-I/O state machine.
//!
//! Send [`Handshake::start`]'s bytes, then feed every reply chunk to [`Handshake::receive`],
//! sending whatever it returns, until it reports [`Progress::Ready`]. After that the
//! connection carries the proxied stream.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, Result};

const VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const METHOD_NONE: u8 = 0x00;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_REFUSED: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// Where the proxy should connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    /// A host name the proxy resolves (at most 255 bytes).
    Domain(String, u16),
}

/// Proxy credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Greeting,
    Auth,
    Connect,
    Done,
}

/// What to do after feeding a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// Need more bytes from the proxy.
    Wait,
    /// Send these bytes, then wait for the next reply.
    Send(Vec<u8>),
    /// The tunnel is open. Holds the address the proxy bound for it.
    Ready(Target),
}

/// The handshake state machine. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct Handshake {
    target: Target,
    credentials: Option<Credentials>,
    stage: Stage,
}

fn fail(msg: impl Into<String>) -> Error {
    Error::new(ErrorKind::Protocol, format!("SOCKS5: {}", msg.into()))
}

/// The meaning of a CONNECT reply code (RFC 1928 §6).
fn reply_text(code: u8) -> &'static str {
    match code {
        0x01 => "general server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown failure",
    }
}

impl Handshake {
    pub fn new(target: Target, credentials: Option<Credentials>) -> Result<Handshake> {
        if let Target::Domain(host, _) = &target
            && (host.is_empty() || host.len() > 255)
        {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "SOCKS5 host names must be 1-255 bytes",
            ));
        }
        if let Some(c) = &credentials
            && (c.username.is_empty() || c.username.len() > 255 || c.password.len() > 255)
        {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "SOCKS5 user names must be 1-255 bytes and passwords at most 255",
            ));
        }
        Ok(Handshake {
            target,
            credentials,
            stage: Stage::Greeting,
        })
    }

    /// The greeting listing the authentication methods we accept.
    pub fn start(&self) -> Vec<u8> {
        if self.credentials.is_some() {
            vec![VERSION, 2, METHOD_NONE, METHOD_PASSWORD]
        } else {
            vec![VERSION, 1, METHOD_NONE]
        }
    }

    fn connect_request(&self) -> Vec<u8> {
        let mut out = vec![VERSION, CMD_CONNECT, 0];
        encode_target(&self.target, &mut out);
        out
    }

    /// Consumes as much of the proxy's reply as the current stage needs.
    pub fn receive(&mut self, buf: &mut ByteBuffer) -> Result<Progress> {
        let data = buf.as_slice();
        match self.stage {
            Stage::Greeting => {
                if data.len() < 2 {
                    return Ok(Progress::Wait);
                }
                let (version, method) = (data[0], data[1]);
                buf.consume(2);
                if version != VERSION {
                    return Err(fail(format!("proxy speaks version {version}")));
                }
                match (method, &self.credentials) {
                    (METHOD_NONE, _) => {
                        self.stage = Stage::Connect;
                        Ok(Progress::Send(self.connect_request()))
                    }
                    (METHOD_PASSWORD, Some(c)) => {
                        self.stage = Stage::Auth;
                        let mut out = vec![AUTH_VERSION, c.username.len() as u8];
                        out.extend_from_slice(c.username.as_bytes());
                        out.push(c.password.len() as u8);
                        out.extend_from_slice(c.password.as_bytes());
                        Ok(Progress::Send(out))
                    }
                    (METHOD_REFUSED, _) => Err(fail("no acceptable authentication method")),
                    (other, _) => Err(fail(format!("proxy chose unoffered method {other}"))),
                }
            }
            Stage::Auth => {
                if data.len() < 2 {
                    return Ok(Progress::Wait);
                }
                let status = data[1];
                buf.consume(2);
                if status != 0 {
                    return Err(fail("authentication rejected"));
                }
                self.stage = Stage::Connect;
                Ok(Progress::Send(self.connect_request()))
            }
            Stage::Connect => {
                if data.len() < 5 {
                    return Ok(Progress::Wait);
                }
                if data[0] != VERSION {
                    return Err(fail("bad reply version"));
                }
                if data[1] != 0 {
                    return Err(fail(reply_text(data[1])));
                }
                let Some((bound, used)) = decode_target(&data[3..])? else {
                    return Ok(Progress::Wait);
                };
                buf.consume(3 + used);
                self.stage = Stage::Done;
                Ok(Progress::Ready(bound))
            }
            Stage::Done => Err(Error::new(ErrorKind::InvalidState, "handshake finished")),
        }
    }
}

fn encode_target(target: &Target, out: &mut Vec<u8>) {
    match target {
        Target::Ip(SocketAddr::V4(a)) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Domain(host, port) => {
            out.push(ATYP_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

/// Decodes `ATYP ADDR PORT`; `None` if incomplete. Returns the bytes used.
fn decode_target(data: &[u8]) -> Result<Option<(Target, usize)>> {
    let Some(&atyp) = data.first() else {
        return Ok(None);
    };
    let (addr_len, skip) = match atyp {
        ATYP_V4 => (4, 1),
        ATYP_V6 => (16, 1),
        ATYP_DOMAIN => match data.get(1) {
            Some(&n) => (n as usize, 2),
            None => return Ok(None),
        },
        other => return Err(fail(format!("unknown address type {other}"))),
    };
    let end = skip + addr_len + 2;
    let Some(field) = data.get(skip..end) else {
        return Ok(None);
    };
    let (addr, port) = field.split_at(addr_len);
    let port = u16::from_be_bytes([port[0], port[1]]);
    let target = match atyp {
        ATYP_V4 => Target::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
            port,
        )),
        ATYP_V6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(addr);
            Target::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Target::Domain(String::from_utf8_lossy(addr).into_owned(), port),
    };
    Ok(Some((target, end)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_flow_with_domain_target() {
        let creds = Credentials {
            username: "u".into(),
            password: "pw".into(),
        };
        let mut hs =
            Handshake::new(Target::Domain("example.test".into(), 443), Some(creds)).unwrap();
        assert_eq!(hs.start(), [5, 2, 0, 2]);

        let mut buf = ByteBuffer::from(&[5u8][..]);
        assert_eq!(hs.receive(&mut buf).unwrap(), Progress::Wait);
        buf.extend_from_slice(&[2]);
        assert_eq!(
            hs.receive(&mut buf).unwrap(),
            Progress::Send(vec![1, 1, b'u', 2, b'p', b'w'])
        );

        buf.extend_from_slice(&[1, 0]);
        let Progress::Send(connect) = hs.receive(&mut buf).unwrap() else {
            panic!("expected CONNECT")
        };
        let mut expected = vec![5, 1, 0, 3, 12];
        expected.extend_from_slice(b"example.test");
        expected.extend_from_slice(&[1, 187]);
        assert_eq!(connect, expected);

        buf.extend_from_slice(&[5, 0, 0, 1, 10, 0, 0, 1]);
        assert_eq!(hs.receive(&mut buf).unwrap(), Progress::Wait);
        buf.extend_from_slice(&[0x1F, 0x90, 0xAA]);
        assert_eq!(
            hs.receive(&mut buf).unwrap(),
            Progress::Ready(Target::Ip("10.0.0.1:8080".parse().unwrap()))
        );
        assert_eq!(buf.as_slice(), [0xAA], "tunnel data is left in place");
    }

    #[test]
    fn failures() {
        let target = Target::Ip("[::1]:80".parse().unwrap());
        let mut hs = Handshake::new(target.clone(), None).unwrap();
        assert!(hs.receive(&mut ByteBuffer::from(&[5u8, 0xFF][..])).is_err());

        let mut hs = Handshake::new(target.clone(), None).unwrap();
        hs.receive(&mut ByteBuffer::from(&[5u8, 0][..])).unwrap();
        let err = hs
            .receive(&mut ByteBuffer::from(&[5u8, 5, 0, 1, 0, 0, 0, 0, 0, 0][..]))
            .unwrap_err();
        assert!(err.to_string().contains("connection refused"));

        let mut hs = Handshake::new(target, None).unwrap();
        assert!(
            hs.receive(&mut ByteBuffer::from(&[5u8, 2][..])).is_err(),
            "unoffered"
        );
        assert!(Handshake::new(Target::Domain(String::new(), 1), None).is_err());
    }
}
