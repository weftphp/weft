//! Socket addresses: IP (v4/v6) and Unix-domain, with conversion to and from the kernel's
//! `sockaddr` representation.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::core::{Error, ErrorKind, Result};

/// The name of a Unix-domain socket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UnixName {
    /// A filesystem path.
    Path(PathBuf),
    /// A Linux abstract-namespace name (no filesystem entry), given without the leading NUL.
    Abstract(Vec<u8>),
    /// An unbound socket (for example, the client end of a connection).
    Unnamed,
}

/// Any address weft can bind or connect to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SocketAddress {
    Inet(SocketAddr),
    Unix(UnixName),
}

/// Address family of a [`SocketAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
    Unix,
}

impl Family {
    pub(crate) fn raw(self) -> libc::c_int {
        match self {
            Family::V4 => libc::AF_INET,
            Family::V6 => libc::AF_INET6,
            Family::Unix => libc::AF_UNIX,
        }
    }
}

/// Room for the longest `sun_path` on any supported OS.
fn sun_path_capacity() -> usize {
    // SAFETY: sockaddr_un is plain old data.
    let addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_path.len()
}

fn sun_path_offset() -> usize {
    mem::offset_of!(libc::sockaddr_un, sun_path)
}

impl SocketAddress {
    /// A Unix-domain socket at `path`.
    pub fn unix(path: impl Into<PathBuf>) -> SocketAddress {
        SocketAddress::Unix(UnixName::Path(path.into()))
    }

    pub fn family(&self) -> Family {
        match self {
            SocketAddress::Inet(SocketAddr::V4(_)) => Family::V4,
            SocketAddress::Inet(SocketAddr::V6(_)) => Family::V6,
            SocketAddress::Unix(_) => Family::Unix,
        }
    }

    /// The IP socket address, if this is one.
    pub fn as_inet(&self) -> Option<SocketAddr> {
        match self {
            SocketAddress::Inet(addr) => Some(*addr),
            SocketAddress::Unix(_) => None,
        }
    }

    /// The filesystem path, if this is a path-based Unix socket.
    pub fn as_path(&self) -> Option<&Path> {
        match self {
            SocketAddress::Unix(UnixName::Path(path)) => Some(path),
            _ => None,
        }
    }

    /// Encodes the address for a syscall.
    pub(crate) fn to_raw(&self) -> Result<(libc::sockaddr_storage, libc::socklen_t)> {
        // SAFETY: sockaddr_storage is plain old data, valid when zeroed.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let len = match self {
            SocketAddress::Inet(SocketAddr::V4(v4)) => {
                // SAFETY: sockaddr_storage is larger than and aligned for sockaddr_in.
                let sin = unsafe { &mut *(&raw mut storage).cast::<libc::sockaddr_in>() };
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                sin.sin_port = v4.port().to_be();
                sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                set_len(sin, mem::size_of::<libc::sockaddr_in>());
                mem::size_of::<libc::sockaddr_in>()
            }
            SocketAddress::Inet(SocketAddr::V6(v6)) => {
                // SAFETY: sockaddr_storage is larger than and aligned for sockaddr_in6.
                let sin6 = unsafe { &mut *(&raw mut storage).cast::<libc::sockaddr_in6>() };
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = v6.port().to_be();
                sin6.sin6_addr.s6_addr = v6.ip().octets();
                sin6.sin6_flowinfo = v6.flowinfo().to_be();
                sin6.sin6_scope_id = v6.scope_id();
                set_len(sin6, mem::size_of::<libc::sockaddr_in6>());
                mem::size_of::<libc::sockaddr_in6>()
            }
            SocketAddress::Unix(name) => {
                // SAFETY: sockaddr_storage is larger than and aligned for sockaddr_un.
                let sun = unsafe { &mut *(&raw mut storage).cast::<libc::sockaddr_un>() };
                sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
                let used = match name {
                    UnixName::Unnamed => 0,
                    UnixName::Path(path) => {
                        let bytes = path.as_os_str().as_bytes();
                        // Room for the terminating NUL is required.
                        if bytes.len() >= sun_path_capacity() || bytes.contains(&0) {
                            return Err(Error::new(
                                ErrorKind::InvalidArgument,
                                format!("unusable Unix socket path {}", path.display()),
                            ));
                        }
                        copy_path(&mut sun.sun_path, bytes, 0);
                        bytes.len() + 1
                    }
                    UnixName::Abstract(name) => {
                        if name.len() + 1 > sun_path_capacity() {
                            return Err(Error::new(
                                ErrorKind::InvalidArgument,
                                "abstract socket name too long",
                            ));
                        }
                        copy_path(&mut sun.sun_path, name, 1);
                        name.len() + 1
                    }
                };
                let len = sun_path_offset() + used;
                set_len(sun, len);
                len
            }
        };
        Ok((storage, len as libc::socklen_t))
    }

    /// Decodes an address filled in by the kernel.
    pub(crate) fn from_raw(
        storage: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> io::Result<SocketAddress> {
        let len = len as usize;
        match storage.ss_family as libc::c_int {
            libc::AF_INET if len >= mem::size_of::<libc::sockaddr_in>() => {
                // SAFETY: the family and length say the storage holds a sockaddr_in.
                let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                Ok(SocketAddress::Inet(SocketAddr::V4(SocketAddrV4::new(
                    ip,
                    u16::from_be(sin.sin_port),
                ))))
            }
            libc::AF_INET6 if len >= mem::size_of::<libc::sockaddr_in6>() => {
                // SAFETY: the family and length say the storage holds a sockaddr_in6.
                let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
                Ok(SocketAddress::Inet(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                    u16::from_be(sin6.sin6_port),
                    u32::from_be(sin6.sin6_flowinfo),
                    sin6.sin6_scope_id,
                ))))
            }
            libc::AF_UNIX => {
                // SAFETY: the family says the storage holds a sockaddr_un, and storage is
                // large enough for one regardless of `len`.
                let sun = unsafe { &*(storage as *const _ as *const libc::sockaddr_un) };
                let used = len
                    .saturating_sub(sun_path_offset())
                    .min(sun.sun_path.len());
                let path: Vec<u8> = sun.sun_path[..used]
                    .iter()
                    .map(|c| c.to_ne_bytes()[0])
                    .collect();
                let name = match path.split_first() {
                    None => UnixName::Unnamed,
                    Some((0, rest)) if cfg!(any(target_os = "linux", target_os = "android")) => {
                        UnixName::Abstract(rest.to_vec())
                    }
                    Some(_) => {
                        let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
                        if end == 0 {
                            UnixName::Unnamed
                        } else {
                            UnixName::Path(PathBuf::from(OsStr::from_bytes(&path[..end])))
                        }
                    }
                };
                Ok(SocketAddress::Unix(name))
            }
            family => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported address family {family}"),
            )),
        }
    }
}

fn copy_path(dest: &mut [libc::c_char], bytes: &[u8], start: usize) {
    for (slot, &b) in dest[start..].iter_mut().zip(bytes) {
        *slot = b as libc::c_char;
    }
}

/// BSD-derived systems store the structure length in its first byte.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn set_len<T: HasLen>(addr: &mut T, len: usize) {
    addr.set_len(len as u8);
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
fn set_len<T>(_addr: &mut T, _len: usize) {}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
trait HasLen {
    fn set_len(&mut self, len: u8);
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
mod bsd_len {
    impl super::HasLen for libc::sockaddr_in {
        fn set_len(&mut self, len: u8) {
            self.sin_len = len;
        }
    }
    impl super::HasLen for libc::sockaddr_in6 {
        fn set_len(&mut self, len: u8) {
            self.sin6_len = len;
        }
    }
    impl super::HasLen for libc::sockaddr_un {
        fn set_len(&mut self, len: u8) {
            self.sun_len = len;
        }
    }
}

impl From<SocketAddr> for SocketAddress {
    fn from(addr: SocketAddr) -> Self {
        SocketAddress::Inet(addr)
    }
}

impl From<(IpAddr, u16)> for SocketAddress {
    fn from(addr: (IpAddr, u16)) -> Self {
        SocketAddress::Inet(addr.into())
    }
}

impl FromStr for SocketAddress {
    type Err = Error;

    /// Parses `ip:port`, `[ipv6]:port`, `unix:/path` or an absolute path. Host names are not
    /// accepted here; resolve them with [`dns`](super::dns) first.
    fn from_str(s: &str) -> Result<Self> {
        if let Some(path) = s.strip_prefix("unix:") {
            let path = path.strip_prefix("//").unwrap_or(path);
            return Ok(SocketAddress::unix(path));
        }
        if s.starts_with('/') {
            return Ok(SocketAddress::unix(s));
        }
        s.parse::<SocketAddr>()
            .map(SocketAddress::Inet)
            .map_err(|_| Error::new(ErrorKind::InvalidArgument, format!("bad address {s:?}")))
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddress::Inet(addr) => addr.fmt(f),
            SocketAddress::Unix(UnixName::Path(path)) => write!(f, "unix:{}", path.display()),
            SocketAddress::Unix(UnixName::Abstract(name)) => {
                write!(f, "unix:@{}", String::from_utf8_lossy(name))
            }
            SocketAddress::Unix(UnixName::Unnamed) => f.write_str("unix:(unnamed)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(addr: SocketAddress) {
        let (raw, len) = addr.to_raw().unwrap();
        assert_eq!(SocketAddress::from_raw(&raw, len).unwrap(), addr);
    }

    #[test]
    fn raw_roundtrips() {
        roundtrip("127.0.0.1:8080".parse().unwrap());
        roundtrip("[::1]:443".parse().unwrap());
        roundtrip(SocketAddress::Inet(SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            9,
            7,
            3,
        ))));
        roundtrip(SocketAddress::unix("/tmp/weft.sock"));
        roundtrip(SocketAddress::Unix(UnixName::Unnamed));
        #[cfg(target_os = "linux")]
        roundtrip(SocketAddress::Unix(UnixName::Abstract(b"weft".to_vec())));
    }

    #[test]
    fn port_is_network_order() {
        let (raw, _) = SocketAddress::from("10.0.0.1:258".parse::<SocketAddr>().unwrap())
            .to_raw()
            .unwrap();
        // SAFETY: to_raw wrote a sockaddr_in.
        let sin = unsafe { &*(&raw const raw).cast::<libc::sockaddr_in>() };
        let port_bytes = sin.sin_port.to_ne_bytes();
        assert_eq!(port_bytes, [1, 2]);
        assert_eq!(sin.sin_addr.s_addr.to_ne_bytes(), [10, 0, 0, 1]);
    }

    #[test]
    fn parsing_and_display() {
        assert_eq!(
            "unix:/run/app.sock".parse::<SocketAddress>().unwrap(),
            SocketAddress::unix("/run/app.sock")
        );
        assert_eq!(
            "/run/app.sock"
                .parse::<SocketAddress>()
                .unwrap()
                .to_string(),
            "unix:/run/app.sock"
        );
        assert_eq!(
            "[::1]:80".parse::<SocketAddress>().unwrap().family(),
            Family::V6
        );
        assert!("example.com:80".parse::<SocketAddress>().is_err());
        let long = format!("/{}", "x".repeat(200));
        assert!(SocketAddress::unix(long).to_raw().is_err());
    }
}
