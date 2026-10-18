//! Host-name resolution.
//!
//! [`Resolver`] answers from the hosts file first, then asks the configured name servers
//! directly with the DNS wire protocol (RFC 1035): UDP first, TCP when the answer is
//! truncated. The message encoding is exposed ([`encode_query`], [`decode_response`]) so an
//! event loop or coroutine can drive queries without blocking.
//!
//! [`lookup_system`] instead defers to the C library (`getaddrinfo`), which honours every
//! system-specific source (NSS, mDNS, ...) but blocks the calling thread.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::core::{Error, ErrorKind, Result, random};

/// The DNS port.
pub const PORT: u16 = 53;

/// Resolves `host` with the C library resolver. Blocks.
pub fn lookup_system(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

// ----- wire format -----

/// Address record types weft queries for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// IPv4 address.
    A,
    /// IPv6 address.
    Aaaa,
}

impl RecordType {
    fn code(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Aaaa => 28,
        }
    }
}

const TYPE_CNAME: u16 = 5;
const CLASS_IN: u16 = 1;
const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_TRUNCATED: u16 = 0x0200;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const HEADER_LEN: usize = 12;
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Response codes (RFC 1035 §4.1.1).
pub mod rcode {
    pub const NO_ERROR: u8 = 0;
    pub const FORMAT_ERROR: u8 = 1;
    pub const SERVER_FAILURE: u8 = 2;
    pub const NAME_ERROR: u8 = 3;
    pub const NOT_IMPLEMENTED: u8 = 4;
    pub const REFUSED: u8 = 5;
}

fn malformed(what: &str) -> Error {
    Error::new(
        ErrorKind::Protocol,
        format!("malformed DNS message: {what}"),
    )
}

/// Builds a recursive query for `name`.
pub fn encode_query(id: u16, name: &str, kind: RecordType) -> Result<Vec<u8>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(Error::new(
            ErrorKind::InvalidArgument,
            format!("bad host name {name:?}"),
        ));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    for field in [id, FLAG_RECURSION_DESIRED, 1, 0, 0, 0] {
        out.extend_from_slice(&field.to_be_bytes());
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                format!("bad label in host name {name:?}"),
            ));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&kind.code().to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// What a name server answered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    pub id: u16,
    pub rcode: u8,
    /// The answer did not fit in a UDP datagram; retry over TCP.
    pub truncated: bool,
    /// A and AAAA records in the answer section, in order.
    pub addresses: Vec<IpAddr>,
    /// The last CNAME target seen, if the name was an alias.
    pub canonical_name: Option<String>,
    /// Smallest TTL among the address records.
    pub ttl: Option<Duration>,
}

struct Reader<'a> {
    msg: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let bytes = self
            .msg
            .get(self.pos..self.pos + n)
            .ok_or_else(|| malformed("truncated"))?;
        self.pos += n;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a possibly compressed name starting at the cursor.
    fn name(&mut self) -> Result<String> {
        let mut name = String::new();
        let mut pos = self.pos;
        // Where the cursor resumes: right after the first pointer, if any.
        let mut resume = None;
        // Each pointer must go strictly backwards, which rules out loops.
        let mut limit = pos;
        loop {
            let len = *self.msg.get(pos).ok_or_else(|| malformed("name"))? as usize;
            match len & 0xC0 {
                0x00 if len == 0 => {
                    self.pos = resume.unwrap_or(pos + 1);
                    return Ok(name);
                }
                0x00 => {
                    let label = self
                        .msg
                        .get(pos + 1..pos + 1 + len)
                        .ok_or_else(|| malformed("label"))?;
                    if !name.is_empty() {
                        name.push('.');
                    }
                    name.push_str(&String::from_utf8_lossy(label));
                    if name.len() > MAX_NAME_LEN {
                        return Err(malformed("name too long"));
                    }
                    pos += 1 + len;
                }
                0xC0 => {
                    let low = *self.msg.get(pos + 1).ok_or_else(|| malformed("pointer"))?;
                    let target = (len & 0x3F) << 8 | low as usize;
                    if target >= limit {
                        return Err(malformed("forward or looping pointer"));
                    }
                    resume.get_or_insert(pos + 2);
                    limit = target;
                    pos = target;
                }
                _ => return Err(malformed("reserved label type")),
            }
        }
    }
}

/// Parses a response message.
pub fn decode_response(msg: &[u8]) -> Result<Response> {
    let mut r = Reader { msg, pos: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    if flags & FLAG_RESPONSE == 0 {
        return Err(malformed("not a response"));
    }
    let questions = r.u16()?;
    let answers = r.u16()?;
    r.u16()?; // authority records: unused
    r.u16()?; // additional records: unused

    let mut response = Response {
        id,
        rcode: (flags & 0x000F) as u8,
        truncated: flags & FLAG_TRUNCATED != 0,
        ..Response::default()
    };
    for _ in 0..questions {
        r.name()?;
        r.take(4)?;
    }
    for _ in 0..answers {
        r.name()?;
        let kind = r.u16()?;
        let class = r.u16()?;
        let ttl = Duration::from_secs(u64::from(r.u32()?));
        let len = r.u16()? as usize;
        let data_start = r.pos;
        let data = r.take(len)?;
        if class != CLASS_IN {
            continue;
        }
        let address = match (kind, len) {
            (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            (TYPE_CNAME, _) => {
                let mut inner = Reader {
                    msg,
                    pos: data_start,
                };
                response.canonical_name = Some(inner.name()?);
                None
            }
            _ => None,
        };
        if let Some(address) = address {
            response.addresses.push(address);
            response.ttl = Some(response.ttl.map_or(ttl, |t| t.min(ttl)));
        }
    }
    Ok(response)
}

// ----- system configuration -----

/// Static name-to-address mappings in `/etc/hosts` format.
#[derive(Debug, Clone, Default)]
pub struct Hosts {
    entries: HashMap<String, Vec<IpAddr>>,
}

impl Hosts {
    /// Parses hosts-file text. Malformed lines are skipped.
    pub fn parse(text: &str) -> Hosts {
        let mut entries: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut fields = line.split_whitespace();
            let Some(Ok(ip)) = fields.next().map(str::parse::<IpAddr>) else {
                continue;
            };
            for name in fields {
                let list = entries.entry(name.to_ascii_lowercase()).or_default();
                if !list.contains(&ip) {
                    list.push(ip);
                }
            }
        }
        Hosts { entries }
    }

    /// Loads a hosts file; a missing file yields an empty table.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Hosts> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Hosts::parse(&text)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Hosts::default()),
            Err(err) => Err(err),
        }
    }

    /// Addresses for `name` (case-insensitive).
    pub fn lookup(&self, name: &str) -> &[IpAddr] {
        let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
        self.entries.get(&name).map_or(&[], Vec::as_slice)
    }

    pub fn insert(&mut self, name: &str, ip: IpAddr) {
        self.entries
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(ip);
    }
}

/// Resolver settings in `/etc/resolv.conf` format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvConf {
    pub nameservers: Vec<SocketAddr>,
    pub search: Vec<String>,
    /// Names with fewer dots than this are tried with search suffixes first.
    pub ndots: usize,
    /// Wait per query attempt.
    pub timeout: Duration,
    /// Passes over the server list.
    pub attempts: usize,
}

impl Default for ResolvConf {
    fn default() -> Self {
        ResolvConf {
            nameservers: Vec::new(),
            search: Vec::new(),
            ndots: 1,
            timeout: Duration::from_secs(5),
            attempts: 2,
        }
    }
}

impl ResolvConf {
    /// Parses resolv.conf text. With no `nameserver` line, the local host is assumed.
    pub fn parse(text: &str) -> ResolvConf {
        let mut conf = ResolvConf::default();
        for line in text.lines() {
            let line = line.split(['#', ';']).next().unwrap_or("");
            let mut fields = line.split_whitespace();
            match fields.next() {
                Some("nameserver") => {
                    if let Some(Ok(ip)) = fields.next().map(str::parse::<IpAddr>) {
                        conf.nameservers.push(SocketAddr::new(ip, PORT));
                    }
                }
                Some("search") | Some("domain") => {
                    conf.search = fields.map(str::to_owned).collect();
                }
                Some("options") => {
                    for option in fields {
                        let (key, value) = option.split_once(':').unwrap_or((option, ""));
                        let value = value.parse::<u64>().ok();
                        match (key, value) {
                            ("ndots", Some(v)) => conf.ndots = v.min(15) as usize,
                            ("timeout", Some(v)) => {
                                conf.timeout = Duration::from_secs(v.clamp(1, 30))
                            }
                            ("attempts", Some(v)) => conf.attempts = v.clamp(1, 5) as usize,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        if conf.nameservers.is_empty() {
            conf.nameservers
                .push(SocketAddr::from(([127, 0, 0, 1], PORT)));
        }
        conf
    }

    pub fn load(path: impl AsRef<Path>) -> io::Result<ResolvConf> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(ResolvConf::parse(&text)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(ResolvConf::parse("")),
            Err(err) => Err(err),
        }
    }

    /// The names to try for `name`, in order, applying search domains and `ndots`.
    pub fn candidates(&self, name: &str) -> Vec<String> {
        if let Some(absolute) = name.strip_suffix('.') {
            return vec![absolute.to_owned()];
        }
        let suffixed = self.search.iter().map(|domain| format!("{name}.{domain}"));
        if name.matches('.').count() >= self.ndots {
            std::iter::once(name.to_owned()).chain(suffixed).collect()
        } else {
            suffixed.chain(std::iter::once(name.to_owned())).collect()
        }
    }
}

// ----- resolver -----

/// Which address families a lookup wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Want {
    V4,
    V6,
    /// IPv4 then IPv6.
    #[default]
    Any,
}

impl Want {
    fn record_types(self) -> &'static [RecordType] {
        match self {
            Want::V4 => &[RecordType::A],
            Want::V6 => &[RecordType::Aaaa],
            Want::Any => &[RecordType::A, RecordType::Aaaa],
        }
    }

    fn accepts(self, ip: &IpAddr) -> bool {
        match self {
            Want::V4 => ip.is_ipv4(),
            Want::V6 => ip.is_ipv6(),
            Want::Any => true,
        }
    }
}

/// A blocking stub resolver. See the [module documentation](self).
#[derive(Debug, Clone, Default)]
pub struct Resolver {
    pub hosts: Hosts,
    pub config: ResolvConf,
}

impl Resolver {
    /// Uses `/etc/hosts` and `/etc/resolv.conf`.
    pub fn from_system() -> io::Result<Resolver> {
        Ok(Resolver {
            hosts: Hosts::load("/etc/hosts")?,
            config: ResolvConf::load("/etc/resolv.conf")?,
        })
    }

    pub fn new(hosts: Hosts, config: ResolvConf) -> Resolver {
        Resolver { hosts, config }
    }

    /// Resolves `name`. Fails with [`ErrorKind::NotFound`] if no server knows it.
    pub fn lookup(&self, name: &str, want: Want) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let local: Vec<IpAddr> = self
            .hosts
            .lookup(name)
            .iter()
            .copied()
            .filter(|ip| want.accepts(ip))
            .collect();
        if !local.is_empty() {
            return Ok(local);
        }

        let mut last_error = Error::new(ErrorKind::NotFound, format!("no address for {name}"));
        for candidate in self.config.candidates(name) {
            let mut found = Vec::new();
            for &kind in want.record_types() {
                match self.query(&candidate, kind) {
                    Ok(response) => found.extend(response.addresses),
                    Err(err) => last_error = err,
                }
            }
            if !found.is_empty() {
                return Ok(found);
            }
        }
        Err(last_error)
    }

    /// Sends one question to the configured servers until one answers.
    pub fn query(&self, name: &str, kind: RecordType) -> Result<Response> {
        let mut last_error = Error::new(ErrorKind::NotFound, "no name servers configured");
        for _ in 0..self.config.attempts.max(1) {
            for &server in &self.config.nameservers {
                match self.ask(server, name, kind) {
                    Ok(response) if response.rcode == rcode::NO_ERROR => return Ok(response),
                    Ok(response) if response.rcode == rcode::NAME_ERROR => {
                        return Err(Error::new(
                            ErrorKind::NotFound,
                            format!("{name} does not exist"),
                        ));
                    }
                    Ok(response) => {
                        last_error = Error::new(
                            ErrorKind::Protocol,
                            format!("server {server} answered with rcode {}", response.rcode),
                        );
                    }
                    Err(err) => last_error = err,
                }
            }
        }
        Err(last_error)
    }

    fn ask(&self, server: SocketAddr, name: &str, kind: RecordType) -> Result<Response> {
        let id = random::u64()? as u16;
        let query = encode_query(id, name, kind)?;
        let response = self.ask_udp(server, id, &query)?;
        if response.truncated {
            return self.ask_tcp(server, id, &query);
        }
        Ok(response)
    }

    fn ask_udp(&self, server: SocketAddr, id: u16, query: &[u8]) -> Result<Response> {
        let local: SocketAddr = match server {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(local)?;
        socket.connect(server)?;
        socket.send(query)?;
        let deadline = Instant::now() + self.config.timeout;
        let mut buf = [0u8; 1232];
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| {
                    Error::new(ErrorKind::TimedOut, format!("no reply from {server}"))
                })?;
            socket.set_read_timeout(Some(left))?;
            let n = match socket.recv(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            // Ignore stray or spoofed datagrams that do not match our query.
            match decode_response(&buf[..n]) {
                Ok(response) if response.id == id => return Ok(response),
                _ => continue,
            }
        }
    }

    fn ask_tcp(&self, server: SocketAddr, id: u16, query: &[u8]) -> Result<Response> {
        let mut stream = TcpStream::connect_timeout(&server, self.config.timeout)?;
        stream.set_read_timeout(Some(self.config.timeout))?;
        stream.set_write_timeout(Some(self.config.timeout))?;
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(query);
        stream.write_all(&framed)?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len)?;
        let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut msg)?;
        let response = decode_response(&msg)?;
        if response.id != id {
            return Err(malformed("reply id does not match the query"));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn query_layout() {
        let q = encode_query(0xBEEF, "www.example.org.", RecordType::Aaaa).unwrap();
        let mut expected = vec![0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        expected.extend_from_slice(b"\x03www\x07example\x03org\x00");
        expected.extend_from_slice(&[0, 28, 0, 1]);
        assert_eq!(q, expected);
        assert!(encode_query(1, "a..b", RecordType::A).is_err());
        assert!(encode_query(1, &"x".repeat(64), RecordType::A).is_err());
    }

    /// Builds a reply to `query` with a CNAME (using a compression pointer to the question)
    /// followed by the given address records.
    fn reply(query: &[u8], flags: u16, rcode: u8, addresses: &[IpAddr]) -> Vec<u8> {
        let mut msg = query[..2].to_vec();
        msg.extend_from_slice(&(FLAG_RESPONSE | flags | u16::from(rcode)).to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&(addresses.len() as u16 + 1).to_be_bytes());
        msg.extend_from_slice(&[0, 0, 0, 0]);
        msg.extend_from_slice(&query[HEADER_LEN..]);
        // CNAME: owner = pointer to the question name (offset 12), target "real" + pointer.
        msg.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60]);
        let target_at = msg.len() + 2;
        msg.extend_from_slice(&7u16.to_be_bytes());
        msg.extend_from_slice(b"\x04real\xC0\x0C");
        for (i, ip) in addresses.iter().enumerate() {
            msg.extend_from_slice(&[0xC0, target_at as u8]);
            let (kind, data): (u16, Vec<u8>) = match ip {
                IpAddr::V4(v4) => (1, v4.octets().to_vec()),
                IpAddr::V6(v6) => (28, v6.octets().to_vec()),
            };
            msg.extend_from_slice(&kind.to_be_bytes());
            msg.extend_from_slice(&CLASS_IN.to_be_bytes());
            msg.extend_from_slice(&(300 - i as u32 * 100).to_be_bytes());
            msg.extend_from_slice(&(data.len() as u16).to_be_bytes());
            msg.extend_from_slice(&data);
        }
        msg
    }

    #[test]
    fn decodes_compressed_answers() {
        let query = encode_query(7, "alias.test", RecordType::A).unwrap();
        let ips: [IpAddr; 2] = ["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
        let response = decode_response(&reply(&query, 0, 0, &ips)).unwrap();
        assert_eq!(response.id, 7);
        assert_eq!(response.addresses, ips);
        assert_eq!(response.canonical_name.as_deref(), Some("real.alias.test"));
        assert_eq!(response.ttl, Some(Duration::from_secs(200)));
    }

    #[test]
    fn rejects_hostile_messages() {
        assert!(decode_response(&[0; 5]).is_err());
        let query = encode_query(1, "a.test", RecordType::A).unwrap();
        assert!(
            decode_response(&query).is_err(),
            "a query is not a response"
        );
        let mut looping = reply(&query, 0, 0, &[]);
        // Point the CNAME owner at itself.
        let owner = HEADER_LEN + (query.len() - HEADER_LEN);
        looping[owner + 1] = owner as u8;
        assert!(decode_response(&looping).is_err());
    }

    #[test]
    fn hosts_and_resolv_conf() {
        let hosts = Hosts::parse(
            "127.0.0.1 localhost loopback # comment\n::1 localhost\nbogus line\n10.0.0.5 Db.Internal",
        );
        assert_eq!(hosts.lookup("LOCALHOST").len(), 2);
        assert_eq!(
            hosts.lookup("db.internal."),
            ["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
        assert!(hosts.lookup("missing").is_empty());

        let conf = ResolvConf::parse(
            "nameserver 10.0.0.53\nnameserver ::1\nsearch corp.test lab.test\noptions ndots:2 timeout:1 attempts:3 rotate\n",
        );
        assert_eq!(conf.nameservers.len(), 2);
        assert_eq!(conf.timeout, Duration::from_secs(1));
        assert_eq!(conf.attempts, 3);
        assert_eq!(conf.candidates("db"), ["db.corp.test", "db.lab.test", "db"]);
        assert_eq!(conf.candidates("a.b.c")[0], "a.b.c");
        assert_eq!(conf.candidates("abs.")[..], ["abs"]);
        assert_eq!(ResolvConf::parse("").nameservers.len(), 1);
    }

    /// A fake name server: UDP replies are truncated for "big.test", which is then served
    /// over TCP; "gone.test" gets NXDOMAIN.
    fn fake_server() -> SocketAddr {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(addr).unwrap();
        let answer = |query: &[u8]| -> (Vec<u8>, bool) {
            let name = String::from_utf8_lossy(&query[HEADER_LEN..]).into_owned();
            let ip: IpAddr = if query[query.len() - 3] == 28 {
                "2001:db8::1".parse().unwrap()
            } else {
                "192.0.2.10".parse().unwrap()
            };
            if name.contains("gone") {
                (reply(query, 0, rcode::NAME_ERROR, &[]), false)
            } else {
                (reply(query, 0, 0, &[ip]), name.contains("big"))
            }
        };
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = udp.recv_from(&mut buf) {
                let (msg, truncate) = answer(&buf[..n]);
                let msg = if truncate {
                    reply(&buf[..n], FLAG_TRUNCATED, 0, &[])
                } else {
                    msg
                };
                udp.send_to(&msg, peer).unwrap();
            }
        });
        thread::spawn(move || {
            for mut stream in tcp.incoming().flatten() {
                let mut len = [0u8; 2];
                stream.read_exact(&mut len).unwrap();
                let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
                stream.read_exact(&mut query).unwrap();
                let (msg, _) = answer(&query);
                stream.write_all(&(msg.len() as u16).to_be_bytes()).unwrap();
                stream.write_all(&msg).unwrap();
            }
        });
        addr
    }

    #[test]
    fn resolves_over_udp_and_tcp() {
        let mut config = ResolvConf::parse("");
        config.nameservers = vec![fake_server()];
        config.timeout = Duration::from_secs(2);
        let mut resolver = Resolver::new(Hosts::default(), config);
        resolver
            .hosts
            .insert("pinned.test", "10.1.1.1".parse().unwrap());

        let found = resolver.lookup("small.test", Want::Any).unwrap();
        assert_eq!(
            found,
            [
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
        let big = resolver.lookup("big.test", Want::V4).unwrap();
        assert_eq!(big, ["192.0.2.10".parse::<IpAddr>().unwrap()]);
        let err = resolver.lookup("gone.test", Want::V4).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert_eq!(
            resolver.lookup("pinned.test", Want::Any).unwrap(),
            ["10.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            resolver.lookup("192.0.2.99", Want::Any).unwrap(),
            ["192.0.2.99".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn system_lookup_of_localhost() {
        let addrs = lookup_system("localhost", 80).unwrap();
        assert!(addrs.iter().all(|a| a.port() == 80 && a.ip().is_loopback()));
    }
}
