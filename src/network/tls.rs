//! TLS over non-blocking sockets, backed by OpenSSL (3.0 or newer).
//!
//! [`ServerTls`] and [`ClientTls`] are built once from [`ServerTlsOptions`] and
//! [`ClientTlsOptions`]. Building loads every certificate and key, so configuration mistakes
//! surface at startup rather than on the first connection. The built values are cheap to
//! clone and are shared by every connection that uses them.
//!
//! Connections use them through [`CoSocket`](crate::coroutine::CoSocket) (TLS clients and
//! servers in coroutines) and through server [`Listener`](crate::server::Listener)s.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openssl::error::ErrorStack;
use openssl::ssl::{
    AlpnError, ErrorCode, Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslMode,
    SslOptions, SslStream, SslVerifyMode, SslVersion,
};
use openssl::x509::{X509Name, X509VerifyResult};

use super::socket::Socket;
use crate::core::{Error, ErrorKind, Result};
use crate::reactor::Interest;

/// The largest plaintext a single TLS record carries; writes are cut to this size.
const RECORD: usize = 16 * 1024;

/// The oldest protocol version a context accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsVersion {
    #[default]
    Tls12,
    Tls13,
}

impl TlsVersion {
    fn raw(self) -> SslVersion {
        match self {
            TlsVersion::Tls12 => SslVersion::TLS1_2,
            TlsVersion::Tls13 => SslVersion::TLS1_3,
        }
    }
}

/// Whether a server asks clients for a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientAuth {
    /// Clients are not asked for a certificate.
    #[default]
    None,
    /// A certificate is requested and verified if sent, but not required.
    Optional,
    /// Handshakes without a valid client certificate fail.
    Required,
}

/// Settings for the server side of TLS.
#[derive(Debug, Clone)]
pub struct ServerTlsOptions {
    /// PEM file holding the server certificate followed by any intermediate certificates.
    pub certificate_chain: PathBuf,
    /// PEM file holding the private key of the certificate.
    pub private_key: PathBuf,
    pub client_auth: ClientAuth,
    /// PEM file of the CAs that sign acceptable client certificates. Required unless
    /// `client_auth` is [`ClientAuth::None`].
    pub client_ca: Option<PathBuf>,
    /// Application protocols offered through ALPN, most preferred first, for example
    /// `["h2", "http/1.1"]`. Empty disables ALPN.
    pub alpn: Vec<String>,
    pub min_version: TlsVersion,
    /// An OpenSSL cipher list for TLS 1.2. TLS 1.3 suites keep OpenSSL's defaults.
    pub ciphers: Option<String>,
}

impl ServerTlsOptions {
    pub fn new(
        certificate_chain: impl Into<PathBuf>,
        private_key: impl Into<PathBuf>,
    ) -> ServerTlsOptions {
        ServerTlsOptions {
            certificate_chain: certificate_chain.into(),
            private_key: private_key.into(),
            client_auth: ClientAuth::None,
            client_ca: None,
            alpn: Vec::new(),
            min_version: TlsVersion::default(),
            ciphers: None,
        }
    }

    pub fn with_alpn<S: Into<String>>(mut self, protocols: impl IntoIterator<Item = S>) -> Self {
        self.alpn = protocols.into_iter().map(Into::into).collect();
        self
    }

    /// Loads the certificates and keys and builds the shared server context.
    pub fn build(&self) -> Result<ServerTls> {
        alpn_wire(&self.alpn)?;
        let mut builder = base_context(self.min_version, self.ciphers.as_deref())?;
        builder
            .set_certificate_chain_file(&self.certificate_chain)
            .map_err(|e| load_error("certificate chain", &self.certificate_chain, e))?;
        builder
            .set_private_key_file(&self.private_key, SslFiletype::PEM)
            .map_err(|e| load_error("private key", &self.private_key, e))?;
        builder.check_private_key().map_err(|_| {
            Error::new(
                ErrorKind::InvalidArgument,
                format!(
                    "private key {} does not match certificate {}",
                    self.private_key.display(),
                    self.certificate_chain.display()
                ),
            )
        })?;

        if self.client_auth != ClientAuth::None {
            let ca = self.client_ca.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidArgument,
                    "client certificate checks need a client_ca file",
                )
            })?;
            builder
                .set_ca_file(ca)
                .map_err(|e| load_error("client CA file", ca, e))?;
            // Tells clients which CAs are acceptable, so they can pick a certificate.
            let names = X509Name::load_client_ca_file(ca)
                .map_err(|e| load_error("client CA file", ca, e))?;
            builder.set_client_ca_list(names);
            let mut mode = SslVerifyMode::PEER;
            if self.client_auth == ClientAuth::Required {
                mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
            }
            builder.set_verify(mode);
            // Session resumption with client verification needs a context id.
            builder
                .set_session_id_context(b"weft")
                .map_err(|e| config_error("session id context", e))?;
        }

        if !self.alpn.is_empty() {
            let ours = self.alpn.clone();
            builder.set_alpn_select_callback(move |_, offered| {
                choose_alpn(&ours, offered).ok_or(AlpnError::NOACK)
            });
        }

        Ok(ServerTls {
            context: builder.build(),
            alpn: self.alpn.clone().into(),
        })
    }
}

/// A server TLS context: certificates, keys and policy, shared by every connection.
#[derive(Clone)]
pub struct ServerTls {
    context: SslContext,
    alpn: Arc<[String]>,
}

impl ServerTls {
    /// The protocols this server offers through ALPN, most preferred first.
    pub fn alpn(&self) -> &[String] {
        &self.alpn
    }
}

impl fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerTls")
            .field("alpn", &self.alpn)
            .finish_non_exhaustive()
    }
}

/// Settings for the client side of TLS.
#[derive(Debug, Clone)]
pub struct ClientTlsOptions {
    /// Check the server's certificate chain and that it names the host being contacted.
    /// Without this anyone on the network path can impersonate the server, so turn it off
    /// only for tests.
    pub verify_peer: bool,
    /// PEM file of trusted CAs. `None` uses OpenSSL's default trust store.
    pub ca_file: Option<PathBuf>,
    /// PEM certificate chain to present when the server asks for one.
    pub certificate_chain: Option<PathBuf>,
    /// Private key of `certificate_chain`.
    pub private_key: Option<PathBuf>,
    /// Application protocols offered through ALPN, most preferred first. Empty disables ALPN.
    pub alpn: Vec<String>,
    pub min_version: TlsVersion,
    /// An OpenSSL cipher list for TLS 1.2. TLS 1.3 suites keep OpenSSL's defaults.
    pub ciphers: Option<String>,
}

impl Default for ClientTlsOptions {
    fn default() -> Self {
        ClientTlsOptions {
            verify_peer: true,
            ca_file: None,
            certificate_chain: None,
            private_key: None,
            alpn: Vec::new(),
            min_version: TlsVersion::default(),
            ciphers: None,
        }
    }
}

impl ClientTlsOptions {
    pub fn with_alpn<S: Into<String>>(mut self, protocols: impl IntoIterator<Item = S>) -> Self {
        self.alpn = protocols.into_iter().map(Into::into).collect();
        self
    }

    /// Loads the trust store and any client certificate and builds the shared context.
    pub fn build(&self) -> Result<ClientTls> {
        let wire = alpn_wire(&self.alpn)?;
        let mut builder = base_context(self.min_version, self.ciphers.as_deref())?;
        if self.verify_peer {
            match &self.ca_file {
                Some(ca) => builder
                    .set_ca_file(ca)
                    .map_err(|e| load_error("CA file", ca, e))?,
                None => builder
                    .set_default_verify_paths()
                    .map_err(|e| config_error("default trust store", e))?,
            }
            builder.set_verify(SslVerifyMode::PEER);
        } else {
            builder.set_verify(SslVerifyMode::NONE);
        }
        match (&self.certificate_chain, &self.private_key) {
            (Some(chain), Some(key)) => {
                builder
                    .set_certificate_chain_file(chain)
                    .map_err(|e| load_error("certificate chain", chain, e))?;
                builder
                    .set_private_key_file(key, SslFiletype::PEM)
                    .map_err(|e| load_error("private key", key, e))?;
                builder.check_private_key().map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidArgument,
                        "client private key does not match its certificate",
                    )
                })?;
            }
            (None, None) => {}
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidArgument,
                    "a client certificate needs both certificate_chain and private_key",
                ));
            }
        }
        if !wire.is_empty() {
            builder
                .set_alpn_protos(&wire)
                .map_err(|e| config_error("ALPN protocols", e))?;
        }
        Ok(ClientTls {
            context: builder.build(),
            verify_peer: self.verify_peer,
        })
    }
}

/// A client TLS context: trust store, optional client certificate and policy.
#[derive(Clone)]
pub struct ClientTls {
    context: SslContext,
    verify_peer: bool,
}

impl ClientTls {
    /// A verifying client that trusts OpenSSL's default trust store.
    pub fn new() -> Result<ClientTls> {
        ClientTlsOptions::default().build()
    }
}

impl fmt::Debug for ClientTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientTls")
            .field("verify_peer", &self.verify_peer)
            .finish_non_exhaustive()
    }
}

/// What a finished handshake negotiated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    /// Protocol version, such as `"TLSv1.3"`.
    pub version: String,
    /// Cipher suite name, as OpenSSL reports it.
    pub cipher: Option<String>,
    /// The protocol both sides agreed on through ALPN.
    pub alpn: Option<Vec<u8>>,
    /// The peer's certificate in DER form, if it sent one.
    pub peer_certificate: Option<Vec<u8>>,
}

fn base_context(min_version: TlsVersion, ciphers: Option<&str>) -> Result<SslContextBuilder> {
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).map_err(|e| config_error("TLS context", e))?;
    builder
        .set_min_proto_version(Some(min_version.raw()))
        .map_err(|e| config_error("minimum TLS version", e))?;
    if let Some(list) = ciphers {
        builder
            .set_cipher_list(list)
            .map_err(|e| config_error("cipher list", e))?;
    }
    // A peer that closes without close_notify reads as a plain EOF: protocols on top frame
    // their own messages, and many real clients skip the alert.
    builder.set_options(
        SslOptions::NO_COMPRESSION
            | SslOptions::NO_RENEGOTIATION
            | SslOptions::IGNORE_UNEXPECTED_EOF,
    );
    // Writes come from queues whose front may move in memory between retries, and each
    // write is reported as soon as one record is out.
    builder.set_mode(
        SslMode::ACCEPT_MOVING_WRITE_BUFFER
            | SslMode::ENABLE_PARTIAL_WRITE
            | SslMode::RELEASE_BUFFERS,
    );
    Ok(builder)
}

fn load_error(what: &str, path: &Path, e: ErrorStack) -> Error {
    Error::new(
        ErrorKind::InvalidArgument,
        format!("cannot load {what} {}: {e}", path.display()),
    )
}

fn config_error(what: &str, e: ErrorStack) -> Error {
    Error::new(ErrorKind::InvalidArgument, format!("TLS {what}: {e}"))
}

/// Encodes protocol names as ALPN's list of length-prefixed strings (RFC 7301 §3.1).
fn alpn_wire(protocols: &[String]) -> Result<Vec<u8>> {
    let mut wire = Vec::new();
    for name in protocols {
        let len = u8::try_from(name.len())
            .ok()
            .filter(|&n| n > 0)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidArgument,
                    format!("ALPN protocol name {name:?} must be 1 to 255 bytes"),
                )
            })?;
        wire.push(len);
        wire.extend_from_slice(name.as_bytes());
    }
    Ok(wire)
}

/// The first of `ours` that the client's ALPN list `offered` also contains.
fn choose_alpn<'a>(ours: &[String], offered: &'a [u8]) -> Option<&'a [u8]> {
    let mut names = Vec::new();
    let mut rest = offered;
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len);
        if len == 0 || len > tail.len() {
            // A malformed list: agree on nothing rather than guess.
            return None;
        }
        names.push(&tail[..len]);
        rest = &tail[len..];
    }
    ours.iter()
        .find_map(|want| names.iter().copied().find(|n| *n == want.as_bytes()))
}

/// Lets OpenSSL do I/O on a descriptor whose [`Socket`] is owned elsewhere.
struct SocketView(ManuallyDrop<Socket>);

impl Read for SocketView {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf)
    }
}

impl Write for SocketView {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One TLS session over a non-blocking socket owned by the caller.
///
/// No operation blocks. When one fails with [`io::ErrorKind::WouldBlock`],
/// [`wants`](Self::wants) says which readiness to wait for before retrying. That is not
/// always the direction of the call: a read can need to send a handshake message, and a
/// write can need to receive one. TLS failures surface as [`io::ErrorKind::InvalidData`].
pub(crate) struct TlsSession {
    stream: SslStream<SocketView>,
    handshaking: bool,
    /// Set after a fatal error, when OpenSSL forbids sending close_notify.
    failed: bool,
    wants: Interest,
    /// Staging for gathered writes and file data. OpenSSL requires a write that would
    /// block to be retried with the same bytes, which the callers guarantee by retrying
    /// from the same queue position or file offset.
    scratch: Vec<u8>,
}

impl TlsSession {
    /// Starts the server side of a session on `socket`.
    ///
    /// # Safety
    ///
    /// `socket` must outlive the session: the session keeps doing I/O on its descriptor.
    pub(crate) unsafe fn server(tls: &ServerTls, socket: &Socket) -> Result<TlsSession> {
        let mut ssl = Ssl::new(&tls.context).map_err(|e| config_error("session", e))?;
        ssl.set_accept_state();
        // SAFETY: forwarded from this function's contract.
        unsafe { TlsSession::new(ssl, socket, Interest::READABLE) }
    }

    /// Starts the client side of a session on `socket`. `server_name` (a host name or IP
    /// address) is sent through SNI and, when the context verifies peers, must match the
    /// server's certificate.
    ///
    /// # Safety
    ///
    /// `socket` must outlive the session: the session keeps doing I/O on its descriptor.
    pub(crate) unsafe fn client(
        tls: &ClientTls,
        server_name: &str,
        socket: &Socket,
    ) -> Result<TlsSession> {
        let mut ssl = Ssl::new(&tls.context).map_err(|e| config_error("session", e))?;
        let host = server_name.trim_start_matches('[').trim_end_matches(']');
        let ip = host.parse::<IpAddr>().ok();
        // SNI carries host names only (RFC 6066 §3).
        if ip.is_none() && !host.is_empty() {
            ssl.set_hostname(host)
                .map_err(|e| config_error("server name", e))?;
        }
        if tls.verify_peer {
            let param = ssl.param_mut();
            match ip {
                Some(ip) => param.set_ip(ip),
                None => param.set_host(host),
            }
            .map_err(|e| config_error("expected server name", e))?;
        }
        ssl.set_connect_state();
        // SAFETY: forwarded from this function's contract.
        unsafe { TlsSession::new(ssl, socket, Interest::WRITABLE) }
    }

    /// # Safety
    ///
    /// `socket` must outlive the session.
    unsafe fn new(ssl: Ssl, socket: &Socket, wants: Interest) -> Result<TlsSession> {
        // SAFETY: the descriptor stays open for the session's lifetime (the caller's
        // contract), and `ManuallyDrop` keeps this second owner from ever closing it.
        let view = SocketView(ManuallyDrop::new(Socket::from(unsafe {
            OwnedFd::from_raw_fd(socket.as_raw_fd())
        })));
        let stream = SslStream::new(ssl, view).map_err(|e| config_error("session", e))?;
        Ok(TlsSession {
            stream,
            handshaking: true,
            failed: false,
            wants,
            scratch: Vec::new(),
        })
    }

    /// The readiness the last operation that would block was waiting for.
    pub(crate) fn wants(&self) -> Interest {
        self.wants
    }

    /// Decrypted bytes OpenSSL holds that the next read returns without touching the socket.
    pub(crate) fn buffered(&self) -> usize {
        self.stream.ssl().pending()
    }

    /// Advances the handshake; `Ok` once it has finished.
    pub(crate) fn handshake(&mut self) -> io::Result<()> {
        if !self.handshaking {
            return Ok(());
        }
        match self.stream.do_handshake() {
            Ok(()) => {
                self.handshaking = false;
                Ok(())
            }
            Err(e) => Err(self.convert(e)),
        }
    }

    /// Reads decrypted data, finishing the handshake first. `Ok(0)` means the peer closed.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handshake()?;
        match self.stream.ssl_read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.code() == ErrorCode::ZERO_RETURN => Ok(0),
            Err(e) => Err(self.convert(e)),
        }
    }

    /// Encrypts and sends some of `buf` (at most one record); returns how much.
    pub(crate) fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handshake()?;
        if buf.is_empty() {
            return Ok(0);
        }
        match self.stream.ssl_write(buf) {
            Ok(n) => Ok(n),
            Err(e) => Err(self.convert(e)),
        }
    }

    /// Sends the front of `bufs`, coalescing small slices into one record.
    pub(crate) fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let mut parts = bufs.iter().filter(|b| !b.is_empty());
        let Some(first) = parts.next() else {
            return Ok(0);
        };
        if first.len() >= RECORD {
            return self.write(first);
        }
        let mut staged = std::mem::take(&mut self.scratch);
        staged.clear();
        for part in std::iter::once(first).chain(parts) {
            let take = part.len().min(RECORD - staged.len());
            staged.extend_from_slice(&part[..take]);
            if staged.len() == RECORD {
                break;
            }
        }
        let result = self.write(&staged);
        self.scratch = staged;
        result
    }

    /// Sends up to `len` bytes of `file` from `offset`; `Ok(0)` if the file ends there.
    pub(crate) fn send_file(&mut self, file: &File, offset: u64, len: usize) -> io::Result<usize> {
        self.handshake()?;
        let mut staged = std::mem::take(&mut self.scratch);
        staged.resize(len.min(RECORD), 0);
        let result = match file.read_at(&mut staged, offset) {
            Ok(0) => Ok(0),
            Ok(n) => self.write(&staged[..n]),
            Err(e) => Err(e),
        };
        self.scratch = staged;
        result
    }

    /// Sends close_notify if the session is in a state to, without waiting for the peer's.
    /// Best effort: a full send buffer or a broken session skips it.
    pub(crate) fn close_notify(&mut self) {
        if !self.handshaking && !self.failed {
            let _ = self.stream.shutdown();
        }
    }

    /// What the handshake negotiated, once it has finished.
    pub(crate) fn info(&self) -> Option<TlsInfo> {
        if self.handshaking {
            return None;
        }
        let ssl = self.stream.ssl();
        Some(TlsInfo {
            version: ssl.version_str().to_owned(),
            cipher: ssl.current_cipher().map(|c| c.name().to_owned()),
            alpn: ssl.selected_alpn_protocol().map(<[u8]>::to_vec),
            peer_certificate: ssl.peer_certificate().and_then(|c| c.to_der().ok()),
        })
    }

    fn convert(&mut self, e: openssl::ssl::Error) -> io::Error {
        match e.code() {
            ErrorCode::WANT_READ => {
                self.wants = Interest::READABLE;
                return io::ErrorKind::WouldBlock.into();
            }
            ErrorCode::WANT_WRITE => {
                self.wants = Interest::WRITABLE;
                return io::ErrorKind::WouldBlock.into();
            }
            _ => {}
        }
        self.failed = true;
        let stage = if self.handshaking {
            "TLS handshake failed"
        } else {
            "TLS session failed"
        };
        let verify = self.stream.ssl().verify_result();
        if self.handshaking && verify != X509VerifyResult::OK {
            return io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{stage}: certificate rejected: {}", verify.error_string()),
            );
        }
        match e.code() {
            ErrorCode::ZERO_RETURN => io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{stage}: peer closed the connection"),
            ),
            ErrorCode::SYSCALL => match e.into_io_error() {
                Ok(io) => io,
                Err(_) => io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("{stage}: peer closed the connection"),
                ),
            },
            _ => io::Error::new(io::ErrorKind::InvalidData, format!("{stage}: {e}")),
        }
    }
}

impl fmt::Debug for TlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSession")
            .field("handshaking", &self.handshaking)
            .field("wants", &self.wants)
            .finish_non_exhaustive()
    }
}

/// Throwaway certificates for tests: a CA, and a leaf it signs for `localhost` and
/// `127.0.0.1`, written as PEM files to a fresh temporary directory.
#[cfg(test)]
pub(crate) mod test_pki {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use openssl::x509::{X509, X509NameBuilder};

    pub struct Pki {
        pub dir: PathBuf,
        pub ca: PathBuf,
        pub cert: PathBuf,
        pub key: PathBuf,
        /// A second CA that signed nothing used here.
        pub other_ca: PathBuf,
    }

    impl Drop for Pki {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn cert(name: &str, key: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>) -> X509 {
        let mut subject = X509NameBuilder::new().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(rand_serial()).unwrap();
        b.set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&subject).unwrap();
        b.set_pubkey(key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        match issuer {
            None => {
                b.set_issuer_name(&subject).unwrap();
                b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                    .unwrap();
                b.append_extension(
                    KeyUsage::new()
                        .critical()
                        .key_cert_sign()
                        .crl_sign()
                        .build()
                        .unwrap(),
                )
                .unwrap();
                b.sign(key, MessageDigest::sha256()).unwrap();
            }
            Some((ca, ca_key)) => {
                b.set_issuer_name(ca.subject_name()).unwrap();
                let san = SubjectAlternativeName::new()
                    .dns("localhost")
                    .ip("127.0.0.1")
                    .build(&b.x509v3_context(Some(ca), None))
                    .unwrap();
                b.append_extension(san).unwrap();
                b.append_extension(
                    ExtendedKeyUsage::new()
                        .server_auth()
                        .client_auth()
                        .build()
                        .unwrap(),
                )
                .unwrap();
                b.sign(ca_key, MessageDigest::sha256()).unwrap();
            }
        }
        b.build()
    }

    fn rand_serial() -> u32 {
        let mut bytes = [0u8; 4];
        openssl::rand::rand_bytes(&mut bytes).unwrap();
        u32::from_be_bytes(bytes) >> 1
    }

    pub fn generate() -> Pki {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "weft-pki-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_key = key();
        let ca = cert("weft test CA", &ca_key, None);
        let leaf_key = key();
        let leaf = cert("localhost", &leaf_key, Some((&ca, &ca_key)));
        let other_key = key();
        let other = cert("unrelated CA", &other_key, None);

        let write = |name: &str, pem: Vec<u8>| {
            let path = dir.join(name);
            std::fs::write(&path, pem).unwrap();
            path
        };
        Pki {
            ca: write("ca.pem", ca.to_pem().unwrap()),
            cert: write("cert.pem", leaf.to_pem().unwrap()),
            key: write("key.pem", leaf_key.private_key_to_pem_pkcs8().unwrap()),
            other_ca: write("other-ca.pem", other.to_pem().unwrap()),
            dir,
        }
    }

    pub fn server_options(pki: &Pki) -> super::ServerTlsOptions {
        super::ServerTlsOptions::new(&pki.cert, &pki.key)
    }

    pub fn client_options(pki: &Pki) -> super::ClientTlsOptions {
        super::ClientTlsOptions {
            ca_file: Some(pki.ca.clone()),
            ..super::ClientTlsOptions::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_pki::{client_options, generate, server_options};
    use super::*;
    use crate::network::SocketType;

    #[test]
    fn alpn_encoding_and_choice() {
        let wire = alpn_wire(&["h2".into(), "http/1.1".into()]).unwrap();
        assert_eq!(wire, b"\x02h2\x08http/1.1");
        assert!(alpn_wire(&[String::new()]).is_err());
        assert!(alpn_wire(&["x".repeat(256)]).is_err());

        let ours = ["h2".to_owned(), "http/1.1".to_owned()];
        // Server preference wins over the client's order.
        assert_eq!(choose_alpn(&ours, b"\x08http/1.1\x02h2"), Some(&b"h2"[..]));
        assert_eq!(choose_alpn(&ours, b"\x08http/1.1"), Some(&b"http/1.1"[..]));
        assert_eq!(choose_alpn(&ours, b"\x06spdy/3"), None);
        assert_eq!(choose_alpn(&ours, b"\x09h2"), None);
        assert_eq!(choose_alpn(&ours, b""), None);
    }

    #[test]
    fn configuration_errors_surface_when_built() {
        let pki = generate();
        let missing = ServerTlsOptions::new(pki.dir.join("nope.pem"), &pki.key);
        let err = missing.build().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidArgument);
        assert!(err.to_string().contains("nope.pem"), "{err}");

        // The CA's certificate with the leaf's key: they do not match.
        let mismatched = ServerTlsOptions::new(&pki.ca, &pki.key);
        let err = mismatched.build().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidArgument);
        assert!(err.to_string().contains("key"), "{err}");

        let mut needs_ca = server_options(&pki);
        needs_ca.client_auth = ClientAuth::Required;
        assert!(needs_ca.build().is_err());

        let half = ClientTlsOptions {
            certificate_chain: Some(pki.cert.clone()),
            ..ClientTlsOptions::default()
        };
        assert!(half.build().is_err());
    }

    /// Drives both sessions of a socket pair until `done` holds for both results.
    fn pump<T>(
        client: &mut TlsSession,
        server: &mut TlsSession,
        mut op: impl FnMut(&mut TlsSession, bool) -> io::Result<T>,
    ) -> (io::Result<T>, io::Result<T>) {
        let mut results: (Option<io::Result<T>>, Option<io::Result<T>>) = (None, None);
        for _ in 0..1000 {
            if results.0.is_none() {
                match op(client, true) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    other => results.0 = Some(other),
                }
            }
            if results.1.is_none() {
                match op(server, false) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    other => results.1 = Some(other),
                }
            }
            if let (Some(_), Some(_)) = &results {
                return (results.0.unwrap(), results.1.unwrap());
            }
        }
        panic!("sessions made no progress");
    }

    fn sessions(
        server: &ServerTls,
        client: &ClientTls,
        name: &str,
    ) -> (Socket, Socket, TlsSession, TlsSession) {
        let (a, b) = Socket::pair(SocketType::Stream).unwrap();
        // SAFETY: the sockets are returned alongside the sessions and every test drops the
        // sessions first.
        let c = unsafe { TlsSession::client(client, name, &a) }.unwrap();
        // SAFETY: as above.
        let s = unsafe { TlsSession::server(server, &b) }.unwrap();
        (a, b, c, s)
    }

    #[test]
    fn handshake_transfer_and_close() {
        let pki = generate();
        let server = server_options(&pki)
            .with_alpn(["h2", "http/1.1"])
            .build()
            .unwrap();
        let client = client_options(&pki)
            .with_alpn(["http/1.1"])
            .build()
            .unwrap();
        let (_a, _b, mut c, mut s) = sessions(&server, &client, "localhost");
        let (rc, rs) = pump(&mut c, &mut s, |t, _| t.handshake());
        rc.unwrap();
        rs.unwrap();
        let info = c.info().unwrap();
        assert_eq!(info.version, "TLSv1.3");
        assert_eq!(info.alpn.as_deref(), Some(&b"http/1.1"[..]));
        assert!(info.peer_certificate.is_some());
        assert_eq!(s.info().unwrap().peer_certificate, None);

        // More than one record each way, written with gathered slices.
        let big: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
        let mut sent = 0;
        let mut received = Vec::new();
        while received.len() < big.len() {
            if sent < big.len() {
                let rest = &big[sent..];
                let (head, tail) = rest.split_at(rest.len().min(100));
                match c.write_vectored(&[io::IoSlice::new(head), io::IoSlice::new(tail)]) {
                    Ok(n) => sent += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("{e}"),
                }
            }
            let mut buf = [0u8; 4096];
            match s.read(&mut buf) {
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(received, big);

        c.close_notify();
        let mut buf = [0u8; 16];
        let (_, eof) = pump(&mut c, &mut s, |t, is_client| {
            if is_client { Ok(0) } else { t.read(&mut buf) }
        });
        assert_eq!(eof.unwrap(), 0);
    }

    #[test]
    fn verification_failures() {
        let pki = generate();
        let server = server_options(&pki).build().unwrap();

        // A name the certificate does not cover.
        let client = client_options(&pki).build().unwrap();
        let (_a, _b, mut c, mut s) = sessions(&server, &client, "example.test");
        let (rc, rs) = pump(&mut c, &mut s, |t, _| t.handshake());
        let err = rc.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("certificate rejected"), "{err}");
        assert!(rs.is_err());

        // An IP address SAN matches; an untrusted CA does not.
        let (_a, _b, mut c, mut s) = sessions(&server, &client, "127.0.0.1");
        let (rc, _) = pump(&mut c, &mut s, |t, _| t.handshake());
        rc.unwrap();
        let untrusted = ClientTlsOptions {
            ca_file: Some(pki.other_ca.clone()),
            ..ClientTlsOptions::default()
        }
        .build()
        .unwrap();
        let (_a, _b, mut c, mut s) = sessions(&server, &untrusted, "localhost");
        assert!(pump(&mut c, &mut s, |t, _| t.handshake()).0.is_err());

        // Without verification anything goes.
        let trusting = ClientTlsOptions {
            verify_peer: false,
            ..ClientTlsOptions::default()
        }
        .build()
        .unwrap();
        let (_a, _b, mut c, mut s) = sessions(&server, &trusting, "example.test");
        pump(&mut c, &mut s, |t, _| t.handshake()).0.unwrap();
    }

    #[test]
    fn client_certificates() {
        let pki = generate();
        let mut options = server_options(&pki);
        options.client_auth = ClientAuth::Required;
        options.client_ca = Some(pki.ca.clone());
        let server = options.build().unwrap();

        let anonymous = client_options(&pki).build().unwrap();
        let (_a, _b, mut c, mut s) = sessions(&server, &anonymous, "localhost");
        // In TLS 1.3 the client finishes first; the server's rejection arrives after.
        let (_, rs) = pump(&mut c, &mut s, |t, _| t.handshake());
        assert!(rs.is_err());

        let identified = ClientTlsOptions {
            certificate_chain: Some(pki.cert.clone()),
            private_key: Some(pki.key.clone()),
            ..client_options(&pki)
        }
        .build()
        .unwrap();
        let (_a, _b, mut c, mut s) = sessions(&server, &identified, "localhost");
        let (rc, rs) = pump(&mut c, &mut s, |t, _| t.handshake());
        rc.unwrap();
        rs.unwrap();
        assert!(s.info().unwrap().peer_certificate.is_some());
    }
}
