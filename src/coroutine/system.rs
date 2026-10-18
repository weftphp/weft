//! Coroutine versions of blocking system services.
//!
//! - [`blocking`] runs any closure on a helper thread and suspends until it finishes; file
//!   operations ([`read_file`], [`write_file`], ...) and [`lookup_system`] are built on it.
//! - [`exec`] runs a shell command and collects its output.
//! - [`resolve`] queries DNS servers directly over coroutine sockets, using no threads.
//! - [`wait_signal`] waits for a POSIX signal.
//! - [`read_fd`] / [`write_fd`] wrap raw descriptors (pipes, terminals, sockets).

use std::cell::RefCell;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::runtime::{Waiter, Wake, wait_fd, with_reactor};
use super::socket::CoSocket;
use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, Result, random};
use crate::network::SocketAddress;
use crate::network::dns::{self, RecordType, ResolvConf, Want, rcode};
use crate::os::blocking::{BlockingPool, PoolConfig};
use crate::os::fd;
use crate::os::process::ExitStatus;
use crate::protocol::framing::{LengthPrefixed, Width};
use crate::reactor::Interest;

thread_local! {
    static POOL: RefCell<Option<BlockingPool>> = const { RefCell::new(None) };
}

static ATFORK: std::sync::Once = std::sync::Once::new();

/// Helper threads do not survive `fork`, so a child must not wait on (or join) its
/// parent's pool; it starts a new one on demand.
extern "C" fn forget_pool_in_child() {
    POOL.with(|pool| {
        if let Ok(mut pool) = pool.try_borrow_mut() {
            std::mem::forget(pool.take());
        }
    });
}

/// Runs `task` on a helper thread and suspends the calling coroutine until it returns.
/// A panic in `task` resumes in the caller.
pub fn blocking<T: Send + 'static>(task: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    let waiter = Waiter::new()?;
    let slot: Arc<Mutex<Option<std::thread::Result<T>>>> = Arc::new(Mutex::new(None));
    let remote = with_reactor(|r| {
        // Keep the loop alive while the task runs.
        r.hold();
        r.remote()
    })?;
    let result_slot = Arc::clone(&slot);
    let job = move || {
        let outcome = catch_unwind(AssertUnwindSafe(task));
        *result_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
        let _ = remote.post(move |r| {
            r.release();
            waiter.wake(r, Wake::Done);
        });
    };
    POOL.with(|pool| -> Result<()> {
        let mut pool = pool.borrow_mut();
        if pool.is_none() {
            ATFORK.call_once(|| {
                // SAFETY: registering a child handler has no preconditions; the handler
                // only moves a value out of thread-local storage.
                unsafe { libc::pthread_atfork(None, None, Some(forget_pool_in_child)) };
            });
            *pool = Some(BlockingPool::new(PoolConfig::default(), || {})?);
        }
        if let Some(pool) = pool.as_mut() {
            // Results travel through `slot`; the pool's own completions are not needed.
            pool.take_completed();
            pool.submit(job)?;
        }
        Ok(())
    })?;
    match waiter.wait(None)? {
        Wake::Done => match slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
            Some(Ok(value)) => Ok(value),
            Some(Err(panic)) => resume_unwind(panic),
            None => Err(Error::new(
                ErrorKind::InvalidState,
                "task produced no result",
            )),
        },
        _ => Err(Error::new(
            ErrorKind::Closed,
            "cancelled while waiting for a helper thread",
        )),
    }
}

// ----- files -----

/// Reads a whole file without blocking the event loop.
pub fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref().to_path_buf();
    Ok(blocking(move || std::fs::read(path))??)
}

/// Writes (replacing) a whole file without blocking the event loop.
pub fn write_file(path: impl AsRef<Path>, data: Vec<u8>) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    Ok(blocking(move || std::fs::write(path, data))??)
}

/// Appends to a file, creating it if needed.
pub fn append_file(path: impl AsRef<Path>, data: Vec<u8>) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    Ok(blocking(move || -> io::Result<()> {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?
            .write_all(&data)
    })??)
}

pub fn metadata(path: impl AsRef<Path>) -> Result<std::fs::Metadata> {
    let path = path.as_ref().to_path_buf();
    Ok(blocking(move || std::fs::metadata(path))??)
}

pub fn remove_file(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    Ok(blocking(move || std::fs::remove_file(path))??)
}

/// Takes an advisory lock on a file (exclusive or shared), suspending while another holder
/// has it. The lock lasts as long as the returned file stays open.
pub fn lock_file(path: impl AsRef<Path>, exclusive: bool) -> Result<std::fs::File> {
    let path: PathBuf = path.as_ref().to_path_buf();
    Ok(blocking(move || -> io::Result<std::fs::File> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        if exclusive {
            file.lock()?;
        } else {
            file.lock_shared()?;
        }
        Ok(file)
    })??)
}

// ----- raw descriptors -----

/// Reads from a descriptor, waiting while it has nothing. The descriptor is switched to
/// non-blocking mode.
pub fn read_fd(fd: BorrowedFd<'_>, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize> {
    fd::set_nonblocking(fd, true)?;
    loop {
        match fd::read(fd, buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait_fd(fd.as_raw_fd(), Interest::READABLE, timeout)?;
            }
            other => return Ok(other?),
        }
    }
}

/// Writes to a descriptor, waiting while it is full. Returns how much was written.
pub fn write_fd(fd: BorrowedFd<'_>, data: &[u8], timeout: Option<Duration>) -> Result<usize> {
    fd::set_nonblocking(fd, true)?;
    loop {
        match fd::write(fd, data) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait_fd(fd.as_raw_fd(), Interest::WRITABLE, timeout)?;
            }
            other => return Ok(other?),
        }
    }
}

// ----- processes -----

/// Output of [`exec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
}

/// Runs `command` with `/bin/sh -c`, collecting its standard output while other coroutines
/// keep running.
pub fn exec(command: &str) -> Result<ExecOutput> {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::new(ErrorKind::InvalidState, "child has no stdout"))?;
    let mut output = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = read_fd(stdout.as_fd(), &mut chunk, None)?;
        if n == 0 {
            break;
        }
        output.extend_from_slice(&chunk[..n]);
    }
    drop(stdout);
    let status = blocking(move || child.wait())??;
    let status = match (
        status.code(),
        std::os::unix::process::ExitStatusExt::signal(&status),
    ) {
        (Some(code), _) => ExitStatus::Exited(code),
        (None, Some(signal)) => ExitStatus::Signaled {
            signal,
            core_dumped: std::os::unix::process::ExitStatusExt::core_dumped(&status),
        },
        (None, None) => ExitStatus::Exited(-1),
    };
    Ok(ExecOutput {
        status,
        stdout: output,
    })
}

// ----- signals -----

/// Waits for `signal` (routing it through the event loop while waiting). Returns `false` on
/// timeout.
pub fn wait_signal(signal: i32, timeout: Option<Duration>) -> Result<bool> {
    let waiter = Waiter::new()?;
    with_reactor(|r| {
        r.on_signal(signal, move |r, _| {
            waiter.wake(r, Wake::Done);
        })
    })??;
    let wake = waiter.wait(timeout);
    with_reactor(|r| r.remove_signal(signal))??;
    match wake? {
        Wake::Done => Ok(true),
        Wake::Timeout => Ok(false),
        _ => Err(Error::new(ErrorKind::Closed, "signal wait cancelled")),
    }
}

// ----- name resolution -----

/// Resolves `host` with the C library on a helper thread.
pub fn lookup_system(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let host = host.to_owned();
    Ok(blocking(move || dns::lookup_system(&host, port))??)
}

/// Settings for [`resolve`].
#[derive(Debug, Clone, Default)]
pub struct ResolveOptions {
    pub hosts: dns::Hosts,
    pub config: ResolvConf,
}

impl ResolveOptions {
    /// Reads `/etc/hosts` and `/etc/resolv.conf` (on a helper thread).
    pub fn from_system() -> Result<ResolveOptions> {
        let resolver = blocking(dns::Resolver::from_system)??;
        Ok(ResolveOptions {
            hosts: resolver.hosts,
            config: resolver.config,
        })
    }
}

/// Resolves `name` by asking the configured servers directly over UDP (TCP for truncated
/// answers), suspending only the calling coroutine.
pub fn resolve(name: &str, want: Want, options: &ResolveOptions) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let pinned: Vec<IpAddr> = options
        .hosts
        .lookup(name)
        .iter()
        .copied()
        .filter(|ip| match want {
            Want::V4 => ip.is_ipv4(),
            Want::V6 => ip.is_ipv6(),
            Want::Any => true,
        })
        .collect();
    if !pinned.is_empty() {
        return Ok(pinned);
    }
    let kinds: &[RecordType] = match want {
        Want::V4 => &[RecordType::A],
        Want::V6 => &[RecordType::Aaaa],
        Want::Any => &[RecordType::A, RecordType::Aaaa],
    };
    let mut last = Error::new(ErrorKind::NotFound, format!("no address for {name}"));
    for candidate in options.config.candidates(name) {
        let mut found = Vec::new();
        for &kind in kinds {
            match query(&candidate, kind, &options.config) {
                Ok(addresses) => found.extend(addresses),
                Err(e) => last = e,
            }
        }
        if !found.is_empty() {
            return Ok(found);
        }
    }
    Err(last)
}

fn query(name: &str, kind: RecordType, config: &ResolvConf) -> Result<Vec<IpAddr>> {
    let mut last = Error::new(ErrorKind::NotFound, "no name servers configured");
    for _ in 0..config.attempts.max(1) {
        for &server in &config.nameservers {
            match ask(server, name, kind, config.timeout) {
                Ok(response) if response.rcode == rcode::NO_ERROR => {
                    return Ok(response.addresses);
                }
                Ok(response) if response.rcode == rcode::NAME_ERROR => {
                    return Err(Error::new(
                        ErrorKind::NotFound,
                        format!("{name} does not exist"),
                    ));
                }
                Ok(response) => {
                    last = Error::new(
                        ErrorKind::Protocol,
                        format!("server {server} answered with rcode {}", response.rcode),
                    );
                }
                Err(e) => last = e,
            }
        }
    }
    Err(last)
}

fn ask(
    server: SocketAddr,
    name: &str,
    kind: RecordType,
    timeout: Duration,
) -> Result<dns::Response> {
    let id = random::u64()? as u16;
    let message = dns::encode_query(id, name, kind)?;
    let local: SocketAddress = match server {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    }
    .parse()?;
    let mut udp = CoSocket::bind_datagram(&local)?;
    udp.read_timeout = Some(timeout);
    udp.write_timeout = Some(timeout);
    let server_addr = SocketAddress::from(server);
    udp.send_to(&message, &server_addr)?;
    let mut buf = [0u8; 1232];
    let response = loop {
        let (n, from) = udp.recv_from(&mut buf)?;
        if from != server_addr {
            continue;
        }
        match dns::decode_response(&buf[..n]) {
            Ok(r) if r.id == id => break r,
            _ => continue,
        }
    };
    if !response.truncated {
        return Ok(response);
    }
    let mut tcp = CoSocket::connect(&server_addr, Some(timeout))?;
    tcp.read_timeout = Some(timeout);
    tcp.write_timeout = Some(timeout);
    let mut codec = LengthPrefixed::simple(Width::U16, 65_537);
    tcp.send_all(&codec.encode(&message)?)?;
    let reply = tcp
        .recv_message(&mut codec, &mut ByteBuffer::new())?
        .ok_or_else(|| Error::new(ErrorKind::Closed, "DNS server closed the connection"))?;
    let response = dns::decode_response(&reply)?;
    if response.id != id {
        return Err(Error::new(ErrorKind::Protocol, "DNS reply id mismatch"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::super::runtime::{run, spawn};
    use super::*;
    use std::rc::Rc;

    #[test]
    fn blocking_work_runs_off_thread() {
        run(|| {
            let main_thread = std::thread::current().id();
            let (value, thread) = blocking(|| (6 * 7, std::thread::current().id())).unwrap();
            assert_eq!(value, 42);
            assert_ne!(thread, main_thread);

            let caught = std::panic::catch_unwind(AssertUnwindSafe(|| {
                blocking(|| -> () { panic!("in helper") }).unwrap();
            }));
            assert!(caught.is_err());
        })
        .unwrap();
    }

    #[test]
    fn files_and_locks() {
        run(|| {
            let dir = std::env::temp_dir().join(format!("weft-co-fs-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("f.txt");
            write_file(&path, b"one".to_vec()).unwrap();
            append_file(&path, b" two".to_vec()).unwrap();
            assert_eq!(read_file(&path).unwrap(), b"one two");
            assert_eq!(metadata(&path).unwrap().len(), 7);
            let lock = lock_file(dir.join("lock"), true).unwrap();
            drop(lock);
            remove_file(&path).unwrap();
            assert!(read_file(&path).is_err());
            std::fs::remove_dir_all(&dir).unwrap();
        })
        .unwrap();
    }

    #[test]
    fn exec_collects_output_concurrently() {
        let ticks = Rc::new(std::cell::Cell::new(0));
        let t = Rc::clone(&ticks);
        run(move || {
            spawn(move || {
                for _ in 0..3 {
                    super::super::runtime::sleep(Duration::from_millis(5)).unwrap();
                    t.set(t.get() + 1);
                }
            })
            .unwrap();
            let out = exec("sleep 0.05; printf 'done'; exit 3").unwrap();
            assert_eq!(out.stdout, b"done");
            assert_eq!(out.status, ExitStatus::Exited(3));
        })
        .unwrap();
        assert_eq!(ticks.get(), 3, "other coroutines ran during exec");
    }

    #[test]
    fn pipes_through_raw_descriptors() {
        run(|| {
            let (r, w) = fd::pipe(true).unwrap();
            spawn(move || {
                super::super::runtime::sleep(Duration::from_millis(2)).unwrap();
                write_fd(w.as_fd(), b"via pipe", None).unwrap();
            })
            .unwrap();
            let mut buf = [0u8; 16];
            let n = read_fd(r.as_fd(), &mut buf, Some(Duration::from_secs(5))).unwrap();
            assert_eq!(&buf[..n], b"via pipe");
        })
        .unwrap();
    }

    #[test]
    fn resolves_against_a_local_server() {
        // A one-shot UDP DNS server answering every A query with 192.0.2.7.
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            let query = &buf[..n];
            let mut reply = query[..2].to_vec();
            reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            reply.extend_from_slice(&query[12..]);
            reply.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
            server.send_to(&reply, peer).unwrap();
        });
        run(move || {
            let mut options = ResolveOptions {
                config: ResolvConf::parse(""),
                ..ResolveOptions::default()
            };
            options.config.nameservers = vec![addr];
            options.config.timeout = Duration::from_secs(2);
            options
                .hosts
                .insert("pinned.test", "10.9.9.9".parse().unwrap());
            let found = resolve("api.test", Want::V4, &options).unwrap();
            assert_eq!(found, ["192.0.2.7".parse::<IpAddr>().unwrap()]);
            assert_eq!(
                resolve("pinned.test", Want::Any, &options).unwrap(),
                ["10.9.9.9".parse::<IpAddr>().unwrap()]
            );
            let local = lookup_system("localhost", 80).unwrap();
            assert!(local.iter().all(|a| a.ip().is_loopback()));
        })
        .unwrap();
    }

    #[test]
    fn signal_wait() {
        run(|| {
            spawn(|| {
                super::super::runtime::sleep(Duration::from_millis(5)).unwrap();
                // SAFETY: SIGWINCH is being waited for, so its handler routes it to the loop.
                unsafe { libc::raise(libc::SIGWINCH) };
            })
            .unwrap();
            assert!(wait_signal(libc::SIGWINCH, Some(Duration::from_secs(5))).unwrap());
            assert!(!wait_signal(libc::SIGWINCH, Some(Duration::from_millis(5))).unwrap());
        })
        .unwrap();
    }
}
