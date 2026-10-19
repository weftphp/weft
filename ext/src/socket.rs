//! `Weft\Socket`: a TCP stream socket whose operations suspend the calling coroutine.

use std::cell::RefCell;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::OnceLock;

use weft::core::ErrorKind;
use weft::coroutine::runtime::release_fd;
use weft::coroutine::{self, CoSocket, system};
use weft::network::SocketAddress;

use crate::php::{Args, Class, ClassBuilder, PhpResult, Ret, fail, handler};

static SOCKET: OnceLock<Class> = OnceLock::new();

struct PhpSocket(RefCell<Option<Rc<CoSocket>>>);

fn need_coroutine() -> PhpResult {
    if coroutine::in_coroutine() {
        Ok(())
    } else {
        fail("sockets can only be used inside a coroutine")
    }
}

fn resolve(host: &str, port: u16) -> PhpResult<SocketAddress> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddress::from((ip, port)));
    }
    let found = system::lookup_system(host, port)?;
    match found.into_iter().next() {
        Some(addr) => Ok(SocketAddress::from(addr)),
        None => fail(format!("cannot resolve {host}")),
    }
}

fn port_arg(args: &Args, i: usize) -> PhpResult<u16> {
    let port = args.long(i, -1);
    if !(0..=65535).contains(&port) {
        return fail("the port must be between 0 and 65535");
    }
    Ok(port as u16)
}

fn open(args: &Args) -> PhpResult<Rc<CoSocket>> {
    match &*args.this::<PhpSocket>()?.0.borrow() {
        Some(sock) => Ok(Rc::clone(sock)),
        None => fail("the socket is closed"),
    }
}

fn wrap(class: Class, ret: Ret, sock: CoSocket) {
    ret.object(class, PhpSocket(RefCell::new(Some(Rc::new(sock)))));
}

handler!(fn socket_connect(args, ret) {
    args.check(2, 3)?;
    need_coroutine()?;
    let host = args.text(0)?;
    let port = port_arg(&args, 1)?;
    let timeout = args.timeout(2);
    let addr = resolve(&host, port)?;
    let mut sock = CoSocket::connect(&addr, timeout)?;
    sock.read_timeout = timeout;
    sock.write_timeout = timeout;
    let Some(class) = SOCKET.get() else { return fail("socket class missing") };
    wrap(*class, ret, sock);
    Ok(())
});

handler!(fn socket_listen(args, ret) {
    args.check(2, 3)?;
    let host = args.text(0)?;
    let port = port_arg(&args, 1)?;
    let backlog = args.long(2, 128).clamp(1, i64::from(i32::MAX)) as i32;
    let addr = resolve(&host, port)?;
    let sock = CoSocket::listen(&addr, backlog)?;
    let Some(class) = SOCKET.get() else { return fail("socket class missing") };
    wrap(*class, ret, sock);
    Ok(())
});

handler!(fn socket_accept(args, ret) {
    args.check(0, 1)?;
    need_coroutine()?;
    let sock = open(&args)?;
    match sock.accept(args.timeout(0)) {
        Ok((conn, _)) => {
            let Some(class) = SOCKET.get() else { return fail("socket class missing") };
            wrap(*class, ret, conn);
        }
        Err(e) if e.kind() == ErrorKind::TimedOut => ret.null(),
        Err(e) => return Err(e.into()),
    }
    Ok(())
});

handler!(fn socket_send(args, ret) {
    args.check(1, 1)?;
    need_coroutine()?;
    let sock = open(&args)?;
    let data = args.string(0)?;
    sock.send_all(&data)?;
    ret.long(data.len() as i64);
    Ok(())
});

handler!(fn socket_recv(args, ret) {
    args.check(0, 1)?;
    need_coroutine()?;
    let sock = open(&args)?;
    let max = args.long(0, 65536).clamp(1, 64 * 1024 * 1024) as usize;
    let mut buf = vec![0u8; max];
    match sock.recv(&mut buf) {
        Ok(n) => ret.bytes(&buf[..n]),
        Err(e) if e.kind() == ErrorKind::TimedOut => ret.null(),
        Err(e) => return Err(e.into()),
    }
    Ok(())
});

handler!(fn socket_close(args, ret) {
    args.check(0, 0)?;
    let taken = args.this::<PhpSocket>()?.0.borrow_mut().take();
    if let Some(sock) = taken {
        // Coroutines blocked on this socket wake up with an error instead of hanging.
        release_fd(std::os::fd::AsRawFd::as_raw_fd(sock.socket()));
    }
    ret.null();
    Ok(())
});

handler!(fn socket_peer(args, ret) {
    args.check(0, 0)?;
    ret.str(&open(&args)?.peer_address()?.to_string());
    Ok(())
});

handler!(fn socket_local(args, ret) {
    args.check(0, 0)?;
    ret.str(&open(&args)?.local_address()?.to_string());
    Ok(())
});

handler!(fn socket_is_closed(args, ret) {
    args.check(0, 0)?;
    ret.bool(args.this::<PhpSocket>()?.0.borrow().is_none());
    Ok(())
});

pub fn register() -> bool {
    let class = ClassBuilder::new("Weft\\Socket")
        .static_method("connect", socket_connect, 2, 3)
        .static_method("listen", socket_listen, 2, 3)
        .method("accept", socket_accept, 0, 1)
        .method("send", socket_send, 1, 1)
        .method("recv", socket_recv, 0, 1)
        .method("close", socket_close, 0, 0)
        .method("peer", socket_peer, 0, 0)
        .method("local", socket_local, 0, 0)
        .method("isClosed", socket_is_closed, 0, 0)
        .register();
    if let Some(c) = class {
        let _ = SOCKET.set(c);
    }
    class.is_some()
}
