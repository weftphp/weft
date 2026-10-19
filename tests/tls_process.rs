//! A TLS listener in process mode: the context is built before the workers fork.
//!
//! Kept to a single test so no other test thread is running when the process forks.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use weft::network::{ServerTlsOptions, SocketAddress};
use weft::os::process::{self, ExitStatus, Fork};
use weft::protocol::framing::Delimited;
use weft::server::{Config, ConnId, Context, Framing, Handler, Listener, Mode, Server};

struct Pid;

impl Handler for Pid {
    fn on_receive(&mut self, ctx: &mut Context<'_>, conn: ConnId, data: Vec<u8>) {
        let reply = format!(
            "{} {}\n",
            process::Pid::current(),
            String::from_utf8_lossy(&data)
        );
        ctx.send(conn, reply.as_bytes()).unwrap();
    }
}

#[test]
fn forked_workers_serve_tls_over_unix_sockets() {
    let pki = common::pki();
    let path = pki.dir.join("tls.sock");
    let tls = ServerTlsOptions::new(&pki.cert, &pki.key).build().unwrap();

    // SAFETY: the child only runs the server and exits.
    let master = match unsafe { process::fork() }.unwrap() {
        Fork::Child => {
            let config = Config {
                listeners: vec![
                    Listener::stream(SocketAddress::unix(&path))
                        .with_framing(Framing::Delimited(Delimited::new(&b"\n"[..], 4096)))
                        .with_tls(tls),
                ],
                mode: Mode::Process,
                workers: 2,
                ..Config::default()
            };
            let code = match Server::new(config, |_| Pid).and_then(Server::run) {
                Ok(()) => 0,
                Err(_) => 1,
            };
            process::exit_now(code)
        }
        Fork::Parent(pid) => pid,
    };

    let deadline = Instant::now() + Duration::from_secs(10);
    let stream = loop {
        match UnixStream::connect(&path) {
            Ok(s) => break s,
            Err(e) => {
                assert!(Instant::now() < deadline, "server never came up: {e}");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut tls = BufReader::new(common::tls_client(&pki, stream, &[]));
    for word in ["one", "two"] {
        tls.get_mut()
            .write_all(format!("{word}\n").as_bytes())
            .unwrap();
        let mut line = String::new();
        tls.read_line(&mut line).unwrap();
        let (pid, echoed) = line.trim_end().split_once(' ').unwrap();
        assert_ne!(pid, master.to_string(), "answered by a forked worker");
        assert_eq!(echoed, word);
    }
    drop(tls);

    process::kill(master, libc::SIGTERM).unwrap();
    let (_, status) = process::wait(Some(master), true).unwrap().unwrap();
    assert_eq!(status, ExitStatus::Exited(0));
}
