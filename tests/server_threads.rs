//! The server in thread mode, driven by plain blocking clients.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use weft::network::SocketAddress;
use weft::protocol::framing::Delimited;
use weft::server::{
    Config, ConnId, Context, Framing, Handler, Listener, Mode, Role, Server, TaskContext, TaskId,
};

fn tcp(addr: &SocketAddress) -> TcpStream {
    let stream = TcpStream::connect(addr.as_inet().unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

fn read_line(reader: &mut BufReader<TcpStream>) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    line.trim_end().to_owned()
}

/// Line protocol:
/// - `echo X` replies `X`
/// - `task X` runs X through a task worker, which upper-cases it
/// - `whoami` replies the worker index
/// - `relay X` sends X to every connection of every worker via pipe messages
/// - `quit` closes the connection
struct Lines {
    role: Role,
    /// Connections waiting for a task result.
    waiting: Vec<(TaskId, ConnId)>,
}

impl Handler for Lines {
    fn on_receive(&mut self, ctx: &mut Context<'_>, conn: ConnId, data: Vec<u8>) {
        let line = String::from_utf8(data).unwrap();
        let (cmd, arg) = line.split_once(' ').unwrap_or((&line, ""));
        match cmd {
            "echo" => ctx.send(conn, format!("{arg}\n").as_bytes()).unwrap(),
            "task" => {
                let task = ctx.task(arg.as_bytes()).unwrap();
                self.waiting.push((task, conn));
            }
            "whoami" => ctx
                .send(conn, format!("{}\n", ctx.worker_id()).as_bytes())
                .unwrap(),
            "relay" => {
                for worker in 0..ctx.worker_count() {
                    let msg = format!("{arg}|{}", conn.as_u64());
                    ctx.send_message(worker, msg.as_bytes()).unwrap();
                }
            }
            "quit" => {
                ctx.send(conn, b"bye\n").unwrap();
                ctx.close(conn).unwrap();
            }
            _ => ctx.send(conn, b"?\n").unwrap(),
        }
    }

    fn on_pipe_message(&mut self, ctx: &mut Context<'_>, _from: usize, data: Vec<u8>) {
        // Every worker answers on the original connection, which may live on another
        // worker.
        let text = String::from_utf8(data).unwrap();
        let (_, origin) = text.rsplit_once('|').unwrap();
        let origin = ConnId::from_u64(origin.parse().unwrap());
        let reply = format!("worker {} saw relay\n", ctx.worker_id());
        // `send` reaches the origin connection through whichever worker owns it.
        ctx.send(origin, reply.as_bytes()).unwrap();
    }

    fn on_finish(&mut self, ctx: &mut Context<'_>, task: TaskId, result: Vec<u8>) {
        if let Some(i) = self.waiting.iter().position(|(t, _)| *t == task) {
            let (_, conn) = self.waiting.remove(i);
            let mut reply = result;
            reply.push(b'\n');
            ctx.send(conn, &reply).unwrap();
        }
    }

    fn on_task(&mut self, ctx: &TaskContext, data: Vec<u8>) -> Option<Vec<u8>> {
        assert!(matches!(self.role, Role::Task(_)));
        let mut out = data.to_ascii_uppercase();
        out.extend_from_slice(format!(" (task worker {})", ctx.worker_id).as_bytes());
        Some(out)
    }
}

fn start(config: Config) -> weft::server::RunningServer {
    Server::new(config, |role| Lines {
        role,
        waiting: Vec::new(),
    })
    .unwrap()
    .start_threads()
    .unwrap()
}

#[test]
fn echo_tasks_and_cross_worker_messages() {
    let config = Config {
        listeners: vec![
            Listener::stream("127.0.0.1:0".parse().unwrap())
                .with_framing(Framing::Delimited(Delimited::new(&b"\n"[..], 1024))),
        ],
        mode: Mode::Thread,
        workers: 2,
        task_workers: 1,
        ..Config::default()
    };
    let server = start(config);
    let addr = server.addresses()[0].clone();

    let stream = tcp(&addr);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    writer.write_all(b"echo hello\necho world\n").unwrap();
    assert_eq!(read_line(&mut reader), "hello");
    assert_eq!(read_line(&mut reader), "world");

    writer.write_all(b"task shout\n").unwrap();
    assert_eq!(read_line(&mut reader), "SHOUT (task worker 0)");

    writer.write_all(b"relay ping\n").unwrap();
    let mut seen = vec![read_line(&mut reader), read_line(&mut reader)];
    seen.sort();
    assert_eq!(seen, ["worker 0 saw relay", "worker 1 saw relay"]);

    writer.write_all(b"quit\n").unwrap();
    assert_eq!(read_line(&mut reader), "bye");
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "closed after bye");

    // Many clients spread over the workers all get answers.
    let clients: Vec<_> = (0..8)
        .map(|i| {
            let addr = addr.clone();
            std::thread::spawn(move || {
                let stream = tcp(&addr);
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                writer.write_all(format!("echo {i}\n").as_bytes()).unwrap();
                assert_eq!(read_line(&mut reader), i.to_string());
            })
        })
        .collect();
    for c in clients {
        c.join().unwrap();
    }

    server.stop();
    server.join().unwrap();
}

struct Idle;

impl Handler for Idle {
    fn on_receive(&mut self, ctx: &mut Context<'_>, conn: ConnId, data: Vec<u8>) {
        ctx.send(conn, &data).unwrap();
    }

    fn on_packet(
        &mut self,
        ctx: &mut Context<'_>,
        port: usize,
        from: SocketAddress,
        data: Vec<u8>,
    ) {
        let mut reply = b"udp:".to_vec();
        reply.extend_from_slice(&data);
        ctx.send_to(port, &from, &reply).unwrap();
    }
}

#[test]
fn idle_connections_are_closed_and_udp_works() {
    let config = Config {
        listeners: vec![
            Listener::stream("127.0.0.1:0".parse().unwrap()),
            Listener::datagram("127.0.0.1:0".parse().unwrap()),
        ],
        mode: Mode::Thread,
        workers: 1,
        idle_timeout: Some(Duration::from_millis(100)),
        ..Config::default()
    };
    let server = Server::new(config, |_| Idle)
        .unwrap()
        .start_threads()
        .unwrap();
    let tcp_addr = server.addresses()[0].clone();
    let udp_addr = server.addresses()[1].as_inet().unwrap();

    let mut stream = tcp(&tcp_addr);
    stream.write_all(b"raw bytes").unwrap();
    let mut buf = [0u8; 9];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"raw bytes");
    // Stay silent past the idle timeout: the server closes the connection.
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    udp.send_to(b"dgram", udp_addr).unwrap();
    let mut buf = [0u8; 32];
    let n = udp.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"udp:dgram");

    server.stop();
    server.join().unwrap();
}
