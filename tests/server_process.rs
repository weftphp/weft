//! The server in process mode: a supervisor process with forked event and task workers.
//!
//! Kept to a single test so no other test thread is running when the process forks.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use weft::network::SocketAddress;
use weft::os::process::{self, ExitStatus, Fork};
use weft::protocol::framing::Delimited;
use weft::server::{
    Config, ConnId, Context, Framing, Handler, Listener, Mode, Server, TaskContext, TaskId,
};

struct App {
    waiting: Vec<(TaskId, ConnId)>,
}

impl Handler for App {
    fn on_receive(&mut self, ctx: &mut Context<'_>, conn: ConnId, data: Vec<u8>) {
        let line = String::from_utf8(data).unwrap();
        match line.split_once(' ').unwrap_or((&line, "")) {
            ("echo", arg) => ctx.send(conn, format!("{arg}\n").as_bytes()).unwrap(),
            ("pid", _) => ctx
                .send(conn, format!("{}\n", process::Pid::current()).as_bytes())
                .unwrap(),
            ("task", arg) => {
                let task = ctx.task(arg.as_bytes()).unwrap();
                self.waiting.push((task, conn));
            }
            ("crash", _) => process::exit_now(3),
            _ => ctx.send(conn, b"?\n").unwrap(),
        }
    }

    fn on_finish(&mut self, ctx: &mut Context<'_>, task: TaskId, result: Vec<u8>) {
        if let Some(i) = self.waiting.iter().position(|(t, _)| *t == task) {
            let (_, conn) = self.waiting.remove(i);
            let mut reply = result;
            reply.push(b'\n');
            ctx.send(conn, &reply).unwrap();
        }
    }

    fn on_task(&mut self, _ctx: &TaskContext, data: Vec<u8>) -> Option<Vec<u8>> {
        Some(data.to_ascii_uppercase())
    }
}

fn connect(path: &Path) -> (BufReader<UnixStream>, UnixStream) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return (BufReader::new(stream.try_clone().unwrap()), stream);
            }
            Err(e) => {
                assert!(Instant::now() < deadline, "server never came up: {e}");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn ask(conn: &mut (BufReader<UnixStream>, UnixStream), line: &str) -> String {
    conn.1.write_all(format!("{line}\n").as_bytes()).unwrap();
    let mut reply = String::new();
    conn.0.read_line(&mut reply).unwrap();
    reply.trim_end().to_owned()
}

#[test]
fn supervisor_restarts_crashed_workers_and_stops_cleanly() {
    let path = std::env::temp_dir().join(format!("weft-server-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);

    // SAFETY: the child only runs the server and exits.
    let master = match unsafe { process::fork() }.unwrap() {
        Fork::Child => {
            let config = Config {
                listeners: vec![
                    Listener::stream(SocketAddress::unix(&path))
                        .with_framing(Framing::Delimited(Delimited::new(&b"\n"[..], 4096))),
                ],
                mode: Mode::Process,
                workers: 2,
                task_workers: 1,
                ..Config::default()
            };
            let code = match Server::new(config, |_| App {
                waiting: Vec::new(),
            })
            .and_then(Server::run)
            {
                Ok(()) => 0,
                Err(_) => 1,
            };
            process::exit_now(code)
        }
        Fork::Parent(pid) => pid,
    };

    let mut conn = connect(&path);
    assert_eq!(ask(&mut conn, "echo hi"), "hi");
    assert_eq!(ask(&mut conn, "task make me loud"), "MAKE ME LOUD");
    let worker_pid = ask(&mut conn, "pid");
    assert_ne!(
        worker_pid,
        master.to_string(),
        "workers are separate processes"
    );

    // Kill the worker serving us; the supervisor replaces it.
    conn.1.write_all(b"crash\n").unwrap();
    let mut rest = String::new();
    let _ = conn.0.read_line(&mut rest);
    assert!(rest.is_empty(), "connection dropped with its worker");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut fresh = connect(&path);
        let alive_workers = ask(&mut fresh, "echo still serving");
        assert_eq!(alive_workers, "still serving");
        // Once the crashed slot is refilled, connections may land on a new pid.
        let pid = ask(&mut fresh, "pid");
        if pid != worker_pid || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    process::kill(master, libc::SIGTERM).unwrap();
    let (_, status) = process::wait(Some(master), true).unwrap().unwrap();
    assert_eq!(status, ExitStatus::Exited(0));
    assert!(
        UnixStream::connect(&path).is_err(),
        "nothing listens after shutdown"
    );
    let _ = std::fs::remove_file(&path);
}
