//! A multi-worker network server.
//!
//! A [`Server`] binds its [`Listener`]s, then starts `workers` event workers (forked
//! processes or threads, see [`Mode`]) that each run an event loop: they accept connections,
//! cut input into messages per the listener's [`Framing`], and call a [`Handler`]. Each
//! worker has its own handler instance, built by the factory passed to [`Server::new`].
//!
//! Optional task workers run [`Handler::on_task`] for work handed off with
//! [`Context::task`]; results come back to the submitting worker's [`Handler::on_finish`].
//! Workers can message each other ([`Context::send_message`]) and send to or close
//! connections owned by other workers.
//!
//! Stream listeners can serve TLS ([`Listener::with_tls`]); handlers then see plaintext.
//!
//! In process mode the main process supervises the workers: it restarts crashed ones,
//! replaces them all one by one on `SIGUSR1`, and shuts down on `SIGTERM`/`SIGINT`.

pub mod config;
pub mod http;
mod ipc;
pub mod static_files;
pub mod task;
mod worker;

pub use config::{Config, Framing, Listener, Mode, Transport};
pub use ipc::TaskId;
pub use task::TaskContext;
pub use worker::{Context, wake as wake_worker};

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crate::core::log::logger;
use crate::core::{Error, ErrorKind, Result};
use crate::memory::queue::SharedQueue;
use crate::network::{Socket, SocketAddress, socket};
use crate::os::process_pool::{PoolOptions, ProcessPool};
use crate::os::signal;
use ipc::{Envelope, Mailboxes, Peers, ThreadPeers};
use worker::{Core, ListenerSlot};

/// Identifies a connection across the whole server. The owning worker is encoded in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub(crate) u64);

impl ConnId {
    /// Index of the event worker that owns the connection.
    pub fn worker(self) -> usize {
        (self.0 >> 40) as usize
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Rebuilds an id from [`as_u64`](Self::as_u64), e.g. after passing it between workers.
    pub fn from_u64(raw: u64) -> ConnId {
        ConnId(raw)
    }
}

impl fmt::Display for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.worker(), self.0 & ((1 << 40) - 1))
    }
}

/// A snapshot of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnInfo {
    pub id: ConnId,
    /// Index of the listener it arrived on.
    pub port: usize,
    pub peer: SocketAddress,
    pub connected_at: SystemTime,
    /// Time since data last arrived.
    pub idle: Duration,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub pending_output: u64,
    /// What the TLS handshake negotiated, for connections on TLS listeners.
    pub tls: Option<crate::network::TlsInfo>,
}

/// Which kind of worker a handler instance serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// An event worker, by index.
    Event(usize),
    /// A task worker, by index among task workers.
    Task(usize),
}

/// Application callbacks. Every method has a no-op default.
#[allow(unused_variables)]
pub trait Handler: 'static {
    /// The worker's event loop is starting.
    fn on_worker_start(&mut self, ctx: &mut Context<'_>) {}
    /// A stream connection was accepted.
    fn on_connect(&mut self, ctx: &mut Context<'_>, conn: ConnId) {}
    /// A message (per the listener's framing) arrived on `conn`.
    fn on_receive(&mut self, ctx: &mut Context<'_>, conn: ConnId, data: Vec<u8>) {}
    /// A datagram arrived on datagram listener `port`.
    fn on_packet(
        &mut self,
        ctx: &mut Context<'_>,
        port: usize,
        from: SocketAddress,
        data: Vec<u8>,
    ) {
    }
    /// `conn` closed (by either side).
    fn on_close(&mut self, ctx: &mut Context<'_>, conn: ConnId) {}
    /// Another worker sent a message with [`Context::send_message`].
    fn on_pipe_message(&mut self, ctx: &mut Context<'_>, from: usize, data: Vec<u8>) {}
    /// A task submitted by this worker finished with `result`.
    fn on_finish(&mut self, ctx: &mut Context<'_>, task: TaskId, result: Vec<u8>) {}
    /// [`wake_worker`] was called on this worker.
    fn on_wake(&mut self, ctx: &mut Context<'_>) {}
    /// The worker is stopping; connections get `stop_grace` to finish.
    fn on_worker_stop(&mut self, ctx: &mut Context<'_>) {}
    /// Runs in a task worker. Returning `Some` sends the result back to the submitter.
    fn on_task(&mut self, ctx: &TaskContext, data: Vec<u8>) -> Option<Vec<u8>> {
        None
    }
}

type Factory = Arc<dyn Fn(Role) -> Box<dyn Handler> + Send + Sync>;

/// See the [module documentation](self).
pub struct Server {
    config: Arc<Config>,
    factory: Factory,
}

fn bind(listener: &Listener, reuse_port: bool) -> Result<Socket> {
    match listener.transport {
        Transport::Stream => socket::listen(&listener.address, listener.backlog, reuse_port),
        Transport::Datagram => {
            let s = Socket::for_address(&listener.address, crate::network::SocketType::Datagram)?;
            if reuse_port {
                s.set_reuse_port(true)?;
            }
            s.bind(&listener.address)?;
            Ok(s)
        }
    }
}

impl Server {
    /// `factory` builds a handler for each worker (in the worker itself).
    pub fn new<H: Handler>(
        config: Config,
        factory: impl Fn(Role) -> H + Send + Sync + 'static,
    ) -> Result<Server> {
        config.validate()?;
        Ok(Server {
            config: Arc::new(config),
            factory: Arc::new(move |role| Box::new(factory(role)) as Box<dyn Handler>),
        })
    }

    fn bind_all(&self, reuse_port: bool) -> Result<Vec<Socket>> {
        self.config
            .listeners
            .iter()
            .map(|l| bind(l, reuse_port))
            .collect()
    }

    fn slots(&self, sockets: Vec<Socket>) -> Vec<ListenerSlot> {
        sockets
            .into_iter()
            .enumerate()
            .map(|(port, socket)| ListenerSlot {
                socket,
                port,
                transport: self.config.listeners[port].transport,
                token: None,
            })
            .collect()
    }

    fn task_queue(&self) -> Result<Option<Arc<SharedQueue>>> {
        if self.config.task_workers == 0 {
            return Ok(None);
        }
        Ok(Some(Arc::new(SharedQueue::new(
            self.config.task_queue_bytes.max(self.config.max_task + 64),
            self.config.max_task + 12,
        )?)))
    }

    /// Runs the server until `SIGTERM` or `SIGINT`, in the configured [`Mode`].
    pub fn run(self) -> Result<()> {
        match self.config.mode {
            Mode::Process => self.run_processes(),
            Mode::Thread => {
                let running = self.start_threads()?;
                for sig in [libc::SIGTERM, libc::SIGINT] {
                    signal::watch(sig)?;
                }
                let notifier = signal::notifier()?;
                loop {
                    let pending = signal::take_pending();
                    if pending.contains(&libc::SIGTERM) || pending.contains(&libc::SIGINT) {
                        break;
                    }
                    let mut pfd = libc::pollfd {
                        fd: std::os::fd::AsRawFd::as_raw_fd(&notifier),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: one valid pollfd.
                    unsafe { libc::poll(&mut pfd, 1, 1000) };
                }
                running.stop();
                running.join()
            }
        }
    }

    fn run_processes(self) -> Result<()> {
        let config = Arc::clone(&self.config);
        let reuse = config.reuse_port && cfg!(any(target_os = "linux", target_os = "android"));
        // With per-worker SO_REUSEPORT sockets each worker binds in its own process.
        let shared = if reuse {
            None
        } else {
            Some(self.bind_all(false)?)
        };
        let mailboxes = Mailboxes::new(config.workers)?;
        let tasks = self.task_queue()?;
        let factory = Arc::clone(&self.factory);
        let workers = config.workers;
        let this = self;

        let pool_options = PoolOptions {
            workers: workers + config.task_workers,
            stop_timeout: config.stop_grace + Duration::from_secs(2),
            min_lifetime: Duration::from_secs(1),
        };
        let pool = ProcessPool::new(pool_options, move |index| {
            let outcome = if index < workers {
                (|| -> Result<()> {
                    let sockets = match &shared {
                        Some(sockets) => sockets
                            .iter()
                            .map(Socket::try_clone)
                            .collect::<std::io::Result<Vec<_>>>()?,
                        None => this.bind_all(true)?,
                    };
                    let (inbox, peers) = mailboxes.for_worker(index)?;
                    let core = Core::new(
                        index,
                        Arc::clone(&config),
                        this.slots(sockets),
                        Box::new(peers),
                        tasks.clone(),
                    );
                    worker::run(core, factory(Role::Event(index)), inbox, |_| {}, true)
                })()
            } else {
                (|| -> Result<()> {
                    let task_index = index - workers;
                    let queue = tasks
                        .clone()
                        .ok_or_else(|| Error::new(ErrorKind::InvalidState, "no task queue"))?;
                    let (_, peers) = mailboxes.for_worker(index)?;
                    signal::watch(libc::SIGTERM)?;
                    signal::watch(libc::SIGINT)?;
                    task::run(
                        task_index,
                        queue,
                        &peers,
                        factory(Role::Task(task_index)),
                        || !signal::take_pending().is_empty(),
                    );
                    Ok(())
                })()
            };
            match outcome {
                Ok(()) => 0,
                Err(e) => {
                    logger().error(format!("worker {index} failed: {e}"));
                    1
                }
            }
        })?;
        signal::ignore(libc::SIGPIPE)?;
        pool.run(|_| false)
    }

    /// Starts the server in thread mode in the background and returns a handle to it.
    pub fn start_threads(self) -> Result<RunningServer> {
        signal::ignore(libc::SIGPIPE)?;
        let sockets = self.bind_all(false)?;
        let addresses = sockets
            .iter()
            .map(Socket::local_address)
            .collect::<std::io::Result<Vec<_>>>()?;
        let peers = ThreadPeers::new(self.config.workers);
        let tasks = self.task_queue()?;
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();

        for index in 0..self.config.workers {
            let dup = sockets
                .iter()
                .map(Socket::try_clone)
                .collect::<std::io::Result<Vec<_>>>()?;
            let slots = self.slots(dup);
            let (config, factory, tasks) = (
                Arc::clone(&self.config),
                Arc::clone(&self.factory),
                tasks.clone(),
            );
            let peers = peers.clone();
            threads.push(
                std::thread::Builder::new()
                    .name(format!("weft-worker-{index}"))
                    .spawn(move || {
                        let remotes = Arc::clone(&peers.remotes);
                        let core = Core::new(index, config, slots, Box::new(peers), tasks);
                        worker::run(
                            core,
                            factory(Role::Event(index)),
                            None,
                            |reactor| {
                                let _ = remotes[index].set(reactor.remote());
                            },
                            false,
                        )
                    })?,
            );
        }

        for task_index in 0..self.config.task_workers {
            let (factory, peers, stop) =
                (Arc::clone(&self.factory), peers.clone(), Arc::clone(&stop));
            let queue = tasks
                .clone()
                .ok_or_else(|| Error::new(ErrorKind::InvalidState, "no task queue"))?;
            threads.push(
                std::thread::Builder::new()
                    .name(format!("weft-task-{task_index}"))
                    .spawn(move || {
                        task::run(
                            task_index,
                            queue,
                            &peers,
                            factory(Role::Task(task_index)),
                            || stop.load(Ordering::Relaxed),
                        );
                        Ok(())
                    })?,
            );
        }

        Ok(RunningServer {
            addresses,
            peers,
            stop,
            threads,
            workers: self.config.workers,
        })
    }
}

/// A server running in thread mode.
pub struct RunningServer {
    addresses: Vec<SocketAddress>,
    peers: ThreadPeers,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<Result<()>>>,
    workers: usize,
}

impl RunningServer {
    /// The bound address of each listener (useful with port 0).
    pub fn addresses(&self) -> &[SocketAddress] {
        &self.addresses
    }

    /// Asks every worker to stop gracefully.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in 0..self.workers {
            // A worker that has not published its handle yet is retried briefly.
            for _ in 0..100 {
                if self.peers.deliver(worker, Envelope::Stop).is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    /// Waits for every worker thread to finish.
    pub fn join(self) -> Result<()> {
        let mut first_error = None;
        for thread in self.threads {
            match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    first_error.get_or_insert(e);
                }
                Err(_) => {
                    first_error
                        .get_or_insert(Error::new(ErrorKind::InvalidState, "worker panicked"));
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
