//! The event worker: one reactor that accepts connections, frames their input, calls the
//! [`Handler`], and writes replies with backpressure.
//!
//! Reactor callbacks only update state and queue [`Event`]s; [`pump`] then feeds the events
//! to the handler one at a time. Handler actions that would produce further events (such as
//! closing a connection) queue them too, so the handler is never re-entered.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io;
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use super::config::{BoxDecoder, Config, Transport};
use super::ipc::{Envelope, Inbox, Peers, TaskId, encode_task};
use super::{ConnId, ConnInfo, Handler};
use crate::core::buffer::{Segment, WriteQueue};
use crate::core::bytes::ByteBuffer;
use crate::core::timer::TimerId;
use crate::core::{Error, ErrorKind, Result};
use crate::memory::queue::SharedQueue;
use crate::network::{Socket, SocketAddress};
use crate::reactor::{Interest, Reactor, Readiness, Token};

/// A listening socket of this worker.
pub(crate) struct ListenerSlot {
    pub socket: Socket,
    pub port: usize,
    pub transport: Transport,
    pub token: Option<Token>,
}

struct Conn {
    socket: Socket,
    token: Token,
    port: usize,
    peer: SocketAddress,
    connected_at: SystemTime,
    last_active: Instant,
    input: ByteBuffer,
    output: WriteQueue,
    decoder: Option<BoxDecoder>,
    interest: Interest,
    /// Close once the output drains.
    closing: bool,
    /// Reading suspended by the handler.
    paused: bool,
    bytes_in: u64,
    bytes_out: u64,
}

type TimerFn = Box<dyn FnOnce(&mut Context<'_>)>;

pub(crate) enum Event {
    Connect(ConnId),
    Receive(ConnId, Vec<u8>),
    Packet {
        port: usize,
        from: SocketAddress,
        data: Vec<u8>,
    },
    Close(ConnId),
    PipeMessage {
        from: usize,
        data: Vec<u8>,
    },
    TaskResult {
        task: TaskId,
        data: Vec<u8>,
    },
    Timer(TimerFn),
    Stop,
}

/// Worker state reached from reactor callbacks.
pub(crate) struct Core {
    pub index: usize,
    pub config: Arc<Config>,
    pub listeners: Vec<ListenerSlot>,
    conns: HashMap<ConnId, Conn>,
    by_token: HashMap<Token, ConnId>,
    next_conn: u64,
    events: VecDeque<Event>,
    pub peers: Box<dyn Peers>,
    pub tasks: Option<Arc<SharedQueue>>,
    next_task: u64,
    handled: u64,
    stopping: Option<Instant>,
}

pub(crate) struct Shared {
    core: RefCell<Core>,
    handler: RefCell<Option<Box<dyn Handler>>>,
}

thread_local! {
    static CURRENT: RefCell<Option<Rc<Shared>>> = const { RefCell::new(None) };
}

fn current() -> Option<Rc<Shared>> {
    CURRENT.with(|c| c.borrow().clone())
}

/// What a handler can do while handling an event.
pub struct Context<'a> {
    core: &'a mut Core,
    reactor: &'a mut Reactor,
}

impl Core {
    pub fn new(
        index: usize,
        config: Arc<Config>,
        listeners: Vec<ListenerSlot>,
        peers: Box<dyn Peers>,
        tasks: Option<Arc<SharedQueue>>,
    ) -> Core {
        Core {
            index,
            config,
            listeners,
            conns: HashMap::new(),
            by_token: HashMap::new(),
            next_conn: 0,
            events: VecDeque::new(),
            peers,
            tasks,
            next_task: 0,
            handled: 0,
            stopping: None,
        }
    }

    fn new_conn_id(&mut self) -> ConnId {
        self.next_conn += 1;
        ConnId((self.index as u64) << 40 | self.next_conn)
    }

    // ----- input -----

    fn accept(&mut self, r: &mut Reactor, slot: usize) {
        for _ in 0..64 {
            let (socket, peer) = match self.listeners[slot].socket.accept() {
                Ok(pair) => pair,
                // WouldBlock (another worker won the race), or a transient error such as
                // a connection reset before we accepted it.
                Err(_) => return,
            };
            if self.conns.len() >= self.config.max_connections || self.stopping.is_some() {
                continue;
            }
            let port = self.listeners[slot].port;
            let config = Arc::clone(&self.config);
            let listener = &config.listeners[port];
            if listener.nodelay && peer.as_inet().is_some() {
                let _ = socket.set_nodelay(true);
            }
            let id = self.new_conn_id();
            let fd = socket.as_raw_fd();
            let token = match r.add(fd, Interest::READABLE, move |r, _, readiness| {
                with_core(r, |core, r| core.on_conn_ready(r, id, readiness));
            }) {
                Ok(token) => token,
                Err(_) => continue,
            };
            self.by_token.insert(token, id);
            self.conns.insert(
                id,
                Conn {
                    socket,
                    token,
                    port,
                    peer,
                    connected_at: SystemTime::now(),
                    last_active: Instant::now(),
                    input: ByteBuffer::new(),
                    output: WriteQueue::default(),
                    decoder: listener.framing.decoder(),
                    interest: Interest::READABLE,
                    closing: false,
                    paused: false,
                    bytes_in: 0,
                    bytes_out: 0,
                },
            );
            self.events.push_back(Event::Connect(id));
        }
    }

    fn receive_datagrams(&mut self, slot: usize) {
        let mut buf = vec![0u8; 65_536];
        for _ in 0..64 {
            match self.listeners[slot].socket.recv_from(&mut buf) {
                Ok((n, from)) => self.events.push_back(Event::Packet {
                    port: self.listeners[slot].port,
                    from,
                    data: buf[..n].to_vec(),
                }),
                Err(_) => return,
            }
        }
    }

    fn on_conn_ready(&mut self, r: &mut Reactor, id: ConnId, readiness: Readiness) {
        if readiness.writable {
            self.flush(r, id);
        }
        if readiness.readable || readiness.hangup || readiness.error {
            self.read(r, id);
        }
    }

    fn read(&mut self, r: &mut Reactor, id: ConnId) {
        let chunk = self.config.read_chunk;
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        if conn.paused || conn.closing {
            return;
        }
        let socket = &conn.socket;
        let result = conn.input.fill_with(chunk, |space| socket.recv(space));
        match result {
            Ok(0) => {
                // Deliver anything still decodable, then close.
                self.decode(id);
                self.close_now(r, id);
            }
            Ok(n) => {
                conn.bytes_in += n as u64;
                conn.last_active = Instant::now();
                self.decode(id);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => self.close_now(r, id),
        }
    }

    fn decode(&mut self, id: ConnId) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        match &mut conn.decoder {
            None => {
                if !conn.input.is_empty() {
                    let data = conn.input.as_slice().to_vec();
                    conn.input.clear();
                    self.events.push_back(Event::Receive(id, data));
                }
            }
            Some(decoder) => loop {
                match decoder.decode(&mut conn.input) {
                    Ok(Some(message)) => self.events.push_back(Event::Receive(id, message)),
                    Ok(None) => break,
                    Err(_) => {
                        // Unframeable input: drop the connection once pending output is out.
                        conn.closing = true;
                        conn.input.clear();
                        break;
                    }
                }
            },
        }
    }

    // ----- output -----

    fn set_interest(&mut self, r: &mut Reactor, id: ConnId) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        let mut want = Interest::NONE;
        if !conn.paused && !conn.closing {
            want = want | Interest::READABLE;
        }
        if !conn.output.is_empty() {
            want = want | Interest::WRITABLE;
        }
        if want != conn.interest && r.set_interest(conn.token, want).is_ok() {
            conn.interest = want;
        }
    }

    /// Writes as much pending output as the socket takes.
    fn flush(&mut self, r: &mut Reactor, id: ConnId) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        loop {
            let step: io::Result<Option<usize>> = match conn.output.front_mut() {
                None => break,
                Some(Segment::Bytes { .. }) => {
                    let slices = conn.output.io_slices(64);
                    conn.socket.send_vectored(&slices).map(Some)
                }
                Some(Segment::File {
                    file,
                    offset,
                    remaining,
                }) => crate::os::sendfile::send_file(
                    conn.socket.as_fd(),
                    file,
                    *offset,
                    (*remaining).min(usize::MAX as u64) as usize,
                )
                .map(Some),
                Some(Segment::Shutdown) => {
                    let _ = conn.socket.shutdown(Shutdown::Write);
                    conn.output.pop_front();
                    Ok(None)
                }
            };
            match step {
                Ok(Some(0)) => {
                    // A file segment ended early: drop it rather than spin.
                    conn.output.pop_front();
                }
                Ok(Some(n)) => {
                    conn.bytes_out += n as u64;
                    conn.output.advance(n as u64);
                }
                Ok(None) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.close_now(r, id);
                    return;
                }
            }
        }
        if conn.output.is_empty() && conn.closing {
            self.close_now(r, id);
            return;
        }
        self.set_interest(r, id);
    }

    fn close_now(&mut self, r: &mut Reactor, id: ConnId) {
        if let Some(conn) = self.conns.remove(&id) {
            self.by_token.remove(&conn.token);
            let _ = r.remove(conn.token);
            self.events.push_back(Event::Close(id));
        }
    }

    // ----- envelopes from other workers -----

    pub fn handle_envelope(&mut self, r: &mut Reactor, envelope: Envelope) {
        match envelope {
            Envelope::Message { from, data } => {
                self.events.push_back(Event::PipeMessage { from, data })
            }
            Envelope::Send { conn, data } => {
                let _ = self.send_local(r, conn, &data);
            }
            Envelope::Close { conn } => self.close(r, conn),
            Envelope::TaskResult { task, data } => {
                self.events.push_back(Event::TaskResult { task, data })
            }
            Envelope::Stop => self.begin_stop(r),
        }
    }

    fn send_local(&mut self, r: &mut Reactor, id: ConnId, data: &[u8]) -> Result<()> {
        let limit = self.config.max_output as u64;
        let conn = self
            .conns
            .get_mut(&id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no connection {}", id.0)))?;
        if conn.closing {
            return Err(Error::new(ErrorKind::Closed, "connection is closing"));
        }
        if conn.output.pending() + data.len() as u64 > limit {
            return Err(Error::new(ErrorKind::Full, "output buffer full"));
        }
        conn.output.push_bytes(data);
        self.flush(r, id);
        Ok(())
    }

    fn close(&mut self, r: &mut Reactor, id: ConnId) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        if conn.output.is_empty() {
            self.close_now(r, id);
        } else {
            conn.closing = true;
            self.set_interest(r, id);
        }
    }

    // ----- lifecycle -----

    fn begin_stop(&mut self, r: &mut Reactor) {
        if self.stopping.is_some() {
            return;
        }
        self.stopping = Some(Instant::now());
        for slot in &mut self.listeners {
            if let Some(token) = slot.token.take() {
                let _ = r.remove(token);
            }
        }
        self.events.push_back(Event::Stop);
        let grace = self.config.stop_grace;
        let _ = r.every(Duration::from_millis(20), move |r, timer| {
            with_core(r, |core, r| {
                let expired = core.stopping.is_some_and(|since| since.elapsed() >= grace);
                if core.conns.is_empty() || expired {
                    let ids: Vec<ConnId> = core.conns.keys().copied().collect();
                    for id in ids {
                        core.close_now(r, id);
                    }
                    r.cancel_timer(timer);
                    // Let the close events reach the handler before the loop ends.
                    r.defer(|r| r.stop());
                }
            });
        });
    }

    fn check_idle(&mut self, r: &mut Reactor, idle: Duration) {
        let stale: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| c.last_active.elapsed() >= idle)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.close_now(r, id);
        }
    }
}

/// Runs `f` on the current thread's worker core, then feeds queued events to the handler.
fn with_core(r: &mut Reactor, f: impl FnOnce(&mut Core, &mut Reactor)) {
    let Some(shared) = current() else {
        return;
    };
    {
        let mut core = shared.core.borrow_mut();
        f(&mut core, r);
    }
    pump(&shared, r);
}

/// Delivers an envelope posted from another thread to this thread's worker.
pub(crate) fn deliver_local(r: &mut Reactor, envelope: Envelope) {
    with_core(r, |core, r| core.handle_envelope(r, envelope));
}

/// Feeds every queued event to the handler.
fn pump(shared: &Rc<Shared>, r: &mut Reactor) {
    loop {
        let Some(event) = shared.core.borrow_mut().events.pop_front() else {
            return;
        };
        let Some(mut handler) = shared.handler.borrow_mut().take() else {
            return;
        };
        {
            let mut core = shared.core.borrow_mut();
            let mut ctx = Context {
                core: &mut core,
                reactor: r,
            };
            match event {
                Event::Connect(id) => handler.on_connect(&mut ctx, id),
                Event::Receive(id, data) => {
                    ctx.core.handled += 1;
                    handler.on_receive(&mut ctx, id, data);
                    if let Some(max) = ctx.core.config.max_requests
                        && ctx.core.handled >= max
                    {
                        ctx.core.begin_stop(ctx.reactor);
                    }
                }
                Event::Packet { port, from, data } => handler.on_packet(&mut ctx, port, from, data),
                Event::Close(id) => handler.on_close(&mut ctx, id),
                Event::PipeMessage { from, data } => handler.on_pipe_message(&mut ctx, from, data),
                Event::TaskResult { task, data } => handler.on_finish(&mut ctx, task, data),
                Event::Timer(f) => f(&mut ctx),
                Event::Stop => handler.on_worker_stop(&mut ctx),
            }
        }
        *shared.handler.borrow_mut() = Some(handler);
    }
}

impl<'a> Context<'a> {
    /// This worker's index.
    pub fn worker_id(&self) -> usize {
        self.core.index
    }

    /// Number of event workers in the server.
    pub fn worker_count(&self) -> usize {
        self.core.config.workers
    }

    /// Queues `data` on `conn`. Connections owned by another worker are reached through it.
    /// Fails with [`ErrorKind::Full`] when the connection's output buffer is over its limit.
    pub fn send(&mut self, conn: ConnId, data: &[u8]) -> Result<()> {
        if conn.worker() != self.core.index {
            return self.core.peers.deliver(
                conn.worker(),
                Envelope::Send {
                    conn,
                    data: data.to_vec(),
                },
            );
        }
        self.core.send_local(self.reactor, conn, data)
    }

    /// Streams `len` bytes of the file at `path` from `offset`, after any queued data.
    pub fn send_file(
        &mut self,
        conn: ConnId,
        path: impl AsRef<std::path::Path>,
        offset: u64,
        len: Option<u64>,
    ) -> Result<()> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        let len = len
            .unwrap_or(size.saturating_sub(offset))
            .min(size.saturating_sub(offset));
        let c = self
            .core
            .conns
            .get_mut(&conn)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "no such local connection"))?;
        c.output.push_file(file, offset, len);
        self.core.flush(self.reactor, conn);
        Ok(())
    }

    /// Closes `conn` after its queued output is sent. `on_close` follows.
    pub fn close(&mut self, conn: ConnId) -> Result<()> {
        if conn.worker() != self.core.index {
            return self
                .core
                .peers
                .deliver(conn.worker(), Envelope::Close { conn });
        }
        self.core.close(self.reactor, conn);
        Ok(())
    }

    /// Sends FIN after queued output, keeping the read side open.
    pub fn shutdown_write(&mut self, conn: ConnId) -> Result<()> {
        let c = self
            .core
            .conns
            .get_mut(&conn)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "no such local connection"))?;
        c.output.push_shutdown();
        self.core.flush(self.reactor, conn);
        Ok(())
    }

    /// Stops reading from `conn` (its data waits in the kernel) until [`resume`](Self::resume).
    pub fn pause(&mut self, conn: ConnId) {
        if let Some(c) = self.core.conns.get_mut(&conn) {
            c.paused = true;
        }
        self.core.set_interest(self.reactor, conn);
    }

    pub fn resume(&mut self, conn: ConnId) {
        if let Some(c) = self.core.conns.get_mut(&conn) {
            c.paused = false;
            // Bytes buffered while paused may already form messages.
            self.core.decode(conn);
        }
        self.core.set_interest(self.reactor, conn);
    }

    /// Details of a connection owned by this worker.
    pub fn info(&self, conn: ConnId) -> Option<ConnInfo> {
        self.core.conns.get(&conn).map(|c| ConnInfo {
            id: conn,
            port: c.port,
            peer: c.peer.clone(),
            connected_at: c.connected_at,
            idle: c.last_active.elapsed(),
            bytes_in: c.bytes_in,
            bytes_out: c.bytes_out,
            pending_output: c.output.pending(),
        })
    }

    /// Connections owned by this worker.
    pub fn connections(&self) -> Vec<ConnId> {
        self.core.conns.keys().copied().collect()
    }

    /// Sends a datagram from datagram listener `port`.
    pub fn send_to(&mut self, port: usize, to: &SocketAddress, data: &[u8]) -> Result<()> {
        let slot = self
            .core
            .listeners
            .iter()
            .find(|l| l.port == port && l.transport == Transport::Datagram)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no datagram port {port}")))?;
        slot.socket.send_to(data, to)?;
        Ok(())
    }

    /// Hands `data` to a task worker; the result arrives in `on_finish`.
    pub fn task(&mut self, data: &[u8]) -> Result<TaskId> {
        let queue = self
            .core
            .tasks
            .clone()
            .ok_or_else(|| Error::new(ErrorKind::InvalidState, "no task workers configured"))?;
        if data.len() > self.core.config.max_task {
            return Err(Error::new(ErrorKind::TooLarge, "task exceeds max_task"));
        }
        self.core.next_task += 1;
        let id = TaskId((self.core.index as u64) << 40 | self.core.next_task);
        queue.try_push(&encode_task(id, self.core.index, data))?;
        Ok(id)
    }

    /// Sends a message to another event worker's `on_pipe_message`.
    pub fn send_message(&mut self, worker: usize, data: &[u8]) -> Result<()> {
        let from = self.core.index;
        if worker == from {
            self.core.events.push_back(Event::PipeMessage {
                from,
                data: data.to_vec(),
            });
            return Ok(());
        }
        self.core.peers.deliver(
            worker,
            Envelope::Message {
                from,
                data: data.to_vec(),
            },
        )
    }

    /// Runs `f` with a context after `delay`.
    pub fn after(
        &mut self,
        delay: Duration,
        f: impl FnOnce(&mut Context<'_>) + 'static,
    ) -> TimerId {
        self.reactor.after(delay, move |r| {
            with_core(r, |core, _| {
                core.events.push_back(Event::Timer(Box::new(f)))
            });
        })
    }

    /// Runs `f` with a context every `period` until cancelled.
    pub fn every(
        &mut self,
        period: Duration,
        f: impl FnMut(&mut Context<'_>, TimerId) + 'static,
    ) -> Result<TimerId> {
        let f = Rc::new(RefCell::new(f));
        self.reactor.every(period, move |r, id| {
            let f = Rc::clone(&f);
            with_core(r, |core, _| {
                core.events.push_back(Event::Timer(Box::new(move |ctx| {
                    (f.borrow_mut())(ctx, id);
                })))
            });
        })
    }

    pub fn cancel_timer(&mut self, timer: TimerId) -> bool {
        self.reactor.cancel_timer(timer)
    }

    /// Begins a graceful stop of this worker (it will be restarted in process mode unless
    /// the server is shutting down).
    pub fn stop_worker(&mut self) {
        self.core.begin_stop(self.reactor);
    }

    /// The worker's event loop, for registering custom descriptors.
    pub fn reactor(&mut self) -> &mut Reactor {
        self.reactor
    }
}

/// Runs an event worker on the current thread until it stops.
pub(crate) fn run(
    mut core: Core,
    handler: Box<dyn Handler>,
    inbox: Option<Inbox>,
    publish_remote: impl FnOnce(&Reactor),
    stop_on_signal: bool,
) -> Result<()> {
    let mut reactor = Reactor::new()?;
    publish_remote(&reactor);

    for (slot, listener) in core.listeners.iter_mut().enumerate() {
        let transport = listener.transport;
        let token = reactor.add(
            listener.socket.as_raw_fd(),
            Interest::READABLE,
            move |r, _, _| {
                with_core(r, |core, r| match transport {
                    Transport::Stream => core.accept(r, slot),
                    Transport::Datagram => core.receive_datagrams(slot),
                });
            },
        )?;
        listener.token = Some(token);
    }

    if let Some(mut inbox) = inbox {
        let fd = inbox.socket.as_raw_fd();
        // The inbox lives in the callback; the worker never outlives its reactor.
        reactor.add(fd, Interest::READABLE, move |r, _, _| {
            let envelopes = inbox.drain();
            with_core(r, |core, r| {
                for envelope in envelopes {
                    core.handle_envelope(r, envelope);
                }
            });
        })?;
    }

    if let Some(idle) = core.config.idle_timeout {
        let period = (idle / 2).max(Duration::from_millis(10));
        reactor.every(period, move |r, _| {
            with_core(r, |core, r| core.check_idle(r, idle))
        })?;
    }

    if stop_on_signal {
        for sig in [libc::SIGTERM, libc::SIGINT] {
            reactor.on_signal(sig, |r, _| with_core(r, |core, r| core.begin_stop(r)))?;
        }
        crate::os::signal::ignore(libc::SIGPIPE)?;
    }

    let shared = Rc::new(Shared {
        core: RefCell::new(core),
        handler: RefCell::new(Some(handler)),
    });
    CURRENT.with(|c| *c.borrow_mut() = Some(Rc::clone(&shared)));

    // on_worker_start runs first, through the same machinery as other events.
    reactor.defer(|r| {
        let Some(shared) = current() else { return };
        let Some(mut handler) = shared.handler.borrow_mut().take() else {
            return;
        };
        {
            let mut core = shared.core.borrow_mut();
            let mut ctx = Context {
                core: &mut core,
                reactor: r,
            };
            handler.on_worker_start(&mut ctx);
        }
        *shared.handler.borrow_mut() = Some(handler);
        pump(&shared, r);
    });
    // Keep running even before the first connection arrives.
    reactor.hold();
    let result = reactor.run();
    CURRENT.with(|c| c.borrow_mut().take());
    result
}
