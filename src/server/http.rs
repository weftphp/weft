//! An HTTP server on top of [`Server`]: HTTP/1.1 with keep-alive and pipelining, HTTP/2,
//! WebSocket upgrades, and static files.
//!
//! HTTP/2 is recognised by its connection preface: in cleartext that is prior knowledge,
//! and over TLS it follows an ALPN agreement on `h2`. For HTTPS, give listeners a
//! [`ServerTls`](crate::network::ServerTls) offering `["h2", "http/1.1"]`.
//!
//! Applications implement [`HttpApp`]. [`HttpApp::on_request`] may answer at once by
//! returning a [`Response`], or later through [`HttpContext::respond`] (for example after a
//! task or timer); HTTP/1.1 responses still go out in request order.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use super::config::{Config, Framing};
use super::static_files::{self, Reply};
use super::{ConnId, Context, Handler, Role, Server, TaskContext, TaskId};
use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, Result};
use crate::protocol::http::{self, Limits, Method, Request, RequestParser, Response, Version};
use crate::protocol::http2::frame::{PREFACE, Reason};
use crate::protocol::http2::hpack::Field;
use crate::protocol::http2::session::{self, Event, ServerSession};
use crate::protocol::websocket::{
    self, Assembler, FrameDecoder, Message, close_code, encode_frame,
};

/// HTTP behaviour on top of the server [`Config`].
#[derive(Debug, Clone)]
pub struct HttpOptions {
    pub limits: Limits,
    /// Serve GET/HEAD requests from this directory when a file matches the path.
    pub static_root: Option<PathBuf>,
    /// Files tried for directory paths under `static_root`.
    pub index_files: Vec<String>,
    /// Accept WebSocket upgrades (each still needs [`HttpApp::on_upgrade`] to agree).
    pub websocket: bool,
    /// Accept HTTP/2 connections that start with the connection preface. When off, TLS
    /// listeners must not offer `h2` through ALPN.
    pub http2: bool,
    pub max_ws_message: usize,
    /// Value of the `Server` header, if any.
    pub server_name: Option<String>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        HttpOptions {
            limits: Limits::default(),
            static_root: None,
            index_files: vec!["index.html".into()],
            websocket: true,
            http2: true,
            max_ws_message: 16 * 1024 * 1024,
            server_name: Some("weft".into()),
        }
    }
}

/// Identifies one request on one connection (its pipeline position, or HTTP/2 stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId {
    pub conn: ConnId,
    seq: u64,
}

/// HTTP application callbacks. Only [`on_request`](Self::on_request) is required.
#[allow(unused_variables)]
pub trait HttpApp: 'static {
    fn on_worker_start(&mut self, ctx: &mut HttpContext<'_, '_>) {}

    /// Answers a request now (`Some`) or later with [`HttpContext::respond`] (`None`).
    fn on_request(
        &mut self,
        ctx: &mut HttpContext<'_, '_>,
        id: RequestId,
        request: Request,
    ) -> Option<Response>;

    /// Whether to accept a WebSocket upgrade for `request`.
    fn on_upgrade(
        &mut self,
        ctx: &mut HttpContext<'_, '_>,
        conn: ConnId,
        request: &Request,
    ) -> bool {
        false
    }

    /// A WebSocket message (pings are answered automatically and not reported).
    fn on_message(&mut self, ctx: &mut HttpContext<'_, '_>, conn: ConnId, message: Message) {}

    /// A WebSocket connection ended.
    fn on_ws_close(&mut self, ctx: &mut HttpContext<'_, '_>, conn: ConnId) {}

    fn on_finish(&mut self, ctx: &mut HttpContext<'_, '_>, task: TaskId, result: Vec<u8>) {}

    fn on_pipe_message(&mut self, ctx: &mut HttpContext<'_, '_>, from: usize, data: Vec<u8>) {}

    fn on_task(&mut self, ctx: &TaskContext, data: Vec<u8>) -> Option<Vec<u8>> {
        None
    }
}

/// A ready response, serialized.
enum Ready {
    Bytes(Vec<u8>),
    File {
        head: Vec<u8>,
        path: PathBuf,
        offset: u64,
        len: u64,
    },
}

struct Pipelined {
    seq: u64,
    head_only: bool,
    keep_alive: bool,
    ready: Option<Ready>,
}

struct Http1 {
    parser: RequestParser,
    buffer: ByteBuffer,
    next_seq: u64,
    queue: VecDeque<Pipelined>,
    /// No more requests are read after a non-keep-alive one.
    last_seq: Option<u64>,
    continue_sent: bool,
}

struct WebSocket {
    buffer: ByteBuffer,
    decoder: FrameDecoder,
    assembler: Assembler,
    closing: bool,
}

enum Proto {
    Http1(Http1),
    WebSocket(WebSocket),
    Http2(Box<ServerSession>),
}

/// What [`HttpApp`] callbacks can do.
pub struct HttpContext<'c, 'a> {
    ctx: &'c mut Context<'a>,
    conns: &'c mut HashMap<ConnId, Proto>,
    deferred: &'c mut Vec<(RequestId, Response)>,
    options: &'c HttpOptions,
}

impl<'c, 'a> HttpContext<'c, 'a> {
    /// The underlying server context (tasks, timers, raw sends, worker info).
    pub fn server(&mut self) -> &mut Context<'a> {
        self.ctx
    }

    /// Answers request `id` that [`HttpApp::on_request`] left pending.
    pub fn respond(&mut self, id: RequestId, response: Response) -> Result<()> {
        if !self.conns.contains_key(&id.conn) {
            // The connection is being processed right now; apply once it is back.
            self.deferred.push((id, response));
            return Ok(());
        }
        deliver(self.ctx, self.conns, self.options, id, response)
    }

    /// Sends a WebSocket message. Works for connections owned by other workers too.
    pub fn ws_send(&mut self, conn: ConnId, message: Message) -> Result<()> {
        self.ctx
            .send(conn, &encode_frame(&message.into_frame(), None))
    }

    /// Starts the WebSocket closing handshake.
    pub fn ws_close(&mut self, conn: ConnId, code: u16, reason: &str) -> Result<()> {
        let frame = Message::Close(Some(websocket::CloseReason {
            code,
            reason: reason.to_owned(),
        }))
        .into_frame();
        self.ctx.send(conn, &encode_frame(&frame, None))?;
        if let Some(Proto::WebSocket(ws)) = self.conns.get_mut(&conn) {
            ws.closing = true;
        }
        Ok(())
    }

    /// WebSocket connections owned by this worker.
    pub fn websockets(&self) -> Vec<ConnId> {
        self.conns
            .iter()
            .filter(|(_, p)| matches!(p, Proto::WebSocket(_)))
            .map(|(id, _)| *id)
            .collect()
    }
}

fn finalize(options: &HttpOptions, mut response: Response, keep_alive: bool) -> Response {
    if !response.headers.contains("date") {
        response
            .headers
            .append("Date", http::date::format(SystemTime::now()));
    }
    if let Some(name) = &options.server_name
        && !response.headers.contains("server")
    {
        response.headers.append("Server", name.clone());
    }
    if !keep_alive {
        response.headers.set("Connection", "close");
    }
    response
}

/// Puts a response into its pipeline slot (or HTTP/2 stream) and sends what is ready.
fn deliver(
    ctx: &mut Context<'_>,
    conns: &mut HashMap<ConnId, Proto>,
    options: &HttpOptions,
    id: RequestId,
    response: Response,
) -> Result<()> {
    match conns.get_mut(&id.conn) {
        Some(Proto::Http1(h1)) => {
            let slot = h1
                .queue
                .iter_mut()
                .find(|p| p.seq == id.seq && p.ready.is_none())
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "request already answered"))?;
            let response = finalize(options, response, slot.keep_alive);
            slot.ready = Some(if slot.head_only {
                Ready::Bytes(response.encode_head(response.body.len()))
            } else {
                Ready::Bytes(response.encode())
            });
            flush_pipeline(ctx, h1, id.conn)
        }
        Some(Proto::Http2(session)) => {
            respond_h2(session, id.seq as u32, finalize(options, response, true))?;
            ctx.send(id.conn, &session.take_output())
        }
        _ => Err(Error::new(ErrorKind::NotFound, "connection is gone")),
    }
}

fn flush_pipeline(ctx: &mut Context<'_>, h1: &mut Http1, conn: ConnId) -> Result<()> {
    while h1.queue.front().is_some_and(|p| p.ready.is_some()) {
        let Some(done) = h1.queue.pop_front() else {
            break;
        };
        match done.ready {
            Some(Ready::Bytes(bytes)) => ctx.send(conn, &bytes)?,
            Some(Ready::File {
                head,
                path,
                offset,
                len,
            }) => {
                ctx.send(conn, &head)?;
                ctx.send_file(conn, &path, offset, Some(len))?;
            }
            None => {}
        }
        if !done.keep_alive {
            ctx.close(conn)?;
        }
    }
    Ok(())
}

fn respond_h2(session: &mut ServerSession, stream: u32, response: Response) -> Result<()> {
    let mut fields = vec![Field::new(":status", response.status.to_string())];
    for (name, value) in response.headers.iter() {
        let name = name.to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
        ) {
            continue;
        }
        fields.push(Field::new(name, value));
    }
    let empty = response.body.is_empty() || response.is_bodiless();
    session.send_headers(stream, &fields, empty)?;
    if !empty {
        session.send_data(stream, &response.body, true)?;
    }
    Ok(())
}

fn h2_request(head: session::RequestHead, headers: Vec<Field>, body: Vec<u8>) -> Option<Request> {
    let method = head.method.parse::<Method>().ok()?;
    let target = head.path.clone().or_else(|| head.authority.clone())?;
    let mut request = Request::new(method, target);
    request.version = Version::Http11;
    if let Some(authority) = &head.authority {
        request.headers.append("host", authority.clone());
    }
    for field in headers {
        request.headers.append(
            String::from_utf8_lossy(&field.name).into_owned(),
            String::from_utf8_lossy(&field.value).into_owned(),
        );
    }
    request.body = body;
    Some(request)
}

/// The [`Handler`] that runs an [`HttpApp`].
struct Adapter<A> {
    app: A,
    conns: HashMap<ConnId, Proto>,
    deferred: Vec<(RequestId, Response)>,
    options: Arc<HttpOptions>,
}

impl<A: HttpApp> Adapter<A> {
    fn new_http1(&self) -> Proto {
        Proto::Http1(Http1 {
            parser: RequestParser::new(self.options.limits),
            buffer: ByteBuffer::new(),
            next_seq: 0,
            queue: VecDeque::new(),
            last_seq: None,
            continue_sent: false,
        })
    }

    /// Runs `f` with the app and a context, then applies responses deferred meanwhile.
    fn call<R>(
        &mut self,
        ctx: &mut Context<'_>,
        f: impl FnOnce(&mut A, &mut HttpContext<'_, '_>) -> R,
    ) -> R {
        let mut hctx = HttpContext {
            ctx,
            conns: &mut self.conns,
            deferred: &mut self.deferred,
            options: &self.options,
        };
        f(&mut self.app, &mut hctx)
    }

    fn apply_deferred(&mut self, ctx: &mut Context<'_>) {
        for (id, response) in std::mem::take(&mut self.deferred) {
            let _ = deliver(ctx, &mut self.conns, &self.options, id, response);
        }
    }

    fn http1(
        &mut self,
        ctx: &mut Context<'_>,
        conn: ConnId,
        mut h1: Http1,
        data: &[u8],
    ) -> Option<Proto> {
        h1.buffer.extend_from_slice(data);
        if self.options.http2 && h1.next_seq == 0 {
            let have = h1.buffer.len().min(PREFACE.len());
            if h1.buffer.as_slice()[..have] == PREFACE[..have] {
                if have < PREFACE.len() {
                    return Some(Proto::Http1(h1));
                }
                let config = session::Config {
                    max_body: self.options.limits.max_body,
                    ..session::Config::default()
                };
                let session = Box::new(ServerSession::new(config));
                let buffered = h1.buffer.as_slice().to_vec();
                return self.http2(ctx, conn, session, &buffered);
            }
        }
        loop {
            if h1.last_seq.is_some() {
                h1.buffer.clear();
                break;
            }
            match h1.parser.parse(&mut h1.buffer) {
                Err(err) => {
                    let response = finalize(
                        &self.options,
                        Response::new(err.status).with_body(err.message.clone()),
                        false,
                    );
                    let seq = h1.next_seq;
                    h1.next_seq += 1;
                    h1.last_seq = Some(seq);
                    h1.queue.push_back(Pipelined {
                        seq,
                        head_only: false,
                        keep_alive: false,
                        ready: Some(Ready::Bytes(response.encode())),
                    });
                    break;
                }
                Ok(None) => {
                    if !h1.continue_sent
                        && let Some((_, _, headers)) = h1.parser.pending()
                        && headers
                            .get("expect")
                            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
                    {
                        h1.continue_sent = true;
                        let _ = ctx.send(conn, b"HTTP/1.1 100 Continue\r\n\r\n");
                    }
                    break;
                }
                Ok(Some(request)) => {
                    h1.continue_sent = false;
                    let seq = h1.next_seq;
                    h1.next_seq += 1;
                    let keep_alive = request.keep_alive();
                    if !keep_alive {
                        h1.last_seq = Some(seq);
                    }
                    let head_only = request.method == Method::Head;

                    if self.options.websocket
                        && request.wants_upgrade("websocket")
                        && h1.queue.is_empty()
                        && self.call(ctx, |app, c| app.on_upgrade(c, conn, &request))
                    {
                        match websocket::handshake_response(&request, None) {
                            Ok(response) => {
                                let _ = ctx.send(
                                    conn,
                                    &finalize(&self.options, response, true).encode_head(0),
                                );
                                let leftover = h1.buffer.as_slice().to_vec();
                                let ws = WebSocket {
                                    buffer: ByteBuffer::new(),
                                    decoder: FrameDecoder::new(
                                        websocket::Role::Server,
                                        self.options.max_ws_message,
                                    ),
                                    assembler: Assembler::new(self.options.max_ws_message),
                                    closing: false,
                                };
                                return self.websocket(ctx, conn, ws, &leftover);
                            }
                            Err(err) => {
                                let response = finalize(
                                    &self.options,
                                    Response::new(err.status).with_body(err.message),
                                    false,
                                );
                                h1.last_seq = Some(seq);
                                h1.queue.push_back(Pipelined {
                                    seq,
                                    head_only: false,
                                    keep_alive: false,
                                    ready: Some(Ready::Bytes(response.encode())),
                                });
                                continue;
                            }
                        }
                    }

                    let mut slot = Pipelined {
                        seq,
                        head_only,
                        keep_alive,
                        ready: None,
                    };
                    if let Some(root) = &self.options.static_root
                        && let Some(path) = static_files::resolve(root, request.path())
                    {
                        let index: Vec<&str> = self
                            .options
                            .index_files
                            .iter()
                            .map(String::as_str)
                            .collect();
                        match static_files::serve(&request, &path, &index) {
                            Some(Reply::Head(response)) => {
                                slot.ready = Some(Ready::Bytes(
                                    finalize(&self.options, response, keep_alive).encode_head(0),
                                ));
                            }
                            Some(Reply::File {
                                head,
                                path,
                                offset,
                                len,
                            }) => {
                                slot.ready = Some(Ready::File {
                                    head: finalize(&self.options, head, keep_alive)
                                        .encode_head(len as usize),
                                    path,
                                    offset,
                                    len,
                                });
                            }
                            None => {}
                        }
                    }
                    if slot.ready.is_some() {
                        h1.queue.push_back(slot);
                        continue;
                    }
                    h1.queue.push_back(slot);
                    let id = RequestId { conn, seq };
                    // The connection's state is out of the map while the app runs, so
                    // responses to it are deferred and applied below.
                    if let Some(response) = self.call(ctx, |app, c| app.on_request(c, id, request))
                        && let Some(p) = h1.queue.iter_mut().find(|p| p.seq == seq)
                    {
                        let response = finalize(&self.options, response, keep_alive);
                        p.ready = Some(Ready::Bytes(if head_only {
                            response.encode_head(response.body.len())
                        } else {
                            response.encode()
                        }));
                    }
                }
            }
        }
        let _ = flush_pipeline(ctx, &mut h1, conn);
        Some(Proto::Http1(h1))
    }

    fn websocket(
        &mut self,
        ctx: &mut Context<'_>,
        conn: ConnId,
        mut ws: WebSocket,
        data: &[u8],
    ) -> Option<Proto> {
        ws.buffer.extend_from_slice(data);
        loop {
            let frame = match ws.decoder.decode_frame(&mut ws.buffer) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(err) => {
                    let close = Message::Close(Some(websocket::CloseReason {
                        code: err.code,
                        reason: String::new(),
                    }));
                    let _ = ctx.send(conn, &encode_frame(&close.into_frame(), None));
                    let _ = ctx.close(conn);
                    ws.buffer.clear();
                    break;
                }
            };
            match ws.assembler.push(frame) {
                Ok(Some(Message::Ping(payload))) => {
                    let _ = ctx.send(
                        conn,
                        &encode_frame(&Message::Pong(payload).into_frame(), None),
                    );
                }
                Ok(Some(Message::Pong(_))) | Ok(None) => {}
                Ok(Some(Message::Close(reason))) => {
                    if !ws.closing {
                        let code = reason.map_or(close_code::NORMAL, |r| r.code);
                        let reply = Message::Close(Some(websocket::CloseReason {
                            code,
                            reason: String::new(),
                        }));
                        let _ = ctx.send(conn, &encode_frame(&reply.into_frame(), None));
                    }
                    ws.closing = true;
                    let _ = ctx.close(conn);
                    break;
                }
                Ok(Some(message)) => {
                    self.call(ctx, |app, c| app.on_message(c, conn, message));
                }
                Err(err) => {
                    let close = Message::Close(Some(websocket::CloseReason {
                        code: err.code,
                        reason: String::new(),
                    }));
                    let _ = ctx.send(conn, &encode_frame(&close.into_frame(), None));
                    let _ = ctx.close(conn);
                    break;
                }
            }
        }
        Some(Proto::WebSocket(ws))
    }

    fn http2(
        &mut self,
        ctx: &mut Context<'_>,
        conn: ConnId,
        mut session: Box<ServerSession>,
        data: &[u8],
    ) -> Option<Proto> {
        let failed = session.receive(data).is_err();
        let _ = ctx.send(conn, &session.take_output());
        if failed {
            let _ = ctx.close(conn);
            return Some(Proto::Http2(session));
        }
        while let Some(event) = session.poll_event() {
            match event {
                Event::Request {
                    stream,
                    head,
                    headers,
                    body,
                    ..
                } => {
                    let Some(request) = h2_request(head, headers, body) else {
                        session.cancel(stream, Reason::ProtocolError);
                        continue;
                    };
                    let id = RequestId {
                        conn,
                        seq: u64::from(stream),
                    };
                    let response = match self.static_reply(&request) {
                        Some(response) => Some(response),
                        None => self.call(ctx, |app, c| app.on_request(c, id, request)),
                    };
                    if let Some(response) = response {
                        let _ = respond_h2(
                            &mut session,
                            stream,
                            finalize(&self.options, response, true),
                        );
                    }
                }
                Event::Reset { .. } => {}
                Event::GoAway { .. } => session.go_away(Reason::NoError, ""),
            }
        }
        let _ = ctx.send(conn, &session.take_output());
        if session.is_closed() {
            let _ = ctx.close(conn);
        }
        Some(Proto::Http2(session))
    }

    /// Static files for HTTP/2, which cannot use sendfile inside a stream.
    fn static_reply(&self, request: &Request) -> Option<Response> {
        let root = self.options.static_root.as_ref()?;
        let path = static_files::resolve(root, request.path())?;
        let index: Vec<&str> = self
            .options
            .index_files
            .iter()
            .map(String::as_str)
            .collect();
        match static_files::serve(request, &path, &index)? {
            Reply::Head(response) => Some(response),
            Reply::File {
                mut head,
                path,
                offset,
                len,
            } => {
                use std::io::{Read, Seek, SeekFrom};
                let mut file = std::fs::File::open(path).ok()?;
                file.seek(SeekFrom::Start(offset)).ok()?;
                let mut body = Vec::with_capacity(len as usize);
                file.take(len).read_to_end(&mut body).ok()?;
                head.body = body;
                Some(head)
            }
        }
    }
}

impl<A: HttpApp> Handler for Adapter<A> {
    fn on_worker_start(&mut self, ctx: &mut Context<'_>) {
        self.call(ctx, |app, c| app.on_worker_start(c));
        self.apply_deferred(ctx);
    }

    fn on_connect(&mut self, _ctx: &mut Context<'_>, conn: ConnId) {
        let proto = self.new_http1();
        self.conns.insert(conn, proto);
    }

    fn on_receive(&mut self, ctx: &mut Context<'_>, conn: ConnId, data: Vec<u8>) {
        let Some(proto) = self.conns.remove(&conn) else {
            return;
        };
        let next = match proto {
            Proto::Http1(h1) => self.http1(ctx, conn, h1, &data),
            Proto::WebSocket(ws) => self.websocket(ctx, conn, ws, &data),
            Proto::Http2(session) => self.http2(ctx, conn, session, &data),
        };
        if let Some(next) = next {
            self.conns.insert(conn, next);
        }
        self.apply_deferred(ctx);
    }

    fn on_close(&mut self, ctx: &mut Context<'_>, conn: ConnId) {
        if let Some(Proto::WebSocket(_)) = self.conns.remove(&conn) {
            self.call(ctx, |app, c| app.on_ws_close(c, conn));
        }
        self.apply_deferred(ctx);
    }

    fn on_finish(&mut self, ctx: &mut Context<'_>, task: TaskId, result: Vec<u8>) {
        self.call(ctx, |app, c| app.on_finish(c, task, result));
        self.apply_deferred(ctx);
    }

    fn on_pipe_message(&mut self, ctx: &mut Context<'_>, from: usize, data: Vec<u8>) {
        self.call(ctx, |app, c| app.on_pipe_message(c, from, data));
        self.apply_deferred(ctx);
    }

    fn on_task(&mut self, ctx: &TaskContext, data: Vec<u8>) -> Option<Vec<u8>> {
        self.app.on_task(ctx, data)
    }
}

/// Builds a [`Server`] that speaks HTTP on every listener of `config`.
pub fn server<A: HttpApp>(
    mut config: Config,
    options: HttpOptions,
    factory: impl Fn(Role) -> A + Send + Sync + 'static,
) -> Result<Server> {
    for listener in &mut config.listeners {
        listener.framing = Framing::Raw;
        if !options.http2
            && let Some(tls) = &listener.tls
            && tls.alpn().iter().any(|p| p == "h2")
        {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "a TLS listener offers h2 through ALPN, but HttpOptions::http2 is off",
            ));
        }
    }
    let options = Arc::new(options);
    Server::new(config, move |role| Adapter {
        app: factory(role),
        conns: HashMap::new(),
        deferred: Vec::new(),
        options: Arc::clone(&options),
    })
}
