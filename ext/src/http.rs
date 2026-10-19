//! `Weft\Http\Server`, `Request`, `Response` and the client function `Weft\Http\request`.
//!
//! The server runs the engine's multi-process HTTP server. Each worker is a forked copy of the
//! PHP process; every request is handled by the user's callable in its own coroutine, so the
//! handler may sleep, use channels or call other coroutine-aware functions.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::Duration;

use weft::coroutine;
use weft::coroutine::http_client::{HttpClient, parse_url};
use weft::network::{ClientTls, ServerTlsOptions, SocketAddress};
use weft::protocol::http::{Method, Request, Response};
use weft::server::http::{self, HttpApp, HttpContext, HttpOptions, RequestId, Responder};
use weft::server::{Config, Listener};

use crate::coro::{self, Finish};
use crate::php::{
    Args, Callable, Class, ClassBuilder, PhpError, PhpResult, Zval, fail, handler,
    register_function,
};
use crate::vm;

static REQUEST: OnceLock<Class> = OnceLock::new();
static RESPONSE: OnceLock<Class> = OnceLock::new();

// ----- Request -----

struct PhpRequest(Request);

fn request_of<'a>(args: &Args) -> PhpResult<&'a Request> {
    Ok(&args.this::<PhpRequest>()?.0)
}

handler!(fn req_method(args, ret) {
    args.check(0, 0)?;
    ret.str(request_of(&args)?.method.as_str());
    Ok(())
});

handler!(fn req_uri(args, ret) {
    args.check(0, 0)?;
    ret.str(&request_of(&args)?.target);
    Ok(())
});

handler!(fn req_path(args, ret) {
    args.check(0, 0)?;
    ret.str(request_of(&args)?.path());
    Ok(())
});

handler!(fn req_query_string(args, ret) {
    args.check(0, 0)?;
    ret.str(request_of(&args)?.query().unwrap_or(""));
    Ok(())
});

handler!(fn req_query(args, ret) {
    args.check(0, 0)?;
    let out = ret.array();
    for (k, v) in request_of(&args)?.query_pairs() {
        out.set_bytes(&k, v.as_bytes());
    }
    Ok(())
});

handler!(fn req_headers(args, ret) {
    args.check(0, 0)?;
    let req = request_of(&args)?;
    // Names are lowercase; repeated headers are joined the way HTTP defines.
    let mut seen: Vec<(String, String)> = Vec::new();
    for (name, value) in req.headers.iter() {
        let name = name.to_ascii_lowercase();
        match seen.iter_mut().find(|(n, _)| *n == name) {
            Some((_, joined)) => {
                joined.push_str(", ");
                joined.push_str(value);
            }
            None => seen.push((name, value.to_owned())),
        }
    }
    let out = ret.array();
    for (k, v) in seen {
        out.set_bytes(&k, v.as_bytes());
    }
    Ok(())
});

handler!(fn req_header(args, ret) {
    args.check(1, 1)?;
    let name = args.text(0)?;
    match request_of(&args)?.headers.get(&name) {
        Some(v) => ret.str(v),
        None => ret.null(),
    }
    Ok(())
});

handler!(fn req_cookies(args, ret) {
    args.check(0, 0)?;
    let out = ret.array();
    for (k, v) in request_of(&args)?.cookies() {
        out.set_bytes(&k, v.as_bytes());
    }
    Ok(())
});

handler!(fn req_body(args, ret) {
    args.check(0, 0)?;
    ret.bytes(&request_of(&args)?.body);
    Ok(())
});

// ----- Response -----

struct ResponseState {
    id: RequestId,
    responder: Responder,
    status: Cell<u16>,
    headers: RefCell<Vec<(String, String)>>,
    sent: Cell<bool>,
}

impl ResponseState {
    fn send(&self, status: u16, body: Vec<u8>) -> PhpResult<bool> {
        if self.sent.replace(true) {
            return Ok(false);
        }
        let mut response = Response::new(status).with_body(body);
        for (name, value) in self.headers.borrow().iter() {
            response.headers.append(name.clone(), value.clone());
        }
        let (responder, id) = (self.responder.clone(), self.id);
        coroutine::with_reactor(|r| responder.respond(r, id, response))?;
        Ok(true)
    }
}

struct PhpResponse(Rc<ResponseState>);

handler!(fn res_status(args, ret) {
    args.check(1, 1)?;
    let code = args.long(0, 200);
    if !(100..=999).contains(&code) {
        return fail("the status must be between 100 and 999");
    }
    args.this::<PhpResponse>()?.0.status.set(code as u16);
    args.this_zval(ret);
    Ok(())
});

handler!(fn res_header(args, ret) {
    args.check(2, 3)?;
    let (name, value) = (args.text(0)?, args.text(1)?);
    if !weft::protocol::http::headers::is_token(&name) || !weft::protocol::http::headers::is_valid_value(&value) {
        return fail("invalid header name or value");
    }
    let replace = args.get(2).is_none_or(|z| z.as_bool());
    let state = &args.this::<PhpResponse>()?.0;
    let mut headers = state.headers.borrow_mut();
    if replace {
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case(&name));
    }
    headers.push((name, value));
    drop(headers);
    args.this_zval(ret);
    Ok(())
});

handler!(fn res_end(args, ret) {
    args.check(0, 1)?;
    let body = if args.len() > 0 { args.string(0)? } else { Vec::new() };
    let state = &args.this::<PhpResponse>()?.0;
    let status = state.status.get();
    ret.bool(state.send(status, body)?);
    Ok(())
});

handler!(fn res_is_sent(args, ret) {
    args.check(0, 0)?;
    ret.bool(args.this::<PhpResponse>()?.0.sent.get());
    Ok(())
});

// ----- Server -----

struct PhpServer {
    host: String,
    port: u16,
    workers: usize,
    tls: Option<(PathBuf, PathBuf)>,
    static_root: Option<PathBuf>,
    handler: RefCell<Option<Rc<Callable>>>,
}

/// The user's callable, carried into forked workers.
struct ForkShared(Rc<Callable>);

impl ForkShared {
    fn get(&self) -> Rc<Callable> {
        Rc::clone(&self.0)
    }
}

// SAFETY: the server runs in process mode, so every worker is a forked copy of this process
// with a single thread; the callable is only touched there, after the fork. The supervisor
// never calls the factory that captures it.
unsafe impl Send for ForkShared {}
unsafe impl Sync for ForkShared {}

struct PhpApp {
    handler: Rc<Callable>,
}

impl HttpApp for PhpApp {
    fn on_worker_start(&mut self, _ctx: &mut HttpContext<'_, '_>) {
        vm::install();
    }

    fn on_request(
        &mut self,
        ctx: &mut HttpContext<'_, '_>,
        id: RequestId,
        request: Request,
    ) -> Option<Response> {
        let (Some(request_class), Some(response_class)) = (REQUEST.get(), RESPONSE.get()) else {
            return Some(Response::new(500));
        };
        let state = Rc::new(ResponseState {
            id,
            responder: ctx.responder(),
            status: Cell::new(200),
            headers: RefCell::new(Vec::new()),
            sent: Cell::new(false),
        });
        let args = vec![
            request_class.make_object(PhpRequest(request)),
            response_class.make_object(PhpResponse(Rc::clone(&state))),
        ];
        let on_done: Finish = Box::new(move |threw| {
            if threw {
                let _ = state.send(500, b"Internal Server Error".to_vec());
            }
        });
        if coro::spawn_in(
            ctx.server().reactor(),
            Rc::clone(&self.handler),
            args,
            Some(on_done),
        )
        .is_err()
        {
            return Some(Response::new(500));
        }
        None
    }
}

fn option_text(value: Zval) -> String {
    String::from_utf8_lossy(value.as_bytes().unwrap_or_default()).into_owned()
}

handler!(fn server_new(args, ret) {
    args.check(0, 3)?;
    let host = if args.len() > 0 { args.text(0)? } else { "127.0.0.1".to_owned() };
    let port = args.long(1, 8080);
    if !(0..=65535).contains(&port) {
        return fail("the port must be between 0 and 65535");
    }
    let mut server = PhpServer {
        host,
        port: port as u16,
        workers: 1,
        tls: None,
        static_root: None,
        handler: RefCell::new(None),
    };
    let (mut cert, mut key) = (None, None);
    if let Some(options) = args.get(2) {
        options.each(|k, _, v| match k {
            Some(b"workers") => server.workers = v.as_long().max(1) as usize,
            Some(b"tls_cert") => cert = Some(PathBuf::from(option_text(v))),
            Some(b"tls_key") => key = Some(PathBuf::from(option_text(v))),
            Some(b"static_root") => server.static_root = Some(PathBuf::from(option_text(v))),
            _ => {}
        });
    }
    match (cert, key) {
        (Some(c), Some(k)) => server.tls = Some((c, k)),
        (None, None) => {}
        _ => return fail("tls_cert and tls_key must be given together"),
    }
    args.set_this(server);
    ret.null();
    Ok(())
});

handler!(fn server_handle(args, ret) {
    args.check(1, 1)?;
    let callback = Callable::new(args.require(0)?)?;
    *args.this::<PhpServer>()?.handler.borrow_mut() = Some(Rc::new(callback));
    args.this_zval(ret);
    Ok(())
});

handler!(fn server_start(args, ret) {
    args.check(0, 0)?;
    let server = args.this::<PhpServer>()?;
    let Some(callback) = server.handler.borrow().clone() else {
        return fail("set a handler with handle() before start()");
    };
    if coroutine::in_coroutine() {
        return fail("start() cannot be called from inside a coroutine");
    }
    let host = if server.host.contains(':') && !server.host.starts_with('[') {
        format!("[{}]", server.host)
    } else {
        server.host.clone()
    };
    let address: SocketAddress = format!("{host}:{}", server.port).parse()?;
    let mut listener = Listener::stream(address);
    if let Some((cert, key)) = &server.tls {
        listener = listener.with_tls(ServerTlsOptions::new(cert, key).with_alpn(["h2", "http/1.1"]).build()?);
    }
    let config = Config { listeners: vec![listener], workers: server.workers, ..Config::default() };
    let options = HttpOptions { static_root: server.static_root.clone(), ..HttpOptions::default() };
    let shared = ForkShared(callback);
    http::server(config, options, move |_| PhpApp { handler: shared.get() })?.run()?;
    ret.null();
    Ok(())
});

// ----- client -----

fn collect_headers(request: &mut Request, headers: Zval) {
    headers.each(|k, _, v| {
        if let Some(name) = k {
            let name = String::from_utf8_lossy(name).into_owned();
            request.headers.append(name, option_text(v));
        }
    });
}

handler!(fn client_request(args, ret) {
    args.check(2, 5)?;
    let method: Method = args.text(0)?.parse().map_err(|()| PhpError::Message("invalid HTTP method".into()))?;
    if !coroutine::in_coroutine() {
        return fail("Weft\\Http\\request() must be called inside a coroutine");
    }
    let url = parse_url(&args.text(1)?)?;
    let mut client = HttpClient::new(&url.host, url.port);
    if url.secure {
        client = client.with_tls(ClientTls::new()?);
    }
    client.timeout = Duration::from_secs_f64(args.double(4, 30.0).clamp(0.001, 86_400.0));
    let mut request = Request::new(method, url.path);
    if let Some(h) = args.get(2) {
        collect_headers(&mut request, h);
    }
    if args.len() > 3 {
        request.body = args.string(3)?;
    }
    let response = client.request(request)?;
    let out = ret.array();
    out.set_long("status", i64::from(response.status));
    out.set_bytes("reason", response.reason.as_bytes());
    out.set_bytes("body", &response.body);
    // Header names are lowercased; repeated ones are joined with ", ".
    let mut joined: Vec<(String, String)> = Vec::new();
    for (name, value) in response.headers.iter() {
        let name = name.to_ascii_lowercase();
        match joined.iter_mut().find(|(n, _)| *n == name) {
            Some((_, v)) => {
                v.push_str(", ");
                v.push_str(value);
            }
            None => joined.push((name, value.to_owned())),
        }
    }
    let headers = out.child("headers");
    for (name, value) in joined {
        headers.set_bytes(&name, value.as_bytes());
    }
    Ok(())
});

pub fn register() -> bool {
    let request = ClassBuilder::new("Weft\\Http\\Request")
        .method("method", req_method, 0, 0)
        .method("uri", req_uri, 0, 0)
        .method("path", req_path, 0, 0)
        .method("queryString", req_query_string, 0, 0)
        .method("query", req_query, 0, 0)
        .method("headers", req_headers, 0, 0)
        .method("header", req_header, 1, 1)
        .method("cookies", req_cookies, 0, 0)
        .method("body", req_body, 0, 0)
        .register();
    let response = ClassBuilder::new("Weft\\Http\\Response")
        .method("status", res_status, 1, 1)
        .method("header", res_header, 2, 3)
        .method("end", res_end, 0, 1)
        .method("isSent", res_is_sent, 0, 0)
        .register();
    let server = ClassBuilder::new("Weft\\Http\\Server")
        .method("__construct", server_new, 0, 3)
        .method("handle", server_handle, 1, 1)
        .method("start", server_start, 0, 0)
        .register();
    if let Some(c) = request {
        let _ = REQUEST.set(c);
    }
    if let Some(c) = response {
        let _ = RESPONSE.set(c);
    }
    request.is_some()
        && response.is_some()
        && server.is_some()
        && register_function("Weft\\Http\\request", client_request, 2, 5)
}
