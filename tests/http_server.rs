//! The HTTP server (thread mode) against raw-socket clients built from weft's protocol codecs.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use weft::core::bytes::ByteBuffer;
use weft::network::SocketAddress;
use weft::protocol::http::{Limits, Request, Response, ResponseParser};
use weft::protocol::http2::frame::{Frame, FrameDecoder, PREFACE};
use weft::protocol::http2::hpack::{self, Field};
use weft::protocol::websocket::{self, FrameDecoder as WsDecoder, Message, Opcode, Role as WsRole};
use weft::server::http::{self, HttpApp, HttpContext, HttpOptions, RequestId};
use weft::server::{Config, ConnId, Listener, Mode, RunningServer};

/// Answers most paths at once; `/slow` is answered 30 ms later. The timer cannot reach the
/// app directly, so it messages its own worker, and `on_pipe_message` responds.
#[derive(Default)]
struct App {
    pending: Vec<RequestId>,
}

impl HttpApp for App {
    fn on_request(
        &mut self,
        ctx: &mut HttpContext<'_, '_>,
        id: RequestId,
        request: Request,
    ) -> Option<Response> {
        match request.path() {
            "/hello" => Some(
                Response::new(200)
                    .with_header("Content-Type", "text/plain")
                    .with_body("hello"),
            ),
            "/slow" => {
                self.pending.push(id);
                ctx.server().after(Duration::from_millis(30), |c| {
                    let me = c.worker_id();
                    c.send_message(me, b"wake").unwrap();
                });
                None
            }
            "/echo" => Some(Response::new(200).with_body(request.body)),
            _ => Some(Response::new(404).with_body("missing")),
        }
    }

    fn on_pipe_message(&mut self, ctx: &mut HttpContext<'_, '_>, _from: usize, _data: Vec<u8>) {
        for id in self.pending.drain(..) {
            ctx.respond(id, Response::new(200).with_body("slow"))
                .unwrap();
        }
    }

    fn on_upgrade(
        &mut self,
        _ctx: &mut HttpContext<'_, '_>,
        _conn: ConnId,
        request: &Request,
    ) -> bool {
        request.path() == "/ws"
    }

    fn on_message(&mut self, ctx: &mut HttpContext<'_, '_>, conn: ConnId, message: Message) {
        let reply = match message {
            Message::Text(t) => Message::Text(format!("echo: {t}")),
            other => other,
        };
        ctx.ws_send(conn, reply).unwrap();
    }
}

fn start(root: Option<std::path::PathBuf>) -> RunningServer {
    let config = Config {
        listeners: vec![Listener::stream("127.0.0.1:0".parse().unwrap())],
        mode: Mode::Thread,
        workers: 1,
        stop_grace: Duration::from_millis(200),
        ..Config::default()
    };
    let options = HttpOptions {
        static_root: root,
        ..HttpOptions::default()
    };
    http::server(config, options, |_| App::default())
        .unwrap()
        .start_threads()
        .unwrap()
}

fn connect(addr: &SocketAddress) -> TcpStream {
    let s = TcpStream::connect(addr.as_inet().unwrap()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn read_responses(stream: &mut TcpStream, count: usize) -> Vec<Response> {
    let mut parser = ResponseParser::new(Limits::default());
    let mut buf = ByteBuffer::new();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while out.len() < count {
        while let Some(r) = parser.parse(&mut buf).unwrap() {
            out.push(r);
        }
        if out.len() >= count {
            break;
        }
        let n = stream.read(&mut chunk).unwrap();
        if n == 0 {
            if let Some(r) = parser.finish().unwrap() {
                out.push(r);
            }
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    out
}

#[test]
fn http1_pipelining_continue_and_errors() {
    let server = start(None);
    let addr = server.addresses()[0].clone();

    let mut s = connect(&addr);
    s.write_all(
        b"GET /hello HTTP/1.1\r\nHost: t\r\n\r\nGET /missing HTTP/1.1\r\nHost: t\r\n\r\nPOST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\n\r\nbody",
    )
    .unwrap();
    let responses = read_responses(&mut s, 3);
    assert_eq!(responses[0].status, 200);
    assert_eq!(responses[0].body, b"hello");
    assert_eq!(responses[0].headers.get("server"), Some("weft"));
    assert!(responses[0].headers.contains("date"));
    assert_eq!(responses[1].status, 404);
    assert_eq!(responses[2].body, b"body");

    // A deferred response holds back the one pipelined after it.
    s.write_all(b"GET /slow HTTP/1.1\r\nHost: t\r\n\r\nGET /hello HTTP/1.1\r\nHost: t\r\n\r\n")
        .unwrap();
    let ordered = read_responses(&mut s, 2);
    assert_eq!(ordered[0].body, b"slow");
    assert_eq!(ordered[1].body, b"hello");

    // Expect: 100-continue gets an interim response before the body is sent.
    s.write_all(
        b"POST /echo HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n",
    )
    .unwrap();
    let interim = read_responses(&mut s, 1);
    assert_eq!(interim[0].status, 100);
    s.write_all(b"ok").unwrap();
    assert_eq!(read_responses(&mut s, 1)[0].body, b"ok");

    // Malformed requests get a 400 and the connection closes.
    let mut bad = connect(&addr);
    bad.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let reply = read_responses(&mut bad, 1);
    assert_eq!(reply[0].status, 400);
    assert_eq!(reply[0].headers.get("connection"), Some("close"));

    // Connection: close is honoured.
    let mut once = connect(&addr);
    once.write_all(b"GET /hello HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut all = Vec::new();
    once.read_to_end(&mut all).unwrap();
    assert!(all.ends_with(b"hello"));

    server.stop();
    server.join().unwrap();
}

#[test]
fn static_files_websocket_and_http2() {
    let root = std::env::temp_dir().join(format!("weft-http-root-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("page.html"), b"<h1>static</h1>").unwrap();
    let server = start(Some(root.clone()));
    let addr = server.addresses()[0].clone();

    // Static file, full and ranged, served with sendfile.
    let mut s = connect(&addr);
    s.write_all(b"GET /page.html HTTP/1.1\r\nHost: t\r\n\r\nGET /page.html HTTP/1.1\r\nHost: t\r\nRange: bytes=4-9\r\n\r\n")
        .unwrap();
    let r = read_responses(&mut s, 2);
    assert_eq!(r[0].body, b"<h1>static</h1>");
    assert_eq!(
        r[0].headers.get("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!((r[1].status, &r[1].body[..]), (206, &b"static"[..]));
    s.write_all(b"GET /../../etc/passwd HTTP/1.1\r\nHost: t\r\n\r\n")
        .unwrap();
    assert_eq!(read_responses(&mut s, 1)[0].status, 404);

    // WebSocket: handshake, echo, ping/pong, close.
    let mut ws = connect(&addr);
    let key = websocket::new_key().unwrap();
    ws.write_all(&websocket::client_request("t", "/ws", &key).encode())
        .unwrap();
    let handshake = read_responses(&mut ws, 1);
    websocket::check_server_response(&handshake[0], &key).unwrap();
    let mask = websocket::new_mask().unwrap();
    ws.write_all(&websocket::encode_frame(
        &Message::Text("hi".into()).into_frame(),
        Some(mask),
    ))
    .unwrap();
    ws.write_all(&websocket::encode_frame(
        &Message::Ping(b"p".to_vec()).into_frame(),
        Some(mask),
    ))
    .unwrap();
    let mut decoder = WsDecoder::new(WsRole::Client, 1 << 20);
    let mut buf = ByteBuffer::new();
    let mut frames = Vec::new();
    let mut chunk = [0u8; 1024];
    while frames.len() < 2 {
        let n = ws.read(&mut chunk).unwrap();
        buf.extend_from_slice(&chunk[..n]);
        while let Some(f) = decoder.decode_frame(&mut buf).unwrap() {
            frames.push(f);
        }
    }
    assert_eq!(frames[0].payload, b"echo: hi");
    assert_eq!(
        (frames[1].opcode, &frames[1].payload[..]),
        (Opcode::Pong, &b"p"[..])
    );
    ws.write_all(&websocket::encode_frame(
        &Message::Close(None).into_frame(),
        Some(mask),
    ))
    .unwrap();
    let mut rest = Vec::new();
    ws.read_to_end(&mut rest).unwrap();
    let mut tail = ByteBuffer::from(rest);
    let close = decoder.decode_frame(&mut tail).unwrap().unwrap();
    assert_eq!(close.opcode, Opcode::Close);

    // HTTP/2 with prior knowledge.
    let mut h2 = connect(&addr);
    let mut wire = PREFACE.to_vec();
    Frame::Settings {
        ack: false,
        values: vec![],
    }
    .encode(&mut wire);
    let mut encoder = hpack::Encoder::default();
    let mut block = Vec::new();
    encoder.encode(
        &[
            Field::new(":method", "GET"),
            Field::new(":scheme", "http"),
            Field::new(":path", "/hello"),
            Field::new(":authority", "t"),
        ],
        &mut block,
    );
    Frame::Headers {
        stream: 1,
        end_stream: true,
        end_headers: true,
        priority: None,
        block,
    }
    .encode(&mut wire);
    h2.write_all(&wire).unwrap();
    let mut frames = FrameDecoder::default();
    let mut decoder = hpack::Decoder::new(4096, 1 << 20);
    let mut buf = ByteBuffer::new();
    let (mut status, mut body, mut done) = (String::new(), Vec::new(), false);
    while !done {
        let n = h2.read(&mut chunk).unwrap();
        assert!(n > 0, "server closed early");
        buf.extend_from_slice(&chunk[..n]);
        while let Some(frame) = frames.decode(&mut buf).unwrap() {
            match frame {
                Frame::Headers {
                    stream: 1,
                    block,
                    end_stream,
                    ..
                } => {
                    let fields = decoder.decode(&block).unwrap();
                    status = String::from_utf8(fields[0].value.clone()).unwrap();
                    done |= end_stream;
                }
                Frame::Data {
                    stream: 1,
                    data,
                    end_stream,
                    ..
                } => {
                    body.extend_from_slice(&data);
                    done |= end_stream;
                }
                _ => {}
            }
        }
    }
    assert_eq!((status.as_str(), &body[..]), ("200", &b"hello"[..]));

    server.stop();
    server.join().unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}
