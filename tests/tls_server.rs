//! TLS listeners on the server (thread mode) against blocking OpenSSL clients.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use weft::core::bytes::ByteBuffer;
use weft::network::{ServerTlsOptions, SocketAddress};
use weft::protocol::http::{Limits, Request, Response, ResponseParser};
use weft::protocol::http2::frame::{Frame, FrameDecoder, PREFACE};
use weft::protocol::http2::hpack::{self, Field};
use weft::server::http::{self, HttpApp, HttpContext, HttpOptions, RequestId};
use weft::server::{Config, ConnId, Context, Handler, Listener, Mode};

fn connect(addr: &SocketAddress) -> TcpStream {
    let s = TcpStream::connect(addr.as_inet().unwrap()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Default)]
struct Log {
    connects: Vec<String>,
    closes: usize,
}

struct Echo(Arc<Mutex<Log>>);

impl Handler for Echo {
    fn on_connect(&mut self, ctx: &mut Context<'_>, conn: ConnId) {
        let tls = ctx.info(conn).unwrap().tls.unwrap();
        self.0.lock().unwrap().connects.push(tls.version);
    }

    fn on_receive(&mut self, ctx: &mut Context<'_>, conn: ConnId, data: Vec<u8>) {
        ctx.send(conn, &data).unwrap();
    }

    fn on_close(&mut self, _ctx: &mut Context<'_>, _conn: ConnId) {
        self.0.lock().unwrap().closes += 1;
    }
}

#[test]
fn tls_stream_listener() {
    let pki = common::pki();
    let tls = ServerTlsOptions::new(&pki.cert, &pki.key).build().unwrap();
    let log = Arc::new(Mutex::new(Log::default()));
    let handler_log = Arc::clone(&log);
    let config = Config {
        listeners: vec![Listener::stream("127.0.0.1:0".parse().unwrap()).with_tls(tls)],
        mode: Mode::Thread,
        workers: 2,
        stop_grace: Duration::from_millis(200),
        ..Config::default()
    };
    let server = weft::server::Server::new(config, move |_| Echo(Arc::clone(&handler_log)))
        .unwrap()
        .start_threads()
        .unwrap();
    let addr = server.addresses()[0].clone();

    // Peers that never complete a handshake are invisible to the handler.
    let mut garbage = connect(&addr);
    garbage.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let mut sink = Vec::new();
    let _ = garbage.read_to_end(&mut sink);
    drop(connect(&addr));

    // Far more than one record and one read chunk, echoed back.
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut client = common::tls_client(&pki, connect(&addr), &[]);
    client.write_all(&payload).unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).unwrap();
    assert!(echoed == payload, "echo differs");
    client.shutdown().unwrap();
    drop(client);

    wait_for("on_close", || log.lock().unwrap().closes == 1);
    let log = log.lock().unwrap();
    assert_eq!(log.connects, ["TLSv1.3"]);
    drop(log);
    server.stop();
    server.join().unwrap();
}

struct Hello;

impl HttpApp for Hello {
    fn on_request(
        &mut self,
        _ctx: &mut HttpContext<'_, '_>,
        _id: RequestId,
        request: Request,
    ) -> Option<Response> {
        Some(Response::new(200).with_body(format!("hello {}", request.path())))
    }
}

fn read_responses(stream: &mut impl Read, count: usize) -> Vec<Response> {
    let mut parser = ResponseParser::new(Limits::default());
    let mut buf = ByteBuffer::new();
    let mut out = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    while out.len() < count {
        while let Some(r) = parser.parse(&mut buf).unwrap() {
            out.push(r);
        }
        if out.len() >= count {
            break;
        }
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "server closed early");
        buf.extend_from_slice(&chunk[..n]);
    }
    out
}

fn h2_get(stream: &mut (impl Read + Write), path: &str) -> (String, Vec<u8>) {
    let mut wire = PREFACE.to_vec();
    Frame::Settings {
        ack: false,
        values: vec![],
    }
    .encode(&mut wire);
    let mut block = Vec::new();
    hpack::Encoder::default().encode(
        &[
            Field::new(":method", "GET"),
            Field::new(":scheme", "https"),
            Field::new(":path", path),
            Field::new(":authority", "localhost"),
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
    stream.write_all(&wire).unwrap();

    let mut frames = FrameDecoder::default();
    let mut decoder = hpack::Decoder::new(4096, 1 << 20);
    let mut buf = ByteBuffer::new();
    let mut chunk = [0u8; 4096];
    let (mut status, mut body, mut done) = (String::new(), Vec::new(), false);
    while !done {
        let n = stream.read(&mut chunk).unwrap();
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
    (status, body)
}

#[test]
fn https_with_alpn_and_static_files() {
    let pki = common::pki();
    let root = pki.dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let big: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
    std::fs::write(root.join("big.bin"), &big).unwrap();

    let tls = ServerTlsOptions::new(&pki.cert, &pki.key)
        .with_alpn(["h2", "http/1.1"])
        .build()
        .unwrap();
    let config = Config {
        listeners: vec![Listener::stream("127.0.0.1:0".parse().unwrap()).with_tls(tls.clone())],
        mode: Mode::Thread,
        workers: 1,
        stop_grace: Duration::from_millis(200),
        ..Config::default()
    };

    // Offering h2 with HTTP/2 turned off is a configuration error.
    let no_h2 = HttpOptions {
        http2: false,
        ..HttpOptions::default()
    };
    assert!(http::server(config.clone(), no_h2, |_| Hello).is_err());

    let options = HttpOptions {
        static_root: Some(root),
        ..HttpOptions::default()
    };
    let server = http::server(config, options, |_| Hello)
        .unwrap()
        .start_threads()
        .unwrap();
    let addr = server.addresses()[0].clone();

    // HTTP/1.1 chosen through ALPN; the static file goes out through TLS, not sendfile.
    let mut h1 = common::tls_client(&pki, connect(&addr), &["http/1.1"]);
    assert_eq!(h1.ssl().selected_alpn_protocol(), Some(&b"http/1.1"[..]));
    h1.write_all(
        b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\nGET /big.bin HTTP/1.1\r\nHost: localhost\r\n\r\nGET /big.bin HTTP/1.1\r\nHost: localhost\r\nRange: bytes=70000-70009\r\n\r\n",
    )
    .unwrap();
    let r = read_responses(&mut h1, 3);
    assert_eq!(r[0].body, b"hello /x");
    assert!(r[1].body == big, "static file differs");
    assert_eq!((r[2].status, &r[2].body[..]), (206, &big[70_000..70_010]));

    // HTTP/2 chosen through ALPN.
    let mut h2 = common::tls_client(&pki, connect(&addr), &["h2", "http/1.1"]);
    assert_eq!(h2.ssl().selected_alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(
        h2_get(&mut h2, "/over-h2"),
        ("200".to_owned(), b"hello /over-h2".to_vec())
    );

    // A client without ALPN gets HTTP/1.1.
    let mut plain_alpn = common::tls_client(&pki, connect(&addr), &[]);
    assert_eq!(plain_alpn.ssl().selected_alpn_protocol(), None);
    plain_alpn
        .write_all(b"GET /y HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    assert_eq!(read_responses(&mut plain_alpn, 1)[0].body, b"hello /y");

    server.stop();
    server.join().unwrap();
}
