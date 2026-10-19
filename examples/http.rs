//! An HTTP server with four worker processes, supervised by the main process.
//!
//! Run with `cargo run --example http`, then `curl http://127.0.0.1:9502/hello`.
//! Stop it with Ctrl-C; `kill -USR1 <pid>` replaces the workers one by one.
//!
//! For HTTPS (HTTP/1.1 and HTTP/2 through ALPN), pass a PEM certificate chain and key:
//! `cargo run --example http -- --tls cert.pem key.pem`, then
//! `curl --cacert ca.pem https://localhost:9502/hello`.

use weft::network::ServerTlsOptions;
use weft::protocol::http::{Request, Response};
use weft::server::http::{self, HttpApp, HttpContext, HttpOptions, RequestId};
use weft::server::{Config, Listener};

struct Hello;

impl HttpApp for Hello {
    fn on_request(
        &mut self,
        ctx: &mut HttpContext<'_, '_>,
        _id: RequestId,
        request: Request,
    ) -> Option<Response> {
        let worker = ctx.server().worker_id();
        Some(
            Response::new(200)
                .with_header("Content-Type", "text/plain")
                .with_body(format!("hello from worker {worker}: {}\n", request.path())),
        )
    }
}

fn main() -> weft::core::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut listener = Listener::stream("127.0.0.1:9502".parse()?);
    let scheme = match args.as_slice() {
        [flag, cert, key] if flag == "--tls" => {
            let tls = ServerTlsOptions::new(cert, key)
                .with_alpn(["h2", "http/1.1"])
                .build()?;
            listener = listener.with_tls(tls);
            "https"
        }
        [] => "http",
        _ => {
            eprintln!("usage: http [--tls CERT_CHAIN.pem KEY.pem]");
            std::process::exit(2);
        }
    };
    let config = Config {
        listeners: vec![listener],
        workers: 4,
        ..Config::default()
    };
    println!(
        "listening on {scheme}://127.0.0.1:9502 (pid {})",
        std::process::id()
    );
    http::server(config, HttpOptions::default(), |_| Hello)?.run()
}
