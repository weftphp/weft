//! An HTTP server with four worker processes, supervised by the main process.
//!
//! Run with `cargo run --example http`, then `curl http://127.0.0.1:9502/hello`.
//! Stop it with Ctrl-C; `kill -USR1 <pid>` replaces the workers one by one.

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
    let config = Config {
        listeners: vec![Listener::stream("127.0.0.1:9502".parse()?)],
        workers: 4,
        ..Config::default()
    };
    println!(
        "listening on http://127.0.0.1:9502 (pid {})",
        std::process::id()
    );
    http::server(config, HttpOptions::default(), |_| Hello)?.run()
}
