//! A TCP echo server where every connection is a coroutine.
//!
//! Run with `cargo run --example echo`, then `nc 127.0.0.1 9501`.

use weft::coroutine::{self, CoSocket};

fn main() -> weft::core::Result<()> {
    coroutine::run(|| {
        let listener = match CoSocket::listen(&"127.0.0.1:9501".parse().unwrap(), 128) {
            Ok(listener) => listener,
            Err(e) => return eprintln!("listen failed: {e}"),
        };
        println!("echo server on 127.0.0.1:9501");
        while let Ok((conn, peer)) = listener.accept(None) {
            println!("{peer} connected");
            let spawned = coroutine::spawn(move || {
                let mut buf = [0u8; 4096];
                // Each recv/send suspends only this coroutine.
                while let Ok(n) = conn.recv(&mut buf) {
                    if n == 0 || conn.send_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                println!("{peer} disconnected");
            });
            if let Err(e) = spawned {
                eprintln!("spawn failed: {e}");
            }
        }
    })
}
