//! Serving files from a directory: safe path mapping, conditional requests and byte ranges.

use std::fs::Metadata;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocol::http::{Method, Request, Response, date, url};
use crate::protocol::mime;

/// What to send for a static request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Headers only (304, 416, or a HEAD request).
    Head(Response),
    /// Headers, then `len` bytes of `path` from `offset`.
    File {
        head: Response,
        path: PathBuf,
        offset: u64,
        len: u64,
    },
}

/// Maps a request path onto a file under `root`. Rejects anything that could escape the
/// root (`..`, absolute components, NUL) or name a hidden file.
pub fn resolve(root: &Path, request_path: &str) -> Option<PathBuf> {
    let decoded = url::percent_decode(request_path, false);
    let decoded = String::from_utf8(decoded).ok()?;
    if decoded.contains('\0') {
        return None;
    }
    let mut path = root.to_path_buf();
    for component in Path::new(decoded.trim_start_matches('/')).components() {
        match component {
            Component::Normal(part) => {
                if part.to_str().is_some_and(|p| p.starts_with('.')) {
                    return None;
                }
                path.push(part);
            }
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(path)
}

fn etag(meta: &Metadata) -> String {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    format!("W/\"{:x}-{:x}\"", meta.len(), mtime)
}

/// Parses a single `bytes=` range against a file of `size` bytes. `Err(())` means the
/// range is unsatisfiable; multi-range requests are answered with the whole file.
fn parse_range(header: &str, size: u64) -> Option<Result<(u64, u64), ()>> {
    let spec = header.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    let (start, end) = (start.trim(), end.trim());
    let range = if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        if suffix == 0 {
            return Some(Err(()));
        }
        (size.saturating_sub(suffix), size.checked_sub(1)?)
    } else {
        let start: u64 = start.parse().ok()?;
        let end = if end.is_empty() {
            size.saturating_sub(1)
        } else {
            end.parse::<u64>().ok()?.min(size.saturating_sub(1))
        };
        (start, end)
    };
    if range.0 >= size || range.0 > range.1 {
        return Some(Err(()));
    }
    Some(Ok(range))
}

/// Builds the reply for a GET or HEAD of `path`, or `None` if it is not a regular file.
/// `index` names are tried for directories.
pub fn serve(req: &Request, path: &Path, index: &[&str]) -> Option<Reply> {
    if !matches!(req.method, Method::Get | Method::Head) {
        return None;
    }
    let mut path = path.to_path_buf();
    let mut meta = std::fs::metadata(&path).ok()?;
    if meta.is_dir() {
        let found = index
            .iter()
            .map(|name| path.join(name))
            .find(|candidate| candidate.is_file())?;
        path = found;
        meta = std::fs::metadata(&path).ok()?;
    }
    if !meta.is_file() {
        return None;
    }

    let size = meta.len();
    let modified = meta.modified().unwrap_or(UNIX_EPOCH);
    let tag = etag(&meta);
    let mut head = Response::new(200)
        .with_header("Content-Type", mime::for_path(&path))
        .with_header("Last-Modified", date::format(modified))
        .with_header("ETag", tag.clone())
        .with_header("Accept-Ranges", "bytes");

    // If-None-Match wins over If-Modified-Since (RFC 9110 §13.2.2).
    let not_modified = match req.headers.get("if-none-match") {
        Some(tags) => tags.split(',').any(|t| {
            t.trim() == "*" || t.trim().trim_start_matches("W/") == tag.trim_start_matches("W/")
        }),
        None => req
            .headers
            .get("if-modified-since")
            .and_then(date::parse)
            .is_some_and(|since| truncate_secs(modified) <= since),
    };
    if not_modified {
        let mut not_modified = Response::new(304);
        not_modified.headers = head.headers;
        not_modified.headers.remove("content-type");
        return Some(Reply::Head(not_modified));
    }

    let (offset, len) = match req.headers.get("range").and_then(|r| parse_range(r, size)) {
        Some(Ok((start, end))) => {
            head.status = 206;
            head.reason = "Partial Content".into();
            head.headers
                .append("Content-Range", format!("bytes {start}-{end}/{size}"));
            (start, end - start + 1)
        }
        Some(Err(())) => {
            let mut unsatisfiable = Response::new(416);
            unsatisfiable
                .headers
                .append("Content-Range", format!("bytes */{size}"));
            return Some(Reply::Head(unsatisfiable));
        }
        None => (0, size),
    };
    head.headers.append("Content-Length", len.to_string());
    if req.method == Method::Head {
        return Some(Reply::Head(head));
    }
    Some(Reply::File {
        head,
        path,
        offset,
        len,
    })
}

fn truncate_secs(t: SystemTime) -> SystemTime {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(target: &str, headers: &[(&str, &str)]) -> Request {
        let mut req = Request::new(Method::Get, target);
        for (n, v) in headers {
            req.headers.append(*n, *v);
        }
        req
    }

    #[test]
    fn path_resolution_stays_inside_root() {
        let root = Path::new("/srv/www");
        assert_eq!(
            resolve(root, "/a/b.txt"),
            Some(PathBuf::from("/srv/www/a/b.txt"))
        );
        assert_eq!(
            resolve(root, "/a%20b.txt"),
            Some(PathBuf::from("/srv/www/a b.txt"))
        );
        assert_eq!(resolve(root, "/../etc/passwd"), None);
        assert_eq!(resolve(root, "/a/%2e%2e/%2e%2e/etc"), None);
        assert_eq!(resolve(root, "/.git/config"), None);
        assert_eq!(resolve(root, "/x%00.txt"), None);
        assert_eq!(resolve(root, "/"), Some(PathBuf::from("/srv/www")));
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-4", 10), Some(Ok((0, 4))));
        assert_eq!(parse_range("bytes=5-", 10), Some(Ok((5, 9))));
        assert_eq!(parse_range("bytes=-3", 10), Some(Ok((7, 9))));
        assert_eq!(parse_range("bytes=8-100", 10), Some(Ok((8, 9))));
        assert_eq!(parse_range("bytes=10-", 10), Some(Err(())));
        assert_eq!(parse_range("bytes=0-1,4-5", 10), None);
        assert_eq!(parse_range("items=0-1", 10), None);
    }

    #[test]
    fn conditional_and_partial_responses() {
        let dir = std::env::temp_dir().join(format!("weft-static-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("hello.txt"), b"hello world").unwrap();
        std::fs::write(dir.join("sub/index.html"), b"<p>").unwrap();

        let Some(Reply::File {
            head, offset, len, ..
        }) = serve(&get("/hello.txt", &[]), &dir.join("hello.txt"), &[])
        else {
            panic!("expected a file");
        };
        assert_eq!((head.status, offset, len), (200, 0, 11));
        assert_eq!(
            head.headers.get("content-type"),
            Some("text/plain; charset=utf-8")
        );
        let tag = head.headers.get("etag").unwrap().to_owned();

        let Some(Reply::Head(cached)) = serve(
            &get("/hello.txt", &[("If-None-Match", &tag)]),
            &dir.join("hello.txt"),
            &[],
        ) else {
            panic!("expected 304");
        };
        assert_eq!(cached.status, 304);

        let Some(Reply::File {
            head, offset, len, ..
        }) = serve(
            &get("/hello.txt", &[("Range", "bytes=6-")]),
            &dir.join("hello.txt"),
            &[],
        )
        else {
            panic!("expected a range");
        };
        assert_eq!((head.status, offset, len), (206, 6, 5));
        assert_eq!(head.headers.get("content-range"), Some("bytes 6-10/11"));

        let Some(Reply::Head(bad)) = serve(
            &get("/hello.txt", &[("Range", "bytes=50-")]),
            &dir.join("hello.txt"),
            &[],
        ) else {
            panic!("expected 416");
        };
        assert_eq!(bad.status, 416);

        assert!(matches!(
            serve(&get("/sub", &[]), &dir.join("sub"), &["index.html"]),
            Some(Reply::File { len: 3, .. })
        ));
        assert!(serve(&get("/missing", &[]), &dir.join("missing"), &[]).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
