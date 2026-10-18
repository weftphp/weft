//! `multipart/form-data` bodies (RFC 7578, using the RFC 2046 multipart syntax).

use super::headers::Headers;
use super::parser::HttpError;
use crate::core::random;

/// One part of a multipart body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Part {
    pub headers: Headers,
    /// Form field name from `Content-Disposition`.
    pub name: Option<String>,
    /// Original file name, for file uploads.
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

impl Part {
    /// A plain form field.
    pub fn field(name: &str, value: impl Into<Vec<u8>>) -> Part {
        Part {
            name: Some(name.to_owned()),
            data: value.into(),
            ..Part::default()
        }
    }

    /// A file upload.
    pub fn file(name: &str, filename: &str, content_type: &str, data: impl Into<Vec<u8>>) -> Part {
        Part {
            name: Some(name.to_owned()),
            filename: Some(filename.to_owned()),
            content_type: Some(content_type.to_owned()),
            data: data.into(),
            ..Part::default()
        }
    }
}

/// Splits a header value like `form-data; name="a"; filename="b.txt"` into its leading value
/// and its parameters (names lower-cased, quoted strings unescaped).
pub fn parse_parameters(value: &str) -> (String, Vec<(String, String)>) {
    let (main, mut rest) = value.split_once(';').unwrap_or((value, ""));
    let mut params = Vec::new();
    loop {
        rest = rest.trim_start_matches([' ', '\t', ';']);
        let Some(eq) = rest.find('=') else { break };
        let name = rest[..eq].trim().to_ascii_lowercase();
        rest = &rest[eq + 1..];
        let value;
        if let Some(quoted) = rest.strip_prefix('"') {
            let mut out = String::new();
            let mut chars = quoted.char_indices();
            let mut end = quoted.len();
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        if let Some((_, escaped)) = chars.next() {
                            out.push(escaped);
                        }
                    }
                    '"' => {
                        end = i + 1;
                        break;
                    }
                    c => out.push(c),
                }
            }
            value = out;
            rest = &quoted[end.min(quoted.len())..];
        } else {
            let end = rest.find(';').unwrap_or(rest.len());
            value = rest[..end].trim().to_owned();
            rest = &rest[end..];
        }
        if !name.is_empty() {
            params.push((name, value));
        }
    }
    (main.trim().to_ascii_lowercase(), params)
}

/// The boundary from a `Content-Type: multipart/...; boundary=...` value.
pub fn boundary(content_type: &str) -> Option<String> {
    let (kind, params) = parse_parameters(content_type);
    if !kind.starts_with("multipart/") {
        return None;
    }
    params
        .into_iter()
        .find(|(name, _)| name == "boundary")
        .map(|(_, value)| value)
        .filter(|b| (1..=70).contains(&b.len()))
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Parses a multipart body into at most `max_parts` parts.
pub fn parse(body: &[u8], boundary: &str, max_parts: usize) -> Result<Vec<Part>, HttpError> {
    let bad = |msg: &str| HttpError {
        status: 400,
        message: format!("malformed multipart body: {msg}"),
    };
    let delimiter = format!("--{boundary}").into_bytes();
    // Every delimiter after the first is preceded by a line break, which belongs to it.
    let inner = format!("\r\n--{boundary}").into_bytes();

    let first = if body.starts_with(&delimiter) {
        0
    } else {
        find(body, &inner, 0).ok_or_else(|| bad("no opening boundary"))? + 2
    };
    let mut pos = first + delimiter.len();
    let mut parts = Vec::new();
    loop {
        if body[pos..].starts_with(b"--") {
            return Ok(parts);
        }
        // Transport padding may follow a delimiter before its line break.
        while matches!(body.get(pos), Some(b' ' | b'\t')) {
            pos += 1;
        }
        if !body[pos..].starts_with(b"\r\n") {
            return Err(bad("boundary not followed by a line break"));
        }
        pos += 2;
        if parts.len() == max_parts {
            return Err(HttpError {
                status: 413,
                message: "too many multipart parts".into(),
            });
        }

        let head_end = if body[pos..].starts_with(b"\r\n") {
            pos
        } else {
            find(body, b"\r\n\r\n", pos).ok_or_else(|| bad("unterminated part headers"))?
        };
        let mut part = Part::default();
        let head = String::from_utf8_lossy(&body[pos..head_end]);
        for line in head.split("\r\n").filter(|l| !l.is_empty()) {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| bad("part header without a colon"))?;
            part.headers.append(name.trim(), value.trim());
        }
        if let Some(disposition) = part.headers.get("content-disposition") {
            for (name, value) in parse_parameters(disposition).1 {
                match name.as_str() {
                    "name" => part.name = Some(value),
                    "filename" => part.filename = Some(value),
                    _ => {}
                }
            }
        }
        part.content_type = part.headers.get("content-type").map(str::to_owned);

        let data_start = head_end + if head_end == pos { 2 } else { 4 };
        let data_end =
            find(body, &inner, data_start).ok_or_else(|| bad("part not closed by a boundary"))?;
        part.data = body[data_start..data_end].to_vec();
        parts.push(part);
        pos = data_end + inner.len();
    }
}

/// A fresh random boundary.
pub fn new_boundary() -> String {
    let mut bytes = [0u8; 12];
    if random::fill(&mut bytes).is_err() {
        // Uniqueness only matters against the body; the time is an adequate fallback.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        bytes.copy_from_slice(&nanos.to_le_bytes()[..12]);
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("weft-{hex}")
}

fn quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Serializes `parts` with `boundary`. Pair it with
/// `Content-Type: multipart/form-data; boundary=<boundary>`.
pub fn encode(parts: &[Part], boundary: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        let mut disposition = String::from("form-data");
        if let Some(name) = &part.name {
            disposition.push_str(&format!("; name=\"{}\"", quote(name)));
        }
        if let Some(filename) = &part.filename {
            disposition.push_str(&format!("; filename=\"{}\"", quote(filename)));
        }
        out.extend_from_slice(format!("Content-Disposition: {disposition}\r\n").as_bytes());
        if let Some(content_type) = &part.content_type {
            out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        for (name, value) in part.headers.iter() {
            if !name.eq_ignore_ascii_case("content-disposition")
                && !name.eq_ignore_ascii_case("content-type")
            {
                out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            }
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&part.data);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_and_files() {
        let body = b"preamble\r\n--XyZ\r\n\
Content-Disposition: form-data; name=\"title\"\r\n\r\n\
Hello\r\n--XyZ \r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"a \\\"b\\\".txt\"\r\n\
Content-Type: text/plain\r\n\r\n\
line1\r\nline2\r\n--XyZ\r\n\r\nno headers\r\n--XyZ--\r\nepilogue";
        let parts = parse(body, "XyZ", 10).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].name.as_deref(), Some("title"));
        assert_eq!(parts[0].data, b"Hello");
        assert_eq!(parts[1].filename.as_deref(), Some("a \"b\".txt"));
        assert_eq!(parts[1].content_type.as_deref(), Some("text/plain"));
        assert_eq!(parts[1].data, b"line1\r\nline2");
        assert_eq!(parts[2].data, b"no headers");
        assert_eq!(parse(body, "XyZ", 2).unwrap_err().status, 413);
        assert!(parse(b"--XyZ\r\nunterminated", "XyZ", 10).is_err());
    }

    #[test]
    fn encode_then_parse() {
        let parts = vec![
            Part::field("a", "1"),
            Part::file(
                "f",
                "x.bin",
                "application/octet-stream",
                vec![0, 13, 10, 255],
            ),
        ];
        let boundary = new_boundary();
        let content_type = format!("multipart/form-data; boundary={boundary}");
        let found = super::boundary(&content_type).unwrap();
        let parsed = parse(&encode(&parts, &found), &found, 10).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].data, b"1");
        assert_eq!(parsed[1].data, [0, 13, 10, 255]);
        assert_eq!(parsed[1].filename.as_deref(), Some("x.bin"));
    }

    #[test]
    fn parameters() {
        let (kind, params) = parse_parameters("Form-Data; Name=x; filename=\"semi;colon\"");
        assert_eq!(kind, "form-data");
        assert_eq!(
            params,
            [
                ("name".into(), "x".into()),
                ("filename".into(), "semi;colon".into())
            ]
        );
        assert_eq!(
            boundary("multipart/form-data; boundary=\"q b\"").as_deref(),
            Some("q b")
        );
        assert_eq!(boundary("text/plain; boundary=x"), None);
    }
}
