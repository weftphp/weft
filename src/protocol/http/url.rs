//! Percent-encoding (RFC 3986), form-encoded query strings and cookies (RFC 6265).

/// Decodes `%XX` escapes. With `plus_as_space`, `+` becomes a space, as in
/// `application/x-www-form-urlencoded`. Malformed escapes are kept literally.
pub fn percent_decode(input: &str, plus_as_space: bool) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push(hi << 4 | lo);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            b'+' if plus_as_space => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    out
}

/// [`percent_decode`] into a string, replacing invalid UTF-8.
pub fn percent_decode_str(input: &str, plus_as_space: bool) -> String {
    String::from_utf8_lossy(&percent_decode(input, plus_as_space)).into_owned()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Escapes every byte except RFC 3986 unreserved characters (`A-Z a-z 0-9 - . _ ~`).
pub fn percent_encode(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xF) as usize] as char);
        }
    }
    out
}

/// Parses `a=1&b=two&flag` into pairs (a key without `=` gets an empty value).
pub fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                percent_decode_str(key, true),
                percent_decode_str(value, true),
            )
        })
        .collect()
}

/// Builds a form-encoded query string from pairs.
pub fn encode_query<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    pairs
        .into_iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                percent_encode(k.as_bytes()),
                percent_encode(v.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Splits a request target into its path and optional query.
pub fn split_target(target: &str) -> (&str, Option<&str>) {
    let target = target.split('#').next().unwrap_or(target);
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

/// Parses a `Cookie` request header into name/value pairs.
pub fn parse_cookies(header: &str) -> Vec<(String, String)> {
    header
        .split(';')
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            Some((name.to_owned(), percent_decode_str(value, false)))
        })
        .collect()
}

/// `SameSite` cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

/// A `Set-Cookie` header value under construction.
#[derive(Debug, Clone, Default)]
pub struct SetCookie {
    pub name: String,
    pub value: String,
    pub path: Option<String>,
    pub domain: Option<String>,
    /// `Max-Age` in seconds (0 or negative deletes the cookie).
    pub max_age: Option<i64>,
    /// Preformatted `Expires` date (see [`super::date::format`]).
    pub expires: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
}

impl SetCookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> SetCookie {
        SetCookie {
            name: name.into(),
            value: value.into(),
            ..SetCookie::default()
        }
    }

    /// Renders the header value. The cookie value is percent-encoded.
    pub fn to_header(&self) -> String {
        let mut out = format!("{}={}", self.name, percent_encode(self.value.as_bytes()));
        if let Some(expires) = &self.expires {
            out.push_str("; Expires=");
            out.push_str(expires);
        }
        if let Some(age) = self.max_age {
            out.push_str(&format!("; Max-Age={age}"));
        }
        if let Some(domain) = &self.domain {
            out.push_str("; Domain=");
            out.push_str(domain);
        }
        if let Some(path) = &self.path {
            out.push_str("; Path=");
            out.push_str(path);
        }
        if self.secure {
            out.push_str("; Secure");
        }
        if self.http_only {
            out.push_str("; HttpOnly");
        }
        if let Some(same_site) = self.same_site {
            out.push_str(match same_site {
                SameSite::Strict => "; SameSite=Strict",
                SameSite::Lax => "; SameSite=Lax",
                SameSite::None => "; SameSite=None",
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_coding() {
        assert_eq!(percent_decode_str("a%20b+c%2Bd", true), "a b c+d");
        assert_eq!(percent_decode_str("a+b", false), "a+b");
        assert_eq!(percent_decode_str("100%", false), "100%");
        assert_eq!(percent_decode_str("%zz%4", false), "%zz%4");
        assert_eq!(percent_encode("é /?".as_bytes()), "%C3%A9%20%2F%3F");
        assert_eq!(
            percent_decode_str(&percent_encode(b"x=1&y"), false),
            "x=1&y"
        );
    }

    #[test]
    fn queries_and_targets() {
        assert_eq!(
            parse_query("a=1&b=two+words&flag&&c=%26"),
            [
                ("a".into(), "1".into()),
                ("b".into(), "two words".into()),
                ("flag".into(), String::new()),
                ("c".into(), "&".into())
            ]
        );
        assert_eq!(encode_query([("q", "a b"), ("n", "1")]), "q=a%20b&n=1");
        assert_eq!(split_target("/p/a?x=1#frag"), ("/p/a", Some("x=1")));
        assert_eq!(split_target("/only"), ("/only", None));
    }

    #[test]
    fn cookies() {
        assert_eq!(
            parse_cookies("sid=abc; theme=\"dark\"; bad; empty=; n=a%20b"),
            [
                ("sid".into(), "abc".into()),
                ("theme".into(), "dark".into()),
                ("empty".into(), String::new()),
                ("n".into(), "a b".into())
            ]
        );
        let mut c = SetCookie::new("sid", "a b");
        c.path = Some("/".into());
        c.max_age = Some(3600);
        c.http_only = true;
        c.same_site = Some(SameSite::Lax);
        assert_eq!(
            c.to_header(),
            "sid=a%20b; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax"
        );
    }
}
