//! An ordered, case-insensitive header map.

use std::fmt;

/// Header fields in arrival order. Names compare case-insensitively; repeated fields are kept
/// as separate entries (important for `Set-Cookie`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    fields: Vec<(String, String)>,
}

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    /// The first value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every value of `name`, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Whether `name` holds `token` in its comma-separated value list (case-insensitive),
    /// e.g. `Connection: keep-alive, Upgrade`.
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name)
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }

    /// Adds a field, keeping existing ones of the same name.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.fields.push((name.into(), value.into()));
    }

    /// Replaces every field named `name` with one holding `value`.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        self.remove(&name);
        self.fields.push((name, value.into()));
    }

    /// Removes every field named `name`; returns how many were removed.
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.fields.len();
        self.fields.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        before - self.fields.len()
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// Appends the fields in wire format (`Name: value\r\n` each).
    pub fn write_to(&self, out: &mut Vec<u8>) {
        for (name, value) in &self.fields {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
}

impl<N: Into<String>, V: Into<String>> FromIterator<(N, V)> for Headers {
    fn from_iter<I: IntoIterator<Item = (N, V)>>(iter: I) -> Self {
        Headers {
            fields: iter
                .into_iter()
                .map(|(n, v)| (n.into(), v.into()))
                .collect(),
        }
    }
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (name, value) in &self.fields {
            writeln!(f, "{name}: {value}")?;
        }
        Ok(())
    }
}

/// Whether `name` is a valid field name (an RFC 9110 token).
pub fn is_token(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_token_byte)
}

pub(crate) fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Whether `value` may appear in a field value (no control characters except tab).
pub fn is_valid_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7F))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_insensitive_and_ordered() {
        let mut h = Headers::new();
        h.append("Set-Cookie", "a=1");
        h.append("Content-Type", "text/plain");
        h.append("set-cookie", "b=2");
        assert_eq!(h.get("CONTENT-TYPE"), Some("text/plain"));
        assert_eq!(h.get_all("Set-Cookie").collect::<Vec<_>>(), ["a=1", "b=2"]);

        h.set("SET-COOKIE", "c=3");
        assert_eq!(h.get_all("set-cookie").collect::<Vec<_>>(), ["c=3"]);
        assert_eq!(h.remove("content-type"), 1);

        h.append("Connection", "keep-alive, Upgrade");
        assert!(h.has_token("connection", "upgrade"));
        assert!(!h.has_token("connection", "close"));

        let mut wire = Vec::new();
        h.write_to(&mut wire);
        assert_eq!(
            wire,
            b"SET-COOKIE: c=3\r\nConnection: keep-alive, Upgrade\r\n"
        );
    }

    #[test]
    fn validation() {
        assert!(is_token("X-Request-Id"));
        assert!(!is_token("Bad Name"));
        assert!(!is_token(""));
        assert!(is_valid_value("a\tb c"));
        assert!(!is_valid_value("a\r\nInjected: 1"));
    }
}
