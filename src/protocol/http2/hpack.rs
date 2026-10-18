//! HPACK header compression (RFC 7541).
//!
//! Each direction of an HTTP/2 connection has one [`Encoder`] on the sending side and one
//! [`Decoder`] on the receiving side; both keep a dynamic table that must evolve identically,
//! so header blocks have to be processed in the order they are sent.

use std::collections::VecDeque;

use super::huffman;
use crate::core::{Error, ErrorKind, Result};

/// Per-entry overhead counted toward the table size (RFC 7541 §4.1).
const ENTRY_OVERHEAD: usize = 32;

/// The default `SETTINGS_HEADER_TABLE_SIZE`.
pub const DEFAULT_TABLE_SIZE: usize = 4096;

/// The static table (RFC 7541 Appendix A). Index 1 is the first entry.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// One header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    /// Ask intermediaries never to compress this field (for secrets such as credentials).
    pub sensitive: bool,
}

impl Field {
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Field {
        Field {
            name: name.into(),
            value: value.into(),
            sensitive: false,
        }
    }

    fn size(&self) -> usize {
        self.name.len() + self.value.len() + ENTRY_OVERHEAD
    }
}

fn compression_error(msg: impl Into<String>) -> Error {
    Error::new(ErrorKind::Protocol, format!("HPACK: {}", msg.into()))
}

#[derive(Debug, Clone)]
struct DynamicTable {
    /// Newest first.
    entries: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    fn new(max_size: usize) -> Self {
        DynamicTable {
            entries: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    fn evict_to(&mut self, limit: usize) {
        while self.size > limit {
            match self.entries.pop_back() {
                Some((name, value)) => self.size -= name.len() + value.len() + ENTRY_OVERHEAD,
                None => break,
            }
        }
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        self.evict_to(max_size);
    }

    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let size = name.len() + value.len() + ENTRY_OVERHEAD;
        if size > self.max_size {
            // An entry larger than the table empties it and is not stored (§4.4).
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.evict_to(self.max_size - size);
        self.entries.push_front((name, value));
        self.size += size;
    }

    /// Resolves a 1-based index across the static and dynamic tables.
    fn get(&self, index: usize) -> Option<(&[u8], &[u8])> {
        match index {
            0 => None,
            1..=61 => {
                let (n, v) = STATIC[index - 1];
                Some((n.as_bytes(), v.as_bytes()))
            }
            _ => self
                .entries
                .get(index - 62)
                .map(|(n, v)| (n.as_slice(), v.as_slice())),
        }
    }
}

// ----- primitives -----

/// Appends an integer with an `prefix`-bit prefix; `flags` fills the byte's high bits.
fn encode_int(mut value: usize, prefix: u32, flags: u8, out: &mut Vec<u8>) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    value -= max;
    while value >= 128 {
        out.push((value % 128) as u8 | 0x80);
        value /= 128;
    }
    out.push(value as u8);
}

/// Decodes an integer with a `prefix`-bit prefix starting at `data[0]`. Returns
/// (value, bytes used). Values beyond 2^28 are rejected as hostile.
fn decode_int(data: &[u8], prefix: u32) -> Result<(usize, usize)> {
    let max = (1usize << prefix) - 1;
    let first = *data
        .first()
        .ok_or_else(|| compression_error("truncated integer"))?;
    let mut value = first as usize & max;
    if value < max {
        return Ok((value, 1));
    }
    let mut shift = 0;
    for (i, &byte) in data[1..].iter().enumerate() {
        value += ((byte & 0x7F) as usize) << shift;
        if value > 1 << 28 {
            return Err(compression_error("integer too large"));
        }
        if byte & 0x80 == 0 {
            return Ok((value, i + 2));
        }
        shift += 7;
    }
    Err(compression_error("truncated integer"))
}

fn encode_string(data: &[u8], huffman_allowed: bool, out: &mut Vec<u8>) {
    let coded_len = huffman::encoded_len(data);
    if huffman_allowed && coded_len < data.len() {
        encode_int(coded_len, 7, 0x80, out);
        huffman::encode(data, out);
    } else {
        encode_int(data.len(), 7, 0, out);
        out.extend_from_slice(data);
    }
}

fn decode_string(data: &[u8], max_len: usize) -> Result<(Vec<u8>, usize)> {
    let huffman_coded = data.first().is_some_and(|b| b & 0x80 != 0);
    let (len, used) = decode_int(data, 7)?;
    let raw = data
        .get(used..used + len)
        .ok_or_else(|| compression_error("truncated string"))?;
    let value = if huffman_coded {
        huffman::decode(raw, max_len)?
    } else if raw.len() > max_len {
        return Err(Error::new(ErrorKind::TooLarge, "HPACK string too long"));
    } else {
        raw.to_vec()
    };
    Ok((value, used + len))
}

// ----- decoder -----

/// Decodes header blocks.
#[derive(Debug, Clone)]
pub struct Decoder {
    table: DynamicTable,
    /// The table size we advertised; size updates may not exceed it.
    allowed_table_size: usize,
    /// Limit on the decoded header list (`SETTINGS_MAX_HEADER_LIST_SIZE`).
    pub max_header_list: usize,
}

impl Decoder {
    pub fn new(table_size: usize, max_header_list: usize) -> Decoder {
        Decoder {
            table: DynamicTable::new(table_size),
            allowed_table_size: table_size,
            max_header_list,
        }
    }

    /// Changes the table size we allow the peer's encoder to use (after our SETTINGS with a
    /// new `SETTINGS_HEADER_TABLE_SIZE` is acknowledged).
    pub fn set_allowed_table_size(&mut self, size: usize) {
        self.allowed_table_size = size;
        if self.table.max_size > size {
            self.table.set_max_size(size);
        }
    }

    /// Decodes one complete header block.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<Field>> {
        let mut fields = Vec::new();
        let mut list_size = 0usize;
        let mut pos = 0;
        let mut updates_allowed = true;
        while pos < block.len() {
            let data = &block[pos..];
            let first = data[0];
            if first & 0x80 != 0 {
                let (index, used) = decode_int(data, 7)?;
                let (name, value) = self
                    .table
                    .get(index)
                    .ok_or_else(|| compression_error(format!("bad index {index}")))?;
                fields.push(Field::new(name, value));
                pos += used;
            } else if first & 0xE0 == 0x20 {
                if !updates_allowed {
                    return Err(compression_error("table size update after a field"));
                }
                let (size, used) = decode_int(data, 5)?;
                if size > self.allowed_table_size {
                    return Err(compression_error("table size update above the limit"));
                }
                self.table.set_max_size(size);
                pos += used;
                continue;
            } else {
                // Literal: with indexing (6-bit prefix), without, or never indexed (4-bit).
                let (prefix, index, sensitive) = match first & 0xF0 {
                    f if f & 0xC0 == 0x40 => (6, true, false),
                    0x10 => (4, false, true),
                    _ => (4, false, false),
                };
                let (name_index, mut used) = decode_int(data, prefix)?;
                let name = if name_index == 0 {
                    let (name, n) = decode_string(&data[used..], self.max_header_list)?;
                    used += n;
                    name
                } else {
                    self.table
                        .get(name_index)
                        .ok_or_else(|| compression_error(format!("bad name index {name_index}")))?
                        .0
                        .to_vec()
                };
                let (value, n) = decode_string(&data[used..], self.max_header_list)?;
                used += n;
                if index {
                    self.table.insert(name.clone(), value.clone());
                }
                fields.push(Field {
                    name,
                    value,
                    sensitive,
                });
                pos += used;
            }
            updates_allowed = false;
            list_size += fields.last().map_or(0, Field::size);
            if list_size > self.max_header_list {
                return Err(Error::new(ErrorKind::TooLarge, "header list too large"));
            }
        }
        Ok(fields)
    }
}

// ----- encoder -----

/// Encodes header blocks.
#[derive(Debug, Clone)]
pub struct Encoder {
    table: DynamicTable,
    /// Size updates to announce at the start of the next block (smallest, then final).
    pending_updates: Option<(usize, usize)>,
    pub use_huffman: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Encoder::new(DEFAULT_TABLE_SIZE)
    }
}

impl Encoder {
    pub fn new(table_size: usize) -> Encoder {
        Encoder {
            table: DynamicTable::new(table_size),
            pending_updates: None,
            use_huffman: true,
        }
    }

    /// Applies the peer's new `SETTINGS_HEADER_TABLE_SIZE`. Weft never uses more than the
    /// default size even if the peer allows more.
    pub fn set_max_table_size(&mut self, size: usize) {
        let size = size.min(DEFAULT_TABLE_SIZE);
        self.table.set_max_size(size);
        self.pending_updates = Some(match self.pending_updates {
            Some((low, _)) => (low.min(size), size),
            None => (size, size),
        });
    }

    fn find(&self, name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
        let mut name_match = None;
        let statics = STATIC.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes()));
        let dynamics = self
            .table
            .entries
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice()));
        for (i, (n, v)) in statics.chain(dynamics).enumerate() {
            if n == name {
                if v == value {
                    return (Some(i + 1), None);
                }
                name_match.get_or_insert(i + 1);
            }
        }
        (None, name_match)
    }

    /// Appends the encoding of `fields` as one header block.
    pub fn encode(&mut self, fields: &[Field], out: &mut Vec<u8>) {
        if let Some((low, last)) = self.pending_updates.take() {
            if low != last {
                encode_int(low, 5, 0x20, out);
            }
            encode_int(last, 5, 0x20, out);
        }
        for field in fields {
            let sensitive = field.sensitive
                || field.name == b"authorization"
                || field.name == b"proxy-authorization";
            let (exact, name_index) = self.find(&field.name, &field.value);
            if let (Some(index), false) = (exact, sensitive) {
                encode_int(index, 7, 0x80, out);
                continue;
            }
            let name_index = exact.or(name_index);
            // Large values would flush the table for little gain.
            let index_it = !sensitive && field.size() <= self.table.max_size / 2;
            let (prefix, flags) = if index_it {
                (6, 0x40)
            } else if sensitive {
                (4, 0x10)
            } else {
                (4, 0x00)
            };
            encode_int(name_index.unwrap_or(0), prefix, flags, out);
            if name_index.is_none() {
                encode_string(&field.name, self.use_huffman, out);
            }
            encode_string(&field.value, self.use_huffman, out);
            if index_it {
                self.table.insert(field.name.clone(), field.value.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fields(list: &[(&str, &str)]) -> Vec<Field> {
        list.iter().map(|(n, v)| Field::new(*n, *v)).collect()
    }

    const REQ1: &[(&str, &str)] = &[
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/"),
        (":authority", "www.example.com"),
    ];
    const REQ2: &[(&str, &str)] = &[
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/"),
        (":authority", "www.example.com"),
        ("cache-control", "no-cache"),
    ];
    const REQ3: &[(&str, &str)] = &[
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/index.html"),
        (":authority", "www.example.com"),
        ("custom-key", "custom-value"),
    ];
    const RES1: &[(&str, &str)] = &[
        (":status", "302"),
        ("cache-control", "private"),
        ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
        ("location", "https://www.example.com"),
    ];
    const RES2: &[(&str, &str)] = &[
        (":status", "307"),
        ("cache-control", "private"),
        ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
        ("location", "https://www.example.com"),
    ];
    const RES3: &[(&str, &str)] = &[
        (":status", "200"),
        ("cache-control", "private"),
        ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
        ("location", "https://www.example.com"),
        ("content-encoding", "gzip"),
        (
            "set-cookie",
            "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        ),
    ];

    fn check_sequence(table_size: usize, steps: &[(&str, &[(&str, &str)])]) {
        let mut decoder = Decoder::new(table_size, 64 * 1024);
        for (wire, expected) in steps {
            assert_eq!(decoder.decode(&hex(wire)).unwrap(), fields(expected));
        }
    }

    // RFC 7541 Appendix C.3-C.6.
    #[test]
    fn rfc_request_examples() {
        check_sequence(
            4096,
            &[
                ("828684410f7777772e6578616d706c652e636f6d", REQ1),
                ("828684be58086e6f2d6361636865", REQ2),
                (
                    "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
                    REQ3,
                ),
            ],
        );
        check_sequence(
            4096,
            &[
                ("828684418cf1e3c2e5f23a6ba0ab90f4ff", REQ1),
                ("828684be5886a8eb10649cbf", REQ2),
                ("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf", REQ3),
            ],
        );
    }

    #[test]
    fn rfc_response_examples_with_eviction() {
        check_sequence(
            256,
            &[
                (
                    "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
                    RES1,
                ),
                ("4803333037c1c0bf", RES2),
                (
                    "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
                    RES3,
                ),
            ],
        );
        check_sequence(
            256,
            &[
                (
                    "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
                    RES1,
                ),
                ("4883640effc1c0bf", RES2),
                (
                    "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
                    RES3,
                ),
            ],
        );
    }

    #[test]
    fn integer_examples() {
        // RFC 7541 C.1: 10 and 1337 with a 5-bit prefix, 42 with an 8-bit prefix.
        let mut out = Vec::new();
        encode_int(10, 5, 0, &mut out);
        encode_int(1337, 5, 0, &mut out);
        encode_int(42, 8, 0, &mut out);
        assert_eq!(out, [0x0A, 0x1F, 0x9A, 0x0A, 0x2A]);
        assert_eq!(decode_int(&out[1..], 5).unwrap(), (1337, 3));
        assert!(decode_int(&[0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F], 5).is_err());
        assert!(decode_int(&[0x1F, 0x80], 5).is_err());
    }

    #[test]
    fn encoder_and_decoder_stay_in_sync() {
        let mut encoder = Encoder::new(256);
        let mut decoder = Decoder::new(4096, 64 * 1024);
        let mut sizes = Vec::new();
        for round in 0..50 {
            let mut block = fields(REQ3);
            block.push(Field::new(
                format!("x-round-{}", round % 7),
                format!("v{round}"),
            ));
            let mut secret = Field::new("x-api-key", "s3cr3t");
            secret.sensitive = true;
            block.push(secret);
            block.push(Field::new("authorization", "Bearer abc"));
            if round == 20 {
                encoder.set_max_table_size(64);
                encoder.set_max_table_size(512);
            }
            let mut wire = Vec::new();
            encoder.encode(&block, &mut wire);
            sizes.push(wire.len());
            let decoded = decoder.decode(&wire).unwrap();
            let plain: Vec<_> = decoded.iter().map(|f| (&f.name, &f.value)).collect();
            let expected: Vec<_> = block.iter().map(|f| (&f.name, &f.value)).collect();
            assert_eq!(plain, expected, "round {round}");
            assert!(decoded[decoded.len() - 2].sensitive);
            assert!(decoded[decoded.len() - 1].sensitive);
        }
        assert!(sizes[1] < sizes[0], "repeated headers compress");
    }

    #[test]
    fn decoder_limits() {
        let mut decoder = Decoder::new(4096, 64 * 1024);
        assert!(decoder.decode(&[0x80]).is_err(), "index 0");
        assert!(
            decoder.decode(&[0xFE]).is_err(),
            "index 126 beyond the tables"
        );
        assert!(
            decoder.decode(&[0x3F, 0xE2, 0x1F]).is_err(),
            "size update above limit"
        );
        assert!(
            decoder.decode(&[0x82, 0x20]).is_err(),
            "size update after a field"
        );
        let mut small = Decoder::new(4096, 40);
        assert!(
            small
                .decode(&hex("828684410f7777772e6578616d706c652e636f6d"))
                .is_err()
        );
    }
}
