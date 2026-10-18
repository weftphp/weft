//! MQTT 3.1.1 (OASIS standard): packet framing and the control packets.
//!
//! [`MqttDecoder`] splits a stream into raw packets using the fixed header's variable-length
//! "remaining length". [`Packet::parse`] and [`Packet::encode`] convert the packets a broker
//! or client needs. MQTT 5 properties are not supported.

use super::framing::Decoder;
use crate::core::bytes::ByteBuffer;
use crate::core::{Error, ErrorKind, Result};

/// Largest value the remaining-length field can express.
pub const MAX_REMAINING: usize = 268_435_455;

fn protocol(msg: impl Into<String>) -> Error {
    Error::new(ErrorKind::Protocol, format!("MQTT: {}", msg.into()))
}

/// Encodes a remaining length (1-4 bytes, 7 bits each, low groups first).
pub fn encode_length(mut len: usize, out: &mut Vec<u8>) -> Result<()> {
    if len > MAX_REMAINING {
        return Err(Error::new(ErrorKind::TooLarge, "MQTT packet too large"));
    }
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            return Ok(());
        }
    }
}

/// Decodes a remaining length; `None` if more bytes are needed. Returns (value, bytes used).
pub fn decode_length(data: &[u8]) -> Result<Option<(usize, usize)>> {
    let mut value = 0usize;
    for (i, &byte) in data.iter().take(4).enumerate() {
        value |= ((byte & 0x7F) as usize) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(Some((value, i + 1)));
        }
    }
    if data.len() >= 4 {
        return Err(protocol("remaining length longer than four bytes"));
    }
    Ok(None)
}

/// A raw packet: the first header byte and the rest of the packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacket {
    pub header: u8,
    pub body: Vec<u8>,
}

/// Splits a byte stream into packets.
#[derive(Debug, Clone)]
pub struct MqttDecoder {
    pub max_packet: usize,
}

impl Decoder for MqttDecoder {
    type Item = RawPacket;

    fn decode(&mut self, buf: &mut ByteBuffer) -> Result<Option<RawPacket>> {
        let data = buf.as_slice();
        let Some(&header) = data.first() else {
            return Ok(None);
        };
        let Some((len, used)) = decode_length(&data[1..])? else {
            return Ok(None);
        };
        if len > self.max_packet {
            return Err(Error::new(
                ErrorKind::TooLarge,
                format!("MQTT packet of {len} bytes exceeds the limit"),
            ));
        }
        let start = 1 + used;
        let Some(body) = data.get(start..start + len) else {
            return Ok(None);
        };
        let packet = RawPacket {
            header,
            body: body.to_vec(),
        };
        buf.consume(start + len);
        Ok(Some(packet))
    }
}

/// Delivery guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QoS {
    AtMostOnce,
    AtLeastOnce,
    ExactlyOnce,
}

impl QoS {
    fn from_bits(bits: u8) -> Result<QoS> {
        match bits {
            0 => Ok(QoS::AtMostOnce),
            1 => Ok(QoS::AtLeastOnce),
            2 => Ok(QoS::ExactlyOnce),
            _ => Err(protocol("invalid QoS 3")),
        }
    }

    fn bits(self) -> u8 {
        self as u8
    }
}

/// A last-will message from CONNECT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    pub topic: String,
    pub message: Vec<u8>,
    pub qos: QoS,
    pub retain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    pub client_id: String,
    pub clean_session: bool,
    pub keep_alive: u16,
    pub will: Option<Will>,
    pub username: Option<String>,
    pub password: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub dup: bool,
    pub qos: QoS,
    pub retain: bool,
    pub topic: String,
    /// Present for QoS 1 and 2.
    pub packet_id: Option<u16>,
    pub payload: Vec<u8>,
}

/// The MQTT 3.1.1 control packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Connect(Connect),
    ConnAck {
        session_present: bool,
        code: u8,
    },
    Publish(Publish),
    PubAck(u16),
    PubRec(u16),
    PubRel(u16),
    PubComp(u16),
    Subscribe {
        packet_id: u16,
        filters: Vec<(String, QoS)>,
    },
    /// Per-filter result: granted QoS, or `None` for failure (0x80).
    SubAck {
        packet_id: u16,
        results: Vec<Option<QoS>>,
    },
    Unsubscribe {
        packet_id: u16,
        filters: Vec<String>,
    },
    UnsubAck(u16),
    PingReq,
    PingResp,
    Disconnect,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let out = self
            .data
            .get(self.pos..self.pos + n)
            .ok_or_else(|| protocol("packet ends early"))?;
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn binary(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.bytes(len)
    }

    fn string(&mut self) -> Result<String> {
        let raw = self.binary()?;
        let text = std::str::from_utf8(raw).map_err(|_| protocol("string is not UTF-8"))?;
        if text.contains('\0') {
            return Err(protocol("string contains NUL"));
        }
        Ok(text.to_owned())
    }

    fn rest(&mut self) -> &'a [u8] {
        let out = &self.data[self.pos..];
        self.pos = self.data.len();
        out
    }

    fn done(&self) -> bool {
        self.pos == self.data.len()
    }
}

fn put_binary(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

impl Packet {
    /// Interprets a raw packet, validating fixed-header flags.
    pub fn parse(raw: &RawPacket) -> Result<Packet> {
        let kind = raw.header >> 4;
        let flags = raw.header & 0x0F;
        let mut c = Cursor {
            data: &raw.body,
            pos: 0,
        };
        // Every type except PUBLISH has fixed flags.
        let required_flags = match kind {
            6 | 8 | 10 => 0b0010,
            3 => flags,
            _ => 0,
        };
        if flags != required_flags {
            return Err(protocol(format!(
                "bad flags {flags:#06b} for packet type {kind}"
            )));
        }
        let packet = match kind {
            1 => Packet::Connect(Self::parse_connect(&mut c)?),
            2 => {
                let ack = c.u8()?;
                if ack & 0xFE != 0 {
                    return Err(protocol("reserved CONNACK bits set"));
                }
                Packet::ConnAck {
                    session_present: ack & 1 == 1,
                    code: c.u8()?,
                }
            }
            3 => {
                let qos = QoS::from_bits(flags >> 1 & 0b11)?;
                let topic = c.string()?;
                if topic.contains(['+', '#']) {
                    return Err(protocol("wildcards are not allowed in a PUBLISH topic"));
                }
                let packet_id = if qos == QoS::AtMostOnce {
                    if flags & 0b1000 != 0 {
                        return Err(protocol("DUP set on a QoS 0 message"));
                    }
                    None
                } else {
                    Some(c.u16()?)
                };
                Packet::Publish(Publish {
                    dup: flags & 0b1000 != 0,
                    qos,
                    retain: flags & 1 == 1,
                    topic,
                    packet_id,
                    payload: c.rest().to_vec(),
                })
            }
            4 => Packet::PubAck(c.u16()?),
            5 => Packet::PubRec(c.u16()?),
            6 => Packet::PubRel(c.u16()?),
            7 => Packet::PubComp(c.u16()?),
            8 => {
                let packet_id = c.u16()?;
                let mut filters = Vec::new();
                while !c.done() {
                    let filter = c.string()?;
                    let options = c.u8()?;
                    if options & 0xFC != 0 {
                        return Err(protocol("reserved subscription option bits set"));
                    }
                    filters.push((filter, QoS::from_bits(options)?));
                }
                if filters.is_empty() {
                    return Err(protocol("SUBSCRIBE without filters"));
                }
                Packet::Subscribe { packet_id, filters }
            }
            9 => {
                let packet_id = c.u16()?;
                let results = c
                    .rest()
                    .iter()
                    .map(|&code| match code {
                        0x80 => Ok(None),
                        bits => QoS::from_bits(bits).map(Some),
                    })
                    .collect::<Result<_>>()?;
                Packet::SubAck { packet_id, results }
            }
            10 => {
                let packet_id = c.u16()?;
                let mut filters = Vec::new();
                while !c.done() {
                    filters.push(c.string()?);
                }
                if filters.is_empty() {
                    return Err(protocol("UNSUBSCRIBE without filters"));
                }
                Packet::Unsubscribe { packet_id, filters }
            }
            11 => Packet::UnsubAck(c.u16()?),
            12 => Packet::PingReq,
            13 => Packet::PingResp,
            14 => Packet::Disconnect,
            other => return Err(protocol(format!("unknown packet type {other}"))),
        };
        if !c.done() {
            return Err(protocol("trailing bytes after packet"));
        }
        Ok(packet)
    }

    fn parse_connect(c: &mut Cursor<'_>) -> Result<Connect> {
        if c.string()? != "MQTT" {
            return Err(protocol("unknown protocol name"));
        }
        let level = c.u8()?;
        if level != 4 {
            return Err(protocol(format!("unsupported protocol level {level}")));
        }
        let flags = c.u8()?;
        if flags & 1 != 0 {
            return Err(protocol("reserved CONNECT flag set"));
        }
        let keep_alive = c.u16()?;
        let client_id = c.string()?;
        let will = if flags & 0b100 != 0 {
            Some(Will {
                topic: c.string()?,
                message: c.binary()?.to_vec(),
                qos: QoS::from_bits(flags >> 3 & 0b11)?,
                retain: flags & 0b10_0000 != 0,
            })
        } else {
            if flags & 0b11_1000 != 0 {
                return Err(protocol("will QoS/retain set without a will"));
            }
            None
        };
        let username = (flags & 0x80 != 0).then(|| c.string()).transpose()?;
        let password = (flags & 0x40 != 0)
            .then(|| c.binary().map(<[u8]>::to_vec))
            .transpose()?;
        if password.is_some() && username.is_none() {
            return Err(protocol("password without a user name"));
        }
        Ok(Connect {
            client_id,
            clean_session: flags & 0b10 != 0,
            keep_alive,
            will,
            username,
            password,
        })
    }

    /// Serializes the packet.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let header: u8 = match self {
            Packet::Connect(c) => {
                put_binary(&mut body, b"MQTT");
                body.push(4);
                let mut flags = u8::from(c.clean_session) << 1;
                if let Some(will) = &c.will {
                    flags |= 0b100 | will.qos.bits() << 3 | u8::from(will.retain) << 5;
                }
                flags |= u8::from(c.password.is_some()) << 6 | u8::from(c.username.is_some()) << 7;
                body.push(flags);
                body.extend_from_slice(&c.keep_alive.to_be_bytes());
                put_binary(&mut body, c.client_id.as_bytes());
                if let Some(will) = &c.will {
                    put_binary(&mut body, will.topic.as_bytes());
                    put_binary(&mut body, &will.message);
                }
                if let Some(user) = &c.username {
                    put_binary(&mut body, user.as_bytes());
                }
                if let Some(password) = &c.password {
                    put_binary(&mut body, password);
                }
                0x10
            }
            Packet::ConnAck {
                session_present,
                code,
            } => {
                body.extend_from_slice(&[u8::from(*session_present), *code]);
                0x20
            }
            Packet::Publish(p) => {
                put_binary(&mut body, p.topic.as_bytes());
                if p.qos != QoS::AtMostOnce {
                    let id = p
                        .packet_id
                        .ok_or_else(|| protocol("QoS 1/2 PUBLISH needs a packet id"))?;
                    body.extend_from_slice(&id.to_be_bytes());
                }
                body.extend_from_slice(&p.payload);
                0x30 | u8::from(p.dup) << 3 | p.qos.bits() << 1 | u8::from(p.retain)
            }
            Packet::PubAck(id)
            | Packet::PubRec(id)
            | Packet::PubRel(id)
            | Packet::PubComp(id)
            | Packet::UnsubAck(id) => {
                body.extend_from_slice(&id.to_be_bytes());
                match self {
                    Packet::PubAck(_) => 0x40,
                    Packet::PubRec(_) => 0x50,
                    Packet::PubRel(_) => 0x62,
                    Packet::PubComp(_) => 0x70,
                    _ => 0xB0,
                }
            }
            Packet::Subscribe { packet_id, filters } => {
                body.extend_from_slice(&packet_id.to_be_bytes());
                for (filter, qos) in filters {
                    put_binary(&mut body, filter.as_bytes());
                    body.push(qos.bits());
                }
                0x82
            }
            Packet::SubAck { packet_id, results } => {
                body.extend_from_slice(&packet_id.to_be_bytes());
                body.extend(results.iter().map(|r| r.map_or(0x80, QoS::bits)));
                0x90
            }
            Packet::Unsubscribe { packet_id, filters } => {
                body.extend_from_slice(&packet_id.to_be_bytes());
                for filter in filters {
                    put_binary(&mut body, filter.as_bytes());
                }
                0xA2
            }
            Packet::PingReq => 0xC0,
            Packet::PingResp => 0xD0,
            Packet::Disconnect => 0xE0,
        };
        let mut out = vec![header];
        encode_length(body.len(), &mut out)?;
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Whether `topic` matches the subscription `filter` (`+` one level, `#` the rest).
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    // Wildcards at the first level never match topics starting with `$`.
    if topic.starts_with('$') && filter.starts_with(['+', '#']) {
        return false;
    }
    let mut filter_levels = filter.split('/');
    let mut topic_levels = topic.split('/');
    loop {
        match (filter_levels.next(), topic_levels.next()) {
            (Some("#"), _) => return filter_levels.next().is_none(),
            (Some("+"), Some(_)) => {}
            (Some(f), Some(t)) if f == t => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_length_boundaries() {
        // The boundary values from the specification's table.
        for (value, bytes) in [
            (0, vec![0x00]),
            (127, vec![0x7F]),
            (128, vec![0x80, 0x01]),
            (16_383, vec![0xFF, 0x7F]),
            (16_384, vec![0x80, 0x80, 0x01]),
            (2_097_151, vec![0xFF, 0xFF, 0x7F]),
            (2_097_152, vec![0x80, 0x80, 0x80, 0x01]),
            (MAX_REMAINING, vec![0xFF, 0xFF, 0xFF, 0x7F]),
        ] {
            let mut out = Vec::new();
            encode_length(value, &mut out).unwrap();
            assert_eq!(out, bytes);
            assert_eq!(decode_length(&bytes).unwrap(), Some((value, bytes.len())));
        }
        assert!(encode_length(MAX_REMAINING + 1, &mut Vec::new()).is_err());
        assert!(decode_length(&[0xFF, 0xFF, 0xFF, 0xFF]).is_err());
        assert_eq!(decode_length(&[0x80]).unwrap(), None);
    }

    fn roundtrip(packet: Packet) {
        let wire = packet.encode().unwrap();
        let mut decoder = MqttDecoder { max_packet: 1024 };
        let mut buf = ByteBuffer::new();
        let mut raw = None;
        for &b in &wire {
            buf.extend_from_slice(&[b]);
            if let Some(r) = decoder.decode(&mut buf).unwrap() {
                raw = Some(r);
            }
        }
        assert_eq!(Packet::parse(&raw.unwrap()).unwrap(), packet);
    }

    #[test]
    fn packets_roundtrip() {
        roundtrip(Packet::Connect(Connect {
            client_id: "dev-1".into(),
            clean_session: true,
            keep_alive: 60,
            will: Some(Will {
                topic: "dev/1/status".into(),
                message: b"offline".to_vec(),
                qos: QoS::AtLeastOnce,
                retain: true,
            }),
            username: Some("user".into()),
            password: Some(b"secret".to_vec()),
        }));
        roundtrip(Packet::ConnAck {
            session_present: true,
            code: 0,
        });
        roundtrip(Packet::Publish(Publish {
            dup: false,
            qos: QoS::ExactlyOnce,
            retain: true,
            topic: "a/b".into(),
            packet_id: Some(9),
            payload: b"data".to_vec(),
        }));
        roundtrip(Packet::PubRel(9));
        roundtrip(Packet::Subscribe {
            packet_id: 3,
            filters: vec![
                ("a/+".into(), QoS::AtMostOnce),
                ("b/#".into(), QoS::ExactlyOnce),
            ],
        });
        roundtrip(Packet::SubAck {
            packet_id: 3,
            results: vec![Some(QoS::AtMostOnce), None],
        });
        roundtrip(Packet::Unsubscribe {
            packet_id: 4,
            filters: vec!["a/+".into()],
        });
        roundtrip(Packet::PingReq);
        roundtrip(Packet::Disconnect);
    }

    #[test]
    fn rejects_bad_packets() {
        let raw = |header, body: &[u8]| RawPacket {
            header,
            body: body.to_vec(),
        };
        assert!(
            Packet::parse(&raw(0x80, &[0, 1, 0, 1, b'a', 0])).is_err(),
            "SUBSCRIBE flags"
        );
        assert!(
            Packet::parse(&raw(0x36, &[0, 1, b'a', 0, 1])).is_err(),
            "QoS 3"
        );
        assert!(
            Packet::parse(&raw(0x30, &[0, 1, b'#'])).is_err(),
            "wildcard topic"
        );
        assert!(Packet::parse(&raw(0xC0, &[0])).is_err(), "trailing byte");
        assert!(Packet::parse(&raw(0xF0, &[])).is_err(), "reserved type");
    }

    #[test]
    fn topic_filters() {
        assert!(topic_matches("sport/tennis/+", "sport/tennis/player1"));
        assert!(!topic_matches(
            "sport/tennis/+",
            "sport/tennis/player1/ranking"
        ));
        assert!(topic_matches("sport/#", "sport"));
        assert!(topic_matches("sport/#", "sport/tennis/player1"));
        assert!(topic_matches("+/+", "/finance"));
        assert!(!topic_matches("#", "$SYS/info"));
        assert!(topic_matches("$SYS/#", "$SYS/info"));
        assert!(!topic_matches("a/b", "a/c"));
    }
}
