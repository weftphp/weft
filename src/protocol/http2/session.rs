//! The server side of an HTTP/2 connection as a sans-I/O state machine.
//!
//! Feed received bytes to [`ServerSession::receive`], collect complete requests from
//! [`ServerSession::poll_event`], answer with [`ServerSession::send_headers`] /
//! [`ServerSession::send_data`] / [`ServerSession::send_trailers`], and write out whatever
//! [`ServerSession::take_output`] returns. The session enforces stream states, flow control
//! (in both directions) and the request rules of RFC 9113 §8.
//!
//! Received bodies are buffered until the request ends, bounded by `max_body`; the receive
//! windows are replenished as data arrives.

use std::collections::{BTreeMap, VecDeque};

use super::frame::{self, Frame, FrameDecoder, H2Error, MAX_WINDOW, PREFACE, Reason, Settings};
use super::hpack::{self, Field};
use crate::core::bytes::ByteBuffer;

/// Session limits and advertised settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Settings advertised to the client.
    pub settings: Settings,
    /// Largest request body accepted per stream.
    pub max_body: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            settings: Settings {
                enable_push: false,
                max_concurrent_streams: Some(128),
                max_header_list_size: Some(64 * 1024),
                ..Settings::default()
            },
            max_body: 8 * 1024 * 1024,
        }
    }
}

/// A complete request's pseudo-header fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestHead {
    pub method: String,
    pub scheme: Option<String>,
    pub authority: Option<String>,
    pub path: Option<String>,
    /// `:protocol`, for extended CONNECT (RFC 8441).
    pub protocol: Option<String>,
}

/// Something the application must handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A complete request.
    Request {
        stream: u32,
        head: RequestHead,
        /// Regular (non-pseudo) header fields.
        headers: Vec<Field>,
        body: Vec<u8>,
        trailers: Vec<Field>,
    },
    /// The client cancelled a stream; drop any work for it.
    Reset { stream: u32, reason: Reason },
    /// The client is shutting the connection down.
    GoAway { last_stream: u32, reason: Reason },
}

#[derive(Debug)]
enum Outgoing {
    Data {
        data: Vec<u8>,
        sent: usize,
        end: bool,
    },
    Trailers(Vec<Field>),
}

#[derive(Debug)]
struct Stream {
    /// The client finished its side (END_STREAM received).
    remote_done: bool,
    /// We finished our side (END_STREAM sent).
    local_done: bool,
    /// Response headers were sent.
    headers_sent: bool,
    head: Option<RequestHead>,
    headers: Vec<Field>,
    body: Vec<u8>,
    trailers: Vec<Field>,
    send_window: i64,
    queue: VecDeque<Outgoing>,
}

impl Stream {
    fn new(send_window: u32) -> Stream {
        Stream {
            remote_done: false,
            local_done: false,
            headers_sent: false,
            head: None,
            headers: Vec::new(),
            body: Vec::new(),
            trailers: Vec::new(),
            send_window: i64::from(send_window),
            queue: VecDeque::new(),
        }
    }
}

/// A header block being assembled from HEADERS + CONTINUATION frames.
#[derive(Debug)]
struct PendingBlock {
    stream: u32,
    end_stream: bool,
    block: Vec<u8>,
}

/// Recently reset stream ids remembered so late frames for them can be ignored.
const RESET_MEMORY: usize = 256;

/// See the [module documentation](self).
#[derive(Debug)]
pub struct ServerSession {
    config: Config,
    remote: Settings,
    frames: FrameDecoder,
    hpack_in: hpack::Decoder,
    hpack_out: hpack::Encoder,
    input: ByteBuffer,
    preface_done: bool,
    settings_seen: bool,
    streams: BTreeMap<u32, Stream>,
    reset: VecDeque<u32>,
    last_stream: u32,
    send_window: i64,
    pending: Option<PendingBlock>,
    output: Vec<u8>,
    events: VecDeque<Event>,
    goaway_sent: bool,
}

impl ServerSession {
    /// Creates a session and queues the server's SETTINGS frame.
    pub fn new(config: Config) -> ServerSession {
        let local = config.settings;
        let mut session = ServerSession {
            frames: FrameDecoder {
                max_frame_size: local.max_frame_size,
            },
            hpack_in: hpack::Decoder::new(
                local.header_table_size as usize,
                local
                    .max_header_list_size
                    .map_or(usize::MAX, |n| n as usize),
            ),
            hpack_out: hpack::Encoder::default(),
            config,
            remote: Settings::default(),
            input: ByteBuffer::new(),
            preface_done: false,
            settings_seen: false,
            streams: BTreeMap::new(),
            reset: VecDeque::new(),
            last_stream: 0,
            send_window: i64::from(frame::DEFAULT_WINDOW),
            pending: None,
            output: Vec::new(),
            events: VecDeque::new(),
            goaway_sent: false,
        };
        let values = local.changes();
        session.write(Frame::Settings { ack: false, values });
        // Open the connection window as wide as the per-stream window we advertise.
        let extra = local
            .initial_window_size
            .saturating_sub(frame::DEFAULT_WINDOW);
        if extra > 0 {
            session.write(Frame::WindowUpdate {
                stream: 0,
                increment: extra,
            });
        }
        session
    }

    fn write(&mut self, frame: Frame) {
        frame.encode(&mut self.output);
    }

    /// Bytes to send to the client.
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output)
    }

    pub fn has_output(&self) -> bool {
        !self.output.is_empty()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Number of streams still in progress.
    pub fn active_streams(&self) -> usize {
        self.streams.len()
    }

    /// Whether the connection is finished: GOAWAY was exchanged and no stream is active.
    pub fn is_closed(&self) -> bool {
        self.goaway_sent && self.streams.is_empty()
    }

    /// Processes received bytes. On a connection error a GOAWAY is queued and the error is
    /// returned; the caller should flush the output and close the connection.
    pub fn receive(&mut self, data: &[u8]) -> Result<(), H2Error> {
        if self.goaway_sent && self.streams.is_empty() {
            return Ok(());
        }
        self.input.extend_from_slice(data);
        let result = self.process();
        if let Err(err) = &result {
            self.go_away(err.reason, &err.message);
        }
        result
    }

    fn process(&mut self) -> Result<(), H2Error> {
        if !self.preface_done {
            let have = self.input.len().min(PREFACE.len());
            if self.input.as_slice()[..have] != PREFACE[..have] {
                return Err(H2Error::connection(
                    Reason::ProtocolError,
                    "missing HTTP/2 connection preface",
                ));
            }
            if have < PREFACE.len() {
                return Ok(());
            }
            self.input.consume(PREFACE.len());
            self.preface_done = true;
        }
        while let Some(frame) = self.frames.decode(&mut self.input)? {
            if !self.settings_seen && !matches!(frame, Frame::Settings { ack: false, .. }) {
                return Err(H2Error::connection(
                    Reason::ProtocolError,
                    "first frame must be SETTINGS",
                ));
            }
            match self.handle(frame) {
                Err(H2Error {
                    stream: Some(id),
                    reason,
                    ..
                }) => self.reset_stream(id, reason),
                other => other?,
            }
        }
        self.flush();
        Ok(())
    }

    fn handle(&mut self, frame: Frame) -> Result<(), H2Error> {
        if let Some(pending) = &mut self.pending {
            return match frame {
                Frame::Continuation {
                    stream,
                    end_headers,
                    block,
                } if stream == pending.stream => {
                    pending.block.extend_from_slice(&block);
                    let limit = self.config.settings.max_header_list_size.unwrap_or(1 << 20);
                    if pending.block.len() > limit as usize * 2 {
                        return Err(H2Error::connection(
                            Reason::EnhanceYourCalm,
                            "header block too large",
                        ));
                    }
                    if end_headers {
                        let PendingBlock {
                            stream,
                            end_stream,
                            block,
                        } = self.pending.take().ok_or_else(|| {
                            H2Error::connection(Reason::InternalError, "lost header block")
                        })?;
                        self.headers_complete(stream, end_stream, &block)?;
                    }
                    Ok(())
                }
                _ => Err(H2Error::connection(
                    Reason::ProtocolError,
                    "expected CONTINUATION",
                )),
            };
        }

        match frame {
            Frame::Settings { ack: true, .. } => {
                self.hpack_in
                    .set_allowed_table_size(self.config.settings.header_table_size as usize);
            }
            Frame::Settings { ack: false, values } => {
                self.settings_seen = true;
                let old_window = self.remote.initial_window_size;
                self.remote.apply(&values)?;
                let delta = i64::from(self.remote.initial_window_size) - i64::from(old_window);
                for stream in self.streams.values_mut() {
                    stream.send_window += delta;
                    if stream.send_window > i64::from(MAX_WINDOW) {
                        return Err(H2Error::connection(
                            Reason::FlowControlError,
                            "window overflow after SETTINGS",
                        ));
                    }
                }
                self.hpack_out
                    .set_max_table_size(self.remote.header_table_size as usize);
                self.write(Frame::Settings {
                    ack: true,
                    values: Vec::new(),
                });
            }
            Frame::Ping { ack: false, data } => self.write(Frame::Ping { ack: true, data }),
            Frame::Ping { ack: true, .. } => {}
            Frame::GoAway {
                last_stream,
                reason,
                ..
            } => self.events.push_back(Event::GoAway {
                last_stream,
                reason,
            }),
            Frame::WindowUpdate {
                stream: 0,
                increment,
            } => {
                self.send_window += i64::from(increment);
                if self.send_window > i64::from(MAX_WINDOW) {
                    return Err(H2Error::connection(
                        Reason::FlowControlError,
                        "connection window overflow",
                    ));
                }
            }
            Frame::WindowUpdate { stream, increment } => {
                self.check_not_idle(stream)?;
                if let Some(s) = self.streams.get_mut(&stream) {
                    s.send_window += i64::from(increment);
                    if s.send_window > i64::from(MAX_WINDOW) {
                        return Err(H2Error::stream(
                            stream,
                            Reason::FlowControlError,
                            "stream window overflow",
                        ));
                    }
                }
            }
            Frame::Headers {
                stream,
                end_stream,
                end_headers,
                priority,
                block,
            } => {
                if priority.is_some_and(|p| p.depends_on == stream) {
                    return Err(H2Error::stream(
                        stream,
                        Reason::ProtocolError,
                        "stream depends on itself",
                    ));
                }
                if end_headers {
                    self.headers_complete(stream, end_stream, &block)?;
                } else {
                    self.pending = Some(PendingBlock {
                        stream,
                        end_stream,
                        block,
                    });
                }
            }
            Frame::Data {
                stream,
                end_stream,
                data,
                flow_len,
            } => self.data(stream, end_stream, data, flow_len)?,
            Frame::RstStream { stream, reason } => {
                self.check_not_idle(stream)?;
                if self.streams.remove(&stream).is_some() {
                    self.events.push_back(Event::Reset { stream, reason });
                }
            }
            Frame::Priority { stream, priority } => {
                if priority.depends_on == stream {
                    return Err(H2Error::stream(
                        stream,
                        Reason::ProtocolError,
                        "stream depends on itself",
                    ));
                }
            }
            Frame::PushPromise { .. } => {
                return Err(H2Error::connection(
                    Reason::ProtocolError,
                    "clients cannot push",
                ));
            }
            Frame::Continuation { .. } => {
                return Err(H2Error::connection(
                    Reason::ProtocolError,
                    "CONTINUATION without HEADERS",
                ));
            }
            Frame::Unknown { .. } => {}
        }
        Ok(())
    }

    fn check_not_idle(&self, stream: u32) -> Result<(), H2Error> {
        if stream > self.last_stream {
            return Err(H2Error::connection(
                Reason::ProtocolError,
                format!("frame on idle stream {stream}"),
            ));
        }
        Ok(())
    }

    fn headers_complete(&mut self, id: u32, end_stream: bool, block: &[u8]) -> Result<(), H2Error> {
        // Decode first in every case: the HPACK state must see every block.
        let fields = self
            .hpack_in
            .decode(block)
            .map_err(|e| H2Error::connection(Reason::CompressionError, e.to_string()))?;

        if let Some(stream) = self.streams.get_mut(&id) {
            // A second block on an open stream is a trailer section.
            if stream.remote_done {
                return Err(H2Error::stream(
                    id,
                    Reason::StreamClosed,
                    "HEADERS after END_STREAM",
                ));
            }
            if !end_stream {
                return Err(H2Error::stream(
                    id,
                    Reason::ProtocolError,
                    "trailers must end the stream",
                ));
            }
            if fields.iter().any(|f| f.name.starts_with(b":")) {
                return Err(H2Error::stream(
                    id,
                    Reason::ProtocolError,
                    "pseudo-header in trailers",
                ));
            }
            stream.trailers = fields;
            stream.remote_done = true;
            return self.request_complete(id);
        }

        if id.is_multiple_of(2) || id <= self.last_stream {
            if self.reset.contains(&id) {
                return Ok(());
            }
            return Err(H2Error::connection(
                Reason::ProtocolError,
                format!("client opened invalid stream {id}"),
            ));
        }
        self.last_stream = id;
        if self.goaway_sent {
            return Ok(());
        }
        let limit = self
            .config
            .settings
            .max_concurrent_streams
            .unwrap_or(u32::MAX);
        if self.streams.len() >= limit as usize {
            return Err(H2Error::stream(
                id,
                Reason::RefusedStream,
                "too many streams",
            ));
        }
        let (head, headers) = validate_request(id, fields)?;
        let mut stream = Stream::new(self.remote.initial_window_size);
        stream.head = Some(head);
        stream.headers = headers;
        stream.remote_done = end_stream;
        self.streams.insert(id, stream);
        if end_stream {
            self.request_complete(id)?;
        }
        Ok(())
    }

    fn data(
        &mut self,
        id: u32,
        end_stream: bool,
        data: Vec<u8>,
        flow_len: u32,
    ) -> Result<(), H2Error> {
        self.check_not_idle(id)?;
        // Flow control counts every DATA frame, even ones we then discard.
        if flow_len > 0 {
            self.write(Frame::WindowUpdate {
                stream: 0,
                increment: flow_len,
            });
        }
        let max_body = self.config.max_body;
        let Some(stream) = self.streams.get_mut(&id).filter(|s| !s.remote_done) else {
            if self.reset.contains(&id) {
                return Ok(());
            }
            return Err(H2Error::stream(
                id,
                Reason::StreamClosed,
                "DATA on a closed stream",
            ));
        };
        if stream.body.len() + data.len() > max_body {
            return Err(H2Error::stream(
                id,
                Reason::Cancel,
                "request body too large",
            ));
        }
        stream.body.extend_from_slice(&data);
        if end_stream {
            stream.remote_done = true;
            self.request_complete(id)?;
        } else if flow_len > 0 {
            self.write(Frame::WindowUpdate {
                stream: id,
                increment: flow_len,
            });
        }
        Ok(())
    }

    fn request_complete(&mut self, id: u32) -> Result<(), H2Error> {
        let Some(stream) = self.streams.get_mut(&id) else {
            return Ok(());
        };
        if let Some(length) = stream
            .headers
            .iter()
            .find(|f| f.name == b"content-length")
            .map(|f| String::from_utf8_lossy(&f.value).trim().to_owned())
            && length.parse::<usize>().ok() != Some(stream.body.len())
        {
            return Err(H2Error::stream(
                id,
                Reason::ProtocolError,
                "content-length does not match the body",
            ));
        }
        let head = stream.head.take().unwrap_or_default();
        self.events.push_back(Event::Request {
            stream: id,
            head,
            headers: std::mem::take(&mut stream.headers),
            body: std::mem::take(&mut stream.body),
            trailers: std::mem::take(&mut stream.trailers),
        });
        self.close_if_done(id);
        Ok(())
    }

    fn close_if_done(&mut self, id: u32) {
        if self
            .streams
            .get(&id)
            .is_some_and(|s| s.remote_done && s.local_done)
        {
            self.streams.remove(&id);
        }
    }

    fn remember_reset(&mut self, id: u32) {
        if self.reset.len() == RESET_MEMORY {
            self.reset.pop_front();
        }
        self.reset.push_back(id);
    }

    fn reset_stream(&mut self, id: u32, reason: Reason) {
        self.streams.remove(&id);
        self.last_stream = self.last_stream.max(id);
        self.remember_reset(id);
        self.write(Frame::RstStream { stream: id, reason });
    }

    // ----- sending -----

    fn writable(&mut self, id: u32) -> Result<&mut Stream, H2Error> {
        match self.streams.get_mut(&id) {
            Some(s) if !s.local_done => Ok(s),
            _ => Err(H2Error::stream(
                id,
                Reason::StreamClosed,
                "stream is not open for sending",
            )),
        }
    }

    /// Sends response headers. `fields` must start with `:status`. With `end_stream` the
    /// response has no body.
    pub fn send_headers(
        &mut self,
        id: u32,
        fields: &[Field],
        end_stream: bool,
    ) -> Result<(), H2Error> {
        let stream = self.writable(id)?;
        if stream.headers_sent {
            return Err(H2Error::stream(
                id,
                Reason::InternalError,
                "headers already sent",
            ));
        }
        stream.headers_sent = true;
        stream.local_done = end_stream;
        self.write_header_block(id, fields, end_stream);
        self.close_if_done(id);
        Ok(())
    }

    /// Queues body data, sent as flow control allows.
    pub fn send_data(&mut self, id: u32, data: &[u8], end_stream: bool) -> Result<(), H2Error> {
        let stream = self.writable(id)?;
        if !stream.headers_sent {
            return Err(H2Error::stream(
                id,
                Reason::InternalError,
                "data before headers",
            ));
        }
        if end_stream && matches!(stream.queue.back(), Some(Outgoing::Trailers(_))) {
            return Err(H2Error::stream(
                id,
                Reason::InternalError,
                "data after trailers",
            ));
        }
        stream.queue.push_back(Outgoing::Data {
            data: data.to_vec(),
            sent: 0,
            end: end_stream,
        });
        if end_stream {
            stream.local_done = true;
        }
        self.flush();
        Ok(())
    }

    /// Queues trailers, which end the stream after any queued data.
    pub fn send_trailers(&mut self, id: u32, fields: &[Field]) -> Result<(), H2Error> {
        let stream = self.writable(id)?;
        stream.queue.push_back(Outgoing::Trailers(fields.to_vec()));
        stream.local_done = true;
        self.flush();
        Ok(())
    }

    /// Abandons a stream with RST_STREAM.
    pub fn cancel(&mut self, id: u32, reason: Reason) {
        if self.streams.contains_key(&id) {
            self.reset_stream(id, reason);
        }
    }

    /// Starts a graceful shutdown: streams already open finish, new ones are refused.
    pub fn go_away(&mut self, reason: Reason, debug: &str) {
        if self.goaway_sent {
            return;
        }
        self.goaway_sent = true;
        self.write(Frame::GoAway {
            last_stream: self.last_stream,
            reason,
            debug: debug.as_bytes().to_vec(),
        });
        if reason != Reason::NoError {
            self.streams.clear();
        }
    }

    fn write_header_block(&mut self, id: u32, fields: &[Field], end_stream: bool) {
        let mut block = Vec::new();
        self.hpack_out.encode(fields, &mut block);
        let max = self.remote.max_frame_size as usize;
        let mut chunks = block.chunks(max).peekable();
        let first = chunks.next().unwrap_or(&[]).to_vec();
        self.write(Frame::Headers {
            stream: id,
            end_stream,
            end_headers: chunks.peek().is_none(),
            priority: None,
            block: first,
        });
        while let Some(chunk) = chunks.next() {
            self.write(Frame::Continuation {
                stream: id,
                end_headers: chunks.peek().is_none(),
                block: chunk.to_vec(),
            });
        }
    }

    /// Sends queued data while the windows allow, stream by stream.
    fn flush(&mut self) {
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        let max_frame = self.remote.max_frame_size as usize;
        let mut finished = Vec::new();
        for id in ids {
            while let Some(stream) = self.streams.get_mut(&id) {
                match stream.queue.front_mut() {
                    None => break,
                    Some(Outgoing::Trailers(_)) => {
                        let Some(Outgoing::Trailers(fields)) = stream.queue.pop_front() else {
                            break;
                        };
                        self.write_header_block(id, &fields, true);
                        finished.push(id);
                    }
                    Some(Outgoing::Data { data, sent, end }) => {
                        let left = data.len() - *sent;
                        let allowed = self.send_window.min(stream.send_window).max(0) as usize;
                        let n = left.min(allowed).min(max_frame);
                        if n == 0 && left > 0 {
                            break;
                        }
                        let chunk = data[*sent..*sent + n].to_vec();
                        *sent += n;
                        let done = *sent == data.len();
                        let end_stream = done && *end;
                        stream.send_window -= n as i64;
                        if done {
                            stream.queue.pop_front();
                        }
                        self.send_window -= n as i64;
                        // An empty non-final chunk carries nothing; skip the frame.
                        if n > 0 || end_stream {
                            self.write(Frame::Data {
                                stream: id,
                                end_stream,
                                data: chunk,
                                flow_len: n as u32,
                            });
                        }
                        if end_stream {
                            finished.push(id);
                        }
                    }
                }
            }
        }
        for id in finished {
            self.close_if_done(id);
        }
    }
}

/// Splits pseudo-headers from regular fields and enforces RFC 9113 §8.2-8.3.
fn validate_request(id: u32, fields: Vec<Field>) -> Result<(RequestHead, Vec<Field>), H2Error> {
    let bad = |msg: &str| H2Error::stream(id, Reason::ProtocolError, msg);
    let mut head = RequestHead::default();
    let mut method = None;
    let mut regular = Vec::new();
    for field in fields {
        let value = || String::from_utf8_lossy(&field.value).into_owned();
        if let Some(pseudo) = field.name.strip_prefix(b":") {
            if !regular.is_empty() {
                return Err(bad("pseudo-header after a regular field"));
            }
            let slot = match pseudo {
                b"method" => &mut method,
                b"scheme" => &mut head.scheme,
                b"authority" => &mut head.authority,
                b"path" => &mut head.path,
                b"protocol" => &mut head.protocol,
                _ => return Err(bad("unknown or response pseudo-header")),
            };
            if slot.replace(value()).is_some() {
                return Err(bad("duplicate pseudo-header"));
            }
            continue;
        }
        if field.name.is_empty()
            || field.name.iter().any(|b| b.is_ascii_uppercase())
            || !field
                .name
                .iter()
                .all(|&b| crate::protocol::http::headers::is_token_byte(b))
        {
            return Err(bad("field names must be lowercase tokens"));
        }
        match field.name.as_slice() {
            b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
            | b"upgrade" => return Err(bad("connection-specific header field")),
            b"te" if field.value != b"trailers" => return Err(bad("te other than trailers")),
            _ => {}
        }
        if field
            .value
            .iter()
            .any(|&b| b == 0 || b == b'\r' || b == b'\n')
        {
            return Err(bad("invalid character in a field value"));
        }
        regular.push(field);
    }
    head.method = method.ok_or_else(|| bad("missing :method"))?;
    if head.method == "CONNECT" && head.protocol.is_none() {
        if head.authority.is_none() || head.scheme.is_some() || head.path.is_some() {
            return Err(bad("CONNECT needs :authority and no :scheme or :path"));
        }
    } else if head.scheme.is_none() || head.path.as_deref().is_none_or(str::is_empty) {
        return Err(bad("missing :scheme or :path"));
    }
    Ok((head, regular))
}

#[cfg(test)]
mod tests {
    use super::super::frame::setting;
    use super::*;

    /// A minimal client: encodes frames with its own HPACK state and parses the server's.
    struct Client {
        encoder: hpack::Encoder,
        decoder: hpack::Decoder,
        frames: FrameDecoder,
        input: ByteBuffer,
    }

    impl Client {
        fn new() -> Client {
            Client {
                encoder: hpack::Encoder::default(),
                decoder: hpack::Decoder::new(4096, 1 << 20),
                frames: FrameDecoder::default(),
                input: ByteBuffer::new(),
            }
        }

        fn preface(settings: &[(u16, u32)]) -> Vec<u8> {
            let mut out = PREFACE.to_vec();
            Frame::Settings {
                ack: false,
                values: settings.to_vec(),
            }
            .encode(&mut out);
            out
        }

        fn headers(&mut self, stream: u32, fields: &[(&str, &str)], end_stream: bool) -> Vec<u8> {
            let fields: Vec<Field> = fields.iter().map(|(n, v)| Field::new(*n, *v)).collect();
            let mut block = Vec::new();
            self.encoder.encode(&fields, &mut block);
            let mut out = Vec::new();
            Frame::Headers {
                stream,
                end_stream,
                end_headers: true,
                priority: None,
                block,
            }
            .encode(&mut out);
            out
        }

        fn read(&mut self, bytes: &[u8]) -> Vec<Frame> {
            self.input.extend_from_slice(bytes);
            let mut frames = Vec::new();
            while let Some(frame) = self.frames.decode(&mut self.input).unwrap() {
                frames.push(frame);
            }
            frames
        }
    }

    fn get(path: &str) -> Vec<(&str, &str)> {
        vec![
            (":method", "GET"),
            (":scheme", "https"),
            (":path", path),
            (":authority", "example.test"),
        ]
    }

    #[test]
    fn request_response_roundtrip() {
        let mut server = ServerSession::new(Config::default());
        let mut client = Client::new();
        let mut wire = Client::preface(&[]);
        wire.extend(client.headers(1, &get("/hello"), true));
        let mut post = client.headers(
            3,
            &[
                (":method", "POST"),
                (":scheme", "https"),
                (":path", "/up"),
                ("content-length", "4"),
            ],
            false,
        );
        Frame::Data {
            stream: 3,
            end_stream: true,
            data: b"data".to_vec(),
            flow_len: 4,
        }
        .encode(&mut post);
        wire.extend(post);
        // Deliver in awkward pieces.
        for piece in wire.chunks(5) {
            server.receive(piece).unwrap();
        }

        let Some(Event::Request {
            stream: 1, head, ..
        }) = server.poll_event()
        else {
            panic!("expected first request");
        };
        assert_eq!(head.path.as_deref(), Some("/hello"));
        let Some(Event::Request {
            stream: 3,
            body,
            headers,
            ..
        }) = server.poll_event()
        else {
            panic!("expected POST");
        };
        assert_eq!(body, b"data");
        assert_eq!(headers[0].name, b"content-length");

        server
            .send_headers(1, &[Field::new(":status", "200")], false)
            .unwrap();
        server.send_data(1, b"hi there", true).unwrap();
        server
            .send_headers(3, &[Field::new(":status", "204")], true)
            .unwrap();
        assert_eq!(server.active_streams(), 0);

        let frames = client.read(&server.take_output());
        assert!(matches!(frames[0], Frame::Settings { ack: false, .. }));
        assert!(
            frames
                .iter()
                .any(|f| matches!(f, Frame::Settings { ack: true, .. }))
        );
        let mut statuses = Vec::new();
        for f in &frames {
            if let Frame::Headers { block, .. } = f {
                let fields = client.decoder.decode(block).unwrap();
                statuses.push(String::from_utf8(fields[0].value.clone()).unwrap());
            }
        }
        assert_eq!(statuses, ["200", "204"]);
        assert!(frames.contains(&Frame::Data {
            stream: 1,
            end_stream: true,
            data: b"hi there".to_vec(),
            flow_len: 8
        }));
    }

    #[test]
    fn respects_peer_flow_control() {
        let mut server = ServerSession::new(Config::default());
        let mut client = Client::new();
        let mut wire = Client::preface(&[(setting::INITIAL_WINDOW_SIZE, 10)]);
        wire.extend(client.headers(1, &get("/big"), true));
        server.receive(&wire).unwrap();
        server.poll_event().unwrap();
        server
            .send_headers(1, &[Field::new(":status", "200")], false)
            .unwrap();
        server.send_data(1, &[b'x'; 25], true).unwrap();

        let data_len = |frames: &[Frame]| -> usize {
            frames
                .iter()
                .map(|f| match f {
                    Frame::Data { data, .. } => data.len(),
                    _ => 0,
                })
                .sum()
        };
        assert_eq!(data_len(&client.read(&server.take_output())), 10);

        let mut update = Vec::new();
        Frame::WindowUpdate {
            stream: 1,
            increment: 10,
        }
        .encode(&mut update);
        server.receive(&update).unwrap();
        assert_eq!(data_len(&client.read(&server.take_output())), 10);

        let mut update = Vec::new();
        Frame::WindowUpdate {
            stream: 1,
            increment: 100,
        }
        .encode(&mut update);
        server.receive(&update).unwrap();
        let frames = client.read(&server.take_output());
        assert_eq!(data_len(&frames), 5);
        assert!(matches!(
            frames.last(),
            Some(Frame::Data {
                end_stream: true,
                ..
            })
        ));
        assert_eq!(server.active_streams(), 0);
    }

    #[test]
    fn stream_errors_reset_only_that_stream() {
        let mut server = ServerSession::new(Config::default());
        let mut client = Client::new();
        let mut wire = Client::preface(&[]);
        wire.extend(client.headers(1, &[(":method", "GET"), (":path", "/")], true));
        wire.extend(client.headers(
            3,
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                ("Upper", "x"),
            ],
            true,
        ));
        wire.extend(client.headers(
            5,
            &[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                ("connection", "close"),
            ],
            true,
        ));
        wire.extend(client.headers(7, &get("/ok"), true));
        server.receive(&wire).unwrap();

        let frames = client.read(&server.take_output());
        let resets: Vec<u32> = frames
            .iter()
            .filter_map(|f| match f {
                Frame::RstStream {
                    stream,
                    reason: Reason::ProtocolError,
                } => Some(*stream),
                _ => None,
            })
            .collect();
        assert_eq!(resets, [1, 3, 5]);
        assert!(matches!(
            server.poll_event(),
            Some(Event::Request { stream: 7, .. })
        ));
    }

    #[test]
    fn connection_errors_send_goaway() {
        let cases: Vec<Vec<u8>> = vec![
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            {
                let mut w = PREFACE.to_vec();
                Frame::Ping {
                    ack: false,
                    data: [0; 8],
                }
                .encode(&mut w);
                w
            },
            {
                let mut w = Client::preface(&[]);
                Frame::Data {
                    stream: 9,
                    end_stream: false,
                    data: vec![1],
                    flow_len: 1,
                }
                .encode(&mut w);
                w
            },
            {
                let mut w = Client::preface(&[]);
                w.extend(Client::new().headers(2, &get("/"), true));
                w
            },
        ];
        for wire in cases {
            let mut server = ServerSession::new(Config::default());
            let err = server.receive(&wire).unwrap_err();
            assert_eq!(err.reason, Reason::ProtocolError);
            let frames = Client::new().read(&server.take_output());
            assert!(
                frames.iter().any(|f| matches!(
                    f,
                    Frame::GoAway {
                        reason: Reason::ProtocolError,
                        ..
                    }
                )),
                "{err}"
            );
        }
    }

    #[test]
    fn continuation_and_trailers() {
        let mut server = ServerSession::new(Config::default());
        let mut client = Client::new();
        let mut wire = Client::preface(&[]);
        let fields: Vec<Field> = get("/split")
            .iter()
            .map(|(n, v)| Field::new(*n, *v))
            .collect();
        let mut block = Vec::new();
        client.encoder.encode(&fields, &mut block);
        let (a, b) = block.split_at(3);
        Frame::Headers {
            stream: 1,
            end_stream: false,
            end_headers: false,
            priority: None,
            block: a.to_vec(),
        }
        .encode(&mut wire);
        Frame::Continuation {
            stream: 1,
            end_headers: true,
            block: b.to_vec(),
        }
        .encode(&mut wire);
        Frame::Data {
            stream: 1,
            end_stream: false,
            data: b"abc".to_vec(),
            flow_len: 3,
        }
        .encode(&mut wire);
        wire.extend(client.headers(1, &[("x-checksum", "1")], true));
        server.receive(&wire).unwrap();
        let Some(Event::Request { body, trailers, .. }) = server.poll_event() else {
            panic!("expected request");
        };
        assert_eq!(body, b"abc");
        assert_eq!(trailers, [Field::new("x-checksum", "1")]);
        let frames = client.read(&server.take_output());
        assert!(frames.contains(&Frame::WindowUpdate {
            stream: 1,
            increment: 3
        }));
        assert!(frames.contains(&Frame::WindowUpdate {
            stream: 0,
            increment: 3
        }));
    }

    #[test]
    fn graceful_shutdown_and_ping() {
        let mut server = ServerSession::new(Config::default());
        let mut client = Client::new();
        let mut wire = Client::preface(&[]);
        wire.extend(client.headers(1, &get("/"), true));
        Frame::Ping {
            ack: false,
            data: *b"pingpong",
        }
        .encode(&mut wire);
        server.receive(&wire).unwrap();
        server.poll_event().unwrap();
        server.go_away(Reason::NoError, "");
        assert!(!server.is_closed(), "stream 1 still owes a response");
        server
            .send_headers(1, &[Field::new(":status", "200")], true)
            .unwrap();
        assert!(server.is_closed());
        let frames = client.read(&server.take_output());
        assert!(frames.contains(&Frame::Ping {
            ack: true,
            data: *b"pingpong"
        }));
        assert!(
            frames
                .iter()
                .any(|f| matches!(f, Frame::GoAway { last_stream: 1, .. }))
        );
    }
}
