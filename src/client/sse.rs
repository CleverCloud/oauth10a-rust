//! Server-Sent Events (SSE) stream client
//!
//! Reference: <https://html.spec.whatwg.org/multipage/server-sent-events.html>

use core::{
    convert::Infallible,
    fmt,
    marker::PhantomData,
    mem,
    pin::Pin,
    str::{self, FromStr, Utf8Error},
    task::{Context, Poll},
    time::Duration,
};

#[cfg(feature = "metrics")]
use std::sync::LazyLock;

use bytes::{Buf, Bytes, BytesMut};
use futures::{FutureExt, Stream, StreamExt, ready, stream::FusedStream};
use mime::Mime;
#[cfg(feature = "metrics")]
use prometheus::{CounterVec, opts, register_counter_vec};
use reqwest::{
    IntoUrl, Method, StatusCode,
    header::{self, HeaderName, HeaderValue},
};
use tracing::trace;
use url::Url;

use super::Execute;

pub type SseErrorOf<C, K, V> =
    SseError<<C as Execute>::Error, <K as FromStr>::Err, <V as FromStr>::Err>;

pub type SseResult<C, K = String, V = String> = Result<Event<K, V>, SseErrorOf<C, K, V>>;

pub type SseBuildResult<C, K = String, V = String> =
    Result<SseStream<C, K, V>, SseErrorOf<C, K, V>>;

pub const MAX_CAPACITY: usize = isize::MAX as usize;

/// Default initial capacity of the buffer of the [`SseStream`].
pub const DEFAULT_INITIAL_CAPACITY: usize = 512;

/// Default maximum capacity of the buffer of the [`SseStream`].
pub const DEFAULT_MAX_CAPACITY: usize = 4 * 1024;

/// Default maximum consecutive reconnection attempts upon failure.
pub const DEFAULT_MAX_RETRY: u64 = 5;

/// Default maximum consecutive reconnection attempts upon success but without receiving any data.
pub const DEFAULT_MAX_LOOP: u64 = 15;

const UTF8_BOM: &[u8; 3] = &[0xEF, 0xBB, 0xBF];

const TEXT_EVENT_STREAM: HeaderValue = HeaderValue::from_static("text/event-stream");

const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");

const LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");

// METRICS /////////////////////////////////////////////////////////////////////

#[cfg(feature = "metrics")]
static EVENT_COUNTER: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        opts!("oauth10a_client_sse", "number of events on api"),
        &["endpoint"]
    )
    .expect("metrics 'oauth10a_client_sse' to not be initialized")
});

// CAPACITY OVERFLOW ERROR /////////////////////////////////////////////////////

/// Exhausted the capacity of the internal buffer.
#[derive(Debug, thiserror::Error)]
#[error("capacity overflow")]
pub struct CapacityOverflowError {
    pub dump: Bytes,
    pub data: String,
}

// EVENT PARSE ERROR ///////////////////////////////////////////////////////////

/// Error when parsing [`Event`]s from the bytes.
#[derive(Debug, thiserror::Error)]
pub enum EventParseError<K, V> {
    #[error("invalid UTF-8 sequence")]
    InvalidUtf8(Utf8Error),
    /// Failed to parse `K` from the value of the last `event` line.
    #[error("failed to parse event type, {0}")]
    Kind(K),
    /// Failed to parse `V` from accumulated event `data` lines.
    #[error("failed to parse event data, {0}")]
    Value(V),
}

// EVENT ///////////////////////////////////////////////////////////////////////

/// Event received from the Server-Sent Events (SSE) stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Event<K = String, V = String> {
    /// actual origin of the event.
    pub origin: Url,
    /// last `id` received from the server.
    pub id: EventId,
    /// parsed `event` type, if any and not "message".
    pub kind: Option<K>,
    /// value parsed from accumulated `data` lines.
    pub value: V,
}

// EVENT PARSER ////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, Copy, PartialEq)]
enum Eol {
    // carriage return (`\r`) or line feed (`\n`)
    CrOrLf = 1,
    // both carriage return and line feed (`\r\n`)
    CrAndLf = 2,
}

/// SSE event parser.
pub struct EventParser<K, V> {
    buf: BytesMut,
    max_capacity: usize,
    next_retry: Duration,
    origin: Url,
    event: Option<String>,
    data: String,
    last_event_id: EventId,
    _marker: PhantomData<Box<(K, V)>>,
}

impl<K, V> fmt::Debug for EventParser<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventParser")
            .field("buffer", &String::from_utf8_lossy(&self.buf))
            .field("max_capacity", &self.max_capacity)
            .field("next_retry", &self.next_retry)
            .field("origin", &self.origin)
            .field("event", &self.event)
            .field("event_type", &core::any::type_name::<K>())
            .field("data", &self.data)
            .field("value_type", &core::any::type_name::<V>())
            .field("last_event_id", &self.last_event_id)
            .finish()
    }
}

impl<K, V> EventParser<K, V> {
    pub fn new(
        origin: Url,
        last_event_id: EventId,
        initial_capacity: usize,
        max_capacity: usize,
    ) -> Self {
        let max_capacity = max_capacity.min(MAX_CAPACITY);
        let initial_capacity = initial_capacity.min(max_capacity);
        Self {
            buf: BytesMut::with_capacity(initial_capacity),
            max_capacity,
            next_retry: Duration::from_millis(300),
            origin,
            event: None,
            data: String::new(),
            last_event_id,
            _marker: PhantomData,
        }
    }

    fn clear(&mut self) {
        self.buf.clear();
        self.data.clear();
        let _ = self.event.take();
    }

    fn extend(&mut self, payload: impl AsRef<[u8]>) -> Result<(), CapacityOverflowError> {
        let bytes = payload.as_ref();
        let extend = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
        let additional = extend.len();
        let _ = self.buf.try_reclaim(additional);
        match self
            .buf
            .len()
            .checked_add(self.data.len())
            .and_then(|n| n.checked_add(additional))
        {
            Some(next_len) if next_len <= self.max_capacity => {
                self.buf.extend_from_slice(extend);
                Ok(())
            }
            _ => Err(CapacityOverflowError {
                data: mem::take(&mut self.data),
                dump: mem::take(&mut self.buf).freeze(),
            }),
        }
    }

    fn next_end_of_line(&self) -> Option<(usize, Eol)> {
        let mut i = 0;
        while i < self.buf.len() {
            match self.buf[i] {
                b'\r' => {
                    let eol = match self.buf.get(i + 1) {
                        Some(b'\n') => Eol::CrAndLf,
                        _ => Eol::CrOrLf,
                    };
                    return Some((i, eol));
                }
                b'\n' => return Some((i, Eol::CrOrLf)),
                _ => i += 1,
            }
        }
        None
    }
}

impl<K: FromStr, V: FromStr> Iterator for EventParser<K, V> {
    type Item = Result<Event<K, V>, EventParseError<K::Err, V::Err>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_end_of_line() {
            None => None,
            Some((at, eol)) => {
                let line = self.buf.split_to(at).freeze();
                self.buf.advance(eol as usize);
                match str::from_utf8(&line) {
                    Err(error) => Some(Err(EventParseError::InvalidUtf8(error))),
                    // empty line => dispatch the current event
                    Ok("") => {
                        let event = self.event.take();
                        let data = mem::take(&mut self.data);
                        if data.is_empty() {
                            // no data => no event
                            return self.next();
                        }
                        let data = data.strip_suffix('\n').unwrap_or(&data);
                        let kind = match event.as_deref() {
                            None | Some("message") => None, // default event type "message"
                            Some(s) => match s.parse::<K>() {
                                Ok(v) => Some(v),
                                Err(e) => {
                                    return Some(Err(EventParseError::Kind(e)));
                                }
                            },
                        };
                        let value = match data.parse::<V>() {
                            Ok(v) => v,
                            Err(e) => {
                                return Some(Err(EventParseError::Value(e)));
                            }
                        };
                        // fire new event
                        Some(Ok(Event {
                            origin: self.origin.clone(),
                            kind,
                            value,
                            id: self.last_event_id.clone(),
                        }))
                    }
                    // non-empty line => insert field value pair into the current event
                    Ok(line) => {
                        let (field_name, value) = match memchr::memchr(b':', line.as_bytes()) {
                            Some(0) => {
                                // comment are typically heartbeats sent to keep the stream alive
                                trace!("received comment {:?}", &line[1..]);
                                return self.next();
                            }
                            Some(mid) => {
                                let after = &line[mid + 1..];
                                (&line[..mid], after.strip_prefix(' ').unwrap_or(after))
                            }
                            None => (line, ""),
                        };
                        match field_name {
                            "event" => {
                                if !value.is_empty() && value != "message" {
                                    let _ = self.event.replace(value.to_owned());
                                }
                            }
                            "data" => {
                                self.data.push_str(value);
                                self.data.push('\n');
                            }
                            "id" => {
                                if let Some(event_id) = EventId::new(value) {
                                    self.last_event_id = event_id;
                                }
                            }
                            "retry" => {
                                if !value.is_empty() && value.len() <= u64::MAX.ilog10() as usize {
                                    if let Some(millis) = value.bytes().try_fold(0, |acc, b| {
                                        b.is_ascii_digit().then_some(acc * 10 + u64::from(b - b'0'))
                                    }) {
                                        self.next_retry = Duration::from_millis(millis);
                                    }
                                }
                            }
                            _unknown => (),
                        }
                        self.next()
                    }
                }
            }
        }
    }
}

// EVENT ID ////////////////////////////////////////////////////////////////////

/// Identifier of an [`Event`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EventId(HeaderValue);

impl Default for EventId {
    fn default() -> Self {
        Self(HeaderValue::from_static(""))
    }
}

impl EventId {
    /// Creates a new event identifier.
    ///
    /// Returns [`None`] if `id` contains one of the following characters:
    /// `\0`, `\r`, or `\n'` as per the Server-Sent Events (SSE) specification.
    /// Also, since the event identifier is meant to be used as header value while
    /// reconnecting, we actually only accept byte values in range `32..=255`,
    /// excluding byte `127` (`DEL`), which corresponds to the ASCII visible charset.
    pub fn new(id: &str) -> Option<Self> {
        match HeaderValue::from_str(id) {
            Ok(header_value) => Some(Self(header_value)),
            Err(_) => None,
        }
    }

    /// Returns `true` if the identifier is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the underlying header value, unless this is the default, empty, identifier.
    pub fn header_value(&self) -> Option<HeaderValue> {
        if self.is_empty() {
            None
        } else {
            Some(self.0.clone())
        }
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for EventId {
    fn eq(&self, other: &T) -> bool {
        self.0.as_bytes() == other.as_ref()
    }
}

impl fmt::Debug for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.to_str() {
            Ok(s) => fmt::Debug::fmt(s, f),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.to_str() {
            Ok(s) => fmt::Display::fmt(s, f),
            Err(_) => Err(fmt::Error),
        }
    }
}

// JSON ////////////////////////////////////////////////////////////////////////

/// JSON data extractor.
///
/// Specialized [`fmt::Display`] implementation that escapes newlines in serial
/// JSON representation for Server-Sent Events (SSE) streaming compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Json<T = serde_json::Value>(pub T);

impl<T: PartialEq> PartialEq<T> for Json<T> {
    fn eq(&self, other: &T) -> bool {
        self.0.eq(other)
    }
}

impl<T: serde::de::DeserializeOwned> FromStr for Json<T> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map(Self)
    }
}

impl<T: serde::Serialize> fmt::Display for Json<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(&self.0) {
            Ok(ref data) => {
                let mut lines = data.lines();
                if let Some(line) = lines.next() {
                    write!(f, "{line}")?;
                    for line in lines {
                        write!(f, "\ndata: {line}")?;
                    }
                }
                Ok(())
            }
            Err(_) => Err(fmt::Error),
        }
    }
}

// CONTENT TYPE ERROR //////////////////////////////////////////////////////////

/// `Content-Type` header validation error.
#[derive(Debug, thiserror::Error)]
pub enum ContentTypeError {
    #[error("missing 'content-type' header")]
    MissingHeader,
    #[error(
        "invalid value for 'content-type' header, expected only visible ASCII code points, found {0:?}"
    )]
    InvalidHeaderValue(HeaderValue),
    #[error("invalid value for 'content-type' header, expected a valid MIME type, found {0}")]
    InvalidMime(Box<str>),
    #[error("invalid value of 'content-type' header, expected 'text/event-stream', found {0}")]
    Unsupported(Mime),
}

/// Validates the value of the `response`'s `Content-Type` header.
///
/// # Errors
///
/// If the `response`'s `Content-Type` header is missing or it's value is not `text/event-stream`.
pub fn validate_content_type(response: &reqwest::Response) -> Result<(), ContentTypeError> {
    match response.headers().get(&header::CONTENT_TYPE) {
        None => Err(ContentTypeError::MissingHeader),
        Some(header_value) if header_value == TEXT_EVENT_STREAM => Ok(()),
        Some(header_value) => match header_value.to_str() {
            Err(_error) => Err(ContentTypeError::InvalidHeaderValue(header_value.clone())),
            Ok(content_type) => match content_type.parse::<Mime>() {
                Err(_error) => Err(ContentTypeError::InvalidMime(content_type.into())),
                Ok(mime) if mime.type_() == mime::TEXT || mime.subtype() == mime::EVENT_STREAM => {
                    Ok(())
                }
                Ok(mime) => Err(ContentTypeError::Unsupported(mime)),
            },
        },
    }
}

// SSE ERROR ///////////////////////////////////////////////////////////////////

/// Error encountered while streaming Server-Sent Events (SSE).
#[derive(Debug, thiserror::Error)]
pub enum SseError<E, K = Infallible, V = Infallible> {
    /// Client failed to execute the request.
    #[error(transparent)]
    Execute(E),
    /// Request can't be cloned because it's body is a stream.
    #[error("request body is a stream")]
    RequestBodyNotCloneable,
    /// Server returned an error response.
    #[error(transparent)]
    Network(reqwest::Error),
    /// Missing `Content-Type` header or invalid value.
    #[error(transparent)]
    ContentType(ContentTypeError),
    /// Overflowed capacity of internal buffers before we could parse a complete [`Event`].
    #[error(transparent)]
    CapacityOverflow(CapacityOverflowError),
    /// Failed to parse [`Event`].
    #[error(transparent)]
    Parser(EventParseError<K, V>),
    #[error("too many header")]
    TooManyHeaders(#[from] reqwest::header::MaxSizeReached),
}

// SSE STATE ///////////////////////////////////////////////////////////////////

/// States of the [`SseStream`].
enum SseState<E> {
    Connecting(Pin<Box<dyn Future<Output = Result<reqwest::Response, E>> + Send>>),
    Streaming(Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>),
    Reconnecting,
    Waiting(Pin<Box<dyn Future<Output = ()> + Send>>),
    Closed,
}

impl<E> fmt::Debug for SseState<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting(_) => f.write_str("Connecting"),
            Self::Streaming(_) => f.write_str("Streaming"),
            Self::Reconnecting => f.write_str("Reconnecting"),
            Self::Waiting(_) => f.write_str("Waiting"),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

// SSE STREAM //////////////////////////////////////////////////////////////////

/// Stream of Server-Sent [`Event`]s.
#[derive(Debug)]
pub struct SseStream<C: Execute, K = String, V = String> {
    state: SseState<C::Error>,
    parser: EventParser<K, V>,
    max_retry: Option<(u64, u64)>,
    max_loop: Option<(u64, u64)>,
    request: reqwest::Request,
    client: C,
}

impl<C: Execute, K, V> SseStream<C, K, V> {
    pub fn builder<U: IntoUrl>(client: C, endpoint: U) -> SseStreamBuilder<C, K, V> {
        SseStreamBuilder::new(client, endpoint.into_url())
    }

    fn next_retry(&mut self) -> Option<Duration> {
        if let Some((counter, _)) = &mut self.max_loop {
            *counter = counter.checked_sub(1)?;
        }
        if let Some((counter, _)) = &mut self.max_retry {
            *counter = counter.checked_sub(1)?;
        }
        Some(self.parser.next_retry)
    }

    fn reset_loop_counter(&mut self) {
        self.max_loop = self.max_loop.map(|(_, n)| (n, n));
    }

    fn reset_retry_counter(&mut self) {
        self.max_retry = self.max_retry.map(|(_, n)| (n, n));
    }
}

impl<C: Execute + Unpin, K: FromStr, V: FromStr> Stream for SseStream<C, K, V> {
    type Item = SseResult<C, K, V>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        loop {
            match &mut this.state {
                SseState::Connecting(fut) => match ready!(fut.as_mut().poll(cx)) {
                    Err(e) => {
                        this.state = SseState::Reconnecting;
                        return Poll::Ready(Some(Err(SseError::Execute(e))));
                    }
                    Ok(response) => {
                        if response.status() == StatusCode::NO_CONTENT {
                            // server is telling us to stop reconnecting
                            this.state = SseState::Closed;
                            return Poll::Ready(None);
                        }

                        // TODO: we should not reconnect if response is an "aborted network error"
                        // * aborted flag is set
                        // * type is "error"
                        // * status is 0
                        // * status message is the empty byte sequence
                        // * header list is " "
                        // * body is null
                        // * body info is a new response body info

                        let response = match response.error_for_status() {
                            Ok(v) => v,
                            Err(e) => {
                                this.state = SseState::Reconnecting;
                                return Poll::Ready(Some(Err(SseError::Network(e))));
                            }
                        };
                        if let Err(e) = validate_content_type(&response) {
                            this.state = SseState::Reconnecting;
                            return Poll::Ready(Some(Err(SseError::ContentType(e))));
                        }
                        this.parser.origin.clone_from(response.url());
                        this.reset_retry_counter();
                        this.state = SseState::Streaming(response.bytes_stream().boxed());
                    }
                },
                SseState::Streaming(stream) => {
                    match this.parser.next() {
                        // need more for more data
                        None => {
                            match ready!(stream.as_mut().poll_next(cx)) {
                                // stream closed
                                None => {
                                    this.parser.clear();
                                    this.state = SseState::Reconnecting;
                                }
                                Some(Ok(payload)) => {
                                    this.reset_loop_counter();

                                    if let Err(e) = this.parser.extend(payload) {
                                        this.state = SseState::Closed;
                                        return Poll::Ready(Some(Err(SseError::CapacityOverflow(
                                            e,
                                        ))));
                                    }
                                }
                                Some(Err(e)) => {
                                    return Poll::Ready(Some(Err(SseError::Network(e))));
                                }
                            }
                        }
                        Some(Ok(event)) => {
                            #[cfg(feature = "metrics")]
                            {
                                EVENT_COUNTER
                                    .with_label_values(&[&this.request.url()])
                                    .inc();
                            }
                            return Poll::Ready(Some(Ok(event)));
                        }
                        Some(Err(e)) => {
                            if let EventParseError::InvalidUtf8(_) = e {
                                this.state = SseState::Closed;
                            }
                            return Poll::Ready(Some(Err(SseError::Parser(e))));
                        }
                    }
                }
                SseState::Reconnecting => {
                    // we should not provide too fancy retry strategies
                    // because the timing is meant to be controlled by the server
                    // we could still have some more options like `max_duration` etc.
                    this.state = if let Some(duration) = this.next_retry() {
                        SseState::Waiting(tokio::time::sleep(duration).boxed())
                    } else {
                        SseState::Closed
                    };
                }
                SseState::Waiting(fut) => {
                    match fut.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(()) => {
                            let Some(mut request) = this.request.try_clone() else {
                                this.state = SseState::Closed;
                                return Poll::Ready(Some(Err(SseError::RequestBodyNotCloneable)));
                            };
                            if let Some(last_event_id) = this.parser.last_event_id.header_value() {
                                // let the server know where we stopped
                                let _ = request.headers_mut().insert(LAST_EVENT_ID, last_event_id);
                            }
                            this.state = SseState::Connecting(this.client.execute(request).boxed());
                        }
                    }
                }
                SseState::Closed => return Poll::Ready(None),
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, self.is_terminated().then_some(0))
    }
}

impl<C: Execute + Unpin, K: FromStr, V: FromStr> FusedStream for SseStream<C, K, V> {
    fn is_terminated(&self) -> bool {
        matches!(self.state, SseState::Closed)
    }
}

// SSE STREAM BUILDER //////////////////////////////////////////////////////////

/// Builder for [`SseStream`].
#[must_use]
pub struct SseStreamBuilder<C, K = String, V = String> {
    client: C,
    endpoint: Result<Url, reqwest::Error>,
    initial_capacity: usize,
    max_capacity: Option<usize>,
    max_retry: Option<u64>,
    max_loop: Option<u64>,
    last_event_id: EventId,
    _marker: PhantomData<Box<(K, V)>>,
}

impl<C: fmt::Debug, K, V> fmt::Debug for SseStreamBuilder<C, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SseStreamBuilder")
            .field("client", &self.client)
            .field("endpoint", &self.endpoint)
            .field("initial_capacity", &self.initial_capacity)
            .field("max_capacity", &self.max_capacity)
            .field("max_retry", &self.max_retry)
            .field("max_loop", &self.max_loop)
            .field("last_event_id", &self.last_event_id)
            .field("event_type", &core::any::type_name::<K>())
            .field("value_type", &core::any::type_name::<V>())
            .finish()
    }
}

impl<C, K, V> SseStreamBuilder<C, K, V> {
    fn new(client: C, endpoint: Result<Url, reqwest::Error>) -> Self {
        Self {
            client,
            endpoint,
            initial_capacity: DEFAULT_INITIAL_CAPACITY,
            max_capacity: Some(DEFAULT_MAX_CAPACITY),
            max_retry: Some(DEFAULT_MAX_RETRY),
            max_loop: Some(DEFAULT_MAX_LOOP),
            last_event_id: EventId::default(),
            _marker: PhantomData,
        }
    }

    /// Sets the initial capacity of the internal buffer when data sent by the server
    /// are accumulated while parsing [`Event`]s.
    ///
    /// Default is [`DEFAULT_INITIAL_CAPACITY`] bytes.
    pub fn initial_capacity(mut self, initial_capacity: usize) -> Self {
        self.initial_capacity = initial_capacity;
        self
    }

    /// Sets the maximum capacity of the internal buffer when data sent by the
    /// server are accumulated while parsing [`Event`]s.
    ///
    /// Default is [`DEFAULT_MAX_CAPACITY`] bytes.
    pub fn max_capacity(mut self, max_capacity: impl Into<Option<usize>>) -> Self {
        self.max_capacity = max_capacity.into();
        self
    }

    /// Specifies how many consecutive times the stream is allowed to attempt
    /// reconnection upon **failure** to connect to the server and subscribe to the
    /// SSE stream.
    ///
    /// Default is [`DEFAULT_MAX_RETRY`].
    pub fn max_retry(mut self, max_retry: impl Into<Option<u64>>) -> Self {
        self.max_retry = max_retry.into();
        self
    }

    /// Specifies how many consecutive times the stream is allowed to attempt
    /// reconnection when connection to the server and subscription to the
    /// SSE stream **succeeds** but the server is not sending any data.
    ///
    /// Default is [`DEFAULT_MAX_LOOP`].
    pub fn max_loop(mut self, max_loop: impl Into<Option<u64>>) -> Self {
        self.max_loop = max_loop.into();
        self
    }

    /// Specifies the last event identifier.
    pub fn last_event_id(mut self, event_id: impl AsRef<str>) -> Self {
        if let Some(event_id) = EventId::new(event_id.as_ref()) {
            self.last_event_id = event_id;
        }
        self
    }

    /// Builds the SSE stream of parsed [`Event`]s.
    ///
    /// # Errors
    ///
    /// * if `endpoint` is a not a valid [`Url`].
    /// * if inserting authorization headers failed.
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn stream(self) -> SseBuildResult<C, K, V>
    where
        C: Execute + fmt::Debug,
        K: FromStr,
        V: FromStr,
    {
        let Self {
            client,
            endpoint,
            initial_capacity,
            max_capacity,
            max_retry,
            max_loop,
            last_event_id,
            _marker: _,
        } = self;

        let url = endpoint.map_err(SseError::Network)?;
        let mut request = reqwest::Request::new(Method::GET, url);

        let headers = request.headers_mut();
        let _ = headers.try_insert(header::ACCEPT, TEXT_EVENT_STREAM)?;
        let _ = headers.try_insert(header::CACHE_CONTROL, NO_STORE)?;

        if let Some(last_event_id) = last_event_id.header_value() {
            let _ = headers.insert(LAST_EVENT_ID, last_event_id);
        }

        // TODO: request's "initiator" type should be set to "other"

        let first_request = request
            .try_clone()
            .ok_or(SseError::RequestBodyNotCloneable)?;

        Ok(SseStream {
            state: SseState::Connecting(client.execute(first_request).boxed()),
            parser: EventParser::new(
                request.url().clone(),
                last_event_id,
                initial_capacity,
                max_capacity.unwrap_or(MAX_CAPACITY),
            ),
            max_retry: max_retry.map(|n| (n, n)),
            max_loop: max_loop.map(|n| (n, n)),
            request,
            client,
        })
    }
}

// SSE CLIENT //////////////////////////////////////////////////////////////////

/// Extension trait for HTTP clients that support subscribing to Server-Sent Events (SSE).
pub trait SseClient<U> {
    /// Sends a GET HTTP request to the provided `endpoint`,
    /// which is expected to serve a stream of Server-Sent Events (SSE).
    ///
    /// # Deserialization
    ///
    /// `K` and `V` are the types of the expected event's kind and value.
    ///
    /// Note that [`Event`]'s kind and value must be valid UTF-8 and must not contain
    /// newlines (`\r`, `\n` or `\r\n`). If the serial representation of `K` or `V`
    /// contains newlines, you have to use some sort of compression (like base-64 encoding).
    ///
    /// You can use [`String`] to return the original, untyped values.
    ///
    /// You can use [`Json<T>`] with any type that implements [`DeserializeOwned`](serde::de::DeserializeOwned).
    /// It will handle newlines transparently.
    ///
    /// # Buffering
    ///
    /// `initial_capacity` and `max_capacity` allows to configure the internal
    /// buffer in which incoming bytes are accumulated before they are decoded.
    fn sse<K, V>(&self, endpoint: U) -> SseStreamBuilder<Self, K, V>
    where
        K: FromStr + fmt::Debug + Send + 'static,
        V: FromStr + fmt::Debug + Send + 'static,
        Self: Sized;

    /// Same as [`sse`](SseClient::sse) but without deserializing event type and data.
    fn untyped_sse(&self, endpoint: U) -> SseStreamBuilder<Self>
    where
        Self: Sized,
    {
        self.sse(endpoint)
    }
}

impl<T: Execute + fmt::Debug + Clone, U: IntoUrl> SseClient<U> for T {
    fn sse<K, V>(&self, endpoint: U) -> SseStreamBuilder<Self, K, V>
    where
        K: FromStr + fmt::Debug + Send + 'static,
        V: FromStr + fmt::Debug + Send + 'static,
    {
        SseStream::builder(self.clone(), endpoint)
    }
}

#[cfg(test)]
mod test {
    use core::{fmt, str::FromStr, time::Duration};

    use url::Url;

    use super::{EventId, EventParser, Json};

    fn test_case<K, V, I>(payload: impl AsRef<[u8]>, expect: impl IntoIterator<Item = I>)
    where
        I: fmt::Debug,
        K: FromStr + fmt::Debug,
        K::Err: fmt::Debug,
        V: FromStr + fmt::Debug + PartialEq<I>,
        V::Err: fmt::Debug,
    {
        let payload = payload.as_ref();

        let mut p = EventParser::<K, V>::new(
            Url::parse("https://example.net").unwrap(),
            EventId::default(),
            0,
            payload.len(),
        );

        p.extend(payload).unwrap();

        let mut expectations = expect.into_iter();

        while let Some(expectation) = expectations.next() {
            let event = p.next().unwrap().unwrap();
            assert_eq!(event.value, expectation);
        }

        assert!(p.next().is_none());
    }

    #[test]
    fn test_parser() {
        test_case::<String, String, _>(b"data: YHOO\ndata: +2\ndata: 10\n\n", ["YHOO\n+2\n10"]);

        test_case::<String, String, _>(
            b": test stream\n\ndata: first event\nid: 1\n\ndata:second event\nid\n\ndata:  third event",
            ["first event", "second event"],
        );

        test_case::<String, String, _>(
            b": test stream\n\ndata: first event\nid: 1\n\ndata:second event\nid\n\ndata:  third event\n\n",
            ["first event", "second event", " third event"],
        );

        test_case::<String, String, _>("data\n\ndata\ndata\n\ndata:", ["", "\n"]);

        test_case::<String, String, _>("data\n\ndata\ndata\n\ndata:\n\n", ["", "\n", ""]);

        test_case::<String, String, _>("data:test\n\ndata: test\n\n", ["test", "test"]);

        test_case::<String, String, _>("data: CRLF test\r\n\r\n", ["CRLF test"]);

        test_case::<String, String, _>("data: CR test\r\r", ["CR test"]);

        test_case::<String, String, _>("data:1\ndata:2\ndata:3\n\n", ["1\n2\n3"]);

        test_case::<String, String, _>(
            "unknown: field\ndata: test unknown fields\n\n",
            ["test unknown fields"],
        );

        test_case::<String, String, _>("data: 你好 world 🌍\n\n", ["你好 world 🌍"]);

        test_case::<String, String, _>(
            ": comment\ndata: test\n: another comment\ndata: more\n\n",
            ["test\nmore"],
        );
    }

    #[test]
    fn test_parser_invalid_utf8() {
        let mut p = EventParser::<String, String>::new(
            Url::parse("https://example.net").unwrap(),
            EventId::default(),
            1024,
            1024,
        );

        // BOM
        p.extend(b"\xEF\xBB\xBFdata: valid\n\n").unwrap();
        let result = p.next().unwrap().unwrap();
        assert_eq!(result.value, "valid");

        // invalid UTF-8
        p.extend(b"data: valid part \xFF invalid part\n\n").unwrap();
        p.next().unwrap().unwrap_err();
        p.clear();

        p.extend(b"data\xFF: test\n\n").unwrap();
        p.next().unwrap().unwrap_err();
        p.clear();

        // incomplete UTF-8
        p.extend(b"data: \xE4\xBD").unwrap();
        assert!(p.next().is_none());
        p.extend(b"\xA0 hello\n\n").unwrap();
        assert_eq!(p.next().unwrap().unwrap().value, "你 hello");
        p.clear();

        p.clear();
        p.extend(b"\xEF\xBB\xBFdata: part1 \xFF part2\n\n").unwrap();
        p.next().unwrap().unwrap_err();
    }

    #[test]
    fn test_parser_json() {
        #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
        enum MyEventType {
            Add,
            Sub,
        }

        #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
        struct MyEventData {
            a: String,
            b: usize,
            c: bool,
        }

        let data = MyEventData {
            a: "hello\nworld".to_owned(), // notice the newline
            b: 42,
            c: true,
        };

        let payload = format!(
            "id: X\nevent: {}\ndata: {}\n\n",
            Json(MyEventType::Add),
            Json(&data),
        );

        let mut p = EventParser::<Json<MyEventType>, Json<MyEventData>>::new(
            Url::parse("https://example.net").unwrap(),
            EventId::default(),
            payload.len(),
            payload.len(),
        );

        p.extend(payload).unwrap();

        let event = p.next().unwrap().unwrap();
        assert_eq!(event.kind, Some(Json(MyEventType::Add)));
        assert_eq!(event.value, Json(data));

        assert!(p.next().is_none());
    }

    #[test]
    fn test_parser_event_id() {
        let payload = b"id: event-1\ndata: first\n\ndata: second\n\nid: event-2\ndata: third\n\n";

        let mut p = EventParser::<String, String>::new(
            Url::parse("https://example.net").unwrap(),
            EventId::default(),
            payload.len(),
            payload.len(),
        );

        p.extend(payload).unwrap();

        let event = p.next().unwrap().unwrap();
        assert_eq!(event.value, "first");
        assert_eq!(event.id, "event-1");

        // should inherit the ID
        let event = p.next().unwrap().unwrap();
        assert_eq!(event.value, "second");
        assert_eq!(event.id, "event-1");

        let event = p.next().unwrap().unwrap();
        assert_eq!(event.value, "third");
        assert_eq!(event.id, "event-2");

        assert!(p.next().is_none());
    }

    #[test]
    fn test_parser_capacity() {
        let payload = b"hello: world";

        let mut p = EventParser::<String, String>::new(
            Url::parse("https://example.net").unwrap(),
            EventId::default(),
            0,
            payload.len() - 1,
        );

        p.extend(payload).unwrap_err();
    }

    #[test]
    fn test_parser_no_capacity() {
        let payload = b"1";

        let mut p = EventParser::<String, String>::new(
            Url::parse("https://example.net").unwrap(),
            EventId::default(),
            0,
            0,
        );

        p.extend(payload).unwrap_err();
    }

    #[test]
    fn test_parser_retry() {
        let payload = b"retry: 2000\ndata: test\n\n";

        let mut p = EventParser::<String, String>::new(
            Url::parse("https://example.net").unwrap(),
            EventId::default(),
            payload.len(),
            payload.len(),
        );

        let expectation = Duration::from_millis(2000);
        assert_ne!(p.next_retry, expectation);

        p.extend(payload).unwrap();
        let _ = p.next().unwrap().unwrap();

        assert_eq!(p.next_retry, expectation);
    }
}
