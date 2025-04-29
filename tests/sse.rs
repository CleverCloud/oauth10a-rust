#[cfg(feature = "sse")]
mod sse_integration_tests {
    use core::{
        convert::Infallible,
        fmt,
        net::Ipv4Addr,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use std::str::FromStr;

    use anyhow::Result;
    use axum::{
        Router,
        extract::State,
        response::{
            IntoResponse, Sse,
            sse::{self as sse_server, KeepAlive},
        },
        routing::get,
    };
    use futures::{FutureExt, Stream, StreamExt};
    use oauth10a::client::{
        Client,
        sse::{self as sse_client, EventId, Json, SseClient},
    };
    use reqwest::StatusCode;
    use tokio::{
        net::{TcpListener, ToSocketAddrs},
        sync::broadcast::{self, error::RecvError},
        task::JoinHandle,
    };
    use tracing::debug;
    use url::Url;

    type NextEventOutput = (
        Result<sse_server::Event, RecvError>,
        broadcast::Receiver<sse_server::Event>,
    );

    type NextEvent = Pin<Box<dyn Future<Output = NextEventOutput> + Send + Sync>>;

    fn next_event(receiver: broadcast::Receiver<sse_server::Event>) -> NextEvent {
        Box::pin(async move {
            receiver
                .resubscribe()
                .recv()
                .map(|result| (result, receiver))
                .await
        })
    }

    /// State of the SSE service that receives broadcasted events
    /// and body of the response returned to clients.
    struct SseStream {
        receiver: broadcast::Receiver<sse_server::Event>,
        next_event: NextEvent,
    }

    impl SseStream {
        pub fn new(receiver: broadcast::Receiver<sse_server::Event>) -> Self {
            Self {
                next_event: next_event(receiver.resubscribe()),
                receiver,
            }
        }
    }

    impl Clone for SseStream {
        fn clone(&self) -> Self {
            Self::new(self.receiver.resubscribe())
        }
    }

    impl Stream for SseStream {
        type Item = Result<sse_server::Event, Infallible>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.next_event.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready((result, receiver)) => {
                    self.next_event = next_event(receiver);
                    match result {
                        Ok(event) => {
                            debug!("SSE stream: emitting new event {event:?}");
                            Poll::Ready(Some(Ok(event)))
                        }
                        Err(RecvError::Closed) => {
                            debug!("SSE stream: no more writers closing stream");
                            Poll::Ready(None)
                        }
                        Err(RecvError::Lagged(n)) => {
                            self.receiver = self.receiver.resubscribe();
                            debug!("SSE stream: lagged {n}");
                            Poll::Pending
                        }
                    }
                }
            }
        }
    }

    async fn sse_handler(State(stream): State<SseStream>) -> Sse<SseStream> {
        Sse::new(stream).keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
    }

    async fn fallback_handler() -> impl IntoResponse {
        (StatusCode::NOT_FOUND, "nothing to see here")
    }

    async fn sse_server(
        addr: impl ToSocketAddrs,
    ) -> Result<(JoinHandle<()>, String, broadcast::Sender<sse_server::Event>)> {
        let listener = TcpListener::bind(addr).await?;

        let local_addr = listener.local_addr()?;
        let endpoint = format!("http://{local_addr}/");

        let (event_sender, event_receiver) = broadcast::channel(100);

        let router = Router::new()
            .route("/", get(sse_handler))
            .fallback(fallback_handler)
            .with_state(SseStream::new(event_receiver));

        let server = tokio::spawn(async {
            axum::serve(listener, router).await.unwrap();
        });

        Ok((server, endpoint, event_sender))
    }

    #[tokio::test]
    async fn test_untyped_event_stream() -> Result<()> {
        let addr = (Ipv4Addr::LOCALHOST, 0);

        let (_server, endpoint, event_sender) = sse_server(addr).await?;

        let events = vec![
            sse_server::Event::default()
                .id("1")
                .event("Create")
                .data("Message 1"),
            sse_server::Event::default()
                .id("2")
                .event("Update")
                .data("Message 2")
                .retry(Duration::from_millis(12)),
            sse_server::Event::default()
                .id("3")
                .event("Delete")
                .data("Message 3"),
        ];

        let client = Client::default();

        let mut event_stream = client.untyped_sse(&endpoint).max_loop(0).stream()?;

        let _handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            for event in events {
                event_sender.send(event).expect("stream is open");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            // dropping event_sender closing the stream
        });

        let mut received = Vec::new();

        while let Some(result) = event_stream.next().await {
            received.push(result?);
        }

        assert_eq!(received.len(), 3);

        let origin = endpoint.parse::<Url>()?;

        assert_eq!(
            received[0],
            sse_client::Event {
                origin: origin.clone(),
                id: EventId::new("1").unwrap(),
                kind: Some("Create".into()),
                value: "Message 1".into()
            }
        );

        assert_eq!(
            received[1],
            sse_client::Event {
                origin: origin.clone(),
                id: EventId::new("2").unwrap(),
                kind: Some("Update".into()),
                value: "Message 2".into()
            }
        );

        assert_eq!(
            received[2],
            sse_client::Event {
                origin: origin.clone(),
                id: EventId::new("3").unwrap(),
                kind: Some("Delete".into()),
                value: "Message 3".into()
            }
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_typed_event_stream() -> Result<()> {
        let addr = (Ipv4Addr::LOCALHOST, 0);

        let (_server, endpoint, event_sender) = sse_server(addr).await?;

        #[derive(Debug, Clone, PartialEq)]
        pub enum EventKind {
            Create,
            Update,
            Delete,
        }

        impl FromStr for EventKind {
            type Err = &'static str;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Ok(match s {
                    "Create" => Self::Create,
                    "Update" => Self::Update,
                    "Delete" => Self::Delete,
                    _ => return Err("unsupported event type"),
                })
            }
        }

        impl fmt::Display for EventKind {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Create => f.write_str("Create"),
                    Self::Update => f.write_str("Update"),
                    Self::Delete => f.write_str("Delete"),
                }
            }
        }

        #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
        pub struct EventValue {
            a: String,
            b: u64,
            c: bool,
        }

        let events = [
            (
                Some("1"),
                Some(EventKind::Create),
                Json(EventValue {
                    a: "A".to_owned(),
                    b: 1,
                    c: true,
                }),
                None,
            ),
            (
                None,
                Some(EventKind::Update),
                Json(EventValue {
                    a: "B".to_owned(),
                    b: 2,
                    c: true,
                }),
                Some(Duration::from_millis(123)),
            ),
            (
                Some("3"),
                Some(EventKind::Delete),
                Json(EventValue {
                    a: "C".to_owned(),
                    b: 3,
                    c: false,
                }),
                None,
            ),
        ];

        let client = Client::default();

        let mut event_stream = client
            .sse::<EventKind, Json<EventValue>>(&endpoint)
            .max_loop(0)
            .stream()?;

        let send_events = events.clone();
        let _handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            for (id, kind, value, retry) in send_events {
                let mut event = sse_server::Event::default().data(value.to_string());
                if let Some(kind) = kind {
                    event = event.event(kind.to_string());
                }
                if let Some(id) = id {
                    event = event.id(id);
                }
                if let Some(duration) = retry {
                    event = event.retry(duration);
                }
                event_sender.send(event).expect("stream is open");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            // dropping event_sender closing the stream
        });

        let mut received = Vec::new();

        while let Some(result) = event_stream.next().await {
            received.push(result?);
        }

        assert_eq!(received.len(), 3);

        let origin = endpoint.parse::<Url>()?;

        let mut last_event_id = EventId::default();

        for (i, (id, kind, value, _)) in events.into_iter().enumerate() {
            if let Some(id) = id {
                last_event_id = EventId::new(id).unwrap();
            }
            let event = sse_client::Event {
                id: last_event_id.clone(),
                origin: origin.clone(),
                kind,
                value,
            };
            assert_eq!(received[i], event);
        }

        Ok(())
    }
}

#[cfg(feature = "sse")]
mod sse_e2e_tests {
    use anyhow::Result;
    use futures::StreamExt;
    use oauth10a::client::{Client, Credentials, sse::SseClient};
    use tracing::warn;

    fn oath_env() -> Option<Credentials> {
        if let Ok(token) = std::env::var("CC_TOKEN") {
            if let Ok(secret) = std::env::var("CC_SECRET") {
                if let Ok(consumer_key) = std::env::var("CC_CONSUMER_KEY") {
                    if let Ok(consumer_secret) = std::env::var("CC_CONSUMER_SECRET") {
                        return Some(Credentials::OAuth1 {
                            token,
                            secret,
                            consumer_key,
                            consumer_secret,
                        });
                    }
                }
            }
        }
        None
    }

    #[tokio::test]
    async fn sse_e2e() -> Result<()> {
        const ENDPOINT: &str = "https://api.clever-cloud.com/v4/logs/organisations/orga_20b916c2-4ea3-49e3-bad0-0a7765ef1b25/applications/app_2dab4fd3-c2fc-4d2d-bf4a-00aaaf66ff72/logs?throttleElements=10000&throttlePerInMilliseconds=50";

        let Some(credentials) = oath_env() else {
            warn!("OAuth credentials not found in environment: ignoring end-to-end tests");
            return Ok(());
        };

        let client = {
            let mut client = Client::default();
            client.set_credentials(Some(credentials));
            client
        };

        let mut event_stream = client
            .untyped_sse(ENDPOINT)
            .last_event_id("0:0:0")
            .stream()?
            .take(10);

        while let Some(result) = event_stream.next().await {
            dbg!(result.unwrap());
        }

        Ok(())
    }
}
