use std::sync::LazyLock;

use prometheus::{CounterVec, opts, register_counter_vec};

pub(crate) static CLIENT_REQUEST: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        opts!("oauth10a_client_request", "number of request on api"),
        &["endpoint", "method", "status"]
    )
    .expect("metrics 'oauth10a_client_request' to not be initialized")
});

pub(crate) static CLIENT_REQUEST_DURATION: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        opts!(
            "oauth10a_client_request_duration",
            "duration of request on api"
        ),
        &["endpoint", "method", "status", "unit"]
    )
    .expect("metrics 'oauth10a_client_request_duration' to not be initialized")
});

#[cfg(feature = "sse")]
pub(crate) static SSE_EVENT_COUNTER: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        opts!("oauth10a_client_sse", "number of events received from api"),
        &["endpoint"]
    )
    .expect("metrics 'oauth10a_client_sse' to not be initialized")
});
