# OAuth 1.0a crate

> This crate provides an OAuth 1.0a client implementation fully-async with
> logging, metrics and tracing facilities. It was firstly designed to interact
> with the Clever-Cloud's API, but has been extended to be more generic.

## Status

This crate is ready for production. If you find a bug, please open an issue.

## Installation

To install this dependency, just add the following line to your `Cargo.toml` manifest.

```toml
oauth10a = { version = "^2.1.2", features = ["metrics"] }
```

## Usage

Below, you will find an example of executing a simple request to an API.

```rust
use oauth10a::{client::Client, credentials::Credentials, rest::RestClient};

type MyData = std::collections::BTreeMap<String, String>;
type MyError = String;

#[tokio::main]
async fn main() -> Result<(), Box<dyn core::error::Error + Send + Sync>> {
    let client = Client::new().with_credentials(Credentials::OAuth1 {
        token: "",
        secret: "",
        consumer_key: "",
        consumer_secret: "",
    });

    match client.get::<MyData, MyError>("https://example.com/object.json").await {
        // received HTTP response with JSON payload deserializing to `MyData`
        Ok(Ok(response)) => (),
        // received HTTP error response with JSON payload deserializing to `MyError`
        Ok(Err(error_response)) => (),
        // client failed to execute request
        Err(rest_error) => ()
    }

    Ok(())
}
```

## Features

| name    | description                                                                               |
| ------- | ----------------------------------------------------------------------------------------- |
| default | Default enable features are `client` and `logging`                                        |
| execute | Provides the `ExecuteRequest` trait                                                       |
| client  | Provides an HTTP client that implements `ExecuteRequest` handling request's authorization |
| logging | Use the `log` facility crate to print logs                                                |
| metrics | Use `prometheus` crate to register metrics                                                |
| tracing | Use `tracing` crate to add `tracing::instrument` on functions                             |
| rest    | Enables RESTful API helper methods                                                        |
| sse     | Enables streaming Server-Sent Events (SSE)                                                |
| serde   | Provides `serde` implementation for `Credentials`                                         |
| zeroize | Provides `zeroize::Zeroize` implementations on `Credentials`                              |

### Metrics

Below, the exposed metrics gathered by prometheus:

| name                             | labels                                                          | kind    | description                        |
| -------------------------------- | --------------------------------------------------------------- | ------- | ---------------------------------- |
| oauth10a_client_request          | endpoint: String, method: String, status: Integer               | Counter | number of request on API           |
| oauth10a_client_request_duration | endpoint: String, method: String, status: Integer, unit: String | Counter | duration of request on API         |
| oauth10a_client_sse              | endpoint: String                                                | Counter | number of events received from API |

## License

See the [license](LICENSE).

## Getting in touch

- [@FlorentinDUBOIS](https://twitter.com/FlorentinDUBOIS)
