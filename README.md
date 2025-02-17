# OAuth 1.0a crate

> This crate provides an oauth 1.0a client implementation fully-async with
> logging, metrics and tracing facilities. It was firstly designed to interact
> with the Clever-Cloud's api, but has been extended to be more generic.

## Status

This crate is ready for production, if you may have bugs, so please an issue to
fix the trouble.

## Installation

To install this dependency, just add the following line to your `Cargo.toml` manifest.

```toml
oauth10a = { version = "^1.5.1", features = ["metrics"] }
```

## Usage

Below, you will find an example of executing a simple request to an api.

```rust
use std::error::Error;

use oauth10a::client::{Client, Credentials, RestClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let client = Client::from(Credentials::oauth1("".to_string(), "".to_string(), "".to_string(), "".to_string()));
    let _obj: BtreeMap<String, String> = client.get("https://example.com/object.json").await?;

    Ok(())
}
```

## Features

| name    | description                                        |
|---------|----------------------------------------------------|
| default | Default enable features are `client` and `logging` |
| client  | The oauth 1.0a client implementation               |
| logging | Use the `log` facility crate to print logs         |
| metrics | Use `prometheus` crates to register metrics        |

### Metrics

Below, the exposed metrics gathered by prometheus:

| name                             | labels                                                          | kind    | description                |
| -------------------------------- | --------------------------------------------------------------- | ------- | -------------------------- |
| oauth10a_client_request          | endpoint: String, method: String, status: Integer               | Counter | number of request on api   |
| oauth10a_client_request_duration | endpoint: String, method: String, status: Integer, unit: String | Counter | duration of request on api |

## License

See the [license](LICENSE).

## Getting in touch

- [@FlorentinDUBOIS](https://twitter.com/FlorentinDUBOIS)
