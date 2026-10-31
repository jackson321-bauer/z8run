//! PROXY-1 Nativ-Engine: Login-Handoff, Token-API, DB-Message-Client,
//! WASM-Apps und Streams. Der target-saubere Kern liegt in `proxy-kern`.

pub mod adapters;
pub mod http;
pub mod service;

pub use adapters::{FsStorage, OsRandom, SystemClock};
pub use proxy_kern;
pub use service::{ProxyConfig, ProxyService};
