//! PROXY-1 Nativ-Engine: Login-Handoff, Token-API, DB-Message-Client,
//! WASM-Apps und Streams. Der target-saubere Kern liegt in `proxy-kern`.

pub mod adapters;
pub mod app_api;
pub mod apps;
pub mod bundle;
pub mod db_api;
pub mod http;
pub mod http_admin;
pub mod http_app;
pub mod http_db;
pub mod service;
pub mod stream_api;

pub use adapters::db::UdsDbClient;
pub use adapters::wasm::WasmKvApp;
pub use adapters::{FsStorage, OsRandom, SystemClock};
pub use apps::{AppRegistry, MockLlm};
pub use proxy_kern;
pub use service::{ProxyConfig, ProxyService};
