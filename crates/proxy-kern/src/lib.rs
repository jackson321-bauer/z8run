//! Proxy-Kern (PROXY-1): target-sauber. Dieses Crate enthaelt KEINE
//! Dateisystem-, Netz- oder Socket-APIs — nur Traits, Zustand und Logik.
//! Nativ-/Browser-Adapter implementieren die Ports.

pub mod app;
pub mod error;
pub mod prompts;
pub mod state;
pub mod stream;
pub mod token;
pub mod traits;

pub use app::{AppCallResult, AppInfo, AppReply, AppRequest, KvApp};
pub use error::{ErrorBody, ProxyError};
pub use prompts::PromptStore;
pub use state::{SessionInfo, SessionState, SessionStore};
pub use stream::{pump, RingBuffer};
pub use token::{TokenConfig, TokenGrant, TokenManager};
pub use traits::{ByteSink, ByteSource, Clock, DbPort, LlmPort, Random, StoragePort};
