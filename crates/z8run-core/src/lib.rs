//! # z8run-core
//!
//! Next-generation visual flow engine.
//! This crate contains the data model, flow compiler,
//! scheduler, and motor executor.

pub mod canvas;
/// Target-neutrale Vertraege des DB-NODE (Typen, Storage-Naht). Nativ und
/// Browser nutzen DIESELBEN Definitionen (Steckdosen-Gesetz, keine Kopie).
pub mod dbnode_contract_storage;
pub mod dbnode_contract_types;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod dbnode;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod egress;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod ram;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod udsv3;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod udsv3_stream;
pub mod engine;
pub mod error;
pub mod flow;
pub mod message;
pub mod node;
pub mod nodes;
pub mod scheduler;
pub mod utils;

pub use engine::FlowEngine;
pub use error::{Z8Error, Z8Result};
pub use flow::{Flow, FlowConfig, FlowMeta, FlowStatus};
pub use message::FlowMessage;
pub use node::{Node, NodeType, Port, PortDirection, PortType};
