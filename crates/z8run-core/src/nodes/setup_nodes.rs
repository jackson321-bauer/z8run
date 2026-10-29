//! Z8-Setup-API (API 0): Setup-Flow, Betriebs-Flows und deren Nodes.
//!
//! Alle Krypto- und Format-Primitive kommen aus `kv_login::kette` (EINE
//! Quelle, dieselbe wie Produktion) und `kv-store` (S3/SigV4). Die Nodes
//! hier sind reine Verkabelung.

pub mod setup_crypto;
pub mod setup_io;
pub mod setup_seal_nodes;
pub mod setup_store_nodes;

#[cfg(test)]
mod tests;

use crate::engine::{FlowEngine, NodeExecutorFactory};
use std::sync::Arc;

pub async fn registrieren(engine: &FlowEngine) {
    use setup_seal_nodes::*;
    use setup_store_nodes::*;
    let factories: Vec<Arc<dyn NodeExecutorFactory>> = vec![
        Arc::new(PemGenNodeFactory),
        Arc::new(ShamirSplit2NodeFactory),
        Arc::new(PassboxSealNodeFactory),
        Arc::new(HwboxSealNodeFactory),
        Arc::new(HashdateiWriteNodeFactory),
        Arc::new(S3PutNodeFactory),
        Arc::new(S3ListNodeFactory),
    ];
    for factory in factories {
        engine.register_node_type(factory).await;
    }
}
