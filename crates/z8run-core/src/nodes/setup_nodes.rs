//! Z8-Setup-API (API 0): Setup-Flow, Betriebs-Flows und deren Nodes.
//!
//! Alle Krypto- und Format-Primitive kommen aus `kv_login::kette` (EINE
//! Quelle, dieselbe wie Produktion) und `kv-store` (S3/SigV4). Die Nodes
//! hier sind reine Verkabelung.

pub mod setup_auth;
pub mod setup_challenge;
pub mod setup_crypto;
pub mod setup_db;
pub mod setup_hashdatei;
pub mod setup_io;
pub mod setup_keygen;
pub mod setup_plugin;
pub mod setup_pubkey;
pub mod setup_registry;
pub mod setup_rotate;
pub mod setup_rotate_reseal;
pub mod setup_s3_list;
pub mod setup_seal_boxes;
pub mod setup_seal_keys;
pub mod setup_store_nodes;
pub mod setup_summary;
pub mod setup_validate;
pub mod setup_webauthn;
pub mod setup_webauthn_challenge;
pub mod setup_webauthn_assert;
pub mod setup_webauthn_register;
pub mod setup_world;
pub mod setup_world_build;
pub mod setup_world_factory;
pub mod webauthn_cbor;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_webauthn;
#[cfg(test)]
mod tests_world;

use crate::engine::{FlowEngine, NodeExecutorFactory};
use std::sync::Arc;

pub async fn registrieren(engine: &FlowEngine) {
    use setup_auth::*;
    use setup_hashdatei::*;
    use setup_keygen::*;
    use setup_plugin::*;
    use setup_pubkey::*;
    use setup_rotate::*;
    use setup_s3_list::*;
    use setup_seal_boxes::*;
    use setup_seal_keys::*;
    use setup_store_nodes::*;
    use setup_summary::*;
    use setup_validate::*;
    use setup_webauthn_challenge::*;
    use setup_webauthn_assert::*;
    use setup_webauthn_register::*;
    use setup_world_factory::*;
    let factories: Vec<Arc<dyn NodeExecutorFactory>> = vec![
        Arc::new(PemGenNodeFactory),
        Arc::new(ShamirSplit2NodeFactory),
        Arc::new(PassboxSealNodeFactory),
        Arc::new(HwboxSealNodeFactory),
        Arc::new(HashdateiWriteNodeFactory),
        Arc::new(S3PutNodeFactory),
        Arc::new(S3ListNodeFactory),
        Arc::new(SetupValidateNodeFactory),
        Arc::new(SetupKeygenNodeFactory),
        Arc::new(SetupWorldNodeFactory),
        Arc::new(SetupSummaryNodeFactory),
        Arc::new(SetupResultNodeFactory),
        Arc::new(WebauthnChallengeNodeFactory),
        Arc::new(WebauthnRegisterNodeFactory),
        Arc::new(WebauthnAssertNodeFactory),
        Arc::new(SetupAuthNodeFactory),
        Arc::new(RotateS3NodeFactory),
        Arc::new(PluginAddNodeFactory),
        Arc::new(PubkeyAddNodeFactory),
    ];
    for factory in factories {
        engine.register_node_type(factory).await;
    }
}
