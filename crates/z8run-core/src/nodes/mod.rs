//! Built-in node executor implementations.
//!
//! These are the native nodes shipped with z8run.
//! Each implements `NodeExecutor` and has a corresponding factory.

// Logic-only nodes: available natively and in the WASM build.
pub mod aggregator;
pub mod batch;
pub mod conversation_memory;
pub mod cron_trigger;
pub mod csv_node;
pub mod debug;
pub mod delay;
pub mod filter;
pub mod function;
pub mod http_in;
pub mod http_out;
pub mod if_else;
pub mod join_node;
pub mod json_transform;
pub mod loop_node;
pub mod mapper;
pub mod prompt_template;
pub mod sanitize;
pub mod switch;
pub mod text_splitter;
pub mod timer;
pub mod unix_in;
pub mod vector_store;
pub mod webhook;
pub mod webhook_trigger;

// Network/database/crypto nodes: native only. The WASM exporter rejects
// flows that use them, so they must never enter a WASM build.
#[cfg(not(target_arch = "wasm32"))]
pub mod ai_agent;
#[cfg(not(target_arch = "wasm32"))]
pub mod blob_read_nodes;
#[cfg(not(target_arch = "wasm32"))]
pub mod blob_write_nodes;
#[cfg(not(target_arch = "wasm32"))]
pub mod classifier;
#[cfg(not(target_arch = "wasm32"))]
pub mod crm;
#[cfg(not(target_arch = "wasm32"))]
pub mod dbnode_admin;
#[cfg(not(target_arch = "wasm32"))]
pub mod dbnode_common;
#[cfg(not(target_arch = "wasm32"))]
pub mod dbnode_open;
#[cfg(not(target_arch = "wasm32"))]
pub mod dbnode_query;
#[cfg(not(target_arch = "wasm32"))]
pub mod database;
#[cfg(not(target_arch = "wasm32"))]
pub mod embeddings;
#[cfg(not(target_arch = "wasm32"))]
pub mod http_request;
#[cfg(not(target_arch = "wasm32"))]
pub mod human_handoff;
#[cfg(not(target_arch = "wasm32"))]
pub mod image_gen;
#[cfg(not(target_arch = "wasm32"))]
pub mod kv3_nodes;
#[cfg(not(target_arch = "wasm32"))]
pub mod kv_auth;
#[cfg(not(target_arch = "wasm32"))]
pub mod linefs_nodes;
#[cfg(not(target_arch = "wasm32"))]
pub mod ordner_nodes;
#[cfg(not(target_arch = "wasm32"))]
pub mod setup_nodes;
#[cfg(not(target_arch = "wasm32"))]
pub mod webauthn_login_nodes;
#[cfg(not(target_arch = "wasm32"))]
pub mod llm;
#[cfg(not(target_arch = "wasm32"))]
pub mod mqtt;
#[cfg(not(target_arch = "wasm32"))]
pub mod s3_db_fetch;
#[cfg(not(target_arch = "wasm32"))]
pub mod sqlite_exec;
#[cfg(not(target_arch = "wasm32"))]
pub mod structured_output;
#[cfg(not(target_arch = "wasm32"))]
pub mod stt;
#[cfg(not(target_arch = "wasm32"))]
pub mod summarizer;
#[cfg(not(target_arch = "wasm32"))]
pub mod tts;
#[cfg(not(target_arch = "wasm32"))]
pub mod twilio;
#[cfg(not(target_arch = "wasm32"))]
pub mod unix_out;
#[cfg(not(target_arch = "wasm32"))]
pub mod whatsapp;

use crate::engine::{FlowEngine, NodeExecutorFactory};
use std::sync::Arc;

/// Registers all built-in node types with the engine.
#[cfg(not(target_arch = "wasm32"))]
pub async fn register_builtin_nodes(engine: &FlowEngine) {
    engine
        .register_node_type(Arc::new(debug::DebugNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(function::FunctionNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(http_in::HttpInNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(unix_in::UnixInNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(unix_out::UnixOutNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(http_out::HttpOutNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(delay::DelayNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(switch::SwitchNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(filter::FilterNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(http_request::HttpRequestNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(json_transform::JsonTransformNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(Arc::new(timer::TimerNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(webhook::WebhookNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(database::DatabaseNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(s3_db_fetch::S3DbFetchNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(sqlite_exec::SqliteExecNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    for factory in [
        Arc::new(dbnode_open::DbOpenNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(dbnode_query::DbQueryNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(dbnode_query::DbWriteNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(dbnode_admin::DbSchemaNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(dbnode_admin::DbStatusNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(dbnode_admin::DbSyncNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(blob_write_nodes::BlobPutNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(blob_read_nodes::BlobGetNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(blob_read_nodes::BlobListNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(blob_write_nodes::BlobDeleteNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(linefs_nodes::LinefsOpenNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(linefs_nodes::LinefsReadNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(linefs_nodes::LinefsWriteNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(linefs_nodes::LinefsCloseNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(ordner_nodes::LinefsListNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(ordner_nodes::OrdnerListNodeFactory) as Arc<dyn NodeExecutorFactory>,
        Arc::new(ordner_nodes::OrdnerPfadNodeFactory) as Arc<dyn NodeExecutorFactory>,
    ] {
        engine.register_node_type(factory).await;
    }
    engine
        .register_node_type(Arc::new(kv_auth::KvLoginNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(kv_auth::KvDeriveNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(kv3_nodes::Kv3AdresseNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(Arc::new(join_node::JoinNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(kv3_nodes::Kv3OpenNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(kv3_nodes::Kv3HwshardNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(kv3_nodes::Kv3MasterNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(kv3_nodes::Kv3SocketNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    setup_nodes::registrieren(engine).await;
    engine
        .register_node_type(
            Arc::new(webauthn_login_nodes::WebauthnVerifyNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(Arc::new(llm::LlmNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(mqtt::MqttNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(embeddings::EmbeddingsNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(classifier::ClassifierNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(prompt_template::PromptTemplateNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(text_splitter::TextSplitterNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(Arc::new(structured_output::StructuredOutputNodeFactory)
            as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(summarizer::SummarizerNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(vector_store::VectorStoreNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(Arc::new(ai_agent::AiAgentNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(image_gen::ImageGenNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(stt::SttNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(tts::TtsNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;

    // Communication nodes
    engine
        .register_node_type(Arc::new(twilio::TwilioNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(whatsapp::WhatsAppNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(conversation_memory::ConversationMemoryNodeFactory)
            as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(crm::CrmNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(human_handoff::HumanHandoffNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;

    // Trigger nodes
    engine
        .register_node_type(
            Arc::new(cron_trigger::CronTriggerNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(webhook_trigger::WebhookTriggerNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;

    // Control flow nodes
    engine
        .register_node_type(Arc::new(if_else::IfElseNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(loop_node::LoopNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;

    // Data Engineering nodes
    engine
        .register_node_type(Arc::new(csv_node::CsvNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(aggregator::AggregatorNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(Arc::new(batch::BatchNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;

    // Security nodes
    engine
        .register_node_type(Arc::new(sanitize::SanitizeNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;

    // Data shaping nodes
    engine
        .register_node_type(Arc::new(mapper::MapperNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
}

/// Registers the logic-only node set for the WASM build.
///
/// Network, database and crypto nodes are intentionally absent: the WASM
/// exporter rejects any flow that uses them with a per-node error, so a
/// missing registration can never be reached silently.
#[cfg(target_arch = "wasm32")]
pub async fn register_builtin_nodes(engine: &FlowEngine) {
    engine
        .register_node_type(Arc::new(debug::DebugNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(function::FunctionNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(http_in::HttpInNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(unix_in::UnixInNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(http_out::HttpOutNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(delay::DelayNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(switch::SwitchNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(filter::FilterNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(json_transform::JsonTransformNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(Arc::new(timer::TimerNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(join_node::JoinNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(if_else::IfElseNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(loop_node::LoopNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(mapper::MapperNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(sanitize::SanitizeNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(batch::BatchNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(aggregator::AggregatorNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(Arc::new(csv_node::CsvNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(Arc::new(webhook::WebhookNodeFactory) as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(webhook_trigger::WebhookTriggerNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(cron_trigger::CronTriggerNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(Arc::new(conversation_memory::ConversationMemoryNodeFactory)
            as Arc<dyn NodeExecutorFactory>)
        .await;
    engine
        .register_node_type(
            Arc::new(text_splitter::TextSplitterNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(prompt_template::PromptTemplateNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
    engine
        .register_node_type(
            Arc::new(vector_store::VectorStoreNodeFactory) as Arc<dyn NodeExecutorFactory>
        )
        .await;
}
