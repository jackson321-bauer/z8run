//! Loads a flow either from a JSON file or from the z8run SQLite database.

use anyhow::{bail, Context, Result};
use uuid::Uuid;
use z8run_core::flow::Flow;
use z8run_storage::repository::FlowRepository;
use z8run_storage::sqlite::SqliteStorage;

/// Parses a stored flow JSON document (as saved in the `flows.data` column or
/// exported via the REST API).
pub fn parse_flow_json(text: &str) -> Result<Flow> {
    let flow: Flow = serde_json::from_str(text).context("flow JSON is not a valid Flow")?;
    Ok(flow)
}

/// Loads a flow from the database at `db_path` (plain filesystem path).
pub async fn load_from_db(db_path: &str, flow_id: Uuid) -> Result<Flow> {
    if !std::path::Path::new(db_path).exists() {
        bail!("database not found: {db_path}");
    }
    let storage = SqliteStorage::new(&format!("sqlite://{db_path}?mode=ro"))
        .await
        .context("open sqlite database")?;
    storage
        .get_flow(flow_id)
        .await
        .with_context(|| format!("load flow {flow_id} from {db_path}"))
}
