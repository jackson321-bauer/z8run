//! S3 DB Fetch node: downloads a SQLite database from S3 to local disk.
//!
//! The database stays a file on disk. The node only downloads it when the
//! local cache is missing or empty; afterwards it is a normal SQLite file.
//!
//! Config:
//!   - cacheDir:  local directory for cached databases
//!   - s3Config:  JSON file with host, region, access_key, secret_key, bucket
//!   - aliases:   { "demo": "kv-proxy-test/demo.db" }  (logical name -> S3 key)
//!   - bucket:    optional override for the bucket in s3Config
//!
//! Input (from Unix In):  { "req": { "body": { "db": "demo", "s3Key": "..." } } }
//! Output: the same payload plus dbPath, dbAlias and cached.

use crate::configure_fields;
use crate::engine::NodeExecutor;
use crate::error::{Z8Error, Z8Result};
use crate::message::FlowMessage;
use crate::node_factory;
use crate::utils::node_helpers::require_non_empty;
use kv_store::s3::S3Endpoint;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct S3Config {
    host: String,
    region: String,
    access_key: String,
    secret_key: String,
    #[serde(default)]
    bucket: String,
}

pub struct S3DbFetchNode {
    name: String,
    cache_dir: String,
    s3_config: String,
    aliases: Value,
    bucket: String,
}

impl S3DbFetchNode {
    fn error_output(&self, msg: &FlowMessage, error: impl Into<String>) -> Vec<FlowMessage> {
        let error = error.into();
        warn!(node = %self.name, error = %error, "S3 DB fetch failed");
        vec![msg.derive(
            msg.source_node,
            "error",
            json!({ "status": 400, "error": error }),
        )]
    }

    fn body<'a>(&self, payload: &'a Value) -> &'a Value {
        payload
            .get("req")
            .and_then(|r| r.get("body"))
            .unwrap_or(payload)
    }

    fn sanitize_db(db: &str) -> String {
        let mut s: String = db
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        while s.contains("..") {
            s = s.replace("..", "_");
        }
        let s = s.trim_matches('.').to_string();
        if s.is_empty() {
            "db".to_string()
        } else {
            s
        }
    }
}

#[async_trait::async_trait]
impl NodeExecutor for S3DbFetchNode {
    async fn process(&self, msg: FlowMessage) -> Z8Result<Vec<FlowMessage>> {
        let body = self.body(&msg.payload);
        let db = match body
            .get("db")
            .and_then(|v| v.as_str())
            .or_else(|| msg.payload.get("db").and_then(|v| v.as_str()))
        {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => return Ok(self.error_output(&msg, "Missing 'db' in request body")),
        };

        let key = body
            .get("s3Key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                self.aliases
                    .get(&db)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });

        let key = match key {
            Some(k) if !k.is_empty() => k,
            _ => {
                return Ok(self.error_output(
                    &msg,
                    format!("No S3 key for database '{db}' (set aliases or s3Key)"),
                ))
            }
        };

        let cache = PathBuf::from(&self.cache_dir);
        if let Err(e) = tokio::fs::create_dir_all(&cache).await {
            return Ok(self.error_output(&msg, format!("Cache directory: {e}")));
        }

        let filename = Self::sanitize_db(&db);
        let path = cache.join(format!("{filename}.db"));
        let cached = tokio::fs::metadata(&path)
            .await
            .map(|m| m.len() > 0)
            .unwrap_or(false);

        if !cached {
            let inline_s3 = msg
                .payload
                .get("s3")
                .or_else(|| body.get("s3"))
                .filter(|v| v.is_object());
            let cfg: S3Config = if let Some(v) = inline_s3 {
                match serde_json::from_value(v.clone()) {
                    Ok(v) => v,
                    Err(e) => return Ok(self.error_output(&msg, format!("Inline-S3 parse: {e}"))),
                }
            } else {
                if self.s3_config.is_empty() {
                    return Ok(
                        self.error_output(&msg, "No inline s3 credentials and no s3Config set")
                    );
                }
                let raw = match tokio::fs::read_to_string(&self.s3_config).await {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok(
                            self.error_output(&msg, format!("S3 config {}: {e}", self.s3_config))
                        )
                    }
                };
                match serde_json::from_str(&raw) {
                    Ok(v) => v,
                    Err(e) => return Ok(self.error_output(&msg, format!("S3 config parse: {e}"))),
                }
            };
            let bucket = if self.bucket.is_empty() {
                cfg.bucket.clone()
            } else {
                self.bucket.clone()
            };
            if bucket.is_empty() {
                return Ok(self.error_output(&msg, "No bucket configured"));
            }

            let endpoint = S3Endpoint {
                host: cfg.host,
                region: cfg.region,
                access_key: cfg.access_key,
                secret_key: cfg.secret_key,
            };

            let data = match endpoint.get_object(&bucket, &key).await {
                Ok(v) => v,
                Err(e) => return Ok(self.error_output(&msg, format!("S3 GET {bucket}/{key}: {e}"))),
            };
            if data.is_empty() {
                return Ok(self.error_output(&msg, format!("S3 object {bucket}/{key} is empty")));
            }

            let tmp = cache.join(format!(".{filename}.{}.tmp", uuid::Uuid::now_v7()));
            if let Err(e) = tokio::fs::write(&tmp, &data).await {
                return Ok(self.error_output(&msg, format!("Write cache: {e}")));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            if let Err(e) = tokio::fs::rename(&tmp, &path).await {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Ok(self.error_output(&msg, format!("Rename cache: {e}")));
            }
            info!(
                node = %self.name,
                db = %db,
                bucket = %bucket,
                key = %key,
                bytes = data.len(),
                path = %path.display(),
                "S3 DB downloaded"
            );
        } else {
            info!(node = %self.name, db = %db, path = %path.display(), "S3 DB cache hit");
        }

        let mut payload = msg.payload.clone();
        match payload.as_object_mut() {
            Some(obj) => {
                // Credentials were used above; never carry them into the
                // response or into downstream node logs.
                obj.remove("s3");
                obj.remove("buckets");
                obj.remove("derive");
                obj.insert("dbPath".to_string(), json!(path.to_string_lossy()));
                obj.insert("dbAlias".to_string(), json!(db));
                obj.insert("cached".to_string(), json!(cached));
                obj.insert("status".to_string(), json!(200));
            }
            None => {
                payload = json!({
                    "status": 200,
                    "dbPath": path.to_string_lossy(),
                    "dbAlias": db,
                    "cached": cached,
                    "input": payload,
                });
            }
        }

        Ok(vec![msg.derive(msg.source_node, "output", payload)])
    }

    async fn configure(&mut self, config: Value) -> Z8Result<()> {
        configure_fields!(config, self,
            "name" => name: str,
            "cacheDir" => cache_dir: str,
            "s3Config" => s3_config: str,
            "bucket" => bucket: str,
            "aliases" => aliases: value,
        );
        Ok(())
    }

    async fn validate(&self) -> Z8Result<()> {
        require_non_empty(&self.cache_dir, "S3 DB Fetch requires a cacheDir")?;
        if self.s3_config.is_empty() && !self.aliases.is_object() {
            return Err(Z8Error::Internal(
                "S3 DB Fetch without s3Config requires aliases".to_string(),
            ));
        }
        if !self.aliases.is_object() {
            return Err(Z8Error::Internal(
                "S3 DB Fetch aliases must be a JSON object".to_string(),
            ));
        }
        Ok(())
    }

    fn node_type(&self) -> &str {
        "s3-db-fetch"
    }
}

node_factory!(S3DbFetchNodeFactory, S3DbFetchNode, "s3-db-fetch", {
    name: "S3 DB Fetch".to_string(),
    cache_dir: "/data/z8run/kv".to_string(),
    s3_config: "/etc/z8run/s3.json".to_string(),
    aliases: serde_json::json!({}),
    bucket: String::new()
});
