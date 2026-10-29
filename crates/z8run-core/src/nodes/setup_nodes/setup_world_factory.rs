//! Factory für den setup-world-Node (eigene Datei wegen Zeilenlimit).

use super::setup_registry as reg;
use super::setup_world::SetupWorldNode;
use crate::engine::NodeExecutor;
use crate::node_factory;

node_factory!(SetupWorldNodeFactory, SetupWorldNode, "setup-world", {
    name: "setup-world".to_string(),
    s3_config: "/etc/z8run/kv3-s3.json".to_string(),
    out_dir: "/data/z8run/setup-keys".to_string(),
    vec0_path: "/tmp/vecprobe/vec0.so".to_string(),
    hw_keys: 2_usize,
    registry_key: reg::REGISTRY_KEY.to_string(),
});
