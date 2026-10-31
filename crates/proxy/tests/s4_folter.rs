//! S4: LAST-FOLTER ×20 (nur mit --features folter; im Alltag uebersprungen).
#![cfg(feature = "folter")]

#[path = "folter/memdb.rs"]
mod memdb;
#[path = "folter/workloads.rs"]
mod workloads;
#[path = "folter/workloads_ws.rs"]
mod workloads_ws;
#[path = "folter/runner.rs"]
mod runner;
