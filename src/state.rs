//! Resumable crawl state. Persisting the frontier (addresses still to explore) plus
//! the discovered nodes and edges lets a long crawl be stopped and later continue
//! exactly where it left off, instead of restarting from the seed peers.
//!
//! `seen` (the visited/queued set) is NOT stored — it's reconstructed on resume from
//! `nodes ∪ frontier`, which keeps the file smaller.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::node::{Edge, NodeInfo};

#[derive(Serialize, Deserialize, Default)]
pub struct CrawlState {
    /// Pending work: `(peer address string, depth)` still to be probed.
    pub frontier: Vec<(String, u32)>,
    /// Nodes discovered so far (probed — reachable or unreachable stub).
    pub nodes: Vec<NodeInfo>,
    /// Edges discovered so far.
    pub edges: Vec<Edge>,
}

impl CrawlState {
    /// Load state from `path`, or `None` if it doesn't exist yet (fresh crawl).
    pub fn load(path: &Path) -> Result<Option<CrawlState>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading state {}", path.display()))?;
        let st = serde_json::from_str(&raw)
            .with_context(|| format!("parsing state {}", path.display()))?;
        Ok(Some(st))
    }

    /// Persist atomically (tmp + rename) so an interrupted write can't corrupt it.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string(self)?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
        Ok(())
    }
}
