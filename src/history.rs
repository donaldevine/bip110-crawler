//! Persistent, accumulating node history.
//!
//! Each crawl is merged into a growing store keyed by node address. Nodes are never
//! dropped: a node that goes offline keeps its last-known implementation/version and
//! is simply marked `online: false`, so the dataset grows over time and retains data
//! for nodes that are no longer reachable.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::node::NodeInfo;

#[derive(Default, Serialize, Deserialize)]
pub struct History {
    /// addr -> the best record we have for that node.
    pub nodes: BTreeMap<String, NodeInfo>,
}

impl History {
    /// Load history from `path`, or start empty if it doesn't exist yet.
    pub fn load(path: &Path) -> Result<History> {
        if !path.exists() {
            return Ok(History::default());
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading history {}", path.display()))?;
        let hist: History =
            serde_json::from_str(&raw).with_context(|| format!("parsing history {}", path.display()))?;
        Ok(hist)
    }

    /// Merge one crawl's nodes into the store.
    ///
    /// - A node reachable this crawl refreshes its record (impl/version/etc), bumps
    ///   `times_seen`, and sets `last_seen = now`, `online = true`.
    /// - A node discovered but unreachable this crawl keeps its last-known good record
    ///   and is marked `online = false` (we don't overwrite good data with "Unreachable").
    /// - A node not seen at all this crawl is marked `online = false` but retained.
    pub fn merge(&mut self, current: Vec<NodeInfo>, now: &str) {
        let current_addrs: HashSet<String> = current.iter().map(|n| n.addr.clone()).collect();

        for cur in current {
            match self.nodes.get_mut(&cur.addr) {
                Some(existing) => {
                    if cur.handshaked {
                        let first_seen = if existing.first_seen.is_empty() {
                            now.to_string()
                        } else {
                            existing.first_seen.clone()
                        };
                        let times = existing.times_seen + 1;
                        let mut fresh = cur;
                        fresh.first_seen = first_seen;
                        fresh.last_seen = now.to_string();
                        fresh.times_seen = times;
                        fresh.online = true;
                        *existing = fresh;
                    } else {
                        // Unreachable this crawl — keep the good record, just mark offline.
                        existing.online = false;
                    }
                }
                None => {
                    let mut n = cur;
                    n.first_seen = now.to_string();
                    if n.handshaked {
                        n.last_seen = now.to_string();
                        n.times_seen = 1;
                        n.online = true;
                    } else {
                        n.times_seen = 0;
                        n.online = false;
                    }
                    self.nodes.insert(n.addr.clone(), n);
                }
            }
        }

        // Everything not seen at all this crawl is offline (but retained).
        for (addr, rec) in self.nodes.iter_mut() {
            if !current_addrs.contains(addr) {
                rec.online = false;
            }
        }
    }

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

    pub fn into_nodes(self) -> Vec<NodeInfo> {
        self.nodes.into_values().collect()
    }

    pub fn online_count(&self) -> usize {
        self.nodes.values().filter(|n| n.online).count()
    }
}
