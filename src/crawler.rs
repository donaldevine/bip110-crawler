//! Depth-first crawl of the P2P network.
//!
//! Seeds are the caller's known peers (typically the direct peers of your own node,
//! read over RPC). From each node we handshake to learn its implementation/version and
//! `getaddr` to learn the nodes *it* knows about; those become the next depth level.
//!
//! Note on semantics: a remote node will not tell you its live peer list (that needs
//! authenticated RPC you don't have). `getaddr` returns its *address manager* gossip,
//! which is the standard, and only, way to expand a crawl. Edges therefore mean
//! "A gossiped B", i.e. reachability, not a confirmed live connection.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use std::path::PathBuf;

use crate::node::{self, Bip110Rule, Edge, NodeInfo};
use crate::p2p::{self, NetworkParams, Peer};
use crate::state::CrawlState;

/// Called periodically during a crawl with a snapshot of the current nodes and edges,
/// so a long-running crawl can write an up-to-date report before it finishes.
pub type SnapshotFn = Arc<dyn Fn(Vec<NodeInfo>, Vec<Edge>) + Send + Sync>;

/// Optional I/O for a crawl: live report snapshots, resume-from state, and where/how
/// often to persist resumable state.
#[derive(Default)]
pub struct CrawlIo {
    pub snapshot: Option<(Duration, SnapshotFn)>,
    /// Prior state to continue from (frontier + nodes + edges).
    pub resume: Option<CrawlState>,
    /// Persist state to this path every `Duration` (and once at the end).
    pub persist: Option<(Duration, PathBuf)>,
}

#[derive(Clone)]
pub struct CrawlConfig {
    pub net: NetworkParams,
    /// Maximum crawl depth. 0 = unlimited (crawl the whole reachable network).
    pub max_depth: u32,
    /// Stop after this many nodes. 0 = unlimited.
    pub max_nodes: usize,
    /// Clearnet worker count.
    pub threads: usize,
    /// Onion worker count (a separate pool, only spawned when a Tor proxy is set, so
    /// slow Tor dials can't hold up clearnet progress).
    pub tor_threads: usize,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub addr_collect: Duration,
    /// Extra connection attempts before marking a peer unreachable (0 = single try).
    pub retries: usize,
    /// Max edges recorded per node (caps data.json size on big crawls). 0 = unlimited.
    pub edges_per_node: usize,
    /// SOCKS5 proxy for dialing onion peers (e.g. Tor at 127.0.0.1:9050). None = clearnet only.
    pub tor_proxy: Option<SocketAddr>,
    pub rules: Arc<Vec<Bip110Rule>>,
    /// Block locator `(hash, height)` for the chain check, newest first. Empty disables it —
    /// peers are then not asked for headers at all, so the crawl behaves exactly as before.
    pub locator: Arc<Vec<([u8; 32], i64)>>,
    /// Height at which peers' block hashes are compared to group them onto chains.
    pub chain_ref_height: i64,
}

/// A frontier entry: peer to probe and the depth at which we reached it.
type Task = (Peer, u32);

/// Two separate frontiers (clearnet + onion) under one mutex, so a clearnet worker and
/// an onion worker never contend for the same task. `active` counts busy workers across
/// both pools; the crawl is done only when both stacks are empty and `active == 0`.
struct Frontier {
    clearnet: Vec<Task>,
    onion: Vec<Task>,
    active: usize,
}

struct Shared {
    frontier: Mutex<Frontier>,
    /// Separate condvars per pool so producing clearnet work doesn't wake idle onion
    /// workers and vice-versa (both are notified together only at termination).
    cv_clearnet: Condvar,
    cv_onion: Condvar,
    seen: Mutex<HashSet<Peer>>,
    nodes: Mutex<HashMap<Peer, NodeInfo>>,
    edges: Mutex<Vec<Edge>>,
}

pub struct CrawlResult {
    pub nodes: Vec<NodeInfo>,
    pub edges: Vec<Edge>,
}

/// Run the crawl. `seeds` are `(addr, depth, optional pre-known NodeInfo)`.
/// Pre-known info (e.g. your own node's direct peers from RPC) is recorded even
/// if the peer later refuses a P2P handshake.
pub fn crawl(seeds: Vec<(Peer, u32, Option<NodeInfo>)>, cfg: CrawlConfig, io: CrawlIo) -> CrawlResult {
    let shared = Arc::new(Shared {
        frontier: Mutex::new(Frontier {
            clearnet: Vec::new(),
            onion: Vec::new(),
            active: 0,
        }),
        cv_clearnet: Condvar::new(),
        cv_onion: Condvar::new(),
        seen: Mutex::new(HashSet::new()),
        nodes: Mutex::new(HashMap::new()),
        edges: Mutex::new(Vec::new()),
    });

    // Onion peers are only crawlable through a proxy; without one we never queue them.
    let onion_enabled = cfg.tor_proxy.is_some();

    // Resume from prior state: restore discovered nodes/edges and re-queue the pending
    // frontier (routed to the right pool). `seen` is rebuilt from nodes ∪ frontier.
    if let Some(st) = io.resume {
        let port = cfg.net.default_port;
        let mut frontier = shared.frontier.lock().unwrap();
        let mut seen = shared.seen.lock().unwrap();
        let mut nodes = shared.nodes.lock().unwrap();
        let mut edges = shared.edges.lock().unwrap();
        for n in st.nodes {
            if let Some(p) = Peer::parse(&n.addr, port) {
                seen.insert(p.clone());
                nodes.insert(p, n);
            }
        }
        for (s, d) in st.frontier {
            if let Some(p) = Peer::parse(&s, port) {
                if p.is_onion() && !onion_enabled {
                    continue;
                }
                seen.insert(p.clone());
                if p.is_onion() {
                    frontier.onion.push((p, d));
                } else {
                    frontier.clearnet.push((p, d));
                }
            }
        }
        edges.extend(st.edges);
        eprintln!(
            "[resume] restored {} nodes, {} clearnet + {} onion queued",
            nodes.len(),
            frontier.clearnet.len(),
            frontier.onion.len()
        );
    }

    {
        let mut frontier = shared.frontier.lock().unwrap();
        let mut seen = shared.seen.lock().unwrap();
        let mut nodes = shared.nodes.lock().unwrap();
        for (addr, depth, pre) in seeds {
            if addr.is_onion() && !onion_enabled {
                continue;
            }
            if seen.insert(addr.clone()) {
                if let Some(info) = pre {
                    nodes.insert(addr.clone(), info);
                }
                if addr.is_onion() {
                    frontier.onion.push((addr, depth));
                } else {
                    frontier.clearnet.push((addr, depth));
                }
            }
        }
    }

    // Progress monitor: heartbeat, optional live report snapshots, and optional periodic
    // persistence of resumable state.
    let running = Arc::new(AtomicBool::new(true));
    let monitor = {
        let shared = Arc::clone(&shared);
        let running = Arc::clone(&running);
        let snapshot = io.snapshot.clone();
        let persist = io.persist.clone();
        std::thread::spawn(move || {
            let mut last_snapshot = Instant::now();
            let mut last_persist = Instant::now();
            while running.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(5));
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                let (done, online, onion) = {
                    let n = shared.nodes.lock().unwrap();
                    (
                        n.len(),
                        n.values().filter(|x| x.online).count(),
                        n.keys().filter(|p| p.is_onion()).count(),
                    )
                };
                let (qc, qo) = {
                    let f = shared.frontier.lock().unwrap();
                    (f.clearnet.len(), f.onion.len())
                };
                eprintln!(
                    "[crawl] {done} probed ({online} reachable, {onion} onion), {qc} clearnet + {qo} onion queued…"
                );

                if let Some((interval, ref cb)) = snapshot {
                    if last_snapshot.elapsed() >= interval {
                        let nodes: Vec<NodeInfo> =
                            shared.nodes.lock().unwrap().values().cloned().collect();
                        let edges: Vec<Edge> = shared.edges.lock().unwrap().clone();
                        cb(nodes, edges);
                        last_snapshot = Instant::now();
                    }
                }
                if let Some((interval, ref path)) = persist {
                    if last_persist.elapsed() >= interval {
                        save_state(&shared, path);
                        last_persist = Instant::now();
                    }
                }
            }
        })
    };

    let mut handles = Vec::new();
    // Clearnet pool.
    for _ in 0..cfg.threads.max(1) {
        let shared = Arc::clone(&shared);
        let cfg = cfg.clone();
        handles.push(std::thread::spawn(move || worker(shared, cfg, false)));
    }
    // Onion pool (separate, so slow Tor dials can't starve clearnet workers).
    if onion_enabled {
        for _ in 0..cfg.tor_threads.max(1) {
            let shared = Arc::clone(&shared);
            let cfg = cfg.clone();
            handles.push(std::thread::spawn(move || worker(shared, cfg, true)));
        }
    }
    for h in handles {
        let _ = h.join();
    }
    running.store(false, Ordering::Relaxed);
    let _ = monitor.join();

    // Final state save so a clean finish is also persisted.
    if let Some((_, ref path)) = io.persist {
        save_state(&shared, path);
    }

    // Every worker and the monitor are joined above, so no other Arc owner should remain and
    // this unwrap succeeds. If it somehow doesn't, clone the data out under lock rather than
    // discard the entire crawl — the previous `unwrap_or_default()` silently returned nothing.
    let (nodes_map, edges) = match Arc::try_unwrap(shared) {
        Ok(s) => (s.nodes.into_inner().unwrap(), s.edges.into_inner().unwrap()),
        Err(shared) => {
            eprintln!("[crawl] warning: shared state still referenced at finish; cloning out");
            let nodes = shared.nodes.lock().unwrap().clone();
            let edges = shared.edges.lock().unwrap().clone();
            (nodes, edges)
        }
    };

    CrawlResult {
        nodes: nodes_map.into_values().collect(),
        edges,
    }
}

/// Serialize the current crawl state (pending frontier + discovered nodes/edges) to
/// disk so the crawl can resume from here. Clones under short locks, then writes.
fn save_state(shared: &Arc<Shared>, path: &std::path::Path) {
    let frontier: Vec<(String, u32)> = {
        let f = shared.frontier.lock().unwrap();
        f.clearnet
            .iter()
            .chain(f.onion.iter())
            .map(|(p, d)| (p.to_string(), *d))
            .filter(|(s, _)| s != "127.0.0.1:0")
            .collect()
    };
    let nodes: Vec<NodeInfo> = shared
        .nodes
        .lock()
        .unwrap()
        .values()
        .filter(|n| n.addr != "127.0.0.1:0")
        .cloned()
        .collect();
    let edges: Vec<Edge> = shared.edges.lock().unwrap().clone();
    let st = CrawlState { frontier, nodes, edges };
    match st.save(path) {
        Ok(()) => eprintln!(
            "[state] saved {} nodes, {} queued -> {}",
            st.nodes.len(),
            st.frontier.len(),
            path.display()
        ),
        Err(e) => eprintln!("[state] save failed: {e:#}"),
    }
}

fn notify_all(shared: &Arc<Shared>) {
    shared.cv_clearnet.notify_all();
    shared.cv_onion.notify_all();
}

/// Pop the next task from this worker's pool (LIFO = depth-first). Waits while its own
/// stack is empty but work may still arrive; returns `None` only when the whole crawl
/// is finished — both stacks empty and no worker (either pool) still probing.
fn next_task(shared: &Arc<Shared>, onion_pool: bool) -> Option<Task> {
    let mut frontier = shared.frontier.lock().unwrap();
    loop {
        let popped = if onion_pool {
            frontier.onion.pop()
        } else {
            frontier.clearnet.pop()
        };
        if let Some(t) = popped {
            frontier.active += 1;
            return Some(t);
        }
        if frontier.clearnet.is_empty() && frontier.onion.is_empty() && frontier.active == 0 {
            notify_all(shared); // release the other pool's idle workers too
            return None;
        }
        // Wait on this pool's condvar until its work (or termination) is signalled.
        frontier = if onion_pool {
            shared.cv_onion.wait(frontier).unwrap()
        } else {
            shared.cv_clearnet.wait(frontier).unwrap()
        };
    }
}

/// Mark this worker idle again and push newly-discovered children onto their pools,
/// waking only the relevant pool (and both at termination).
fn finish_task(shared: &Arc<Shared>, new_clearnet: Vec<Task>, new_onion: Vec<Task>) {
    let mut frontier = shared.frontier.lock().unwrap();
    frontier.active -= 1;
    let (has_c, has_o) = (!new_clearnet.is_empty(), !new_onion.is_empty());
    frontier.clearnet.extend(new_clearnet);
    frontier.onion.extend(new_onion);
    if has_c {
        shared.cv_clearnet.notify_all();
    }
    if has_o {
        shared.cv_onion.notify_all();
    }
    if frontier.active == 0 && frontier.clearnet.is_empty() && frontier.onion.is_empty() {
        notify_all(shared); // crawl finished — wake everyone so they can exit
    }
}

/// Whether a failed probe is worth retrying. Only a timeout (the peer was silent or too slow)
/// can plausibly succeed on a second attempt. A refused/reset/unreachable connection is a
/// deterministic answer — the host is up but not a reachable peer — so retrying it only burns
/// a worker, which matters a lot when most gossiped addresses are dead. A non-IO failure (e.g.
/// a protocol error mid-handshake) means the peer *did* respond, so we allow a retry.
///
/// The connect error is wrapped with context in `probe_peer`, so we walk the whole cause chain
/// rather than inspecting only the top-level error.
fn worth_retrying(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            );
        }
    }
    true
}

fn worker(shared: Arc<Shared>, cfg: CrawlConfig, onion_pool: bool) {
    while let Some((addr, depth)) = next_task(&shared, onion_pool) {
        // Respect the global node cap (0 = unlimited).
        if cfg.max_nodes != 0 && shared.nodes.lock().unwrap().len() >= cfg.max_nodes {
            finish_task(&shared, Vec::new(), Vec::new());
            continue;
        }

        // Try to reach the peer, retrying a bounded number of times — but only for failures a
        // retry can plausibly fix (timeouts). An actively refused/reset connection is a
        // deterministic "not a reachable peer", so retrying it just burns a worker on the
        // ~97%-dead address book; those give up after the first attempt.
        // Locator hashes only; the heights come back in when placing the reply.
        let locator: Vec<[u8; 32]> = cfg.locator.iter().map(|(h, _)| *h).collect();
        let probe_once = || {
            p2p::probe_peer(
                &addr,
                cfg.net,
                cfg.connect_timeout,
                cfg.io_timeout,
                cfg.addr_collect,
                cfg.tor_proxy,
                &locator,
            )
        };
        let mut probe = probe_once();
        let mut attempt = 0;
        while attempt < cfg.retries {
            if !matches!(&probe, Err(e) if worth_retrying(e)) {
                break;
            }
            attempt += 1;
            probe = probe_once();
        }

        let addr_str = addr.to_string();
        let mut new_clearnet = Vec::new();
        let mut new_onion = Vec::new();
        match probe {
            Ok((ver, discovered, headers)) => {
                // Which chain is this peer on? Its block hash at the reference height, placed
                // by anchoring the returned run to whichever locator block it extends. Empty
                // when the check is off, the peer didn't answer, or it hasn't reached that
                // height yet — all of which are "unknown", never "agrees with us".
                let chain_hash = p2p::peer_hash_at(&headers, &cfg.locator, cfg.chain_ref_height);
                let (implementation, version) = node::classify_user_agent(&ver.user_agent);
                let bip110 = node::assess_bip110(&implementation, &ver.user_agent, &cfg.rules);
                let info = NodeInfo {
                    addr: addr_str.clone(),
                    depth,
                    protocol_version: ver.protocol_version,
                    user_agent: ver.user_agent.clone(),
                    services: ver.services,
                    start_height: ver.start_height,
                    chain_hash,
                    handshaked: true,
                    implementation,
                    version,
                    bip110,
                    // Stamped at probe time. The DB only writes first_seen once (it keeps
                    // whatever is already stored), so for a peer we've met before this value
                    // is discarded and the original is preserved.
                    first_seen: crate::time::now_iso(),
                    // Stamped at PROBE time (not write time): this is when the peer was
                    // last confirmed reachable, which is what the API ages rows against.
                    last_seen: crate::time::now_iso(),
                    times_seen: 0,
                    online: true,
                };
                shared.nodes.lock().unwrap().insert(addr.clone(), info);

                // Enqueue children if we have depth budget left (max_depth 0 = unlimited).
                if cfg.max_depth == 0 || depth < cfg.max_depth {
                    let mut seen = shared.seen.lock().unwrap();
                    let mut edges = shared.edges.lock().unwrap();
                    let edge_cap = if cfg.edges_per_node == 0 {
                        usize::MAX
                    } else {
                        cfg.edges_per_node
                    };
                    let mut recorded = 0usize;
                    for child in discovered {
                        // Onion peers are only crawlable through a proxy; skip them entirely
                        // (no node, no edge) when none is configured.
                        if child.is_onion() && cfg.tor_proxy.is_none() {
                            continue;
                        }
                        if recorded < edge_cap {
                            edges.push(Edge {
                                from: addr_str.clone(),
                                to: child.to_string(),
                            });
                            recorded += 1;
                        }
                        if seen.insert(child.clone()) {
                            if child.is_onion() {
                                new_onion.push((child, depth + 1));
                            } else {
                                new_clearnet.push((child, depth + 1));
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // Handshake failed: keep a stub only if we had no prior (RPC) record,
                // so the node still appears in the graph as unreachable.
                let mut nodes = shared.nodes.lock().unwrap();
                nodes.entry(addr).or_insert_with(|| NodeInfo {
                    addr: addr_str,
                    depth,
                    protocol_version: 0,
                    user_agent: String::new(),
                    services: 0,
                    start_height: 0,
                    chain_hash: String::new(),
                    handshaked: false,
                    implementation: "Unreachable".to_string(),
                    version: String::new(),
                    bip110: node::Bip110Stance::Unknown,
                    first_seen: String::new(),
                    last_seen: String::new(),
                    times_seen: 0,
                    online: false,
                });
            }
        }

        finish_task(&shared, new_clearnet, new_onion);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn retry_only_on_timeouts() {
        let io = |k: ErrorKind| anyhow::Error::new(std::io::Error::from(k));
        // Deterministic failures — a retry can't change the answer.
        assert!(!worth_retrying(&io(ErrorKind::ConnectionRefused)));
        assert!(!worth_retrying(&io(ErrorKind::ConnectionReset)));
        // Timeouts — the peer was silent/slow, so a retry is worth it.
        assert!(worth_retrying(&io(ErrorKind::TimedOut)));
        assert!(worth_retrying(&io(ErrorKind::WouldBlock)));
        // The kind must survive the context wrap probe_peer adds around the connect error.
        let wrapped = io(ErrorKind::TimedOut).context("connect 1.2.3.4:8333");
        assert!(worth_retrying(&wrapped));
        let wrapped_refused = io(ErrorKind::ConnectionRefused).context("connect 1.2.3.4:8333");
        assert!(!worth_retrying(&wrapped_refused));
        // A non-IO failure means the peer responded but the handshake/parse failed — retryable.
        assert!(worth_retrying(&anyhow::anyhow!("peer never sent version")));
    }
}
