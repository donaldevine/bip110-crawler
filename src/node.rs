//! Data model for a discovered node plus implementation / BIP-110 classification.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single node we learned about during the crawl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// `ip:port` string (canonical id used across the graph).
    pub addr: String,
    /// Depth at which this node was first reached (own node = 0).
    pub depth: u32,
    /// Protocol version reported in the peer's `version` message.
    pub protocol_version: i32,
    /// Raw user-agent / subversion string, e.g. `/Satoshi:27.1.0(knots...)/`.
    pub user_agent: String,
    /// Service bits advertised by the peer.
    pub services: u64,
    /// Block height the peer reported at handshake.
    pub start_height: i32,
    /// The peer's block hash at the chain-check reference height, from its `headers` reply.
    /// Empty when the check is disabled or the peer didn't report that height — which means
    /// "unknown", never "agrees with us". Not persisted; it is aggregated per snapshot.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub chain_hash: String,
    /// Whether we completed a P2P handshake (false = only heard about via gossip / RPC).
    pub handshaked: bool,
    /// Classified implementation family (Bitcoin Core, Knots, btcd, ...).
    pub implementation: String,
    /// Parsed version string, best-effort.
    pub version: String,
    /// How this node relates to BIP-110 (see `Bip110Stance`).
    pub bip110: Bip110Stance,
    /// First crawl (ISO timestamp) this address was ever seen. Populated by history.
    #[serde(default)]
    pub first_seen: String,
    /// Last crawl this node was reachable (handshaked). Populated by history.
    #[serde(default)]
    pub last_seen: String,
    /// Number of crawls in which this node was reachable. Populated by history.
    #[serde(default)]
    pub times_seen: u32,
    /// Reachable in the most recent crawl. Populated by history (default true for
    /// single-shot crawls where every listed node was just seen).
    #[serde(default = "default_true")]
    pub online: bool,
    /// Milliseconds from opening the connection to completing the version/verack handshake,
    /// from our own crawl of this peer. `None` for nodes we've only heard about via RPC/gossip
    /// or that failed to handshake — never a guess, only a measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u32>,
}

fn default_true() -> bool {
    true
}

/// A directed edge in the reachability graph (`from` gossiped/knew about `to`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
}

/// Per-node BIP-110 assessment.
///
/// IMPORTANT: BIP-110 ("Reduced Data Temporary Softfork") is activated by *miners*
/// setting bit 4 in the block `version` field — it is NOT advertised by ordinary
/// nodes in the P2P `version` handshake. So per-node "support" here is a *heuristic*
/// based on the software the node runs (its user agent), not a direct observation.
/// The authoritative, network-wide signalling figure is computed separately from the
/// block-version scan against your own node (see `SignalStats`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bip110Stance {
    /// Runs software that enforces BIP-110-style data limits (e.g. Bitcoin Knots).
    Enforcing,
    /// Runs software that does not enforce the limits by default (e.g. stock Core).
    NotEnforcing,
    /// Implementation unknown or unclassified.
    Unknown,
}

/// A rule mapping an implementation family to a BIP-110 stance.
#[derive(Debug, Clone, Deserialize)]
pub struct Bip110Rule {
    /// Case-insensitive substring matched against the user agent.
    pub user_agent_contains: String,
    pub stance: Bip110Stance,
}

/// Classify a user-agent string into an implementation family + version.
///
/// Recognises the common Bitcoin network clients. Returns `(implementation, version)`.
pub fn classify_user_agent(ua: &str) -> (String, String) {
    let lower = ua.to_lowercase();
    // Knots is a Satoshi fork; it stamps "knots" into the parenthetical comment.
    if lower.contains("knots") {
        return ("Bitcoin Knots".to_string(), extract_satoshi_version(ua));
    }
    if lower.contains("satoshi") {
        return ("Bitcoin Core".to_string(), extract_satoshi_version(ua));
    }
    for (needle, name) in [
        ("btcd", "btcd"),
        ("bcoin", "bcoin"),
        ("bitcoin abc", "Bitcoin ABC"),
        ("bu", "Bitcoin Unlimited"),
        ("libbitcoin", "libbitcoin"),
        ("gocoin", "gocoin"),
        ("bitcoinj", "bitcoinj"),
        ("floresta", "Floresta"),
    ] {
        if lower.contains(needle) {
            return (name.to_string(), extract_generic_version(ua));
        }
    }
    if ua.is_empty() {
        return ("Unknown".to_string(), String::new());
    }
    ("Other".to_string(), extract_generic_version(ua))
}

/// Pull the `x.y.z` out of a `/Satoshi:27.1.0(...)/` style user agent.
fn extract_satoshi_version(ua: &str) -> String {
    if let Some(colon) = ua.find(':') {
        let rest = &ua[colon + 1..];
        let end = rest
            .find(|c: char| c == '/' || c == '(' )
            .unwrap_or(rest.len());
        return rest[..end].trim().to_string();
    }
    String::new()
}

/// Best-effort version extraction for non-Satoshi agents like `/btcd:0.24.0/`.
fn extract_generic_version(ua: &str) -> String {
    if let Some(colon) = ua.find(':') {
        let rest = &ua[colon + 1..];
        let end = rest.find('/').unwrap_or(rest.len());
        return rest[..end].trim().to_string();
    }
    String::new()
}

/// Earliest mainline Bitcoin Knots build date (`YYYYMMDD`) that ships BIP-110
/// *without* an explicit `+bip110` tag. Once BIP-110 was merged into Knots the
/// dedicated tag was dropped, so newer builds like `/Satoshi:29.3.0/Knots:20260508/`
/// are ready by virtue of their build date. Confirmed against `Knots:20260508`.
const BIP110_KNOTS_DATE: u32 = 20260508;

/// Determine BIP-110 readiness from the node's user agent. Two signals, in order:
///  1. An explicit tag — dedicated branch builds stamp `+bip110-v0.4.1` /
///     `UASF-BIP110:0.4` (all contain the substring "bip110").
///  2. A mainline Knots build dated on/after [`BIP110_KNOTS_DATE`] — after BIP-110
///     merged into Knots the tag was dropped, so readiness is inferred from the
///     `knots<YYYYMMDD>` build date embedded in the subversion.
/// Both are signals from the peer itself, not a guess from the implementation family.
/// An optional rule table can override.
pub fn assess_bip110(
    _implementation: &str,
    user_agent: &str,
    rules: &[Bip110Rule],
) -> Bip110Stance {
    let lower_ua = user_agent.to_lowercase();
    for rule in rules {
        if lower_ua.contains(&rule.user_agent_contains.to_lowercase()) {
            return rule.stance;
        }
    }
    if lower_ua.contains("bip110") {
        return Bip110Stance::Enforcing; // explicit tag — advertises BIP-110 support
    }
    if let Some(date) = knots_build_date(&lower_ua) {
        if date >= BIP110_KNOTS_DATE {
            return Bip110Stance::Enforcing; // mainline Knots that merged BIP-110
        }
    }
    Bip110Stance::NotEnforcing
}

/// Extract the 8-digit `YYYYMMDD` build date following a `knots` marker in a user
/// agent, handling both `(knots20240813)` and `/Knots:20260508/` forms. `lower_ua`
/// must already be lowercased.
fn knots_build_date(lower_ua: &str) -> Option<u32> {
    let pos = lower_ua.find("knots")?;
    let after = &lower_ua[pos + "knots".len()..];
    let digits: String = after
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .take(8)
        .collect();
    if digits.len() == 8 {
        digits.parse().ok()
    } else {
        None
    }
}

/// Aggregate counts used to build the report's charts.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Aggregates {
    /// implementation -> count
    pub by_implementation: BTreeMap<String, usize>,
    /// implementation + version -> count
    pub by_version: BTreeMap<String, usize>,
    /// stance label -> count
    pub by_bip110: BTreeMap<String, usize>,
    pub total_nodes: usize,
    pub handshaked_nodes: usize,
    /// Nodes online in the most recent crawl (relevant when history is enabled).
    pub online_nodes: usize,
    /// Tor (onion) nodes among the counted set. Aggregated over the full set so the
    /// figure is exact even when the node list shown in the report is capped for size.
    pub onion_nodes: usize,
    /// Handshake-latency histogram, over online nodes with a measured latency. A `Vec` in
    /// ascending order (not a map) — bucket labels like "100-200ms" don't sort correctly as
    /// strings ("100-200ms" < "3000ms+" < "50-100ms" lexicographically), so order is carried
    /// structurally instead. Empty bands are omitted.
    pub latency_buckets: Vec<LatencyBucket>,
    /// Median handshake latency (ms) across the same set, or `None` if nothing was measured
    /// (e.g. no crawl has completed yet, or every node came from RPC/gossip only).
    pub median_latency_ms: Option<u32>,
}

/// One band of the handshake-latency histogram: nodes whose measured latency falls in
/// `[min_ms, max_ms)`. `max_ms` is `None` for the open-ended top band.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyBucket {
    pub min_ms: u32,
    pub max_ms: Option<u32>,
    pub count: usize,
}

/// Latency band edges (ms) for the handshake-latency histogram — closer together at the
/// low end, where most real peers land, and coarser above a second or so.
const LATENCY_BUCKET_EDGES: &[u32] = &[50, 100, 200, 400, 800, 1500, 3000];

/// Bucket a set of latency measurements into the fixed bands (dropping empty ones) and
/// report the median alongside. Shared by the in-memory report path (`Aggregates::from_nodes`)
/// and `db::read_report`, which aggregates straight from SQL instead of a `NodeInfo` slice.
pub(crate) fn latency_histogram(mut latencies: Vec<u32>) -> (Vec<LatencyBucket>, Option<u32>) {
    if latencies.is_empty() {
        return (Vec::new(), None);
    }
    latencies.sort_unstable();
    let median = latencies[latencies.len() / 2];

    let n = LATENCY_BUCKET_EDGES.len();
    let mut counts = vec![0usize; n + 1];
    for &ms in &latencies {
        let idx = LATENCY_BUCKET_EDGES.iter().position(|&e| ms < e).unwrap_or(n);
        counts[idx] += 1;
    }
    let mut buckets = Vec::new();
    let mut lo = 0;
    for (i, &count) in counts.iter().enumerate() {
        let hi = LATENCY_BUCKET_EDGES.get(i).copied();
        if count > 0 {
            buckets.push(LatencyBucket { min_ms: lo, max_ms: hi, count });
        }
        if let Some(h) = hi {
            lo = h;
        }
    }
    (buckets, Some(median))
}

impl Aggregates {
    pub fn from_nodes(nodes: &[NodeInfo]) -> Self {
        let mut agg = Aggregates::default();
        let mut latencies = Vec::new();
        for n in nodes {
            agg.total_nodes += 1;
            if n.handshaked {
                agg.handshaked_nodes += 1;
            }
            if n.online {
                agg.online_nodes += 1;
            }
            if n.addr.contains(".onion") {
                agg.onion_nodes += 1;
            }
            if n.online {
                if let Some(ms) = n.latency_ms {
                    latencies.push(ms);
                }
            }
            *agg.by_implementation.entry(n.implementation.clone()).or_default() += 1;
            let vkey = if n.version.is_empty() {
                n.implementation.clone()
            } else {
                format!("{} {}", n.implementation, n.version)
            };
            *agg.by_version.entry(vkey).or_default() += 1;
            let stance = match n.bip110 {
                Bip110Stance::Enforcing => "BIP-110 ready",
                Bip110Stance::NotEnforcing => "Not ready",
                Bip110Stance::Unknown => "Unknown",
            };
            *agg.by_bip110.entry(stance.to_string()).or_default() += 1;
        }
        (agg.latency_buckets, agg.median_latency_ms) = latency_histogram(latencies);
        agg
    }
}

/// Miner signalling statistics derived from the block-version scan on your own node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalStats {
    pub window: u32,
    pub blocks_scanned: u32,
    pub blocks_signalling: u32,
    pub percent: f64,
    pub bit: u8,
    /// 55% of 2016 => 1109 blocks, per BIP-110.
    pub threshold_percent: f64,
    pub tip_height: i64,
}

/// Whether the chain looks split, from two signals — both grounded in identity, not inference,
/// which is what keeps this from crying wolf:
///
/// * **Peer block-hash clusters.** Peers grouped by the block hash they reported at the
///   reference height (the same survey the /chains page shows). A second cluster with real
///   support means peers are provably on a different chain. This is the primary signal.
/// * **`getchaintips` invalid branches.** A branch our own node marked `invalid` *near the
///   tip* — a rule rejection, not an orphan race.
///
/// Deliberately NOT used as triggers: the length of `valid-fork` / `headers-only` branches
/// (getchaintips lists every stale tip a node ever heard of, so those are routine), and peer
/// tip-height medians (an exhaustive crawl spans hours, so heights drift from probe timing
/// alone). Both produced false positives and are gone.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainSplit {
    /// True when the evidence clears the thresholds below.
    pub split: bool,
    /// Our node's active tip height.
    pub active_height: i64,
    /// Branches we know of that aren't the active chain (branchlen > 0). Informational.
    pub forks: Vec<ForkTip>,
    /// Longest non-active branch length. Informational only — NOT a trigger.
    pub longest_fork: i64,
    /// Branches our node considers INVALID near the tip — a genuine rule rejection.
    pub rejected_branches: u32,
    /// Peers that reported a block hash at the reference height (the survey population).
    pub responded: u32,
    /// Distinct block hashes seen across those peers — 1 means everyone agrees.
    pub distinct_chains: u32,
    /// Node count on the largest chain, and on the next-largest (the competing one).
    pub largest_chain: u32,
    pub second_chain: u32,
}

/// A non-active branch, flattened for the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkTip {
    pub height: i64,
    pub branchlen: i64,
    pub status: String,
}

/// A branch our node rejected counts from length 1 — that is a rule disagreement, not a race.
pub const MIN_REJECTED_FORK_LEN: i64 = 1;
/// An `invalid` branch only signals a *current* split if its tip is near ours. `getchaintips`
/// retains ancient known-invalid tips forever; those are history, not a live fork.
pub const REJECT_RECENCY: i64 = 2016;
/// A real network split needs a competing chain with genuine support, not one stray or
/// misconfigured peer reporting an odd block.
pub const MIN_SPLIT_CLUSTER: u32 = 10;

/// Build the split assessment from our node's chain tips and the crawled peer set.
///
/// Peers must carry `chain_hash` (populated by the `--chain-check` header survey) for the
/// network signal; without it only our node's own `invalid`-branch signal is available.
pub fn assess_chain_split(tips: &[crate::rpc::ChainTip], peers: &[&NodeInfo]) -> ChainSplit {
    let active_height = tips.iter().find(|t| t.status == "active").map(|t| t.height).unwrap_or(0);
    let forks: Vec<ForkTip> = tips
        .iter()
        .filter(|t| t.branchlen > 0)
        .map(|t| ForkTip { height: t.height, branchlen: t.branchlen, status: t.status.clone() })
        .collect();
    let longest_fork = forks.iter().map(|f| f.branchlen).max().unwrap_or(0);
    // Only INVALID branches near the tip. A valid-fork / headers-only branch of any length is
    // routine (getchaintips lists every stale tip), and an ancient invalid tip is old history.
    let rejected_branches = forks
        .iter()
        .filter(|f| {
            f.status == "invalid"
                && f.branchlen >= MIN_REJECTED_FORK_LEN
                && (active_height == 0 || (active_height - f.height).abs() <= REJECT_RECENCY)
        })
        .count() as u32;

    // Network view: cluster peers by the block hash they reported at the reference height. A
    // differing hash at the same height is a different chain — identity, not inference. This is
    // exactly the data the /chains page renders, so the two views can no longer disagree.
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for n in peers.iter().filter(|n| n.handshaked && !n.chain_hash.is_empty()) {
        *counts.entry(n.chain_hash.as_str()).or_insert(0) += 1;
    }
    let responded: u32 = counts.values().sum();
    let distinct_chains = counts.len() as u32;
    let mut sizes: Vec<u32> = counts.values().copied().collect();
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    let largest_chain = sizes.first().copied().unwrap_or(0);
    let second_chain = sizes.get(1).copied().unwrap_or(0);

    // A network split = a second chain with real support; a local split = our node rejecting a
    // recent branch. Nothing else trips the alarm.
    let split = rejected_branches > 0 || second_chain >= MIN_SPLIT_CLUSTER;

    ChainSplit {
        split,
        active_height,
        forks,
        longest_fork,
        rejected_branches,
        responded,
        distinct_chains,
        largest_chain,
        second_chain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(height: i64, branchlen: i64, status: &str) -> crate::rpc::ChainTip {
        crate::rpc::ChainTip { height, hash: String::new(), branchlen, status: status.into() }
    }
    fn peer_on(hash: &str) -> NodeInfo {
        NodeInfo {
            addr: "1.2.3.4:8333".into(), depth: 1, protocol_version: 70016,
            user_agent: String::new(), services: 0, start_height: 963_340,
            chain_hash: hash.into(), handshaked: true,
            implementation: "Bitcoin Core".into(), version: String::new(),
            bip110: Bip110Stance::NotEnforcing,
            first_seen: String::new(), last_seen: String::new(), times_seen: 0, online: true,
            latency_ms: None,
        }
    }
    fn peers_on(hash: &str, n: usize) -> Vec<NodeInfo> {
        (0..n).map(|_| peer_on(hash)).collect()
    }

    #[test]
    fn one_chain_across_all_peers_is_not_a_split() {
        let tips = vec![tip(963_346, 0, "active"), tip(963_345, 1, "valid-fork")];
        let peers = peers_on("aaaa", 5000);
        let refs: Vec<&NodeInfo> = peers.iter().collect();
        let s = assess_chain_split(&tips, &refs);
        assert!(!s.split, "everyone on one hash is not a split");
        assert_eq!(s.distinct_chains, 1);
        assert_eq!(s.responded, 5000);
    }

    #[test]
    fn a_historical_orphan_or_headers_only_branch_is_not_a_split() {
        // The exact false positive reported: getchaintips carries old valid-fork / headers-only
        // branches many blocks long. None of these must trip the alarm.
        let tips = vec![
            tip(963_346, 0, "active"),
            tip(900_000, 40, "valid-fork"),     // ancient orphan
            tip(963_300, 8, "headers-only"),    // headers we never fetched blocks for
            tip(963_340, 5, "valid-headers"),
        ];
        let peers = peers_on("aaaa", 3000);
        let refs: Vec<&NodeInfo> = peers.iter().collect();
        assert!(!assess_chain_split(&tips, &refs).split, "stale/headers-only branches are routine");
    }

    #[test]
    fn two_well_supported_chains_are_a_split() {
        let tips = vec![tip(963_346, 0, "active")];
        let mut peers = peers_on("aaaa", 3000);
        peers.extend(peers_on("bbbb", 1500)); // a real competing chain
        let refs: Vec<&NodeInfo> = peers.iter().collect();
        let s = assess_chain_split(&tips, &refs);
        assert!(s.split);
        assert_eq!(s.distinct_chains, 2);
        assert_eq!(s.largest_chain, 3000);
        assert_eq!(s.second_chain, 1500);
    }

    #[test]
    fn a_few_stray_peers_on_an_odd_hash_are_not_a_split() {
        // A handful of misconfigured/regtest/buggy peers must not read as a network split.
        let tips = vec![tip(963_346, 0, "active")];
        let mut peers = peers_on("aaaa", 3000);
        peers.extend(peers_on("cccc", 3)); // below MIN_SPLIT_CLUSTER
        let refs: Vec<&NodeInfo> = peers.iter().collect();
        assert!(!assess_chain_split(&tips, &refs).split);
    }

    #[test]
    fn a_recent_invalid_branch_is_a_split_even_without_peer_data() {
        // Our node rejecting a branch near the tip is a rule disagreement — a local split
        // signal that stands even when the header survey is off (no peer hashes).
        let tips = vec![tip(963_346, 0, "active"), tip(963_350, 3, "invalid")];
        let s = assess_chain_split(&tips, &[]);
        assert!(s.split);
        assert_eq!(s.rejected_branches, 1);
    }

    #[test]
    fn an_ancient_invalid_tip_is_not_a_current_split() {
        // getchaintips keeps known-invalid tips forever; one from long ago is history.
        let tips = vec![tip(963_346, 0, "active"), tip(800_000, 2, "invalid")];
        assert!(!assess_chain_split(&tips, &[]).split, "an old invalid tip is not a live fork");
    }

    fn stance(ua: &str) -> Bip110Stance {
        let (implementation, _) = classify_user_agent(ua);
        assess_bip110(&implementation, ua, &[])
    }

    #[test]
    fn explicit_bip110_tag_is_ready() {
        assert_eq!(stance("/Satoshi:29.2.0(knots20251110+bip110-v0.1)/UASF-BIP110:0.1/"), Bip110Stance::Enforcing);
        assert_eq!(stance("/Satoshi:29.3.0(knots20260210+bip110-v0.4.1)/"), Bip110Stance::Enforcing);
    }

    #[test]
    fn mainline_knots_ready_by_build_date() {
        // Untagged mainline build on/after the cutoff -> ready.
        assert_eq!(stance("/Satoshi:29.3.0/Knots:20260508/"), Bip110Stance::Enforcing);
        // Older Knots predating BIP-110 -> not ready.
        assert_eq!(stance("/Satoshi:25.1.0(knots20240813)/"), Bip110Stance::NotEnforcing);
        assert_eq!(stance("/Satoshi:27.1.0(knots20241201)/"), Bip110Stance::NotEnforcing);
    }

    #[test]
    fn stock_core_is_not_ready() {
        assert_eq!(stance("/Satoshi:27.1.0/"), Bip110Stance::NotEnforcing);
        assert_eq!(stance("/btcd:0.24.2/"), Bip110Stance::NotEnforcing);
    }

    #[test]
    fn knots_build_date_parses_both_forms() {
        assert_eq!(knots_build_date("/satoshi:25.1.0(knots20240813)/"), Some(20240813));
        assert_eq!(knots_build_date("/satoshi:29.3.0/knots:20260508/"), Some(20260508));
        assert_eq!(knots_build_date("/satoshi:27.1.0/"), None);
    }

    #[test]
    fn latency_histogram_buckets_and_reports_the_median() {
        let (buckets, median) = latency_histogram(vec![30, 45, 90, 180, 5000]);
        assert_eq!(median, Some(90), "the middle value of 5 sorted samples");
        assert_eq!(buckets.len(), 4, "empty bands (e.g. 200-400ms) are omitted");
        // Ascending order, structural (not string-sorted) — this is exactly what would break
        // if the buckets were a BTreeMap<String, _> keyed by label instead of a Vec.
        let got: Vec<(u32, Option<u32>, usize)> =
            buckets.iter().map(|b| (b.min_ms, b.max_ms, b.count)).collect();
        assert_eq!(
            got,
            vec![
                (0, Some(50), 2),      // 30, 45
                (50, Some(100), 1),    // 90
                (100, Some(200), 1),   // 180
                (3000, None, 1),       // 5000, open-ended top band
            ]
        );
    }

    #[test]
    fn latency_histogram_of_nothing_is_nothing() {
        let (buckets, median) = latency_histogram(vec![]);
        assert!(buckets.is_empty());
        assert_eq!(median, None);
    }

    #[test]
    fn aggregates_skip_offline_nodes_when_measuring_latency() {
        // An offline node's latency is from a stale crawl, not a live measurement — including
        // it would make the network look faster than it currently is.
        let mut online = peer_on("aaaa");
        online.latency_ms = Some(50);
        let mut offline = peer_on("aaaa");
        offline.online = false;
        offline.latency_ms = Some(5000);
        let agg = Aggregates::from_nodes(&[online, offline]);
        assert_eq!(agg.median_latency_ms, Some(50));
    }
}
