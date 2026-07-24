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
}

impl Aggregates {
    pub fn from_nodes(nodes: &[NodeInfo]) -> Self {
        let mut agg = Aggregates::default();
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

/// Whether the chain looks split, assessed from this node's own view plus the crawl.
///
/// Mandatory signalling is the moment a split becomes possible: a node enforcing BIP-110
/// rejects blocks that don't set bit 4, so if miners don't signal, enforcing and non-enforcing
/// nodes follow different chains. Two independent signals are combined:
///
/// * `getchaintips` on our node — authoritative for what WE reject. A branch we mark
///   `invalid` is the split signature; ordinary orphan races only ever appear as very short
///   branches, hence `MIN_FORK_LEN`.
/// * Peer tip heights grouped by BIP-110 readiness — corroboration from the network. A real
///   split drives those two medians apart and keeps them apart.
///
/// Note `start_height` is each peer's tip *at handshake time*, and an exhaustive crawl spans
/// hours, so a modest spread is normal probe skew rather than evidence of a split. Only the
/// gap between the two medians is meaningful, and only well beyond that skew.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainSplit {
    /// True when the evidence clears the thresholds below.
    pub split: bool,
    /// Our node's active tip height.
    pub active_height: i64,
    /// Branches we know of that aren't the active chain (branchlen > 0).
    pub forks: Vec<ForkTip>,
    /// Longest non-active branch length.
    pub longest_fork: i64,
    /// Branches our node considers INVALID — the BIP-110 rejection signature.
    pub rejected_branches: u32,
    /// Median tip height of reachable BIP-110-ready peers (0 when unknown).
    pub ready_median_height: i64,
    /// Median tip height of reachable peers that are NOT BIP-110 ready.
    pub other_median_height: i64,
    pub ready_peers: u32,
    pub other_peers: u32,
}

/// A non-active branch, flattened for the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkTip {
    pub height: i64,
    pub branchlen: i64,
    pub status: String,
}

/// Orphan races routinely produce 1–2 block branches; a consensus split does not resolve, so
/// a *valid* competing branch only counts once it is longer than a normal reorg.
pub const MIN_FORK_LEN: i64 = 3;
/// A branch our node rejected outright counts sooner — that is a rule disagreement, not a race.
pub const MIN_REJECTED_FORK_LEN: i64 = 1;
/// How far the two medians must diverge before peer heights corroborate a split. An exhaustive
/// crawl takes hours, so peers probed at different times legitimately differ by tens of blocks.
pub const MIN_MEDIAN_GAP: i64 = 60;

/// Build the split assessment from our node's chain tips and the crawled peer set.
pub fn assess_chain_split(tips: &[crate::rpc::ChainTip], peers: &[&NodeInfo]) -> ChainSplit {
    let active_height = tips.iter().find(|t| t.status == "active").map(|t| t.height).unwrap_or(0);
    let forks: Vec<ForkTip> = tips
        .iter()
        .filter(|t| t.branchlen > 0)
        .map(|t| ForkTip { height: t.height, branchlen: t.branchlen, status: t.status.clone() })
        .collect();
    let longest_fork = forks.iter().map(|f| f.branchlen).max().unwrap_or(0);
    let rejected_branches = forks
        .iter()
        .filter(|f| f.status == "invalid" && f.branchlen >= MIN_REJECTED_FORK_LEN)
        .count() as u32;

    // Median tip height per readiness group, over peers that actually handshook.
    let median = |mut v: Vec<i64>| -> i64 {
        if v.is_empty() { return 0; }
        v.sort_unstable();
        v[v.len() / 2]
    };
    let heights = |ready: bool| -> Vec<i64> {
        peers
            .iter()
            .filter(|n| n.handshaked && n.start_height > 0
                && matches!(n.bip110, Bip110Stance::Enforcing) == ready)
            .map(|n| n.start_height as i64)
            .collect()
    };
    let (rh, oh) = (heights(true), heights(false));
    let (ready_peers, other_peers) = (rh.len() as u32, oh.len() as u32);
    let (ready_median_height, other_median_height) = (median(rh), median(oh));

    // Peer corroboration needs both groups to be populated enough to have a meaningful median.
    let peer_gap = if ready_peers >= 20 && other_peers >= 20 {
        (ready_median_height - other_median_height).abs()
    } else {
        0
    };

    let split = rejected_branches > 0
        || longest_fork >= MIN_FORK_LEN
        || peer_gap >= MIN_MEDIAN_GAP;

    ChainSplit {
        split,
        active_height,
        forks,
        longest_fork,
        rejected_branches,
        ready_median_height,
        other_median_height,
        ready_peers,
        other_peers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(height: i64, branchlen: i64, status: &str) -> crate::rpc::ChainTip {
        crate::rpc::ChainTip { height, hash: String::new(), branchlen, status: status.into() }
    }
    fn peer(ready: bool, height: i32) -> NodeInfo {
        NodeInfo {
            addr: "1.2.3.4:8333".into(), depth: 1, protocol_version: 70016,
            user_agent: String::new(), services: 0, start_height: height,
            chain_hash: String::new(), handshaked: true,
            implementation: "Bitcoin Knots".into(), version: String::new(),
            bip110: if ready { Bip110Stance::Enforcing } else { Bip110Stance::NotEnforcing },
            first_seen: String::new(), last_seen: String::new(), times_seen: 0, online: true,
        }
    }

    #[test]
    fn ordinary_orphans_do_not_read_as_a_split() {
        // A 1-block valid-fork is a routine orphan race, not a consensus disagreement.
        let tips = vec![tip(963_346, 0, "active"), tip(963_345, 1, "valid-fork")];
        let s = assess_chain_split(&tips, &[]);
        assert!(!s.split, "a 1-block orphan must not be reported as a split");
        assert_eq!(s.active_height, 963_346);
        assert_eq!(s.longest_fork, 1);
    }

    #[test]
    fn a_rejected_branch_is_the_split_signature() {
        // Our node marking a branch INVALID means a rule disagreement — flag it immediately.
        let tips = vec![tip(963_346, 0, "active"), tip(963_350, 2, "invalid")];
        let s = assess_chain_split(&tips, &[]);
        assert!(s.split, "an invalid branch is a rule disagreement, not a race");
        assert_eq!(s.rejected_branches, 1);
    }

    #[test]
    fn a_long_valid_branch_is_a_split() {
        let tips = vec![tip(963_346, 0, "active"), tip(963_349, MIN_FORK_LEN, "valid-fork")];
        assert!(assess_chain_split(&tips, &[]).split);
    }

    #[test]
    fn peer_height_skew_alone_does_not_trigger_a_split() {
        let tips = vec![tip(963_346, 0, "active")];
        // Probe-time skew: an exhaustive crawl spans hours, so heights legitimately spread.
        let mut peers = Vec::new();
        for i in 0..40 { peers.push(peer(true, 963_300 + i)); }
        for i in 0..40 { peers.push(peer(false, 963_310 + i)); }
        let refs: Vec<&NodeInfo> = peers.iter().collect();
        let s = assess_chain_split(&tips, &refs);
        assert!(!s.split, "a small median gap is normal crawl skew, not a split");

        // A gap well beyond that skew, with both groups populated, does corroborate one.
        let mut wide = Vec::new();
        for i in 0..40 { wide.push(peer(true, 963_300 + i)); }
        for i in 0..40 { wide.push(peer(false, 963_300 + MIN_MEDIAN_GAP as i32 * 2 + i)); }
        let refs: Vec<&NodeInfo> = wide.iter().collect();
        assert!(assess_chain_split(&tips, &refs).split);
    }

    #[test]
    fn peer_corroboration_needs_both_groups_populated() {
        // With only a handful of ready peers the median is noise — don't cry split on it.
        let tips = vec![tip(963_346, 0, "active")];
        let mut peers = vec![peer(true, 900_000)];           // one lone, far-behind ready node
        for i in 0..40 { peers.push(peer(false, 963_300 + i)); }
        let refs: Vec<&NodeInfo> = peers.iter().collect();
        assert!(!assess_chain_split(&tips, &refs).split);
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
}
