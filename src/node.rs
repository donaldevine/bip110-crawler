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

#[cfg(test)]
mod tests {
    use super::*;

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
