//! Renders the crawl into `report/data.json` and a self-contained `report/index.html`.
//!
//! The HTML inlines the JSON (so it opens straight from `file://` with no server),
//! draws a force-directed network graph on a canvas, and renders labelled bar charts
//! for implementation / version / BIP-110 stance. Colours use a CVD-validated
//! categorical palette; identity is never colour-alone (every mark is labelled).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::geo::GeoInfo;
use crate::node::{Aggregates, Edge, NodeInfo, SignalStats};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone)]
pub struct OwnNode {
    pub addr: String,
    pub version: i64,
    pub subversion: String,
    pub implementation: String,
    pub network: String,
}

#[derive(Serialize, Deserialize)]
pub struct ReportData {
    pub generated_at: String,
    pub network: String,
    pub own_node: OwnNode,
    pub signalling: Option<SignalStats>,
    /// Chain-split assessment (absent until the crawler has run one against its node).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_split: Option<crate::node::ChainSplit>,
    pub aggregates: Aggregates,
    /// Total nodes discovered this run (may exceed `nodes.len()` when the report is
    /// capped for size — see `--report-max-nodes`).
    #[serde(default)]
    pub discovered_total: usize,
    pub nodes: Vec<NodeInfo>,
    pub edges: Vec<Edge>,
    /// Per-node-address geolocation (present only when `--geolocate` was used).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<BTreeMap<String, GeoInfo>>,
    /// True when produced by the `--watch` loop; tells the page to poll `data.json`.
    pub live: bool,
    /// How often (seconds) the page should re-fetch `data.json`. 0 = never (static).
    pub refresh_seconds: u32,
}

pub fn write_report(out_dir: &Path, data: &ReportData) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("creating {}", out_dir.display()))?;

    let json = serde_json::to_string(data)?;

    // Write data.json atomically (tmp + rename) so a page polling it never reads a
    // half-written file mid-crawl.
    let data_path = out_dir.join("data.json");
    let tmp_path = out_dir.join("data.json.tmp");
    fs::write(&tmp_path, serde_json::to_string_pretty(data)?).context("writing data.json.tmp")?;
    fs::rename(&tmp_path, &data_path).context("renaming data.json")?;

    // index.html inlines the same data (so it still opens standalone from file://);
    // when served, the page polls data.json for live updates.
    fs::write(out_dir.join("index.html"), render_index_html(&json)).context("writing index.html")?;
    Ok(())
}

/// Slim world-countries geometry (name + rings), embedded so the geographic map
/// draws country outlines with no external assets. Produced by `examples/slim_world.rs`.
const WORLD_GEOJSON: &str = include_str!("../assets/world.min.json");

/// The one stylesheet every page uses (see `web/site.css`): design tokens plus every
/// shared component, based on the dashboard. Pages opt into variations with modifier
/// classes rather than shipping their own CSS.
const SITE_CSS: &str = include_str!("web/site.css");

// Per-page front-end assets (HTML shell + JS), embedded at build time. Each shell carries
// a `/*__CSS__*/` and a `/*__JS__*/` marker that assemble() fills.
const DASH_HTML: &str = include_str!("web/dashboard.html");
const DASH_JS: &str = include_str!("web/dashboard.js");
const WHY_HTML: &str = include_str!("web/why.html");
const WHY_JS: &str = include_str!("web/why.js");
const CODE_HTML: &str = include_str!("web/code.html");
const SUPPORT_HTML: &str = include_str!("web/support.html");
const SUPPORT_JS: &str = include_str!("web/support.js");
const STATS_HTML: &str = include_str!("web/stats.html");
const STATS_JS: &str = include_str!("web/stats.js");
const CHAINS_HTML: &str = include_str!("web/chains.html");
const CHAINS_JS: &str = include_str!("web/chains.js");
const BLOCKS_HTML: &str = include_str!("web/blocks.html");
const BLOCKS_JS: &str = include_str!("web/blocks.js");
const MEMPOOL_HTML: &str = include_str!("web/mempool.html");
const MEMPOOL_JS: &str = include_str!("web/mempool.js");
const ENTROPY_HTML: &str = include_str!("web/entropy.html");
const ENTROPY_JS: &str = include_str!("web/entropy.js");

/// The canonical BIP-39 English wordlist (2048 entries), fetched from the official
/// `bitcoin/bips` repository (`bip-0039/english.txt`) rather than transcribed by hand — a
/// single wrong word would silently corrupt every checksum computed against it. Re-validated
/// at render time in `render_entropy_html`, not just trusted at commit time.
const BIP39_WORDLIST_TXT: &str = include_str!("../assets/bip39-english.txt");

/// The live activity ticker, shared by every page (see `web/ticker.js`). It injects its own
/// element and fetches `/api/ticker` itself, so it works identically on all pages regardless of
/// what else they load — including `/code`, which has no page JS of its own.
const TICKER_JS: &str = include_str!("web/ticker.js");

/// The site icon (see `web/favicon.svg`), served at `/favicon.svg` and `/favicon.ico`.
pub const FAVICON_SVG: &str = include_str!("web/favicon.svg");

/// `(path, label)` for every page, in the order the navbar lists them. One list, so adding a
/// page here is the only place it needs adding — every HTML shell just carries a
/// `<!--__NAV__-->` placeholder instead of its own copy of this list.
const NAV_LINKS: &[(&str, &str)] = &[
    ("/", "◂ Live crawler"),
    ("/why", "Why BIP-110?"),
    ("/code", "Code"),
    ("/blocks", "⛓ Blocks"),
    ("/mempool", "🏊 Mempool"),
    ("/chains", "🔀 Chains"),
    ("/stats", "📊 Stats"),
    ("/entropy", "🎲 Entropy"),
    ("/support", "⚡ Support"),
];

/// Render the shared nav: a brand mark plus a plain horizontal row of text links (no
/// buttons/borders — just an underline on hover and on the current page), wrapping onto a
/// second line on narrow screens rather than hiding behind a toggle. Centralising this in one
/// function is what keeps pages from drifting the way the old per-page-literal nav did
/// (`/mempool` once shipped with a stray link to itself).
fn render_nav(current: &str) -> String {
    let items: String = NAV_LINKS
        .iter()
        .map(|(path, label)| {
            let class = if *path == current { " class=\"active\"" } else { "" };
            format!("<a href=\"{path}\"{class}>{label}</a>")
        })
        .collect();
    format!(
        "<nav>\
           <span class=\"brand\">▚ BIP-110</span>\
           <div class=\"nav-links\">{items}</div>\
         </nav>"
    )
}

/// Assemble a page from its HTML shell: the shared stylesheet at the `<style>` marker, the
/// shared nav at the `<!--__NAV__-->` marker (`current` is that page's own path, for the
/// active-link highlight), then the shared ticker followed by the page's own JS at the
/// `<script>` marker.
///
/// The icon link is injected here rather than written into each shell, so every page — present
/// and future — gets it from one place. Without it browsers request `/favicon.ico` implicitly
/// and log a 404 on every page load.
fn assemble(html: &str, js: &str, current: &str) -> String {
    html.replace("/*__CSS__*/", SITE_CSS)
        .replace("<!--__NAV__-->", &render_nav(current))
        .replace("/*__JS__*/", &format!("{TICKER_JS}\n{js}"))
        .replace(
            "</head>",
            "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\">\n</head>",
        )
}

/// Inline a JSON payload into the report template. Accepts either compact or
/// pretty-printed JSON (both are valid JS object literals).
pub fn render_index_html(json: &str) -> String {
    assemble(DASH_HTML, DASH_JS, "/")
        .replace("/*__DATA__*/null", json)
        .replace("/*__WORLD__*/null", WORLD_GEOJSON)
}

/// The page for `serve` mode: starts with an empty dataset and fetches/polls the API
/// (`/api/report`) instead of inlining data, so it loads instantly at any dataset size.
pub fn render_api_html() -> String {
    const EMPTY: &str = r#"{"generated_at":"","network":"main","own_node":{"addr":"self","version":0,"subversion":"loading…","implementation":"Unknown","network":"main"},"signalling":null,"aggregates":{"by_implementation":{},"by_version":{},"by_bip110":{},"total_nodes":0,"handshaked_nodes":0,"online_nodes":0},"discovered_total":0,"nodes":[],"edges":[],"live":true,"refresh_seconds":10}"#;
    assemble(DASH_HTML, DASH_JS, "/")
        .replace("/*__DATA__*/null", EMPTY)
        .replace("/*__WORLD__*/null", WORLD_GEOJSON)
        .replace("/*__API_URL__*/null", "\"/api/report\"")
}

/// The "Why support BIP-110" explainer page. Static content plus a few live charts
/// that fetch `/api/report` (they degrade gracefully to hidden if no server is up,
/// e.g. when opened from `file://`). Quantitative charts use the real crawl data;
/// conceptual diagrams are explicitly labelled illustrative.
pub fn render_why_html() -> String {
    assemble(WHY_HTML, WHY_JS, "/why")
}

/// The "BIP-110 code walkthrough" page (served at `/code`): the seven consensus rules
/// and how they're implemented. Static content, adapted from the Bitcoin Knots
/// walkthrough (attributed on the page).
pub fn render_code_html() -> String {
    assemble(CODE_HTML, "", "/code")
}

/// The "Crawl stats" page (served at `/stats`): crawl-health figures and the population
/// history, all fetched live from `/api/stats`.
pub fn render_stats_html() -> String {
    assemble(STATS_HTML, STATS_JS, "/stats")
}

/// Chain view (served at `/chains`): which chain each crawled peer is actually on, from the
/// per-peer `headers` survey, plus the local `getchaintips` view. Fed by `/api/chains`.
pub fn render_chains_html() -> String {
    assemble(CHAINS_HTML, CHAINS_JS, "/chains")
}

/// The block explorer (served at `/blocks`): recent blocks from `/api/blocks`, flagged by
/// whether they signal BIP-110.
pub fn render_blocks_html() -> String {
    assemble(BLOCKS_HTML, BLOCKS_JS, "/blocks")
}

/// The mempool view (served at `/mempool`): fee-rate histogram and aggregate stats from the
/// node's own mempool, fed by `/api/mempool`.
pub fn render_mempool_html() -> String {
    assemble(MEMPOOL_HTML, MEMPOOL_JS, "/mempool")
}

/// The entropy generator (served at `/entropy`): a client-side-only page that mixes the
/// browser's CSPRNG with hashed mouse/keyboard input into a BIP-39 recovery phrase or raw hex,
/// for use as extra entropy when creating a hardware wallet. No server-side state at all —
/// the only thing this function contributes is the wordlist, injected as a JSON array.
///
/// Re-validates the wordlist on every call (cheap: 2048 short strings) rather than trusting it
/// once at commit time, so a future accidental edit to the checked-in asset file fails loudly
/// instead of silently serving a corrupted wordlist to something generating real wallets.
pub fn render_entropy_html() -> String {
    let words: Vec<&str> = BIP39_WORDLIST_TXT.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(words.len(), 2048, "BIP-39 wordlist must have exactly 2048 words");
    assert!(
        words.windows(2).all(|w| w[0] < w[1]),
        "BIP-39 wordlist must be strictly ascending with no duplicates"
    );
    let wordlist_json = serde_json::to_string(&words).expect("wordlist always serialises");
    assemble(ENTROPY_HTML, ENTROPY_JS, "/entropy").replace("/*__WORDLIST__*/null", &wordlist_json)
}

/// The "Support this project" page (served at `/support`). Addresses and QR image paths
/// are supplied at render time from gitignored local files (see `serve::load_support`),
/// so donation details never live in the committed source. Empty inputs render a
/// "not configured" notice, keeping a fresh clone functional.
pub fn render_support_html(
    bitcoin_address: &str,
    lightning_address: &str,
    has_bitcoin_qr: bool,
    has_lightning_qr: bool,
) -> String {
    let mut cards = String::new();
    if !bitcoin_address.is_empty() {
        cards += &support_card(
            "Bitcoin",
            "on-chain",
            bitcoin_address,
            if has_bitcoin_qr { Some("/support/bitcoin.png") } else { None },
            "bitcoin:",
        );
    }
    if !lightning_address.is_empty() {
        cards += &support_card(
            "Lightning",
            "instant · low fee",
            lightning_address,
            if has_lightning_qr { Some("/support/lightning.png") } else { None },
            "lightning:",
        );
    }
    if cards.is_empty() {
        cards = "<div class=\"notice\">Support isn't configured on this instance.</div>".to_string();
    }
    assemble(SUPPORT_HTML, SUPPORT_JS, "/support")
        .replace("<!--__CARDS__-->", &cards)
}

/// One donation-method card: an optional QR, the address/invoice in a copyable box, and
/// copy / open-in-wallet buttons.
fn support_card(title: &str, subtitle: &str, value: &str, qr_src: Option<&str>, uri_scheme: &str) -> String {
    let v = html_escape(value);
    let qr = match qr_src {
        Some(src) => format!("<img class=\"qr\" src=\"{src}\" alt=\"{title} QR code\" width=\"220\" height=\"220\">"),
        None => String::new(),
    };
    format!(
        "<div class=\"method\">\
           <div class=\"mhead\"><h2>{title}</h2><span class=\"msub\">{subtitle}</span></div>\
           {qr}\
           <div class=\"addr\" title=\"{v}\">{v}</div>\
           <div class=\"mbtns\">\
             <button class=\"btn copy\" data-val=\"{v}\">Copy</button>\
             <a class=\"btn open\" href=\"{uri_scheme}{v}\">Open in wallet</a>\
           </div>\
         </div>"
    )
}

/// Minimal HTML escaping for donation strings injected into the support page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the exact thing that would silently corrupt every mnemonic checksum computed
    /// against this list: wrong length, a duplicate, or an out-of-order entry. This is the
    /// same check `render_entropy_html` runs at request time; this test just runs it without
    /// needing an HTTP round-trip, and fails the build (not just a live request) if the
    /// checked-in wordlist is ever wrong.
    #[test]
    fn bip39_wordlist_is_exactly_2048_sorted_unique_words() {
        let words: Vec<&str> = BIP39_WORDLIST_TXT.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(words.len(), 2048);
        assert!(words.windows(2).all(|w| w[0] < w[1]), "must be strictly ascending, no duplicates");
        assert!(
            words.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase())),
            "every entry must be pure lowercase ascii"
        );
        assert_eq!(words[0], "abandon");
        assert_eq!(words[2047], "zoo");
    }

    #[test]
    fn entropy_page_renders_with_the_wordlist_embedded() {
        let html = render_entropy_html();
        assert!(html.contains("\"abandon\""), "wordlist JSON should be spliced into the page");
        assert!(html.contains("\"zoo\""));
        assert!(!html.contains("/*__WORDLIST__*/"), "the placeholder must be fully replaced");
    }

    #[test]
    fn nav_marks_exactly_the_current_page_active_and_lists_every_page() {
        let nav = render_nav("/blocks");
        assert_eq!(nav.matches("class=\"active\"").count(), 1, "exactly one page is ever current");
        assert!(nav.contains("href=\"/blocks\" class=\"active\""));
        // Every registered page must appear as a link, or a page could silently vanish from
        // the menu if NAV_LINKS and the set of served routes ever drifted apart.
        for (path, _) in NAV_LINKS {
            assert!(nav.contains(&format!("href=\"{path}\"")), "missing nav link to {path}");
        }
    }

    #[test]
    fn every_page_shell_gets_the_nav_spliced_in_with_no_leftover_placeholder() {
        // One representative from each render_* family: a plain assemble() call
        // (render_blocks_html) and the dashboard's index page, which also has DATA/WORLD
        // markers to fill.
        for html in [render_blocks_html(), render_index_html("{}")] {
            assert!(!html.contains("<!--__NAV__-->"), "the nav placeholder must be fully replaced");
            assert!(html.contains("class=\"nav-links\""), "the actual nav markup must be present");
        }
    }
}




