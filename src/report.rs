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
const BLOCKS_HTML: &str = include_str!("web/blocks.html");
const BLOCKS_JS: &str = include_str!("web/blocks.js");

/// Assemble a page from its HTML shell: the shared stylesheet at the `<style>` marker and
/// the page's JS at the `<script>` marker.
fn assemble(html: &str, js: &str) -> String {
    html.replace("/*__CSS__*/", SITE_CSS)
        .replace("/*__JS__*/", js)
}

/// Inline a JSON payload into the report template. Accepts either compact or
/// pretty-printed JSON (both are valid JS object literals).
pub fn render_index_html(json: &str) -> String {
    assemble(DASH_HTML, DASH_JS)
        .replace("/*__DATA__*/null", json)
        .replace("/*__WORLD__*/null", WORLD_GEOJSON)
}

/// The page for `serve` mode: starts with an empty dataset and fetches/polls the API
/// (`/api/report`) instead of inlining data, so it loads instantly at any dataset size.
pub fn render_api_html() -> String {
    const EMPTY: &str = r#"{"generated_at":"","network":"main","own_node":{"addr":"self","version":0,"subversion":"loading…","implementation":"Unknown","network":"main"},"signalling":null,"aggregates":{"by_implementation":{},"by_version":{},"by_bip110":{},"total_nodes":0,"handshaked_nodes":0,"online_nodes":0},"discovered_total":0,"nodes":[],"edges":[],"live":true,"refresh_seconds":10}"#;
    assemble(DASH_HTML, DASH_JS)
        .replace("/*__DATA__*/null", EMPTY)
        .replace("/*__WORLD__*/null", WORLD_GEOJSON)
        .replace("/*__API_URL__*/null", "\"/api/report\"")
}

/// The "Why support BIP-110" explainer page. Static content plus a few live charts
/// that fetch `/api/report` (they degrade gracefully to hidden if no server is up,
/// e.g. when opened from `file://`). Quantitative charts use the real crawl data;
/// conceptual diagrams are explicitly labelled illustrative.
pub fn render_why_html() -> String {
    assemble(WHY_HTML, WHY_JS)
}

/// The "BIP-110 code walkthrough" page (served at `/code`): the seven consensus rules
/// and how they're implemented. Static content, adapted from the Bitcoin Knots
/// walkthrough (attributed on the page).
pub fn render_code_html() -> String {
    assemble(CODE_HTML, "")
}

/// The "Crawl stats" page (served at `/stats`): crawl-health figures and the population
/// history, all fetched live from `/api/stats`.
pub fn render_stats_html() -> String {
    assemble(STATS_HTML, STATS_JS)
}

/// The block explorer (served at `/blocks`): recent blocks from `/api/blocks`, flagged by
/// whether they signal BIP-110.
pub fn render_blocks_html() -> String {
    assemble(BLOCKS_HTML, BLOCKS_JS)
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
    assemble(SUPPORT_HTML, SUPPORT_JS)
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




