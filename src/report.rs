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

/// Inline a JSON payload into the report template. Accepts either compact or
/// pretty-printed JSON (both are valid JS object literals).
pub fn render_index_html(json: &str) -> String {
    TEMPLATE
        .replace("/*__DATA__*/null", json)
        .replace("/*__WORLD__*/null", WORLD_GEOJSON)
}

/// The page for `serve` mode: starts with an empty dataset and fetches/polls the API
/// (`/api/report`) instead of inlining data, so it loads instantly at any dataset size.
pub fn render_api_html() -> String {
    const EMPTY: &str = r#"{"generated_at":"","network":"main","own_node":{"addr":"self","version":0,"subversion":"loading…","implementation":"Unknown","network":"main"},"signalling":null,"aggregates":{"by_implementation":{},"by_version":{},"by_bip110":{},"total_nodes":0,"handshaked_nodes":0,"online_nodes":0},"discovered_total":0,"nodes":[],"edges":[],"live":true,"refresh_seconds":10}"#;
    TEMPLATE
        .replace("/*__DATA__*/null", EMPTY)
        .replace("/*__WORLD__*/null", WORLD_GEOJSON)
        .replace("/*__API_URL__*/null", "\"/api/report\"")
}

/// The "Why support BIP-110" explainer page. Static content plus a few live charts
/// that fetch `/api/report` (they degrade gracefully to hidden if no server is up,
/// e.g. when opened from `file://`). Quantitative charts use the real crawl data;
/// conceptual diagrams are explicitly labelled illustrative.
pub fn render_why_html() -> String {
    WHY_TEMPLATE.to_string()
}

/// The report is a single self-contained page. `/*__DATA__*/null` is replaced with
/// the serialized `ReportData` at generation time.
const TEMPLATE: &str = r####"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Live Bitcoin BIP-110 Node Crawler</title>

    <!-- X (Twitter) Card Meta Tags -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="Live Bitcoin BIP-110 Node Crawler">
    <meta name="twitter:description" content="Live view of Bitcoin BIP-110 nodes.">
    <meta name="twitter:image" content="https://bip110.xyz/summary_large_image.png">

    <!-- Open Graph Tags (Fallback used by Facebook, LinkedIn, and often X) -->
    <meta property="og:type" content="website">
    <meta property="og:title" content="Live Bitcoin BIP-110 Node Crawler">
    <meta property="og:description" content="Live view of Bitcoin BIP-110 nodes.">
    <meta property="og:image" content="https://bip110.xyz/summary_large_image.png">
    <meta property="og:url" content="https://bip110.xyz/">

<style>
  /* ---- Cyberpunk theme: neon-on-black (dark, default) ---- */
  :root {
    --page:#06060f; --surface:#0c0e1e; --surface-2:#12152c;
    --ink:#eaf2ff; --ink-2:#98a2ce; --muted:#5c6591;
    --grid:#1a2044; --border:rgba(0,229,255,0.22);
    --good:#00ff9c; --warn:#ffcb2b; --neutral:#5c6591;
    --neon:#00e5ff; --neon2:#ff2d95; --glow:rgba(0,229,255,0.55);
    /* categorical slots (distinct + legible on the dark surface) */
    --c1:#3aa0ff; --c2:#1fe0a4; --c3:#ffcf3f; --c4:#37e06a;
    --c5:#9d7bff; --c6:#ff5d73; --c7:#ff77c8; --c8:#ff8a3d; --c9:#6b7398;
    --radius:12px;
    --mono:ui-monospace,"Cascadia Code","JetBrains Mono","Segoe UI Mono",Consolas,monospace;
  }
  /* Always dark (cyberpunk). No light theme. */
  * { box-sizing: border-box; }
  body {
    margin:0; background:var(--page); color:var(--ink);
    font-family: system-ui,-apple-system,"Segoe UI",sans-serif;
    line-height:1.55; position:relative; min-height:100vh;
  }
  /* neon grid + vignette backdrop */
  body::before {
    content:""; position:fixed; inset:0; z-index:-2; pointer-events:none;
    background:
      linear-gradient(var(--grid) 1px, transparent 1px) 0 0/44px 44px,
      linear-gradient(90deg, var(--grid) 1px, transparent 1px) 0 0/44px 44px;
    opacity:.5;
    -webkit-mask-image: radial-gradient(ellipse at 50% 0%, #000 30%, transparent 85%);
            mask-image: radial-gradient(ellipse at 50% 0%, #000 30%, transparent 85%);
  }
  body::after {
    content:""; position:fixed; inset:0; z-index:-1; pointer-events:none;
    background: radial-gradient(1100px 620px at 50% -8%, var(--glow), transparent 70%);
    opacity:.28;
  }
  .wrap { max-width:1200px; margin:0 auto; padding:28px 20px 80px; }
  header { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; }
  header h1 {
    font-family:var(--mono); font-size:24px; margin:0 0 6px; font-weight:700;
    text-transform:uppercase; letter-spacing:.14em; color:var(--ink);
    text-shadow:0 0 8px var(--glow), 0 0 22px var(--glow);
  }
  header h1::before { content:"▚ "; color:var(--neon); }
  header .sub { color:var(--ink-2); font-size:13px; font-family:var(--mono); }
  .theme-toggle {
    flex:none; display:inline-flex; align-items:center; gap:8px; cursor:pointer;
    background:var(--surface); border:1px solid var(--border); color:var(--ink-2);
    border-radius:8px; padding:8px 14px; font-size:12px; font-family:var(--mono);
    text-transform:uppercase; letter-spacing:.08em;
    transition:color .15s, box-shadow .15s, border-color .15s;
  }
  .theme-toggle:hover { color:var(--neon); border-color:var(--neon); box-shadow:0 0 12px var(--glow); }
  .theme-toggle .icon { font-size:14px; line-height:1; }
  .live-dot { display:inline-block; width:8px; height:8px; border-radius:50%;
    background:var(--good); margin-right:6px; vertical-align:middle;
    box-shadow:0 0 8px var(--good), 0 0 3px var(--good);
    animation:pulse 1.6s ease-in-out infinite; }
  @keyframes pulse { 0%,100%{opacity:1; box-shadow:0 0 10px var(--good);} 50%{opacity:.3; box-shadow:0 0 2px var(--good);} }
  .grid { display:grid; gap:16px; }
  .cards { grid-template-columns: repeat(auto-fit,minmax(200px,1fr)); margin:24px 0; }
  .card, .panel {
    background:linear-gradient(180deg, color-mix(in srgb, var(--surface) 92%, var(--neon)), var(--surface));
    border:1px solid var(--border); border-radius:var(--radius); padding:18px 20px;
    position:relative; box-shadow:0 0 0 1px rgba(0,0,0,0.2) inset;
  }
  .card { transition:box-shadow .18s, border-color .18s, transform .18s; }
  .card:hover { border-color:var(--neon); box-shadow:0 0 18px var(--glow); transform:translateY(-2px); }
  .card::after {
    content:""; position:absolute; left:0; top:12px; bottom:12px; width:2px; border-radius:2px;
    background:var(--neon); box-shadow:0 0 8px var(--glow);
  }
  .card .label { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.14em; font-family:var(--mono); }
  .card .value { font-family:var(--mono); font-size:30px; font-weight:700; margin-top:6px; color:var(--ink);
    text-shadow:0 0 10px var(--glow); }
  .card .value small { font-size:15px; color:var(--ink-2); font-weight:500; text-shadow:none; }
  .card .note { color:var(--ink-2); font-size:12px; margin-top:4px; font-family:var(--mono); }
  section { margin-top:34px; }
  section h2 {
    font-family:var(--mono); font-size:15px; margin:0 0 6px; text-transform:uppercase;
    letter-spacing:.1em; color:var(--neon); text-shadow:0 0 10px var(--glow);
    display:flex; align-items:center; gap:8px;
  }
  section h2::before { content:"//"; color:var(--neon2); opacity:.8; }
  section .hint { color:var(--muted); font-size:12.5px; margin:0 0 16px; max-width:74ch; }
  /* bar charts */
  .bars { display:flex; flex-direction:column; gap:10px; }
  .bar-row { display:grid; grid-template-columns: 190px 1fr 46px; align-items:center; gap:12px; }
  .bar-row .name { font-size:12.5px; color:var(--ink-2); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .bar-track { background:var(--surface-2); border-radius:5px; height:20px; overflow:hidden; border:1px solid var(--border); }
  .bar-fill { height:100%; border-radius:4px; filter:saturate(1.3) drop-shadow(0 0 6px currentColor); }
  .bar-row .num { font-size:12.5px; text-align:right; font-variant-numeric:tabular-nums; color:var(--ink); font-family:var(--mono); }
  /* signalling gauge */
  .gauge-track { background:var(--surface-2); border-radius:6px; height:26px; position:relative; overflow:hidden; border:1px solid var(--border); }
  .gauge-fill { height:100%; border-radius:5px; background:var(--good); box-shadow:0 0 14px var(--good); }
  .gauge-threshold { position:absolute; top:-4px; bottom:-4px; width:2px; background:var(--warn); box-shadow:0 0 8px var(--warn); }
  .gauge-threshold::after {
    content:"55% lock-in"; position:absolute; top:-18px; left:6px;
    font-size:10px; color:var(--warn); white-space:nowrap; font-family:var(--mono);
  }
  /* network graph + geo map */
  .graph-wrap { position:relative; }
  #graph, #geomap { width:100%; display:block; border-radius:var(--radius);
    background:radial-gradient(120% 120% at 50% 0%, var(--surface-2), var(--page));
    border:1px solid var(--border); cursor:grab; box-shadow:0 0 20px rgba(0,0,0,0.35) inset; }
  #graph { height:520px; } #geomap { height:460px; }
  #graph:active, #geomap:active { cursor:grabbing; }
  .legend { display:flex; flex-wrap:wrap; gap:14px; margin-top:12px; }
  .legend .item { display:flex; align-items:center; gap:7px; font-size:12px; color:var(--ink-2); font-family:var(--mono); }
  .legend .dot { width:11px; height:11px; border-radius:50%; flex:none; box-shadow:0 0 7px currentColor; }
  .tooltip {
    position:absolute; pointer-events:none; background:rgba(6,8,20,0.92);
    border:1px solid var(--neon); border-radius:8px; padding:8px 10px;
    font-size:12px; font-family:var(--mono); max-width:280px; opacity:0; transition:opacity .1s; z-index:5;
    box-shadow:0 0 16px var(--glow); color:var(--ink-2);
  }
  .tooltip b { color:var(--neon); }
  /* table */
  .controls { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:12px; }
  .controls input, .controls select {
    background:var(--surface-2); border:1px solid var(--border); color:var(--ink);
    border-radius:8px; padding:8px 10px; font-size:12.5px; font-family:var(--mono);
  }
  .controls input:focus, .controls select:focus { outline:none; border-color:var(--neon); box-shadow:0 0 10px var(--glow); }
  table { width:100%; border-collapse:collapse; font-size:12.5px; }
  th, td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--grid); }
  th { color:var(--neon); font-weight:600; cursor:pointer; user-select:none; white-space:nowrap;
    font-family:var(--mono); text-transform:uppercase; letter-spacing:.06em; font-size:11px; }
  tbody tr:hover { background:color-mix(in srgb, var(--neon) 8%, transparent); }
  td { color:var(--ink-2); }
  .pill { display:inline-flex; align-items:center; gap:5px; padding:2px 8px; border-radius:999px; font-size:11px; font-family:var(--mono); }
  .pill.enf { background:color-mix(in srgb, var(--good) 18%, transparent); color:var(--good); box-shadow:0 0 8px color-mix(in srgb, var(--good) 40%, transparent); }
  .pill.not { background:color-mix(in srgb, var(--muted) 22%, transparent); color:var(--ink-2); }
  .pill.unk { background:color-mix(in srgb, var(--muted) 14%, transparent); color:var(--muted); }
  .swatch { display:inline-block; width:9px; height:9px; border-radius:2px; margin-right:6px; vertical-align:middle; box-shadow:0 0 5px currentColor; }
  .disclaimer { font-size:11.5px; color:var(--muted); margin-top:12px; font-family:var(--mono); }
  footer { margin-top:40px; color:var(--muted); font-size:11.5px; font-family:var(--mono); }
  a { color:var(--neon); text-decoration:none; } a:hover { text-shadow:0 0 8px var(--glow); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>BIP-110 Bitcoin Node Crawl</h1>
      <div class="sub" id="subtitle"></div>
    </div>
    <a class="theme-toggle" href="/why">★ Why support BIP-110?</a>
  </header>

  <div class="grid cards" id="cards"></div>

  <section>
    <h2>Miner signalling for BIP-110 (block version bit 4)</h2>
    <p class="hint">This is the authoritative figure. BIP-110 activates when 55% of
      the last 2016 blocks (1109 blocks) set bit 4 in their version field. Measured by
      scanning recent block headers from your own node — not from peer gossip.</p>
    <div class="panel" id="signal-panel"></div>
  </section>

  <section>
    <h2>Network map</h2>
    <p class="hint">A 3D force-directed map. Each node is a peer we handshook with (or
      heard about); a connector means the source node gossiped the target's address via
      <code>getaddr</code> — reachability, not a confirmed live link. <b>Drag to rotate</b>,
      <b>scroll to zoom</b>, hover a node for details. Colour = implementation.</p>
    <div class="graph-wrap panel">
      <canvas id="graph"></canvas>
      <div class="tooltip" id="gtip"></div>
      <div class="legend" id="legend"></div>
    </div>
  </section>

  <section id="geo-section" style="display:none;">
    <h2>Geographic map</h2>
    <p class="hint">Nodes placed by IP geolocation (via ip-api.com). Colour = implementation;
      each dot is a node's approximate location. <b>Drag to pan, scroll to zoom</b>, hover for
      city and client details. Tor/onion nodes are anonymous (no IP) and can't be mapped —
      they appear on the network map above but not here.</p>
    <div class="graph-wrap panel">
      <canvas id="geomap"></canvas>
      <div class="tooltip" id="mtip"></div>
      <div class="legend" id="geolegend"></div>
    </div>
  </section>

  <section class="grid" style="grid-template-columns:repeat(auto-fit,minmax(320px,1fr));">
    <div class="panel">
      <h2>Implementations</h2>
      <p class="hint">Client software across all reachable nodes.</p>
      <div class="bars" id="chart-impl"></div>
    </div>
    <div class="panel">
      <h2>BIP-110 readiness</h2>
      <p class="hint">Detected from each node's user agent: builds that advertise BIP-110
        (e.g. <code>+bip110-v0.4.1</code> / <code>UASF-BIP110</code>) are marked ready. This is
        node-software readiness — separate from the miner block-version signalling above.</p>
      <div class="bars" id="chart-bip"></div>
    </div>
  </section>

  <section class="panel">
    <h2>Version distribution</h2>
    <p class="hint">Top client versions on the network.</p>
    <div class="bars" id="chart-ver"></div>
  </section>

  <section>
    <h2>All nodes</h2>
    <div class="controls">
      <input id="search" type="search" placeholder="Filter by location, client, version…">
      <select id="filter-impl"><option value="">All implementations</option></select>
      <select id="filter-bip">
        <option value="">Any BIP-110 status</option>
        <option value="enforcing">BIP-110 ready</option>
        <option value="not_enforcing">Not ready</option>
        <option value="unknown">Unknown</option>
      </select>
    </div>
    <div class="panel" style="overflow-x:auto;">
      <table id="nodes-table">
        <thead><tr>
          <th data-k="location">Location</th>
          <th data-k="implementation">Implementation</th>
          <th data-k="version">Version</th>
          <th data-k="protocol_version">Protocol</th>
          <th data-k="depth">Depth</th>
          <th data-k="bip110">BIP-110</th>
        </tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </section>

  <p class="disclaimer" id="disclaimer"></p>
  <footer>Generated by bip110-crawler · <span id="gen-time"></span></footer>
</div>

<script>
let DATA = /*__DATA__*/null;
const WORLD = /*__WORLD__*/null;  // [{n:name, r:[[[lon,lat],...],...]}, ...]

// ---- palette: implementation -> categorical slot (fixed order, not cycled) ----
const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const IMPL_ORDER = ["Bitcoin Core","Bitcoin Knots","btcd","bcoin","libbitcoin",
                    "Bitcoin ABC","Bitcoin Unlimited","Other"];
// Explicit implementation -> colour-slot map. Slots: c1 blue, c2 teal, c3 yellow,
// c4 green, c5 violet, c6 red, c7 magenta, c8 orange, c9 grey.
const SLOT_OF = {
  "Bitcoin Core":"--c1",       // blue
  "Bitcoin Knots":"--c8",      // orange
  "btcd":"--c3",               // yellow
  "bcoin":"--c4",              // green
  "libbitcoin":"--c5",         // violet
  "Bitcoin ABC":"--c2",        // teal
  "Bitcoin Unlimited":"--c7",  // magenta
  "Other":"--c6",              // red
};
const implSlot = name => SLOT_OF[name] || "--c9";
// DOM colours are emitted as `var(--cN)` so they re-theme automatically; the canvas
// (which needs concrete values) resolves slots via cssVar() and refreshes on toggle.
const implColor = name => `var(${implSlot(name)})`;

function esc(s){ return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

// The site only shows reachable nodes (unreachable are excluded server-side).
// A non-IP descriptor for a node: its geolocated place, "Tor" for onion, or the
// network type for un-geolocated clearnet. Used instead of the raw address in the list.
function nodeLocation(n){
  const self = n.depth === 0 || n.addr.startsWith("self");
  const g = DATA.geo && DATA.geo[n.addr];
  if (g){
    const loc = [g.city, g.country].filter(Boolean).join(", ") || "—";
    return self ? `${loc} (this node)` : loc;
  }
  if (self) return "This node";
  if (n.addr.includes(".onion")) return "Tor (anonymous)";
  const ipv6 = n.addr.startsWith("[") || (n.addr.split(":").length > 2);
  return ipv6 ? "IPv6" : "IPv4";
}

// ---- render helpers (re-callable so the page can refresh from fresh JSON) ----
const sortDesc = obj => Object.entries(obj).sort((a,b)=>b[1]-a[1]);
const shortTime = iso => (iso && iso.length>=19) ? iso.slice(11,19)+" UTC" : (iso||"");
const shortDate = iso => (iso && iso.length>=10) ? iso.slice(0,10) : (iso||"");

function renderCards(){
  const a = DATA.aggregates, sig = DATA.signalling;
  const reachable = a.total_nodes;
  const tor = DATA.nodes.filter(n => n.addr.includes(".onion")).length;
  const live = DATA.live
    ? ` · <span class="live-dot"></span>live, updated ${esc(shortTime(DATA.generated_at))}`
    : "";
  document.getElementById("subtitle").innerHTML =
    `${esc(DATA.network)} · own node ${esc(DATA.own_node.subversion || "n/a")} · `
    + `${reachable.toLocaleString()} reachable nodes${live}`;
  document.getElementById("gen-time").textContent = DATA.generated_at;
  const cards = [
    ["Reachable nodes", reachable.toLocaleString(), "responding to the crawl"],
    ["Tor nodes", tor.toLocaleString(), "reachable over onion"],
    ["Implementations", Object.keys(a.by_implementation).length, "distinct clients"],
    ["Miner signalling", sig ? sig.percent.toFixed(1)+"%" : "n/a",
       sig ? `${sig.blocks_signalling}/${sig.blocks_scanned} recent blocks` : "RPC not available"],
  ];
  document.getElementById("cards").innerHTML = cards.map(([l,v,n]) =>
    `<div class="card"><div class="label">${esc(l)}</div>
     <div class="value">${esc(String(v))}</div>
     <div class="note">${esc(n)}</div></div>`).join("");
}

function renderSignalling(){
  const sig = DATA.signalling;
  const el = document.getElementById("signal-panel");
  if (!sig){ el.innerHTML = `<div class="note">No RPC connection — run with --rpc-* to measure block-version signalling.</div>`; return; }
  const pct = Math.max(0, Math.min(100, sig.percent));
  const status = sig.percent >= sig.threshold_percent ? "at or above lock-in threshold"
                : `${(sig.threshold_percent - sig.percent).toFixed(1)} points below lock-in`;
  el.innerHTML = `
    <div style="display:flex;justify-content:space-between;font-size:13px;color:var(--ink-2);margin-bottom:6px;">
      <span><b style="color:var(--ink)">${sig.percent.toFixed(1)}%</b> of last ${sig.blocks_scanned} blocks signal (bit ${sig.bit})</span>
      <span>${esc(status)}</span>
    </div>
    <div class="gauge-track">
      <div class="gauge-fill" style="width:${pct}%"></div>
      <div class="gauge-threshold" style="left:${sig.threshold_percent}%"></div>
    </div>
    <div class="note" style="margin-top:14px;">Chain tip height ${sig.tip_height.toLocaleString()}.
      ${sig.blocks_signalling} of ${sig.blocks_scanned} scanned blocks set version bit ${sig.bit}.</div>`;
}

function barChart(elId, entries, colorFn){
  const max = Math.max(1, ...entries.map(e=>e[1]));
  document.getElementById(elId).innerHTML = entries.map(([name,val]) => `
    <div class="bar-row">
      <div class="name" title="${esc(name)}">${esc(name)}</div>
      <div class="bar-track"><div class="bar-fill"
        style="width:${(val/max*100).toFixed(1)}%;background:${colorFn(name)}"></div></div>
      <div class="num">${val}</div>
    </div>`).join("");
}

function renderCharts(){
  const a = DATA.aggregates;
  barChart("chart-impl", sortDesc(a.by_implementation), implColor);
  barChart("chart-ver", sortDesc(a.by_version).slice(0,12),
           n => n.startsWith("Unreachable") ? "var(--muted)"
                : implColor(IMPL_ORDER.find(i=>n.startsWith(i)) || "Other"));
  barChart("chart-bip", sortDesc(a.by_bip110), name =>
    name.startsWith("BIP-110 ready") ? "var(--good)"
    : name.startsWith("Not") ? "var(--neutral)" : "var(--muted)");
  document.getElementById("legend").innerHTML =
    Object.keys(a.by_implementation).map(name =>
      `<span class="item"><span class="dot" style="background:${implColor(name)}"></span>${esc(name)}</span>`
    ).join("");
}

// ---- 3D force-directed graph on canvas ----
const graph = (function(){
  const canvas = document.getElementById("graph");
  const tip = document.getElementById("gtip");
  const ctx = canvas.getContext("2d");
  const DPR = window.devicePixelRatio || 1;

  // Node state lives in 3D space. On a live refresh we reconcile by address so
  // persisting nodes keep their positions (the layout nudges instead of jumping);
  // new nodes are seeded on a small random sphere and dropped nodes disappear.
  let nodes = [], idx = new Map(), links = [];
  const radiusFor = n => n.depth===0 ? 7 : (n.handshaked?3.6:2.6);
  function setData(data){
    const prev = new Map(nodes.map(n=>[n.id,n]));
    nodes = data.nodes.map(n => {
      const p = prev.get(n.addr);
      if (p){ p.info = n; p.r = radiusFor(n); return p; }
      const rr = 120 + Math.random()*80, u = Math.random()*2-1, th = Math.random()*Math.PI*2;
      const s = Math.sqrt(1-u*u);
      return { id:n.addr, info:n, x:rr*s*Math.cos(th), y:rr*s*Math.sin(th), z:rr*u,
               vx:0, vy:0, vz:0, r:radiusFor(n) };
    });
    idx = new Map(nodes.map((n,i)=>[n.id,i]));
    // Only keep edges whose endpoints are both real nodes in the graph.
    links = data.edges
      .filter(e => idx.has(e.from) && idx.has(e.to))
      .map(e => ({s:idx.get(e.from), t:idx.get(e.to)}));
    alpha = Math.max(alpha, 0.5); // reheat the sim so the layout settles around changes
  }

  // Canvas needs resolved colours (CSS var() can't be used as a fillStyle). Cache
  // them and refresh whenever the theme toggles.
  let CV = {};
  function resolveColors(){
    CV = { grid:cssVar("--grid"), good:cssVar("--good"), ink:cssVar("--ink"),
           muted:cssVar("--muted"), surface:cssVar("--surface"), c9:cssVar("--c9"),
           neon:cssVar("--neon"),
           // Connectors: the muted grey reads clearly on both the light and dark
           // surface, unlike the near-invisible hairline grid colour.
           link:cssVar("--muted") };
    IMPL_ORDER.forEach(n => CV[implSlot(n)] = cssVar(implSlot(n)));
  }
  resolveColors();
  (window.__themeListeners = window.__themeListeners || []).push(resolveColors);
  const nodeColor = info => info.implementation==="Unreachable"
      ? CV.muted : (CV[implSlot(info.implementation)] || CV.c9);

  let W=0,H=0;
  function resize(){
    const rect = canvas.getBoundingClientRect();
    W=rect.width; H=rect.height;
    canvas.width=W*DPR; canvas.height=H*DPR; ctx.setTransform(DPR,0,0,DPR,0,0);
  }
  resize(); window.addEventListener("resize", resize);

  // Camera: two rotation angles + a zoom (perspective scale).
  let rotX=0.5, rotY=0.6, zoom=1;
  const FOCAL = 900;

  // 3D velocity-Verlet force simulation.
  let alpha = 1;
  const FIT_R = 220; // layout is renormalised to this radius every frame
  function step(){
    const n = nodes.length;
    const repulse = 2000, spring = 0.03, damp = 0.85, rest = 40;

    // Skip the O(n^2) force pass once the layout has settled; keep animating (rotation)
    // cheaply. Dragging or a live data update reheats alpha to resume simulation.
    if (alpha > 0.04){
      for (let i=0;i<n;i++){
        const a=nodes[i];
        for (let j=i+1;j<n;j++){
          const b=nodes[j];
          let dx=a.x-b.x, dy=a.y-b.y, dz=a.z-b.z; let d2=dx*dx+dy*dy+dz*dz+0.01;
          const f = repulse/d2 * alpha; const d=Math.sqrt(d2);
          const fx=dx/d*f, fy=dy/d*f, fz=dz/d*f;
          a.vx+=fx; a.vy+=fy; a.vz+=fz; b.vx-=fx; b.vy-=fy; b.vz-=fz;
        }
      }
      for (const l of links){
        const a=nodes[l.s], b=nodes[l.t];
        let dx=b.x-a.x, dy=b.y-a.y, dz=b.z-a.z; const d=Math.sqrt(dx*dx+dy*dy+dz*dz)||1;
        const f=(d-rest)*spring*alpha; const fx=dx/d*f, fy=dy/d*f, fz=dz/d*f;
        a.vx+=fx; a.vy+=fy; a.vz+=fz; b.vx-=fx; b.vy-=fy; b.vz-=fz;
      }
      alpha *= 0.996;
    }
    for (const nd of nodes){
      nd.vx*=damp; nd.vy*=damp; nd.vz*=damp;
      nd.x+=nd.vx; nd.y+=nd.vy; nd.z+=nd.vz;
    }
    // Renormalise the whole layout every frame: recenter on the centroid, then rescale
    // to a fixed radius. This keeps the graph framed for ANY node count and force
    // magnitude — it can neither explode off-screen nor collapse to an invisible dot.
    if (n){
      let cx=0,cy=0,cz=0;
      for (const nd of nodes){ cx+=nd.x; cy+=nd.y; cz+=nd.z; }
      cx/=n; cy/=n; cz/=n;
      let maxr=0;
      for (const nd of nodes){
        nd.x-=cx; nd.y-=cy; nd.z-=cz;
        const r=Math.sqrt(nd.x*nd.x+nd.y*nd.y+nd.z*nd.z); if (r>maxr) maxr=r;
      }
      if (maxr>1){ const s=FIT_R/maxr; for (const nd of nodes){ nd.x*=s; nd.y*=s; nd.z*=s; } }
    }
  }

  // Rotate a point by the camera angles and perspective-project to screen space.
  function project(n){
    const cy=Math.cos(rotY), sy=Math.sin(rotY);
    const cx=Math.cos(rotX), sx=Math.sin(rotX);
    const x1 = n.x*cy - n.z*sy;
    const z1 = n.x*sy + n.z*cy;
    const y1 = n.y*cx - z1*sx;
    const z2 = n.y*sx + z1*cx;      // depth from camera plane
    const denom = FOCAL + z2;
    const scale = denom > 1 ? FOCAL/denom*zoom : 0;
    return { sx: W/2 + x1*scale, sy: H/2 + y1*scale, scale, depth: z2 };
  }

  let proj = [];               // last-frame projections (for picking)
  let autoRotate = true;

  function draw(){
    if (autoRotate) rotY += 0.0016;
    ctx.clearRect(0,0,W,H);
    proj = nodes.map(project);

    // Connectors first, depth-shaded so far links recede but stay visible.
    ctx.strokeStyle = CV.link;
    for (const l of links){
      const a=proj[l.s], b=proj[l.t];
      if (a.scale<=0 || b.scale<=0) continue;
      const near = (a.depth+b.depth)/2;
      ctx.globalAlpha = Math.max(0.22, Math.min(0.75, 0.6 - near/2600));
      ctx.lineWidth = Math.max(0.8, (a.scale+b.scale)/2 * 0.85);
      ctx.beginPath(); ctx.moveTo(a.sx,a.sy); ctx.lineTo(b.sx,b.sy); ctx.stroke();
    }
    ctx.globalAlpha = 1;

    // Draw nodes far-to-near (painter's algorithm) so nearer nodes sit on top.
    // Neon glow via shadowBlur, disabled on very large graphs to keep the frame rate up.
    const glow = nodes.length <= 700;
    const order = nodes.map((_,i)=>i).sort((i,j)=>proj[j].depth - proj[i].depth);
    for (const i of order){
      const n=nodes[i], p=proj[i];
      if (p.scale<=0) continue;
      const rad = Math.max(1.6, n.r*p.scale);
      // Fog: nodes further from the camera fade slightly toward the surface. Offline
      // (historical) nodes are dimmed further so the live network stands out.
      let a = Math.max(0.45, Math.min(1, 0.9 - p.depth/1600));
      if (n.info.online === false) a *= 0.4;
      ctx.globalAlpha = a;
      const col = nodeColor(n.info);
      if (glow && n.info.online !== false){ ctx.shadowBlur = rad*2.2; ctx.shadowColor = col; }
      ctx.beginPath(); ctx.arc(p.sx,p.sy,rad,0,Math.PI*2);
      ctx.fillStyle = col; ctx.fill();
      ctx.shadowBlur = 0;
      // Green glow ring = BIP-110 ready (node advertises BIP-110 in its user agent).
      if (n.info.bip110==="enforcing"){
        ctx.globalAlpha=1; ctx.lineWidth=Math.max(1,1.6*p.scale); ctx.strokeStyle=CV.good;
        if (glow){ ctx.shadowBlur=rad*2.0; ctx.shadowColor=CV.good; }
        ctx.stroke(); ctx.shadowBlur=0;
      }
      // Own node gets a bright ring so you can find it.
      if (n.info.depth===0){
        ctx.globalAlpha=1; ctx.lineWidth=Math.max(1.4,2.4*p.scale); ctx.strokeStyle=CV.neon || CV.ink; ctx.stroke();
      }
    }
    ctx.globalAlpha = 1;
  }
  function frame(){ step(); draw(); requestAnimationFrame(frame); }
  setData(DATA);
  frame();

  // Pick the nearest node to a screen point (using the last projection).
  function pick(px,py){
    let best=null,bd=1e9;
    for (let i=0;i<nodes.length;i++){
      const p=proj[i]; if (p.scale<=0) continue;
      const rad=Math.max(1.6, nodes[i].r*p.scale)+4;
      const d=(p.sx-px)**2+(p.sy-py)**2;
      if (d<bd && d<rad*rad){ bd=d; best=nodes[i]; }
    }
    return best;
  }

  // Interaction: drag to rotate, scroll to zoom, hover for details.
  let rotating=false, last={x:0,y:0};
  canvas.addEventListener("mousedown", e=>{
    rotating=true; autoRotate=false; last={x:e.clientX,y:e.clientY};
  });
  window.addEventListener("mousemove", e=>{
    const r=canvas.getBoundingClientRect(); const px=e.clientX-r.left, py=e.clientY-r.top;
    if (rotating){
      rotY += (e.clientX-last.x)*0.008;
      rotX += (e.clientY-last.y)*0.008;
      rotX = Math.max(-1.5, Math.min(1.5, rotX));
      last={x:e.clientX,y:e.clientY};
      tip.style.opacity=0;
    } else {
      const n=pick(px,py);
      if (n){
        const i=n.info;
        const bip = i.bip110==="enforcing" ? "ready" : i.bip110==="not_enforcing" ? "not ready" : "unknown";
        tip.innerHTML = `<b>${esc(i.addr)}</b><br>${esc(i.implementation)} ${esc(i.version)}<br>`
          + `${esc(i.user_agent||"(no handshake)")}<br>depth ${i.depth} · protocol ${i.protocol_version}`
          + `<br>BIP-110: ${bip}`;
        tip.style.left=Math.min(px+14, W-250)+"px"; tip.style.top=(py+14)+"px"; tip.style.opacity=1;
      } else tip.style.opacity=0;
    }
  });
  window.addEventListener("mouseup", ()=>{ rotating=false; });
  canvas.addEventListener("wheel", e=>{
    e.preventDefault(); autoRotate=false;
    zoom = Math.max(0.2, Math.min(6, zoom * (e.deltaY<0 ? 1.12 : 0.89)));
  }, {passive:false});

  return { update:setData };
})();

// ---- geographic map (equirectangular; shown only when geolocation data is present) ----
const geoMap = (function(){
  const canvas = document.getElementById("geomap");
  if (!canvas) return { update(){} };
  const tip = document.getElementById("mtip");
  const ctx = canvas.getContext("2d");
  const DPR = window.devicePixelRatio || 1;

  let CV = {};
  function resolveColors(){
    CV = { ocean:cssVar("--page"), land:cssVar("--surface-2"), border:cssVar("--muted"),
           grid:cssVar("--grid"), ink:cssVar("--ink"), muted:cssVar("--muted"), c9:cssVar("--c9") };
    IMPL_ORDER.forEach(n => CV[implSlot(n)] = cssVar(implSlot(n)));
  }
  resolveColors();
  (window.__themeListeners = window.__themeListeners || []).push(resolveColors);
  const colorFor = info => (info && info.implementation!=="Unreachable")
      ? (CV[implSlot(info.implementation)] || CV.c9) : CV.muted;

  let points = [], labels = [];
  let W=0, H=0, WW=0, HH=0, fitted=false;
  let view = {x:0,y:0,k:1};

  function fitView(){
    view.k = Math.min(W/WW, H/HH) || 1;
    view.x = (W - WW*view.k)/2;
    view.y = (H - HH*view.k)/2;
  }
  function resize(){
    const r = canvas.getBoundingClientRect();
    W=r.width; H=r.height;
    if (!W || !H) return;
    canvas.width=W*DPR; canvas.height=H*DPR; ctx.setTransform(DPR,0,0,DPR,0,0);
    WW=W; HH=W/2;                 // equirectangular: full width, half-width tall
    if (!fitted){ fitView(); fitted=true; }
  }
  window.addEventListener("resize", ()=>{ fitted=false; resize(); });

  // lon/lat -> screen
  function proj(lat, lon){
    const wx=(lon+180)/360*WW, wy=(90-lat)/180*HH;
    return { x: view.x+wx*view.k, y: view.y+wy*view.k };
  }

  function setData(data){
    const section = document.getElementById("geo-section");
    const geo = data.geo;
    if (!geo || Object.keys(geo).length===0){
      if (section) section.style.display="none";
      points=[]; labels=[]; return;
    }
    if (section) section.style.display="";
    const byAddr = new Map(data.nodes.map(n=>[n.addr,n]));
    // Only plot nodes present in the (possibly reachable-only-filtered) node set.
    points = Object.entries(geo)
      .filter(([addr]) => byAddr.has(addr))
      .map(([addr,g])=>({
        addr, lat:g.lat, lon:g.lon, city:g.city, country:g.country, info: byAddr.get(addr)
      }));
    // Country labels at the centroid of each country's nodes (only sizeable clusters).
    const groups = {};
    for (const p of points){
      const c = p.country || "?";
      (groups[c] = groups[c] || {lat:0,lon:0,n:0}); groups[c].lat+=p.lat; groups[c].lon+=p.lon; groups[c].n++;
    }
    labels = Object.entries(groups).filter(([,v])=>v.n>=3)
      .map(([c,v])=>({country:c, lat:v.lat/v.n, lon:v.lon/v.n, n:v.n}));
    // The section was display:none until now, so size the canvas after it's visible.
    fitted=false; resize();
    buildLegend(data);
  }

  function buildLegend(data){
    const impls = new Set(points.map(p=>p.info && p.info.implementation).filter(Boolean));
    document.getElementById("geolegend").innerHTML =
      [...impls].map(name =>
        `<span class="item"><span class="dot" style="background:${implColor(name)}"></span>${esc(name)}</span>`
      ).join("") + `<span class="item">${points.length} located nodes</span>`;
  }

  function line(a,b){ ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke(); }

  function drawCountries(){
    if (!Array.isArray(WORLD)) return;
    ctx.fillStyle = CV.land; ctx.strokeStyle = CV.border; ctx.lineWidth = 0.6;
    for (const feat of WORLD){
      for (const ring of feat.r){
        ctx.beginPath();
        for (let i=0;i<ring.length;i++){
          const s = proj(ring[i][1], ring[i][0]); // ring is [lon,lat]
          if (i===0) ctx.moveTo(s.x, s.y); else ctx.lineTo(s.x, s.y);
        }
        ctx.closePath(); ctx.fill(); ctx.stroke();
      }
    }
  }

  function draw(){
    requestAnimationFrame(draw);      // always keep looping (data/size may not be ready yet)
    if (!W || !H) return;
    ctx.clearRect(0,0,W,H);
    // ocean panel
    ctx.fillStyle = CV.ocean;
    ctx.fillRect(view.x, view.y, WW*view.k, HH*view.k);
    // country landmasses + borders
    drawCountries();
    // graticule every 30 degrees
    ctx.strokeStyle = CV.grid; ctx.lineWidth = 1; ctx.globalAlpha = 0.35;
    for (let lon=-180; lon<=180; lon+=30) line(proj(-90,lon), proj(90,lon));
    for (let lat=-90; lat<=90; lat+=30) line(proj(lat,-180), proj(lat,180));
    ctx.globalAlpha = 1;
    // country labels (under the dots)
    ctx.fillStyle = CV.muted; ctx.font = "11px system-ui, sans-serif"; ctx.textAlign="center";
    for (const l of labels){ const s=proj(l.lat,l.lon); ctx.fillText(l.country, s.x, s.y-8); }
    // dots — offline (historical) nodes are dimmer + smaller; live ones get a neon glow
    const glow = points.length <= 1500;
    for (const p of points){
      const s = proj(p.lat, p.lon);
      const off = p.info && p.info.online === false;
      const col = colorFor(p.info);
      if (glow && !off){ ctx.shadowBlur = 8; ctx.shadowColor = col; }
      ctx.beginPath(); ctx.arc(s.x, s.y, off ? 2.4 : 3.4, 0, Math.PI*2);
      ctx.fillStyle = col; ctx.globalAlpha = off ? 0.35 : 0.95; ctx.fill();
      ctx.shadowBlur = 0;
    }
    ctx.globalAlpha = 1;
  }
  requestAnimationFrame(draw);

  // interaction: pan, zoom, hover
  function pick(px,py){
    let best=null,bd=1e9;
    for (const p of points){ const s=proj(p.lat,p.lon); const d=(s.x-px)**2+(s.y-py)**2; if (d<bd && d<49){ bd=d; best=p; } }
    return best;
  }
  let panning=false, last={x:0,y:0};
  canvas.addEventListener("mousedown", e=>{ panning=true; last={x:e.clientX,y:e.clientY}; });
  window.addEventListener("mousemove", e=>{
    const r=canvas.getBoundingClientRect(); const px=e.clientX-r.left, py=e.clientY-r.top;
    if (panning){ view.x+=e.clientX-last.x; view.y+=e.clientY-last.y; last={x:e.clientX,y:e.clientY}; tip.style.opacity=0; return; }
    if (px<0||py<0||px>W||py>H){ tip.style.opacity=0; return; }
    const p=pick(px,py);
    if (p){
      const i=p.info;
      const status = i && i.online===false
        ? `offline${i.last_seen ? " · last seen "+esc(shortDate(i.last_seen)) : ""}`
        : "online";
      tip.innerHTML = `<b>${esc(p.city||"?")}, ${esc(p.country||"?")}</b><br>${esc(p.addr)}<br>`
        + (i ? `${esc(i.implementation)} ${esc(i.version)}<br>${status}` : "(no node record)");
      tip.style.left=Math.min(px+14, W-240)+"px"; tip.style.top=(py+14)+"px"; tip.style.opacity=1;
    } else tip.style.opacity=0;
  });
  window.addEventListener("mouseup", ()=>{ panning=false; });
  canvas.addEventListener("wheel", e=>{
    e.preventDefault();
    const r=canvas.getBoundingClientRect(); const px=e.clientX-r.left, py=e.clientY-r.top;
    const f = e.deltaY<0 ? 1.15 : 0.87;
    const nk = Math.max(0.5, Math.min(30, view.k*f));
    // zoom toward the cursor
    view.x = px - (px-view.x)*(nk/view.k);
    view.y = py - (py-view.y)*(nk/view.k);
    view.k = nk;
  }, {passive:false});

  return { update:setData };
})();

// ---- nodes table (module: exposes refresh() while preserving filter/sort state) ----
const table = (function(){
  const tbody = document.querySelector("#nodes-table tbody");
  const search = document.getElementById("search");
  const fImpl = document.getElementById("filter-impl");
  const fBip = document.getElementById("filter-bip");
  let sortKey="depth", sortDir=1;
  const pillClass = s => s==="enforcing"?"enf":s==="not_enforcing"?"not":"unk";
  const pillText = s => s==="enforcing"?"Ready":s==="not_enforcing"?"Not ready":"Unknown";

  // Add any newly-seen implementations to the filter without clobbering the selection.
  function syncOptions(){
    const have = new Set([...fImpl.options].map(o=>o.value));
    Object.keys(DATA.aggregates.by_implementation).forEach(i=>{
      if (!have.has(i)){ const o=document.createElement("option"); o.value=i; o.textContent=i; fImpl.appendChild(o); }
    });
  }

  function render(){
    const q=search.value.toLowerCase(), fi=fImpl.value, fb=fBip.value;
    let rows = DATA.nodes.filter(n=>{
      if (fi && n.implementation!==fi) return false;
      if (fb && n.bip110!==fb) return false;
      // Search over the visible, non-IP attributes (location, client, version, UA).
      if (q && !(`${nodeLocation(n)} ${n.implementation} ${n.version} ${n.user_agent}`.toLowerCase().includes(q))) return false;
      return true;
    });
    rows.sort((a,b)=>{
      let x = sortKey==="location" ? nodeLocation(a) : a[sortKey];
      let y = sortKey==="location" ? nodeLocation(b) : b[sortKey];
      if (typeof x==="string") return x.localeCompare(y)*sortDir;
      return (x-y)*sortDir;
    });
    tbody.innerHTML = rows.map(n=>`
      <tr>
        <td>${esc(nodeLocation(n))}${n.addr.includes('.onion') ? ' <span class="pill unk">Tor</span>' : ''}</td>
        <td><span class="swatch" style="background:${implColor(n.implementation)}"></span>${esc(n.implementation)}</td>
        <td>${esc(n.version||"—")}</td>
        <td>${n.protocol_version||"—"}</td>
        <td>${n.depth}</td>
        <td><span class="pill ${pillClass(n.bip110)}">${pillText(n.bip110)}</span></td>
      </tr>`).join("");
  }
  document.querySelectorAll("#nodes-table th").forEach(th=>{
    th.addEventListener("click", ()=>{
      const k=th.dataset.k; if (sortKey===k) sortDir*=-1; else {sortKey=k; sortDir=1;} render();
    });
  });
  [search,fImpl,fBip].forEach(el=>el.addEventListener("input", render));
  return { refresh(){ syncOptions(); render(); } };
})();

document.getElementById("disclaimer").textContent =
  "Note: peer edges come from getaddr address gossip (reachability), not confirmed live "
  + "connections. Per-node BIP-110 readiness is detected from the node's advertised user agent "
  + "(builds carrying a BIP-110/UASF-BIP110 tag); the authoritative activation signal is the "
  + "miner block-version signalling shown above.";

// ---- assemble everything, then live-poll data.json when running under --watch ----
function renderAll(){
  renderCards();
  renderSignalling();
  renderCharts();
  graph.update(DATA);
  geoMap.update(DATA);
  table.refresh();
}
renderAll();

// Data source: in `serve` mode API_URL is set and we fetch/poll the API; otherwise we
// use the inlined DATA and (in --watch mode) poll data.json.
const API_URL = /*__API_URL__*/null;
async function pollOnce(url){
  try {
    const resp = await fetch(url + (url.includes("?")?"&":"?") + "_=" + Date.now(), {cache:"no-store"});
    if (!resp.ok) return;
    const fresh = await resp.json();
    if (fresh && fresh.generated_at !== DATA.generated_at){ DATA = fresh; renderAll(); }
  } catch(e){ /* offline / file:// — keep last data */ }
}
if (API_URL){
  pollOnce(API_URL);                                   // initial load from the API
  setInterval(()=>pollOnce(API_URL), (DATA.refresh_seconds||10) * 1000);
} else if (DATA.live && DATA.refresh_seconds > 0){
  setInterval(()=>pollOnce("data.json"), DATA.refresh_seconds * 1000);
}
</script>
</body>
</html>
"####;

/// Standalone "Why support BIP-110?" page (served at `/why`). Self-contained: its own
/// copy of the cyberpunk theme variables + component styles so it renders identically
/// whether served or opened from a file. Live charts fetch `/api/report`.
const WHY_TEMPLATE: &str = r####"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Why support BIP-110?</title>

  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="Why support BIP-110?">
  <meta name="twitter:description" content="The case for the Reduced Data Temporary Softfork — keep Bitcoin lean, decentralised, and focused on money.">
  <meta name="twitter:image" content="https://bip110.xyz/summary_large_image.png">
  <meta property="og:type" content="article">
  <meta property="og:title" content="Why support BIP-110?">
  <meta property="og:description" content="The case for the Reduced Data Temporary Softfork — keep Bitcoin lean, decentralised, and focused on money.">
  <meta property="og:image" content="https://bip110.xyz/summary_large_image.png">
  <meta property="og:url" content="https://bip110.xyz/why">

<style>
  :root {
    --page:#06060f; --surface:#0c0e1e; --surface-2:#12152c;
    --ink:#eaf2ff; --ink-2:#98a2ce; --muted:#5c6591;
    --grid:#1a2044; --border:rgba(0,229,255,0.22);
    --good:#00ff9c; --warn:#ffcb2b; --neutral:#5c6591;
    --neon:#00e5ff; --neon2:#ff2d95; --glow:rgba(0,229,255,0.55);
    --c1:#3aa0ff; --c8:#ff8a3d; --c6:#ff5d73; --c9:#6b7398;
    --radius:12px;
    --mono:ui-monospace,"Cascadia Code","JetBrains Mono","Segoe UI Mono",Consolas,monospace;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--page); color:var(--ink);
    font-family:system-ui,-apple-system,"Segoe UI",sans-serif; line-height:1.6;
    position:relative; min-height:100vh; }
  body::before { content:""; position:fixed; inset:0; z-index:-2; pointer-events:none;
    background:
      linear-gradient(var(--grid) 1px, transparent 1px) 0 0/44px 44px,
      linear-gradient(90deg, var(--grid) 1px, transparent 1px) 0 0/44px 44px;
    opacity:.5;
    -webkit-mask-image: radial-gradient(ellipse at 50% 0%, #000 30%, transparent 85%);
            mask-image: radial-gradient(ellipse at 50% 0%, #000 30%, transparent 85%); }
  body::after { content:""; position:fixed; inset:0; z-index:-1; pointer-events:none;
    background: radial-gradient(1100px 620px at 50% -8%, var(--glow), transparent 70%); opacity:.28; }
  .wrap { max-width:1000px; margin:0 auto; padding:22px 20px 90px; }
  nav { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:26px; }
  nav a { color:var(--ink-2); text-decoration:none; font-family:var(--mono); font-size:12px;
    text-transform:uppercase; letter-spacing:.08em; border:1px solid var(--border);
    background:var(--surface); border-radius:8px; padding:8px 14px; transition:.15s; }
  nav a:hover { color:var(--neon); border-color:var(--neon); box-shadow:0 0 12px var(--glow); }
  nav .brand { border:none; background:none; color:var(--neon); letter-spacing:.14em; padding-left:0; }
  a { color:var(--neon); text-decoration:none; } a:hover { text-shadow:0 0 8px var(--glow); }
  .hero { text-align:center; padding:22px 0 8px; }
  .hero h1 { font-family:var(--mono); font-size:clamp(28px,5vw,46px); margin:0 0 14px; font-weight:800;
    text-transform:uppercase; letter-spacing:.08em; line-height:1.1;
    text-shadow:0 0 12px var(--glow), 0 0 30px var(--glow); }
  .hero h1 .accent { color:var(--neon); }
  .hero .lead { color:var(--ink-2); font-size:clamp(15px,2.2vw,19px); max-width:70ch; margin:0 auto; }
  .tag { display:inline-block; font-family:var(--mono); font-size:11px; text-transform:uppercase;
    letter-spacing:.16em; color:var(--neon2); border:1px solid color-mix(in srgb,var(--neon2) 45%, transparent);
    border-radius:999px; padding:5px 14px; margin-bottom:18px;
    box-shadow:0 0 14px color-mix(in srgb,var(--neon2) 30%, transparent); }
  section { margin-top:44px; }
  section > h2 { font-family:var(--mono); font-size:16px; margin:0 0 6px; text-transform:uppercase;
    letter-spacing:.1em; color:var(--neon); text-shadow:0 0 10px var(--glow); display:flex; align-items:center; gap:8px; }
  section > h2::before { content:"//"; color:var(--neon2); opacity:.8; }
  section .hint { color:var(--muted); font-size:13px; margin:0 0 18px; max-width:80ch; }
  .panel { background:linear-gradient(180deg, color-mix(in srgb, var(--surface) 92%, var(--neon)), var(--surface));
    border:1px solid var(--border); border-radius:var(--radius); padding:20px 22px; position:relative; }
  .grid { display:grid; gap:16px; }
  .arg-grid { grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); }
  .arg { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius);
    padding:20px; position:relative; transition:.18s; overflow:hidden; }
  .arg:hover { border-color:var(--neon); box-shadow:0 0 20px var(--glow); transform:translateY(-2px); }
  .arg::after { content:""; position:absolute; left:0; top:14px; bottom:14px; width:2px; border-radius:2px;
    background:var(--neon); box-shadow:0 0 8px var(--glow); }
  .arg .ico { font-size:24px; line-height:1; margin-bottom:10px; display:block; }
  .arg h3 { margin:0 0 8px; font-size:16px; color:var(--ink); font-family:var(--mono); letter-spacing:.02em; }
  .arg p { margin:0; color:var(--ink-2); font-size:14px; }
  .charts { grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); align-items:start; }
  .charts h3 { font-family:var(--mono); font-size:13px; color:var(--ink); margin:0 0 4px; text-transform:uppercase; letter-spacing:.06em; }
  .charts .sub { color:var(--muted); font-size:11.5px; font-family:var(--mono); margin:0 0 16px; }
  .bars { display:flex; flex-direction:column; gap:10px; }
  .bar-row { display:grid; grid-template-columns:130px 1fr 52px; align-items:center; gap:12px; }
  .bar-row .name { font-size:12.5px; color:var(--ink-2); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .bar-track { background:var(--surface-2); border-radius:5px; height:22px; overflow:hidden; border:1px solid var(--border); }
  .bar-fill { height:100%; border-radius:4px; filter:saturate(1.3) drop-shadow(0 0 6px currentColor); transition:width .6s ease; }
  .bar-row .num { font-size:12.5px; text-align:right; font-variant-numeric:tabular-nums; color:var(--ink); font-family:var(--mono); }
  .gauge-track { background:var(--surface-2); border-radius:6px; height:28px; position:relative; overflow:hidden; border:1px solid var(--border); margin-top:28px; }
  .gauge-fill { height:100%; border-radius:5px; background:var(--good); box-shadow:0 0 14px var(--good); transition:width .6s ease; }
  .gauge-threshold { position:absolute; top:-6px; bottom:-6px; width:2px; background:var(--warn); box-shadow:0 0 8px var(--warn); }
  .gauge-threshold::after { content:"55% lock-in"; position:absolute; top:-20px; left:6px; font-size:10px; color:var(--warn); white-space:nowrap; font-family:var(--mono); }
  .big { font-family:var(--mono); font-size:34px; font-weight:800; color:var(--ink); text-shadow:0 0 12px var(--glow); }
  .big small { font-size:15px; color:var(--ink-2); font-weight:500; text-shadow:none; }
  .flow { display:flex; flex-wrap:wrap; align-items:stretch; gap:0; margin-top:6px; }
  .flow .step { flex:1 1 150px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius);
    padding:16px; text-align:center; position:relative; }
  .flow .arrow { display:flex; align-items:center; color:var(--neon); font-size:22px; padding:0 6px; }
  .flow .step .n { font-family:var(--mono); font-size:11px; color:var(--neon2); letter-spacing:.1em; }
  .flow .step .t { font-size:13.5px; color:var(--ink); margin-top:6px; }
  .flow .step .d { font-size:11.5px; color:var(--muted); margin-top:4px; }
  ol.steps { counter-reset:s; list-style:none; padding:0; margin:0; display:flex; flex-direction:column; gap:14px; }
  ol.steps li { counter-increment:s; position:relative; padding-left:46px; color:var(--ink-2); font-size:14px; }
  ol.steps li::before { content:counter(s); position:absolute; left:0; top:-2px; width:30px; height:30px;
    display:flex; align-items:center; justify-content:center; font-family:var(--mono); font-weight:700;
    color:var(--page); background:var(--neon); border-radius:8px; box-shadow:0 0 12px var(--glow); }
  ol.steps li b { color:var(--ink); }
  code, pre { font-family:var(--mono); }
  pre { background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:12px 14px;
    overflow-x:auto; font-size:12.5px; color:var(--good); margin:12px 0 0; }
  code.inline { background:var(--surface-2); border:1px solid var(--border); border-radius:5px; padding:1px 6px; font-size:12.5px; color:var(--neon); }
  .callout { border-left:3px solid var(--warn); background:color-mix(in srgb,var(--warn) 8%, var(--surface));
    border-radius:8px; padding:14px 18px; color:var(--ink-2); font-size:13.5px; }
  .callout b { color:var(--warn); }
  .cta { text-align:center; margin-top:44px; }
  .cta a.btn { display:inline-block; font-family:var(--mono); text-transform:uppercase; letter-spacing:.1em;
    font-size:13px; color:var(--page); background:var(--neon); border-radius:10px; padding:14px 28px; font-weight:700;
    box-shadow:0 0 22px var(--glow); transition:.18s; }
  .cta a.btn:hover { transform:translateY(-2px); box-shadow:0 0 34px var(--glow); }
  footer { margin-top:52px; color:var(--muted); font-size:11.5px; font-family:var(--mono); text-align:center; }
  .muted { color:var(--muted); }
</style>
</head>
<body>
<div class="wrap">
  <nav>
    <span class="brand">▚ BIP-110</span>
    <a href="/">◂ Live network crawler</a>
  </nav>

  <div class="hero">
    <span class="tag">Reduced Data Temporary Softfork</span>
    <h1>Why support <span class="accent">BIP-110</span>?</h1>
    <p class="lead">BIP-110 is a temporary, miner-activated soft fork that tightens Bitcoin's limits
      on non-monetary data. The goal is simple: keep the blockchain lean enough that ordinary people
      can keep running full nodes — and keep Bitcoin's scarce block space working for money.</p>
  </div>

  <section>
    <h2>What it actually does</h2>
    <div class="panel">
      <p style="margin:0 0 12px; color:var(--ink-2); font-size:14.5px;">
        Bitcoin blocks are a shared, permanent, every-node-forever resource. Over time, techniques
        emerged to stuff arbitrary data — images, tokens, and other non-financial payloads — into that
        space. Every byte is downloaded, validated, and stored by every full node on Earth, essentially forever.
      </p>
      <p style="margin:0; color:var(--ink-2); font-size:14.5px;">
        BIP-110 restores tighter limits on that arbitrary-data usage. It activates like BIP-9:
        miners set <b>bit 4</b> in the block version, and once <b>1109 of any 2016 blocks (55%)</b>
        signal, the rules lock in. Because it is <b>temporary</b> and <b>soft</b>, it is low-risk and
        does not split the network — nodes that don't upgrade still follow the chain.
      </p>
    </div>
  </section>

  <section>
    <h2>The case for support</h2>
    <p class="hint">Six reasons node operators, miners, and businesses back BIP-110.</p>
    <div class="grid arg-grid">
      <div class="arg"><span class="ico">🌐</span><h3>Protect decentralisation</h3>
        <p>A leaner chain means cheaper disk, bandwidth, and sync time. The lower the cost of running a
          full node, the more people can — and node count is the backbone of Bitcoin's censorship resistance.</p></div>
      <div class="arg"><span class="ico">💸</span><h3>Bitcoin is money first</h3>
        <p>Block space is scarce and paid for by everyone. Reserving it for monetary transactions keeps
          fees predictable for real payments instead of bidding wars over arbitrary data storage.</p></div>
      <div class="arg"><span class="ico">🧹</span><h3>Curb spam &amp; bloat</h3>
        <p>Non-financial payloads inflate block and chain size without adding monetary utility. Tighter
          data limits slow that growth and keep the UTXO set and archive healthier.</p></div>
      <div class="arg"><span class="ico">↩️</span><h3>Low-risk &amp; temporary</h3>
        <p>It's a <em>soft</em> fork (backwards-compatible) and explicitly <em>temporary</em>. It can lapse
          or be revisited — no contentious hard fork, no forced chain split, no permanent commitment.</p></div>
      <div class="arg"><span class="ico">📊</span><h3>Activated by the market</h3>
        <p>Nothing is imposed. Activation requires 55% of recent blocks to signal — a genuine, measurable
          supermajority of hash power choosing the rule, not a top-down decree.</p></div>
      <div class="arg"><span class="ico">🗳️</span><h3>You decide</h3>
        <p>Support is opt-in: run software that enforces the limits and, if you mine, signal for it.
          This crawler exists so anyone can watch that choice play out across the network in real time.</p></div>
    </div>
  </section>

  <section>
    <h2>Where the network stands right now</h2>
    <p class="hint">Live figures from the crawler — real handshakes with reachable peers, updated continuously.
      <span id="live-note" class="muted"></span></p>
    <div id="live-charts" class="grid charts">
      <div class="panel">
        <h3>Miner signalling</h3>
        <p class="sub">Block-version bit 4 over the last 2016 blocks — the authoritative activation signal.</p>
        <div class="big" id="sig-pct">—</div>
        <div class="gauge-track"><div class="gauge-fill" id="sig-fill" style="width:0%"></div>
          <div class="gauge-threshold" id="sig-thr" style="left:55%"></div></div>
        <p class="sub" id="sig-note" style="margin-top:26px;"></p>
      </div>
      <div class="panel">
        <h3>Node readiness</h3>
        <p class="sub">Reachable nodes running BIP-110-ready software (detected from the user agent).</p>
        <div class="bars" id="chart-ready"></div>
      </div>
      <div class="panel">
        <h3>Client software</h3>
        <p class="sub">Implementation mix across the reachable network.</p>
        <div class="bars" id="chart-impl"></div>
      </div>
    </div>
  </section>

  <section>
    <h2>How activation works</h2>
    <p class="hint">BIP-110 uses the same battle-tested miner-signalling mechanism as past soft forks.</p>
    <div class="flow">
      <div class="step"><div class="n">STEP 1</div><div class="t">Software ships</div><div class="d">Nodes run a build that enforces the reduced-data rules.</div></div>
      <div class="arrow">→</div>
      <div class="step"><div class="n">STEP 2</div><div class="t">Miners signal</div><div class="d">Blocks set version bit 4 to show readiness.</div></div>
      <div class="arrow">→</div>
      <div class="step"><div class="n">STEP 3</div><div class="t">55% threshold</div><div class="d">1109 of any 2016 blocks signal → the rule locks in.</div></div>
      <div class="arrow">→</div>
      <div class="step"><div class="n">STEP 4</div><div class="t">Enforced</div><div class="d">The tighter data limits become consensus for signalling nodes.</div></div>
    </div>
  </section>

  <section>
    <h2>How to support it</h2>
    <div class="panel">
      <ol class="steps">
        <li><b>Run a BIP-110-ready node.</b> Use a Bitcoin Knots build that ships BIP-110 — a mainline build
          dated <code class="inline">Knots:20260508</code> or later, or any build tagged
          <code class="inline">+bip110</code> / <code class="inline">UASF-BIP110</code>.</li>
        <li><b>Tighten your data policy.</b> Add these to <code class="inline">bitcoin.conf</code> and restart:
          <pre>datacarrier=0
permitbaremultisig=0
rejectparasites=1
rejecttokens=1</pre></li>
        <li><b>Signal, if you mine.</b> Configure your template so blocks set version bit 4. Every signalling
          block moves the network toward the 55% threshold.</li>
        <li><b>Check yourself on the map.</b> Open the <a href="/">live crawler</a> — reachable nodes running a
          ready build show as <span style="color:var(--good)">BIP-110 ready</span>.</li>
      </ol>
    </div>
  </section>

  <section>
    <h2>An honest note</h2>
    <div class="callout">
      <b>This is a contested topic.</b> Reasonable people disagree about on-chain data limits — some argue
      fees alone should ration block space, or that filters are easy to bypass. BIP-110's temporary,
      opt-in, miner-signalled design is a deliberate response: it lets the market decide with minimal risk.
      Read the specification and judge for yourself before you signal.
    </div>
  </section>

  <div class="cta">
    <a class="btn" href="/">▚ Watch the live network →</a>
  </div>

  <footer>bip110.xyz · a live BIP-110 node crawler · figures on this page are measured from the crawl, diagrams are illustrative</footer>
</div>

<script>
  const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  function bars(elId, entries, colorFn){
    const max = Math.max(1, ...entries.map(e=>e[1]));
    const el = document.getElementById(elId); if (!el) return;
    el.innerHTML = entries.map(([name,val]) => `
      <div class="bar-row">
        <div class="name" title="${name}">${name}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${(val/max*100).toFixed(1)}%;background:${colorFn(name)}"></div></div>
        <div class="num">${val.toLocaleString()}</div>
      </div>`).join("");
  }
  async function loadLive(){
    let d;
    try {
      const r = await fetch("/api/report?max=1&_=" + Date.now(), {cache:"no-store"});
      if (!r.ok) throw 0;
      d = await r.json();
    } catch(e){
      // No server (e.g. opened as a file) — hide the live section rather than show blanks.
      const s = document.getElementById("live-charts");
      if (s) s.innerHTML = '<div class="panel muted">Live figures load when this page is served by the crawler. '
        + 'Open <a href="/">the live crawler</a> to see current numbers.</div>';
      return;
    }
    const a = d.aggregates || {};
    // Signalling gauge (authoritative activation figure).
    const sig = d.signalling;
    if (sig){
      const pct = Math.max(0, Math.min(100, sig.percent));
      document.getElementById("sig-pct").innerHTML = sig.percent.toFixed(1) + "<small>% of last " + sig.blocks_scanned + " blocks</small>";
      document.getElementById("sig-fill").style.width = pct + "%";
      document.getElementById("sig-thr").style.left = (sig.threshold_percent||55) + "%";
      const gap = (sig.threshold_percent||55) - sig.percent;
      document.getElementById("sig-note").textContent = gap > 0
        ? gap.toFixed(1) + " points below the 55% lock-in threshold."
        : "At or above the 55% lock-in threshold.";
    } else {
      document.getElementById("sig-pct").innerHTML = 'n/a <small>RPC not connected</small>';
      document.getElementById("sig-note").textContent = "Run the crawler with --rpc-* to measure block-version signalling.";
    }
    // Readiness (real, derived from user agents).
    const ready = (a.by_bip110 && a.by_bip110["BIP-110 ready"]) || 0;
    const notReady = (a.by_bip110 && a.by_bip110["Not ready"]) || 0;
    const unknown = (a.by_bip110 && a.by_bip110["Unknown"]) || 0;
    bars("chart-ready", [["Ready",ready],["Not ready",notReady],["Unknown",unknown]].filter(e=>e[1]>0),
      name => name==="Ready" ? cssVar("--good") : name==="Not ready" ? cssVar("--neutral") : cssVar("--muted"));
    // Implementation mix (top 6), Knots highlighted.
    const impl = Object.entries(a.by_implementation||{}).sort((x,y)=>y[1]-x[1]).slice(0,6);
    bars("chart-impl", impl, name =>
      name==="Bitcoin Knots" ? cssVar("--c8") : name==="Bitcoin Core" ? cssVar("--c1") : cssVar("--c6"));
    const total = a.total_nodes || 0;
    const note = document.getElementById("live-note");
    if (note && total) note.textContent = "· " + total.toLocaleString() + " reachable nodes · updated " + (d.generated_at||"").slice(11,19) + " UTC";
  }
  loadLive();
  setInterval(loadLive, 30000);
</script>
</body>
</html>
"####;
