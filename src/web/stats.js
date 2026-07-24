// Crawl stats page: everything is fetched live from /api/stats (no inlined data).
// Loading placeholders seeded in the HTML: swept once real data has rendered, or switched to an
// error state if the first fetch never lands (so they don't spin forever). Later failures are
// no-ops, leaving the last good data on screen.
const doneLoading = () => document.querySelectorAll(".loading").forEach(e => e.remove());
const failLoading = msg => document.querySelectorAll(".loading").forEach(e => {
  e.classList.add("err"); e.textContent = msg;
});
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const fmt = n => Number(n || 0).toLocaleString();

// Version lines are coloured by their IMPLEMENTATION family, matching the colour language
// used everywhere else on the site (Knots orange, Core blue, Other red) — colouring by rank
// instead would hand Knots blue and Core orange, which reads as flatly wrong. Versions
// inside a family are separated by progressively lighter shades of the family colour, and
// identity is never colour-alone: the legend and tooltip always name the line.
const SLOT_OF = {
  "Bitcoin Core":"--c1", "Bitcoin Knots":"--c8", "btcd":"--c3", "bcoin":"--c4",
  "libbitcoin":"--c5", "Bitcoin ABC":"--c2", "Bitcoin Unlimited":"--c7", "Other":"--c6",
};
const IMPL_ORDER = Object.keys(SLOT_OF);
const implOf = name => IMPL_ORDER.find(i => name.startsWith(i)) || "Other";

function hexToRgb(h){
  h = String(h).trim().replace("#","");
  if (h.length === 3) h = h.split("").map(c => c + c).join("");
  const n = parseInt(h, 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
/// Mix a colour toward white; used to separate versions within one family.
function lighten(hex, amt){
  const [r,g,b] = hexToRgb(hex);
  const m = v => Math.round(v + (255 - v) * amt);
  return `rgb(${m(r)},${m(g)},${m(b)})`;
}

// Top N versions by population. The long tail isn't lumped into an "other" line — that
// isn't a version, so it has no meaning on a per-version chart; the note reports how many
// versions exist instead.
const MAX_LINES = 10;

let STATS = null;

function renderCards(){
  const s = STATS;
  const pct = s.total_addresses ? (s.reachable / s.total_addresses * 100) : 0;
  const cards = [
    ["Reachable nodes", fmt(s.reachable), `confirmed within ${s.max_age_hours}h`],
    ["Tor nodes", fmt(s.onion), "reachable over onion"],
    ["Addresses known", fmt(s.total_addresses), "everything ever gossiped to us"],
    ["Actually reachable", pct.toFixed(1) + "%", "of the whole address book"],
    ["Edges recorded", fmt(s.edges), "gossip links between nodes"],
  ];
  document.getElementById("cards").innerHTML = cards.map(([l,v,n]) =>
    `<div class="card"><div class="label">${esc(l)}</div>
     <div class="value">${esc(v)}</div>
     <div class="note">${esc(n)}</div></div>`).join("");
}

function renderSplit(){
  const s = STATS;
  const total = s.total_addresses || 1;
  const reachPct = s.reachable / total * 100;
  document.getElementById("split").innerHTML =
    `<div class="reach" style="width:${reachPct}%"></div><div class="dead" style="width:${100-reachPct}%"></div>`;
  document.getElementById("split-legend").innerHTML = `
    <span class="item"><span class="dot" style="background:${cssVar('--good')}"></span>
      Reachable ${fmt(s.reachable)} (${reachPct.toFixed(1)}%)</span>
    <span class="item"><span class="dot" style="background:${cssVar('--surface-2')};border:1px solid ${cssVar('--border')}"></span>
      Never answered ${fmt(s.unreachable)} (${(100-reachPct).toFixed(1)}%)</span>`;
}

// ---- client-mix-over-time line chart ----
const historyChart = (function(){
  const canvas = document.getElementById("history");
  const tip = document.getElementById("htip");
  const ctx = canvas.getContext("2d");
  const DPR = window.devicePixelRatio || 1;
  const PAD = { l: 54, r: 14, t: 14, b: 28 };
  let series = [], colorOf = {}, points = [], W = 0, H = 0;
  let scale = null;   // {x(i), y(v)} published by draw() so hover can hit-test the lines

  function resize(){
    const r = canvas.getBoundingClientRect();
    W = r.width; H = r.height;
    if (!W || !H) return;
    canvas.width = W*DPR; canvas.height = H*DPR; ctx.setTransform(DPR,0,0,DPR,0,0);
  }
  window.addEventListener("resize", () => { resize(); draw(); });

  const versionsAt = p => (p && p.snapshot && p.snapshot.versions) || {};

  function setData(history){
    points = history || [];
    // Rank versions by total population across the series, chart the biggest MAX_LINES.
    const totals = {};
    for (const p of points){
      for (const [k,v] of Object.entries(versionsAt(p))) totals[k] = (totals[k]||0) + v;
    }
    const ranked = Object.keys(totals).sort((a,b)=>totals[b]-totals[a]);
    const top = ranked.slice(0, MAX_LINES);
    // Colour by family; shade successive versions of the same client lighter so they stay
    // tellable apart while still reading as "that's a Knots line" / "that's a Core line".
    // The spread is divided by how many of that family are actually plotted — a fixed
    // per-step increment would clamp and hand several versions the identical colour.
    colorOf = {};
    const famCount = {};
    top.forEach(n => { const f = implOf(n); famCount[f] = (famCount[f] || 0) + 1; });
    const seenInFamily = {};
    top.forEach(n => {
      const fam = implOf(n);
      const j = seenInFamily[fam] = (seenInFamily[fam] === undefined ? 0 : seenInFamily[fam] + 1);
      const base = cssVar(SLOT_OF[fam] || "--c9");
      const amt = famCount[fam] > 1 ? (j / (famCount[fam] - 1)) * 0.7 : 0;
      colorOf[n] = amt === 0 ? base : lighten(base, amt);
    });
    series = top.slice();
    document.getElementById("history-legend").innerHTML = series.map(n =>
      `<span class="item"><span class="dot" style="background:${colorOf[n]}"></span>${esc(n)}</span>`).join("");
    const note = document.getElementById("history-note");
    const distinct = (STATS && STATS.distinct_versions) || 0;
    note.textContent = points.length < 2
      ? "Collecting — the crawler records one point per hour, so the lines appear once there are at least two hours of data."
      : `${points.length} hourly points · showing the ${series.length} most common client versions`
        + (distinct > series.length ? ` of ${fmt(distinct)} running on the network` : "") + ".";
    resize(); draw();
  }

  function draw(){
    if (!W || !H) return;
    ctx.clearRect(0,0,W,H);
    if (points.length < 2 || !series.length) return;
    const maxY = Math.max(1, ...points.map(p => Math.max(...series.map(s => versionsAt(p)[s] || 0))));
    const x = i => PAD.l + i * (W - PAD.l - PAD.r) / Math.max(1, points.length - 1);
    const y = v => H - PAD.b - (v / maxY) * (H - PAD.t - PAD.b);
    scale = { x, y };

    // grid + y labels
    ctx.strokeStyle = cssVar("--grid"); ctx.fillStyle = cssVar("--muted");
    ctx.font = "10px ui-monospace, monospace"; ctx.textAlign = "right"; ctx.lineWidth = 1;
    for (let g = 0; g <= 4; g++){
      const v = maxY * g / 4, yy = y(v);
      ctx.beginPath(); ctx.moveTo(PAD.l, yy); ctx.lineTo(W - PAD.r, yy); ctx.stroke();
      ctx.fillText(Math.round(v).toLocaleString(), PAD.l - 8, yy + 3);
    }
    // x labels (first / middle / last)
    ctx.textAlign = "center";
    [0, Math.floor(points.length/2), points.length-1].forEach(i => {
      const h = points[i].hour.slice(5).replace("T"," ") + ":00";
      ctx.fillText(h, x(i), H - 8);
    });
    // one line per client version
    series.forEach(name => {
      const col = colorOf[name];
      ctx.strokeStyle = col; ctx.lineWidth = 2;
      ctx.shadowBlur = 8; ctx.shadowColor = col;
      ctx.beginPath();
      points.forEach((p, i) => {
        const v = versionsAt(p)[name] || 0;
        i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v));
      });
      ctx.stroke(); ctx.shadowBlur = 0;
    });
  }

  // Hover reports the ONE line nearest the cursor — the version, its count at that hour,
  // and the hour — rather than dumping every series at once.
  canvas.addEventListener("mousemove", e => {
    if (points.length < 2 || !scale || !series.length){ tip.style.opacity = 0; return; }
    const r = canvas.getBoundingClientRect();
    const px = e.clientX - r.left, py = e.clientY - r.top;
    const step = (W - PAD.l - PAD.r) / Math.max(1, points.length - 1);
    const i = Math.max(0, Math.min(points.length-1, Math.round((px - PAD.l) / step)));
    const p = points[i];

    let best = null, bd = Infinity;
    for (const n of series){
      const d = Math.abs(scale.y(versionsAt(p)[n] || 0) - py);
      if (d < bd){ bd = d; best = n; }
    }
    if (!best || bd > 26){ tip.style.opacity = 0; return; }   // not near any line

    tip.innerHTML = `<b style="color:${colorOf[best]}">${esc(best)}</b><br>`
      + `${fmt(versionsAt(p)[best] || 0)} nodes · ${esc(p.hour.replace("T"," "))}:00`;
    tip.style.left = Math.min(px + 14, Math.max(0, W - 250)) + "px";
    tip.style.top = Math.max(4, py - 40) + "px";
    tip.style.opacity = 1;
  });
  canvas.addEventListener("mouseleave", () => { tip.style.opacity = 0; });

  return { update: setData };
})();

document.getElementById("disclaimer").textContent =
  "Note: every figure here counts LISTENING (reachable) nodes — ones that accept inbound "
  + "connections. That's the only kind any crawl can measure: non-listening full nodes (behind "
  + "NAT or a firewall, or running listen=0) validate every consensus rule just the same, but "
  + "accept no connections and don't advertise an address, so there is nothing for a crawler to "
  + "find. They're real and they count for their owners — they're simply uncountable here. Totals "
  + "elsewhere that include them are extrapolations from inbound-connection sampling, which is why "
  + "node counts differ between sites. "
  + "'Addresses known' counts every address ever gossiped to this crawler, most of which never "
  + "answer. 'Reachable' means we completed a Bitcoin handshake within the freshness window; "
  + "peers that stop answering fall out of it rather than lingering forever.";

async function load(){
  try {
    const r = await fetch("/api/stats?_=" + Date.now(), {cache:"no-store"});
    if (!r.ok){ failLoading("Couldn't load crawl stats — retrying…"); return; }
    STATS = await r.json();
  } catch(e){        // offline / file:// — leave any already-rendered data as-is
    failLoading("Couldn't load crawl stats — retrying…");
    return;
  }
  renderCards();
  renderSplit();
  historyChart.update(STATS.history);
  doneLoading();
  document.getElementById("gen").textContent = "updated " + new Date().toISOString().slice(11,19) + " UTC";
}
load();
setInterval(load, 30000);
