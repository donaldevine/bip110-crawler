// Block explorer: recent blocks from /api/blocks, coloured by BIP-110 signalling.
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
// Loading placeholders are seeded in the HTML so the page never shows an empty shell while the
// first fetch is in flight. Renders replace their containers outright; this sweeps up any that
// survive (e.g. one sitting beside a <canvas>). On a first-load failure they switch to an error
// state instead of spinning forever — later failures are no-ops, leaving the last good data up.
const doneLoading = () => document.querySelectorAll(".loading").forEach(e => e.remove());
const failLoading = msg => document.querySelectorAll(".loading").forEach(e => {
  e.classList.add("err"); e.textContent = msg;
});
const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const fmt = n => Number(n || 0).toLocaleString();

// How many blocks the visual grid shows; the table below lists everything recorded.
const GRID_MAX = 24;
// Transaction "motes" suspended inside each translucent block. A block holds thousands of
// transactions — far too many to draw — so each mote stands for TX_PER_MOTE of them, capped
// so the grid stays light (24 blocks x MAX_MOTES elements, all 3D-composited). Real blocks
// run roughly 1,000-5,000 transactions; the divisor spreads that band across the range
// instead of pinning almost every block to the cap.
const TX_PER_MOTE = 140;
const MAX_MOTES = 40;

/// Motes for one block, suspended at varying depths inside the cube.
/// Positions are derived from the block height, so a given block always looks identical
/// across refreshes instead of reshuffling on every poll.
function txMotes(b){
  const n = Math.min(MAX_MOTES, Math.max(3, Math.round((b.tx_count || 0) / TX_PER_MOTE)));
  let seed = (b.height | 0) || 1;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  let out = "";
  for (let i = 0; i < n; i++){
    // Kept well inside the faces: the cube is a rotated prism, so a mote near a corner at
    // full depth would project past the drawn silhouette and read as a dot floating outside.
    const x = 18 + rnd() * 62;          // % across the face
    const y = 20 + rnd() * 56;
    const z = Math.round(rnd() * 56 - 28);  // px through the box depth
    out += `<i class="tx" style="left:${x.toFixed(1)}%;top:${y.toFixed(1)}%;transform:translateZ(${z}px)"></i>`;
  }
  return out;
}

let BLOCKS = [];
// The current retarget period and its recorded signalling blocks, from /api/blocks.
let PERIOD = { start: 0, tip: 0, length: 2016, signalling: [] };
// Highest height we've already drawn, so a refresh can tell genuinely-new blocks from a
// re-render. null on first load: the initial paint must NOT animate every tile.
let lastSeenHeight = null;

const shortAge = ts => {
  const s = Math.max(0, Math.floor(Date.now()/1000) - ts);
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s/60) + "m ago";
  if (s < 86400) return Math.floor(s/3600) + "h ago";
  return Math.floor(s/86400) + "d ago";
};
const humanSize = b => b >= 1048576 ? (b/1048576).toFixed(2) + " MB"
                    : b >= 1024 ? (b/1024).toFixed(0) + " kB" : b + " B";
// Rough wall-clock estimate for a number of unmined blocks at ~10 min/block.
const etaText = blocks => {
  const mins = blocks * 10;
  if (mins >= 1440 * 1.5) return `~${Math.round(mins/1440)} days`;
  if (mins >= 90) return `~${Math.round(mins/60)} hours`;
  return `~${mins} min`;
};
// Weight units -> percentage of a block's 4,000,000 WU budget.
const pctWeight = w => (w / 4_000_000 * 100);
// Satoshis -> BTC string. Fees are small, so 4dp reads better than full precision.
const btc = sats => (sats / 1e8).toFixed(4);
const satsShort = sats => sats >= 1e8 ? btc(sats) + " BTC"
                        : sats >= 1e5 ? (sats/1e3).toFixed(0) + "k sats" : fmt(sats) + " sats";

/// One-line summary of a block's data payloads, e.g. "12 insc · 3 runes".
function payloadSummary(p){
  if (!p) return null;
  const parts = [];
  if (p.insc_count) parts.push(`${fmt(p.insc_count)} insc`);
  if (p.rune_count) parts.push(`${fmt(p.rune_count)} runes`);
  if (p.data_count) parts.push(`${fmt(p.data_count)} OP_RETURN`);
  return parts.length ? parts.join(" · ") : "no data payloads";
}

function renderCards(){
  const n = BLOCKS.length;
  const tip = PERIOD.tip || (n ? BLOCKS[0].height : 0);

  // Every figure on this page is scoped to the CURRENT DIFFICULTY PERIOD — the same window
  // BIP-110 signalling is tallied over — not to the block window the page happens to load.
  // `scanned`/`signalled` come from the node's full header scan; `ps` aggregates payload and
  // fee data across every analysed block in the period (server-side, so it isn't capped by
  // the loaded window). Older `serve` builds don't send these, so each has a local fallback.
  const ps = PERIOD.stats || {};
  const periodBlocks = PERIOD.scanned;            // blocks so far this period
  const periodSignalled = PERIOD.signalled;       // of those, how many set bit 4
  const havePeriod = (periodBlocks != null && periodSignalled != null);
  const sigPct = havePeriod && periodBlocks
    ? (periodSignalled / periodBlocks * 100)
    : (n ? BLOCKS.filter(b => b.signals).length / n * 100 : 0);

  // Payload/fee aggregates over the period's analysed blocks (falling back to the loaded
  // window if the server didn't supply them).
  const havePs = ps.analysed != null;
  const winScanned = BLOCKS.filter(b => b.payload);
  const winSum = k => winScanned.reduce((a,b) => a + (b.payload[k] || 0), 0);
  const analysed  = havePs ? (ps.analysed || 0) : winScanned.length;
  const insc      = havePs ? (ps.insc_count || 0) : winSum("insc_count");
  const runes     = havePs ? (ps.rune_count || 0) : winSum("rune_count");
  const payloadW  = havePs ? (ps.payload_weight || 0) : winSum("payload_weight");
  const rejectW   = havePs ? (ps.reject_weight || 0) : winSum("bip110_reject_weight");
  const budget = analysed * 4_000_000;   // 4M weight units per block
  const payloadPct = budget ? (payloadW / budget * 100) : 0;
  const rejectPct  = budget ? (rejectW  / budget * 100) : 0;

  const winStats = BLOCKS.filter(b => b.stats);
  const nStats = havePs ? (ps.with_stats || 0) : winStats.length;
  const totalFees = havePs ? (ps.total_fee || 0)
                           : winStats.reduce((a,b) => a + (b.stats.total_fee || 0), 0);
  const avgFees = nStats ? totalFees / nStats : 0;
  const medRate = havePs ? (ps.median_feerate || 0)
    : (winStats.length
        ? winStats.map(b => b.stats.median_feerate).sort((a,b)=>a-b)[Math.floor(winStats.length/2)]
        : 0);

  // Current run of non-signalling blocks at the tip. The loaded window gives an exact answer
  // whenever it contains a signalling block; when it doesn't (signalling is sparse, so a run
  // can exceed the window) fall back to the newest signalling height in the period, which is
  // the only way to report a run longer than the blocks on the page.
  let streak = 0;
  for (const b of BLOCKS){ if (b.signals) break; streak++; }
  let streakCapped = (n > 0 && streak >= n);
  const newestSig = (PERIOD.signalling && PERIOD.signalling.length) ? PERIOD.signalling[0].height : null;
  if (streakCapped && newestSig != null && tip){
    streak = tip - newestSig;
    streakCapped = false;
  }

  // Each card carries an explanation shown in a popup, including the sample it is measured
  // over — the counts differ per card (fee stats and payload scans arrive separately), and
  // "over how many blocks?" is the first thing anyone asks of a percentage.
  const cards = [
    ["Chain tip", fmt(tip), n ? shortAge(BLOCKS[0].time) : "—",
      `The highest block this node has, and how long ago it arrived. Read straight from the
       node over RPC — not from peer gossip.
       ${havePeriod ? `The current difficulty period is <b>${fmt(periodBlocks)}</b> blocks in,
       of 2,016.` : ""}`],

    ["Signalling", sigPct.toFixed(1) + "%",
      havePeriod ? `${fmt(periodSignalled)} of ${fmt(periodBlocks)} blocks this period`
                 : `${fmt(BLOCKS.filter(b => b.signals).length)} of the last ${fmt(n)} blocks`,
      `Share of blocks in the <b>current difficulty period</b> whose version field sets bit 4 —
       the authoritative activation figure, counted from a full scan of every block header in
       the period on this node
       ${havePeriod ? `(<b>${fmt(periodSignalled)}</b> of <b>${fmt(periodBlocks)}</b> so far).` : "."}
       <br><br>Lock-in needs <b>55%</b> (1,109 of the 2,016 blocks in a period). This is the
       same figure as the dashboard countdown — not a rolling average of recent blocks.`],

    ["Current run", fmt(streak) + (streakCapped ? "+" : ""),
      streak ? "non-signalling blocks at the tip" : "tip is signalling",
      `How many blocks in a row at the tip did <b>not</b> signal bit 4. Resets to zero the
       moment a signalling block is mined.
       ${streakCapped ? `<br><br>Shown as a minimum (“+”): no signalling block appears in the
       blocks loaded here or in the period detail yet, so the true run is at least this long.` : ""}`],

    ["Avg fees / block", nStats ? btc(avgFees) : "—",
      nStats ? `BTC · ${fmt(medRate)} sat/vB median rate` : "stats pending",
      `Mean total fees paid to the miner per block, across the <b>${fmt(nStats)}</b> block(s) of
       this difficulty period that have fee data. Figures come from the node's own
       <code>getblockstats</code>, so they are exact rather than estimated. The median rate is
       the middle fee rate paid across those blocks.`],

    ["Blocks touched by data", analysed ? payloadPct.toFixed(1) + "%" : "—",
      analysed ? `${fmt(insc)} inscriptions · ${fmt(runes)} runes · ${fmt(analysed)} blocks` : "scan pending",
      `Share of the 4,000,000 weight-unit block budget occupied by transactions that carry a
       data payload — inscriptions, runestones or <code>OP_RETURN</code> — measured across the
       <b>${fmt(analysed)}</b> block(s) of this difficulty period that have been analysed
       ${havePeriod ? `(of <b>${fmt(periodBlocks)}</b> in the period so far; the rest are still
       being scanned).` : "so far."}
       <br><br>It counts <b>whole-transaction weight</b>, not data bytes: such a transaction
       usually moves real value too, and all of that weight is included. So it is an
       <b>upper bound</b> on space spent on data. It also misses schemes it can't fingerprint
       (bare-multisig stamps and the like). Read it as “block space touched by data”, not
       “this much of the chain is arbitrary data”.`],

    ["BIP-110 would reject", analysed ? rejectPct.toFixed(1) + "%" : "—",
      analysed ? `of weight across ${fmt(analysed)} analysed blocks this period` : "scan pending",
      `Share of block weight in transactions BIP-110 would actually have made <b>invalid</b>,
       across the <b>${fmt(analysed)}</b> analysed block(s) of this difficulty period:
       inscriptions (rule 7 bans <code>OP_IF</code> in tapscript), witness items over 256 bytes
       (rule 2), outputs over their size limit (rule 1) and Taproot annexes (rule 4).
       <br><br>Always smaller than “blocks touched by data”, because a small runestone or
       <code>OP_RETURN</code> stays perfectly valid under BIP-110. Rules 3, 5 and 6 can't be
       detected from block data, so this is a lower bound.`],
  ];
  // `info` is authored here (no external input), so it is inserted as markup; label/value/note
  // still go through esc().
  document.getElementById("cards").innerHTML = cards.map(([l,v,note,info]) =>
    `<div class="card" data-label="${esc(l)}">
       <div class="label">${esc(l)}<button class="card-info" type="button"
         aria-label="What ${esc(l)} means">i</button><span class="card-pop">${info}</span></div>
     <div class="value">${esc(v)}</div>
     <div class="note">${esc(note)}</div></div>`).join("");
  // A poll rebuilds these nodes every 30s; re-apply any pinned popup so it doesn't vanish
  // mid-read.
  if (openCard){
    const el = [...document.querySelectorAll("#cards .card")].find(c => c.dataset.label === openCard);
    if (el) el.classList.add("open");
  }
}

// Which card's popup is pinned open (hover handles the rest via CSS). Tracked so the periodic
// re-render can restore it.
let openCard = null;
// Click pins a popup open — touch devices have no hover. Clicking anywhere else closes it.
document.addEventListener("click", e => {
  const btn = e.target.closest ? e.target.closest(".card-info") : null;
  const card = btn ? btn.closest(".card") : null;
  document.querySelectorAll("#cards .card.open").forEach(c => { if (c !== card) c.classList.remove("open"); });
  if (card){
    const nowOpen = !card.classList.contains("open");
    card.classList.toggle("open", nowOpen);
    openCard = nowOpen ? card.dataset.label : null;
  } else {
    openCard = null;
  }
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape"){
    openCard = null;
    document.querySelectorAll("#cards .card.open").forEach(c => c.classList.remove("open"));
  }
});

function renderGrid(){
  const grid = document.getElementById("blockgrid");
  const tip = document.getElementById("btip");
  const shown = BLOCKS.slice(0, GRID_MAX);
  if (!shown.length){
    grid.innerHTML = `<div class="note">No blocks recorded yet — the crawler stores them as new blocks arrive.</div>`;
    return;
  }
  // Animate only blocks that are genuinely new since the last render. On first load
  // lastSeenHeight is null, so nothing animates — otherwise every tile would fly in on
  // arrival, which reads as noise rather than "a block just landed".
  const isNew = b => lastSeenHeight !== null && b.height > lastSeenHeight;
  // Three faces make the visible solid (back/left/bottom are never seen, so they're not
  // rendered). The flat view simply hides top and side.
  grid.innerHTML = shown.map(b => `
    <div class="blk ${b.signals ? 'good' : 'toxic'}${isNew(b) ? ' arriving' : ''}" data-h="${b.height}">
      <div class="cube">
        <div class="txs">${txMotes(b)}</div>
        <div class="face top"></div>
        <div class="face side"></div>
        <div class="face front">
          <div class="blk-h">${fmt(b.height)}</div>
          <div class="blk-tx">${fmt(b.tx_count)} txs</div>
          <div class="blk-age">${esc(shortAge(b.time))}</div>
          <div class="blk-mark">${b.signals ? '✓' : '☣'}</div>
        </div>
      </div>
    </div>`).join("");
  lastSeenHeight = shown[0].height;

  grid.querySelectorAll(".blk").forEach(el => {
    el.addEventListener("mousemove", e => {
      const b = BLOCKS.find(x => String(x.height) === el.dataset.h);
      if (!b) return;
      const r = grid.getBoundingClientRect();
      const p = b.payload;
      let payloadLines = "";
      if (p) {
        payloadLines =
            `<hr class="tiphr">`
          + (p.insc_count ? `inscriptions: ${fmt(p.insc_count)} · ${esc(humanSize(p.insc_bytes))}<br>` : "")
          + (p.rune_count ? `runes: ${fmt(p.rune_count)}<br>` : "")
          + (p.data_count ? `OP_RETURN: ${fmt(p.data_count)} · ${esc(humanSize(p.data_bytes))}<br>` : "")
          + (p.payload_tx_count
              ? `<b>${pctWeight(p.payload_weight).toFixed(1)}%</b> of block weight carries data<br>`
              : `no data payloads<br>`)
          + (p.bip110_reject_count
              ? `<span class="tox">BIP-110 would reject ${fmt(p.bip110_reject_count)} tx `
                + `(${pctWeight(p.bip110_reject_weight).toFixed(1)}% weight)</span>`
              : `<span class="okc">nothing BIP-110 would reject</span>`);
      } else {
        payloadLines = `<hr class="tiphr"><span class="dim">payload scan pending…</span>`;
      }
      const s = b.stats;
      const feeLines = s
        ? `<hr class="tiphr">`
          + `fees: <b>${esc(btc(s.total_fee))} BTC</b><br>`
          + `reward: ${esc(btc(s.total_fee + s.subsidy))} BTC (subsidy ${esc(btc(s.subsidy))})<br>`
          + `rate: ${fmt(s.median_feerate)} sat/vB median · ${fmt(s.min_feerate)}–${fmt(s.max_feerate)} range`
        : "";
      tip.innerHTML = `<b>Block ${fmt(b.height)}</b><br>`
        + `${b.signals ? '✓ signalling BIP-110' : '☣ not signalling'}<br>`
        + `${fmt(b.tx_count)} txs · ${esc(humanSize(b.size))}<br>`
        + `version 0x${(b.version >>> 0).toString(16)}<br>`
        + (b.miner ? `miner: ${esc(b.miner)}<br>` : "")
        + `${esc(shortAge(b.time))}`
        + feeLines
        + payloadLines;
      tip.style.left = Math.min(e.clientX - r.left + 14, r.width - 220) + "px";
      tip.style.top = (e.clientY - r.top + 14) + "px";
      tip.style.opacity = 1;
    });
    el.addEventListener("mouseleave", () => { tip.style.opacity = 0; });
  });

  document.getElementById("blocklegend").innerHTML =
    `<span class="item"><span class="dot" style="background:${cssVar('--good')}"></span>Signalling BIP-110</span>`
    + `<span class="item"><span class="dot" style="background:${cssVar('--c6')}"></span>Not signalling</span>`;
}

function renderTable(){
  const tbody = document.querySelector("#blocks-table tbody");
  tbody.innerHTML = BLOCKS.map(b => {
    const p = b.payload;
    const payloadCell = p
      ? `<span title="whole-transaction weight carrying a data payload">${esc(payloadSummary(p))}</span>`
      : `<span class="dim">pending…</span>`;
    const weightCell = p
      ? `<span class="${p.payload_weight ? 'warn-text' : ''}">${pctWeight(p.payload_weight).toFixed(1)}%</span>`
      : `<span class="dim">—</span>`;
    const rejectCell = p
      ? (p.bip110_reject_count
          ? `<span class="bad-text">${fmt(p.bip110_reject_count)} · ${pctWeight(p.bip110_reject_weight).toFixed(1)}%</span>`
          : `<span class="ok-text">none</span>`)
      : `<span class="dim">—</span>`;
    const s = b.stats;
    const feeCell  = s ? `<span title="${esc(satsShort(s.total_fee))}">${esc(btc(s.total_fee))}</span>` : `<span class="dim">—</span>`;
    const rateCell = s ? `${fmt(s.median_feerate)}` : `<span class="dim">—</span>`;
    return `
    <tr>
      <td class="mono">${fmt(b.height)}</td>
      <td><span class="pill ${b.signals ? 'enf' : 'not'}">${b.signals ? '✓ Signalling' : '☣ Not signalling'}</span></td>
      <td>${esc(b.miner || "—")}</td>
      <td class="mono">${fmt(b.tx_count)}</td>
      <td>${payloadCell}</td>
      <td class="mono">${weightCell}</td>
      <td class="mono">${rejectCell}</td>
      <td class="mono">${feeCell}</td>
      <td class="mono">${rateCell}</td>
      <td class="mono">${esc(humanSize(b.size))}</td>
      <td>${esc(shortAge(b.time))}</td>
    </tr>`;
  }).join("");
}

// The current period's signalling blocks, in a detail table of their own. All of these
// signal by definition, so there's no signalling column — instead the version field is shown
// so the bit-4 vote is visible directly.
function renderPeriod(){
  const tbody = document.querySelector("#period-table tbody");
  const hint = document.getElementById("period-hint");
  const list = PERIOD.signalling || [];
  const range = PERIOD.tip
    ? `blocks ${fmt(PERIOD.start)}–${fmt(PERIOD.tip)}`
    : "the current period";

  // Blocks remaining until the next difficulty retarget — for the current period that boundary
  // is the scheduled BIP-110 lock-in height. Shown regardless of how many blocks signalled.
  const LOCKIN_HEIGHT = 963648;
  const boundary = (PERIOD.start || 0) + (PERIOD.length || 2016);
  // Prefer the authoritative scan tip (start + scanned − 1), so this matches the dashboard
  // countdown exactly; fall back to the stored-blocks tip when no scan figure is present.
  const tipH = (PERIOD.scanned != null && PERIOD.start)
    ? PERIOD.start + PERIOD.scanned - 1
    : PERIOD.tip;
  const left = (tipH && PERIOD.start) ? boundary - tipH : 0;
  const leftEl = document.getElementById("period-left");
  if (leftEl){
    if (left > 0){
      leftEl.style.display = "";
      leftEl.innerHTML = `<b>${fmt(left)}</b> block${left === 1 ? "" : "s"} (${etaText(left)}) left `
        + `in this difficulty period — next retarget at height <b>${fmt(boundary)}</b>`
        + (boundary === LOCKIN_HEIGHT ? `, the scheduled <b>BIP-110 lock-in</b> boundary.` : `.`);
    } else {
      leftEl.style.display = "none";
    }
  }

  // The headline count is the authoritative full-header scan (same figure as the dashboard);
  // the detailed table below is whatever the crawler has fetched full detail for so far. The
  // two differ while the per-block backfill is still catching up — show both so it reconciles.
  const scanned = PERIOD.scanned;
  const total = (PERIOD.signalled != null) ? PERIOD.signalled : list.length;
  const heights = PERIOD.tip ? `${fmt(PERIOD.start)}–${fmt(PERIOD.tip)}` : null;

  if (total === 0){
    hint.innerHTML = `No block in <b>${range}</b> has signalled BIP-110 (version bit 4). `
      + `Every header in the current 2016-block difficulty period is scanned on the node, `
      + `so this is the full count for the period — not a sample.`;
    tbody.innerHTML = `<tr><td colspan="9" class="dim" style="text-align:center;padding:18px;">`
      + `no signalling blocks this period</td></tr>`;
    return;
  }

  const catching = list.length < total;
  const lead = (scanned != null)
    ? `<b>${fmt(total)}</b> of the <b>${fmt(scanned)}</b> blocks so far this period`
    : `<b>${fmt(total)}</b> block${total === 1 ? "" : "s"} this period`;
  hint.innerHTML = `${lead}${heights ? ` (heights ${heights})` : ""} set version bit 4, voting `
    + `for BIP-110 lock-in — counted from a full scan of every block header on the node, tallied `
    + `per 2016-block period and evaluated at the retarget boundary. `
    + (catching
        ? `Detail below for the <b>${fmt(list.length)}</b> fetched so far; the rest fill in as the `
          + `crawler works through the period.`
        : `Full detail for each is below.`);

  if (!list.length){
    tbody.innerHTML = `<tr><td colspan="9" class="dim" style="text-align:center;padding:18px;">`
      + `fetching block detail…</td></tr>`;
    return;
  }

  tbody.innerHTML = list.map(b => {
    const p = b.payload;
    const payloadCell = p
      ? `<span title="whole-transaction weight carrying a data payload">${esc(payloadSummary(p))}</span>`
      : `<span class="dim">pending…</span>`;
    const weightCell = p
      ? `<span class="${p.payload_weight ? 'warn-text' : ''}">${pctWeight(p.payload_weight).toFixed(1)}%</span>`
      : `<span class="dim">—</span>`;
    const s = b.stats;
    const feeCell = s ? `<span title="${esc(satsShort(s.total_fee))}">${esc(btc(s.total_fee))}</span>` : `<span class="dim">—</span>`;
    return `
    <tr>
      <td class="mono">${fmt(b.height)}</td>
      <td>${esc(b.miner || "—")}</td>
      <td class="mono">${fmt(b.tx_count)}</td>
      <td class="mono" title="bit 4 set">0x${(b.version >>> 0).toString(16)}</td>
      <td>${payloadCell}</td>
      <td class="mono">${weightCell}</td>
      <td class="mono">${feeCell}</td>
      <td class="mono">${esc(humanSize(b.size))}</td>
      <td>${esc(shortAge(b.time))}</td>
    </tr>`;
  }).join("");
}

document.getElementById("disclaimer").textContent =
  "Note: 'signalling' means the block's version field sets bit 4, which is how miners vote "
  + "for BIP-110 — it says nothing about the transactions inside, which are valid either way. "
  + "Payload detection is a heuristic based on protocol byte signatures: it identifies "
  + "inscriptions, runestones and OP_RETURN carriers reliably, but 'carries data' is not the "
  + "same as 'non-monetary' — such transactions typically move value too, and other data "
  + "schemes (bare-multisig stamps, and the like) are not counted here. Weight percentages "
  + "are whole-transaction weight, so they overstate the bytes actually spent on data. "
  + "Blocks are recorded and scanned as they arrive, so this history starts when the crawler "
  + "does. Fee figures come from the node's own getblockstats, so they are exact, not "
  + "estimated; 'reward' is subsidy plus fees. Lock-in needs 55% (1109) of the 2016 blocks "
  + "in a difficulty period; see the countdown on the main page.";

// Toast announcing a newly-mined block, so an arrival is visible even when scrolled away
// from the grid. Colour-coded the same as the tiles.
let toastTimer = null;
function announce(block){
  const el = document.getElementById("newblock");
  if (!el) return;
  el.className = "newblock show " + (block.signals ? "good" : "toxic");
  el.innerHTML = `<span class="nb-mark">${block.signals ? '✓' : '☣'}</span>`
    + `<span><b>Block ${fmt(block.height)}</b> — `
    + `${block.signals ? 'signalling BIP-110' : 'not signalling'}`
    + `${block.miner ? ' · ' + esc(block.miner) : ''}</span>`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = "newblock"; }, 9000);
}

async function load(){
  const prevHeight = BLOCKS.length ? BLOCKS[0].height : null;
  try {
    const r = await fetch("/api/blocks?limit=200&_=" + Date.now(), {cache:"no-store"});
    if (!r.ok){ failLoading("Couldn't load block data — retrying…"); return; }
    const d = await r.json();
    BLOCKS = d.blocks || [];
    if (d.period) PERIOD = d.period;
  } catch(e){        // offline / file:// — leave any already-rendered data as-is
    failLoading("Couldn't load block data — retrying…");
    return;
  }
  renderCards();
  renderGrid();          // reads lastSeenHeight, so call before it's updated below
  renderPeriod();
  renderTable();
  doneLoading();
  // Announce only a real new tip (not the first paint, and not a re-render).
  if (prevHeight !== null && BLOCKS.length && BLOCKS[0].height > prevHeight) {
    announce(BLOCKS[0]);
  }
  document.getElementById("gen").textContent =
    "updated " + new Date().toISOString().slice(11,19) + " UTC";
}
load();
setInterval(load, 30000);

// Ages are relative ("3m ago"), so tick them between polls or they look frozen.
setInterval(() => {
  if (!BLOCKS.length) return;
  document.querySelectorAll(".blk").forEach(el => {
    const b = BLOCKS.find(x => String(x.height) === el.dataset.h);
    const age = el.querySelector(".blk-age");
    if (b && age) age.textContent = shortAge(b.time);
  });
}, 15000);
