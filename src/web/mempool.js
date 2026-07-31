// Mempool view: aggregate stats + fee-rate histogram from /api/mempool.
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const doneLoading = () => document.querySelectorAll(".loading").forEach(e => e.remove());
const failLoading = msg => document.querySelectorAll(".loading").forEach(e => {
  e.classList.add("err"); e.textContent = msg;
});
const fmt = n => Number(n || 0).toLocaleString();
const rate = n => Number(n || 0).toLocaleString(undefined, {maximumFractionDigits: 1});
const vmb = vsize => (vsize / 1_000_000).toFixed(2) + " vMB";

let MEMPOOL = null;

function renderCards(){
  const m = MEMPOOL;
  const el = document.getElementById("cards");
  if (!m){
    el.innerHTML = `<div class="note">No mempool snapshot yet — the crawler records one on
      each refresh once it has an RPC connection to your node.</div>`;
    return;
  }
  const blocksWorth = m.vsize / 1_000_000;
  const cards = [
    ["Pending transactions", fmt(m.pending), "sitting in this node's mempool"],
    ["Mempool size", vmb(m.vsize), `~${blocksWorth.toFixed(1)} block${blocksWorth === 1 ? "" : "s"} worth, unmined`],
    ["Fees waiting", Number(m.total_fee || 0).toFixed(4) + " BTC", "sum across all pending transactions"],
    ["Min relay feerate", rate(m.min_relay_feerate) + " sat/vB", "this node won't accept anything cheaper"],
    ["Next-block estimate", m.next_block_feerate != null ? rate(m.next_block_feerate) + " sat/vB" : "—",
      m.next_block_feerate != null
        ? "roughly what clears in the next block"
        : "mempool is smaller than one block — everything likely clears"],
  ];
  el.innerHTML = cards.map(([l,v,n]) =>
    `<div class="card"><div class="label">${esc(l)}</div>
     <div class="value" style="font-size:${String(v).length > 10 ? 22 : 30}px">${esc(String(v))}</div>
     <div class="note">${esc(n)}</div></div>`).join("");
}

// Label a histogram bucket: "<1", "5–6", or "1000+" for the open-ended top band.
function bucketLabel(b){
  if (b.max_feerate == null) return `${rate(b.min_feerate)}+`;
  if (b.min_feerate === 0) return `<${rate(b.max_feerate)}`;
  return `${rate(b.min_feerate)}–${rate(b.max_feerate)}`;
}

function renderHistogram(){
  const el = document.getElementById("chart-fees");
  const m = MEMPOOL;
  const hist = (m && m.histogram) || [];
  if (!hist.length){
    el.innerHTML = `<div class="note">No pending transactions to bucket.</div>`;
    return;
  }
  const max = Math.max(1, ...hist.map(b => b.vsize));
  el.innerHTML = hist.map(b => `
    <div class="bar-row" title="${fmt(b.count)} tx, ${vmb(b.vsize)}">
      <div class="name">${esc(bucketLabel(b))} sat/vB</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(b.vsize/max*100).toFixed(1)}%"></div></div>
      <div class="num">${vmb(b.vsize)}</div>
    </div>`).join("");
}

document.getElementById("disclaimer").textContent =
  "Note: this is a single node's mempool, not a network-wide view — policy differs node to "
  + "node (relay fee floors, replace-by-fee settings, unconfirmed-chain limits), so another "
  + "node's mempool can legitimately differ from this one. 'Fees waiting' and the histogram "
  + "come straight from getrawmempool's per-transaction fee/vsize fields, not an estimate. "
  + "The next-block figure assumes the next block is built purely by feerate (highest first) "
  + "with no reserved space — real miner templates are usually close to this, but not exact.";

async function load(){
  try {
    const r = await fetch("/api/mempool?_=" + Date.now(), {cache:"no-store"});
    if (!r.ok){ failLoading("Couldn't load mempool data — retrying…"); return; }
    const d = await r.json();
    MEMPOOL = d.mempool || null;
  } catch(e){
    failLoading("Couldn't load mempool data — retrying…");
    return;
  }
  renderCards();
  renderHistogram();
  doneLoading();
  document.getElementById("gen").textContent =
    "updated " + new Date().toISOString().slice(11,19) + " UTC";
}
load();
setInterval(load, 20000);
