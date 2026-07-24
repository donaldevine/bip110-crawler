// Chain view: which chain each crawled peer is actually on, from its `headers` reply.
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt = n => Number(n || 0).toLocaleString();
const doneLoading = () => document.querySelectorAll(".loading").forEach(e => e.remove());
const failLoading = msg => document.querySelectorAll(".loading").forEach(e => {
  e.classList.add("err"); e.textContent = msg;
});
// A 64-char hash is unreadable in a table; the ends are what people actually compare.
const shortHash = h => h && h.length > 20 ? h.slice(0, 10) + "…" + h.slice(-8) : (h || "—");

let DATA = { clusters: null, split: null };

function renderCards(){
  const c = DATA.clusters;
  const el = document.getElementById("cards");
  if (!c || !c.clusters){
    el.innerHTML = `<div class="note">No chain survey yet — the crawler records one once it has
      RPC and has completed a pass.</div>`;
    return;
  }
  const list = c.clusters || [];
  const responded = c.responded || 0;
  const ourCluster = list.find(x => x.ours);
  const biggest = list[0];
  // "Agreement" is the share of responding peers on the largest chain — the honest headline.
  const agree = responded && biggest ? (biggest.nodes / responded * 100) : 0;
  const cards = [
    ["Chains seen", fmt(list.length),
      list.length === 1 ? "the network agrees" : "distinct chains among peers"],
    ["Peers surveyed", fmt(responded), "answered with headers"],
    ["Largest chain", agree.toFixed(1) + "%", "of responding peers"],
    ["Your node", ourCluster ? "on the " + (ourCluster === biggest ? "majority" : "minority") + " chain"
                             : (c.our_hash ? "not matched" : "unknown"),
      c.ref_height ? "compared at height " + fmt(c.ref_height) : "no reference height"],
  ];
  el.innerHTML = cards.map(([l,v,n]) =>
    `<div class="card"><div class="label">${esc(l)}</div>
     <div class="value" style="font-size:${String(v).length > 12 ? 17 : 30}px">${esc(String(v))}</div>
     <div class="note">${esc(n)}</div></div>`).join("");
}

// The track diagram is driven by the peer survey: one cluster = one track, two or more = a fork.
function renderTracks(){
  const wrap = document.getElementById("chainsplit");
  const status = document.getElementById("split-status");
  if (!wrap || !status) return;
  const setLabel = (sel, t) => { const e = wrap.querySelector(sel); if (e) e.textContent = t; };
  const c = DATA.clusters;
  const list = (c && c.clusters) || [];

  if (!list.length){
    wrap.classList.remove("is-split");
    setLabel(".tk-lab-one", "");
    status.innerHTML = `<span class="dim">No peers have reported headers yet. The chain survey
      needs the crawler running with RPC — it builds the block locator from your own node.</span>`;
    return;
  }

  const responded = c.responded || 0;
  if (list.length === 1){
    wrap.classList.remove("is-split");
    setLabel(".tk-lab-one", "one chain · " + fmt(list[0].nodes) + " nodes agree");
    status.innerHTML = `<span class="ok">No split.</span> All <b>${fmt(responded)}</b> responding `
      + `peers report the same block at height <b>${fmt(c.ref_height)}</b> `
      + `(<code>${esc(shortHash(list[0].hash))}</code>).`;
    return;
  }

  // Two or more chains. The upper (green) track is always OUR chain, not merely the biggest —
  // green means "the chain this node follows" everywhere else on the site, and assigning the
  // tracks by size would hand green to whichever chain happens to be larger, inverting that.
  // Node counts are on the labels, so size is never hidden by the ordering.
  wrap.classList.add("is-split");
  const ours = list.find(x => x.ours);
  const other = list.find(x => x !== ours) || list[1];
  const [a, b] = ours ? [ours, other] : [list[0], list[1]];
  const tag = x => (x && x.ours ? " ← your node" : "");
  setLabel(".tk-lab-up",   fmt(a.nodes) + " nodes · " + shortHash(a.hash) + tag(a));
  setLabel(".tk-lab-down", fmt(b.nodes) + " nodes · " + shortHash(b.hash) + tag(b));
  const extra = list.length > 2 ? ` (plus ${fmt(list.length - 2)} smaller)` : "";
  const biggest = list[0];
  status.innerHTML = `<span class="bad">⚠ Chain split.</span> Peers report `
    + `<b>${fmt(list.length)}</b> different blocks at height <b>${fmt(c.ref_height)}</b>${extra} — `
    + `<b>${fmt(a.nodes)}</b> vs <b>${fmt(b.nodes)}</b> nodes. A differing block hash at the same `
    + `height is a different chain, not a lag.`
    + (ours
        ? ` Your node is on the <b>${ours === biggest ? "larger" : "smaller"}</b> side `
          + `(${fmt(ours.nodes)} of ${fmt(responded)} responding peers).`
        : ` Your node's own block wasn't matched to any cluster.`);
}

function renderTable(){
  const tbody = document.querySelector("#chains-table tbody");
  const c = DATA.clusters;
  const list = (c && c.clusters) || [];
  if (!list.length){
    tbody.innerHTML = `<tr><td colspan="4" class="dim" style="text-align:center;padding:18px;">`
      + `no peer chain data yet</td></tr>`;
    return;
  }
  const responded = c.responded || 1;
  tbody.innerHTML = list.map(x => {
    const mix = Object.entries(x.by_implementation || {})
      .sort((p,q) => q[1]-p[1])
      .map(([k,v]) => `${esc(k)} ${fmt(v)}`).join(" · ") || "—";
    const share = (x.nodes / responded * 100);
    return `<tr>
      <td class="mono" title="${esc(x.hash)}">${esc(shortHash(x.hash))}
        ${x.ours ? '<span class="pill enf">your node</span>' : ''}</td>
      <td class="mono">${fmt(x.nodes)}</td>
      <td class="mono">${share.toFixed(1)}%</td>
      <td>${mix}</td>
    </tr>`;
  }).join("");
}

function renderTips(){
  const el = document.getElementById("tips-panel");
  const s = DATA.split;
  if (!s){
    el.innerHTML = `<div class="note">No local chain-tip assessment recorded yet.</div>`;
    return;
  }
  const forks = s.forks || [];
  const rows = forks.length
    ? `<table style="margin-top:10px;"><thead><tr><th>Branch tip</th><th>Length</th><th>Status</th></tr></thead>
       <tbody>${forks.map(f => `<tr>
         <td class="mono">${fmt(f.height)}</td>
         <td class="mono">${fmt(f.branchlen)}</td>
         <td><span class="${f.status === 'invalid' ? 'bad-text' : ''}">${esc(f.status)}</span></td>
       </tr>`).join("")}</tbody></table>`
    : `<div class="note" style="margin-top:8px;">No side branches known — your node sees a single
        chain.</div>`;
  el.innerHTML = `<div>Active chain at height <b>${fmt(s.active_height)}</b>.
      ${s.rejected_branches ? `<span class="bad-text">${fmt(s.rejected_branches)} branch(es) rejected as invalid.</span>`
                            : `No branches rejected.`}</div>${rows}`;
}

document.getElementById("disclaimer").textContent =
  "Note: peers are grouped by the block hash they report at a fixed reference height, a few "
  + "blocks below the tip so that nodes slightly behind still answer. A peer that is still "
  + "syncing, is further behind than the locator reaches, or simply didn't reply within the "
  + "collection window is counted as unknown and excluded — never assumed to agree. The survey "
  + "covers reachable, handshakeable nodes only, which is the same population as the rest of "
  + "this site.";

async function load(){
  try {
    const r = await fetch("/api/chains?_=" + Date.now(), {cache:"no-store"});
    if (!r.ok){ failLoading("Couldn't load chain data — retrying…"); return; }
    DATA = await r.json();
  } catch(e){
    failLoading("Couldn't load chain data — retrying…");
    return;
  }
  renderCards();
  renderTracks();
  renderTable();
  renderTips();
  doneLoading();
  document.getElementById("gen").textContent =
    "updated " + new Date().toISOString().slice(11,19) + " UTC";
}
load();
setInterval(load, 30000);
