// Live activity ticker, injected into every page by report.rs::assemble().
//
// Purpose: make it obvious the crawler is always working. It scrolls continuously (so it never
// looks frozen between polls) and re-reads /api/ticker every few seconds. Genuinely new events —
// a block arriving, peers discovered — are surfaced as their own items and briefly highlighted,
// so the motion isn't purely decorative.
//
// It is self-contained: its own fetch, its own element, no dependency on the host page's data or
// helpers. That is what lets one implementation serve all six pages.
(function(){
  // Every identifier is prefixed/scoped to avoid colliding with a page's own globals.
  const TICK_POLL_MS = 8000;
  const el = document.createElement("div");
  el.className = "ticker";
  // Two zones: a PINNED status block on the left that never moves (so the "it's alive" signal
  // is always on screen), and a clipped marquee to its right carrying everything else.
  el.innerHTML =
      '<div class="tk-inner">'
    +   '<span class="tk-fixed"><span class="tk-live"></span>'
    +     '<span id="tk-status" class="tk-dim">connecting…</span></span>'
    +   '<span class="tk-scroll"><span class="tk-run" id="tk-run"></span></span>'
    + '</div>';
  document.body.insertBefore(el, document.body.firstChild);

  const fmt = n => Number(n || 0).toLocaleString();
  const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const ago = ts => {
    const s = Math.max(0, Math.floor(Date.now()/1000) - ts);
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s/60) + "m ago";
    return Math.floor(s/3600) + "h ago";
  };

  // Remembered across polls so we can tell a genuine change from a re-render.
  let lastHeight = null, lastReachable = null, flash = [];

  function item(text, cls){ return `<span class="tk-item ${cls||''}">${text}</span>`; }

  function render(d){
    // The heartbeat lives in the pinned block, never in the marquee — it's the one thing that
    // must be readable at all times, so it must not scroll away.
    const gen = d.generated_at || "";
    const secs = gen ? Math.max(0, Math.round((Date.now() - Date.parse(gen)) / 1000)) : null;
    const st = document.getElementById("tk-status");
    if (st){
      st.className = "";
      st.innerHTML = `<b class="tk-ok">crawler running</b>`
        + (secs != null
            ? `<span class="tk-dim"> · ${secs < 90 ? secs + "s" : Math.round(secs/60) + "m"} ago</span>`
            : "");
    }

    const parts = [];
    // Transient events, newest first — these are what make it feel live.
    flash.forEach(f => parts.push(item(f, "tk-new")));

    if (d.tip){
      const t = d.tip;
      parts.push(item(`⛓ block <b>${fmt(t.height)}</b> · ${fmt(t.tx_count)} txs`
        + (t.miner ? ` · ${esc(t.miner)}` : "")
        + ` · ${t.signals ? '<b class="tk-ok">✓ signalling</b>' : '<b class="tk-bad">☣ not signalling</b>'}`
        + ` · ${ago(t.time)}`));
    }

    parts.push(item(`<b>${fmt(d.reachable)}</b> reachable nodes`));
    if (d.onion) parts.push(item(`<b>${fmt(d.onion)}</b> via Tor`));
    if (d.new_24h) parts.push(item(`<b>+${fmt(d.new_24h)}</b> new peers today`));

    const s = d.signalling;
    if (s){
      parts.push(item(`bit 4: <b>${s.percent.toFixed(1)}%</b> of ${fmt(s.blocks_scanned)} blocks this period`));
      // The retarget boundary is the lock-in height; count down to it.
      const boundary = Math.floor(s.tip_height / 2016) * 2016 + 2016;
      const left = boundary - s.tip_height;
      if (left > 0) parts.push(item(`<b>${fmt(left)}</b> blocks to the retarget`));
    }

    // Duplicated once so the marquee can loop seamlessly: the animation translates by -50%,
    // which lands exactly on the start of the second copy.
    const run = parts.join("");
    document.getElementById("tk-run").innerHTML = run + run;
  }

  async function poll(){
    let d;
    try {
      const r = await fetch("/api/ticker?_=" + Date.now(), {cache:"no-store"});
      if (!r.ok) throw 0;
      d = await r.json();
    } catch(e){
      const st = document.getElementById("tk-status");
      if (st){ st.className = "tk-dim"; st.textContent = "crawler unreachable"; }
      const run = document.getElementById("tk-run");
      if (run) run.innerHTML = item('<span class="tk-dim">retrying…</span>');
      return;
    }
    // Detect real changes since the previous poll and surface them as their own items.
    flash = [];
    if (d.tip && lastHeight != null && d.tip.height > lastHeight){
      flash.push(`<b class="tk-ok">▲ NEW BLOCK ${fmt(d.tip.height)}</b>`);
    }
    if (lastReachable != null && d.reachable > lastReachable){
      flash.push(`<b class="tk-ok">▲ +${fmt(d.reachable - lastReachable)} nodes found</b>`);
    }
    if (d.tip) lastHeight = d.tip.height;
    lastReachable = d.reachable;
    render(d);
  }
  poll();
  setInterval(poll, TICK_POLL_MS);
})();
