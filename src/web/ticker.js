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
  // Scroll speed in px/sec. The duration is derived from the measured content width so the
  // strip always moves at this rate, however much (or little) it is carrying.
  const TICK_PX_PER_SEC = 55;
  // Last markup written to the strip, so an unchanged poll doesn't restart the animation.
  let lastHtml = "";
  const el = document.createElement("div");
  // Starts in the loading state: amber dot, "connecting…", and a placeholder in the marquee so
  // the strip is never blank while the first fetch is in flight. Note it deliberately does NOT
  // use the shared `.loading` class — the host pages call doneLoading(), which removes every
  // `.loading` element on the page, and that would strip the ticker's placeholder too.
  el.className = "ticker tk-loading";
  // Two zones: a PINNED status block on the left that never moves (so the "it's alive" signal
  // is always on screen), and a clipped marquee to its right carrying everything else.
  el.innerHTML =
      '<div class="tk-inner">'
    +   '<span class="tk-fixed"><span class="tk-live"></span>'
    +     '<span id="tk-status" class="tk-wait">connecting…</span></span>'
    +   '<span class="tk-scroll"><span class="tk-run" id="tk-run">'
    +     '<span class="tk-item tk-dim">fetching live network data…</span></span></span>'
    + '</div>';
  document.body.insertBefore(el, document.body.firstChild);

  const fmt = n => Number(n || 0).toLocaleString();
  const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

  // Remembered across polls so we can tell a genuine change from a re-render.
  let lastHeight = null, lastReachable = null, flash = [];

  function item(text, cls){ return `<span class="tk-item ${cls||''}">${text}</span>`; }

  function render(d){
    // The heartbeat lives in the pinned block, never in the marquee — it's the one thing that
    // must be readable at all times, so it must not scroll away.
    const gen = d.generated_at || "";
    const secs = gen ? Math.max(0, Math.round((Date.now() - Date.parse(gen)) / 1000)) : null;
    // Data has landed: leave the loading/error state, so the dot turns green.
    el.className = "ticker";
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
      // Deliberately no "N minutes ago" here: any per-minute value changes the strip's markup,
      // which restarts the scroll. Freshness lives in the pinned block, which never animates.
      parts.push(item(`⛓ block <b>${fmt(t.height)}</b> · ${fmt(t.tx_count)} txs`
        + (t.miner ? ` · ${esc(t.miner)}` : "")
        + ` · ${t.signals ? '<b class="tk-ok">✓ signalling</b>' : '<b class="tk-bad">☣ not signalling</b>'}`));
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
    const html = parts.join("").repeat(2);
    const run = document.getElementById("tk-run");
    if (!run) return;
    // CRITICAL: writing innerHTML restarts the CSS animation from zero. Polling every 8s with
    // a ~30s cycle would therefore snap the strip back to the start before it ever travelled —
    // it looks like a twitch rather than a scroll. Only touch the DOM when the content really
    // changed, so the animation runs uninterrupted across polls.
    if (html === lastHtml) return;
    lastHtml = html;

    // When the content genuinely changes we must rewrite, which restarts the animation at zero
    // — a visible snap back to the start. Capture how far through the cycle we were, then
    // resume there with a negative animation-delay so the strip carries on instead of jumping.
    let elapsed = 0;
    if (run.getAnimations){
      const a = run.getAnimations()[0];
      if (a && typeof a.currentTime === "number") elapsed = a.currentTime / 1000;
    }

    run.innerHTML = html;
    // Drive the duration from the measured width so the speed is constant no matter how many
    // items there are; a fixed duration makes a long strip race and a short one crawl.
    const oneCopy = run.scrollWidth / 2;
    if (oneCopy > 0){
      const dur = Math.max(12, Math.round(oneCopy / TICK_PX_PER_SEC));
      run.style.animationDuration = dur + "s";
      run.style.animationDelay = elapsed > 0 ? `-${(elapsed % dur).toFixed(2)}s` : "0s";
    }
  }

  async function poll(){
    let d;
    try {
      const r = await fetch("/api/ticker?_=" + Date.now(), {cache:"no-store"});
      if (!r.ok) throw 0;
      d = await r.json();
    } catch(e){
      el.className = "ticker tk-error";
      const st = document.getElementById("tk-status");
      if (st){ st.className = "tk-dim"; st.textContent = "crawler unreachable"; }
      const run = document.getElementById("tk-run");
      if (run) run.innerHTML = item('<span class="tk-dim">retrying…</span>');
      lastHtml = "";   // force a full re-render once the crawler comes back
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
