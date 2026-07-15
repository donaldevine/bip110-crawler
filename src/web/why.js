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
      document.getElementById("sig-pct").innerHTML = sig.percent.toFixed(1) + "<small>% of " + sig.blocks_scanned + " blocks this period</small>";
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
    const readyTotal = a.total_nodes || (ready + notReady + unknown);
    const readyPct = readyTotal ? (ready / readyTotal * 100) : 0;
    const rpEl = document.getElementById("ready-pct");
    if (rpEl) rpEl.innerHTML = readyPct.toFixed(1) + "<small>% of reachable nodes ready</small>";
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