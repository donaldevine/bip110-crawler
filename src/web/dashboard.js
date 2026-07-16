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

// A non-IP descriptor for a table row (from /api/nodes): its geolocated place, "Tor" for
// onion, or the network type for un-geolocated clearnet. Used instead of the raw address.
function nodeLocation(n){
  const addr = String(n.addr || "");
  const self = n.depth === 0 || addr.startsWith("self");
  const loc = [n.city, n.country].filter(Boolean).join(", ");
  if (loc) return self ? `${loc} (this node)` : loc;
  if (self) return "This node";
  if (addr.includes(".onion")) return "Tor (anonymous)";
  const ipv6 = addr.startsWith("[") || (addr.split(":").length > 2);
  return ipv6 ? "IPv6" : "IPv4";
}

// ---- render helpers (re-callable so the page can refresh from fresh JSON) ----
const sortDesc = obj => Object.entries(obj).sort((a,b)=>b[1]-a[1]);
const shortTime = iso => (iso && iso.length>=19) ? iso.slice(11,19)+" UTC" : (iso||"");
const shortDate = iso => (iso && iso.length>=10) ? iso.slice(0,10) : (iso||"");

function renderCards(){
  const a = DATA.aggregates, sig = DATA.signalling;
  const reachable = a.total_nodes;
  // Tor count from the server-side aggregate over ALL reachable nodes (exact), falling
  // back to the capped node list only if an older payload lacks the field.
  const tor = (a.onion_nodes != null) ? a.onion_nodes
            : DATA.nodes.filter(n => n.addr.includes(".onion")).length;
  const live = DATA.live
    ? ` · <span class="live-dot"></span>live, updated ${esc(shortTime(DATA.generated_at))}`
    : "";
  document.getElementById("subtitle").innerHTML =
    `${esc(DATA.network)} · own node ${esc(DATA.own_node.subversion || "n/a")} · `
    + `${reachable.toLocaleString()} reachable nodes${live}`;
  document.getElementById("gen-time").textContent = DATA.generated_at;
  // Map cap note: how many of the reachable nodes the (capped) maps are actually drawing.
  const shown = DATA.nodes.length;
  const capNote = shown < reachable
    ? `Currently showing ${shown.toLocaleString()} of ${reachable.toLocaleString()}.` : "";
  ["graph-shown","geo-shown"].forEach(id => { const e = document.getElementById(id); if (e) e.textContent = capNote; });
  const ready = (a.by_bip110 && a.by_bip110["BIP-110 ready"]) || 0;
  const readyPct = reachable ? (ready / reachable * 100) : 0;
  const cards = [
    ["Reachable nodes", reachable.toLocaleString(), "responding to the crawl"],
    ["Tor nodes", tor.toLocaleString(), "reachable over onion"],
    ["BIP-110 ready", readyPct.toFixed(1)+"%",
       `${ready.toLocaleString()} of ${reachable.toLocaleString()} reachable nodes`],
    ["Implementations", Object.keys(a.by_implementation).length, "distinct clients"],
    ["Miner signalling", sig ? sig.percent.toFixed(1)+"%" : "n/a",
       sig ? `${sig.blocks_signalling}/${sig.blocks_scanned} blocks this period` : "RPC not available"],
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
      <span><b style="color:var(--ink)">${sig.percent.toFixed(1)}%</b> of ${sig.blocks_scanned} blocks so far this period signal (bit ${sig.bit})</span>
      <span>${esc(status)}</span>
    </div>
    <div class="gauge-track">
      <div class="gauge-fill" style="width:${pct}%"></div>
      <div class="gauge-threshold" style="left:${sig.threshold_percent}%"></div>
    </div>
    <div class="note" style="margin-top:14px;">Chain tip height ${sig.tip_height.toLocaleString()}.
      ${sig.blocks_signalling} of ${sig.blocks_scanned} blocks so far in the current difficulty
      period (2016 blocks) set version bit ${sig.bit}.</div>`;
}

// BIP-110 activation schedule (block heights, BIP8/BIP9 semantics from the spec):
//  - mandatory signalling spans one retarget period (961632–963647)
//  - lock-in is guaranteed no later than 963648
//  - ACTIVE follows one retarget later (965664); the fork EXPIRES active_duration
//    (52416 blocks, ~1 year) after that, lifting the data limits.
function renderTimeline(){
  const el = document.getElementById("timeline-panel");
  if (!el) return;
  const MANDATORY_START = 961632, LOCKIN = 963648, RETARGET = 2016, ACTIVE_DURATION = 52416;
  const ACTIVE = LOCKIN + RETARGET, EXPIRED = ACTIVE + ACTIVE_DURATION;
  const sig = DATA.signalling;
  const tip = (sig && typeof sig.tip_height === "number") ? sig.tip_height : null;
  const fmt = n => n.toLocaleString();
  const human = blocks => {
    const days = blocks * 10 / 1440;
    if (days >= 60) return `~${(days/30.44).toFixed(1)} months`;
    if (days >= 1.5) return `~${Math.round(days)} days`;
    return `~${Math.max(1, Math.round(days*24))} hours`;
  };
  const etaDate = blocks => new Date(Date.now() + blocks*10*60*1000).toISOString().slice(0,10);

  const milestones = [
    { h: MANDATORY_START, t:"Mandatory signalling begins", d:"Blocks not signalling bit 4 are rejected as invalid" },
    { h: LOCKIN,          t:"Mandatory lock-in",           d:"Lock-in guaranteed no later than this block" },
    { h: ACTIVE,          t:"Active — limits enforced",     d:"Reduced-data rules become consensus" },
    { h: EXPIRED,         t:"Expires (temporary)",          d:`~1 year (${fmt(ACTIVE_DURATION)} blocks) after activation → limits lifted` },
  ];

  let headline;
  if (tip == null){
    headline = `<div class="cd"><div class="cd-sub">Connect the crawler to your node (RPC) to show a live block-countdown from the chain tip.</div></div>`;
  } else {
    const next = milestones.find(m => m.h > tip);
    headline = next
      ? `<div class="cd"><div class="cd-big">${fmt(next.h - tip)}<small> blocks</small></div>`
        + `<div class="cd-sub">to <b>${esc(next.t)}</b> · ${human(next.h - tip)} · est. ${etaDate(next.h - tip)}</div>`
        + `<div class="cd-note">chain tip ${fmt(tip)}</div></div>`
      : `<div class="cd"><div class="cd-big">Expired</div><div class="cd-sub">the temporary soft fork has ended — data limits lifted</div>`
        + `<div class="cd-note">chain tip ${fmt(tip)}</div></div>`;
  }

  const nextH = tip == null ? null : (milestones.find(m => m.h > tip) || {}).h;
  const nodes = milestones.map(m => {
    const state = tip == null ? "" : (tip >= m.h ? "done" : (m.h === nextH ? "next" : "future"));
    const rel = (tip != null && tip < m.h)
      ? `<span class="tl-rel">in ${fmt(m.h - tip)} · ${human(m.h - tip)}</span>` : "";
    return `<div class="tl-node ${state}"><div class="tl-dot"></div>`
      + `<div class="tl-h">block ${fmt(m.h)}</div><div class="tl-t">${esc(m.t)}</div>`
      + `<div class="tl-d">${esc(m.d)}</div>${rel}</div>`;
  }).join("");

  el.innerHTML = headline + `<div class="timeline">${nodes}</div>`;
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

// ---- nodes table: server-side search / filter / sort / pagination over the FULL
// reachable set via /api/nodes (not the size-capped report set), so the table and its
// counts reflect the whole network. Falls back to nothing when opened from file://.
const table = (function(){
  const tbody = document.querySelector("#nodes-table tbody");
  const search = document.getElementById("search");
  const fImpl = document.getElementById("filter-impl");
  const fBip = document.getElementById("filter-bip");
  const prevBtn = document.getElementById("nodes-prev");
  const nextBtn = document.getElementById("nodes-next");
  const pageInfo = document.getElementById("nodes-pageinfo");
  const PAGE = 100;
  let sortKey="depth", sortDir="asc", offset=0, total=0, timer=null;
  const pillClass = s => s==="enforcing"?"enf":s==="not_enforcing"?"not":"unk";
  const pillText = s => s==="enforcing"?"Ready":s==="not_enforcing"?"Not ready":"Unknown";

  // Add any newly-seen implementations to the filter without clobbering the selection.
  function syncOptions(){
    if (!DATA.aggregates || !DATA.aggregates.by_implementation) return;
    const have = new Set([...fImpl.options].map(o=>o.value));
    Object.keys(DATA.aggregates.by_implementation).forEach(i=>{
      if (!have.has(i)){ const o=document.createElement("option"); o.value=i; o.textContent=i; fImpl.appendChild(o); }
    });
  }

  function renderRows(rows){
    tbody.innerHTML = rows.map(n=>`
      <tr>
        <td>${esc(nodeLocation(n))}${String(n.addr).includes('.onion') ? ' <span class="pill unk">Tor</span>' : ''}</td>
        <td><span class="swatch" style="background:${implColor(n.implementation)}"></span>${esc(n.implementation)}</td>
        <td>${esc(n.version||"—")}</td>
        <td>${n.protocol_version||"—"}</td>
        <td>${n.depth}</td>
        <td><span class="pill ${pillClass(n.bip110)}">${pillText(n.bip110)}</span></td>
      </tr>`).join("");
  }
  function updatePager(){
    const from = total ? offset+1 : 0, to = Math.min(offset+PAGE, total);
    if (pageInfo) pageInfo.textContent = `${from.toLocaleString()}–${to.toLocaleString()} of ${total.toLocaleString()} nodes`;
    if (prevBtn) prevBtn.disabled = offset <= 0;
    if (nextBtn) nextBtn.disabled = offset+PAGE >= total;
  }
  async function load(){
    const params = new URLSearchParams({
      q: search.value, impl: fImpl.value, bip: fBip.value,
      sort: sortKey, dir: sortDir, limit: PAGE, offset,
    });
    try {
      const r = await fetch("/api/nodes?" + params.toString(), {cache:"no-store"});
      if (!r.ok) return;
      const data = await r.json();
      total = data.total || 0;
      renderRows(data.rows || []);
      updatePager();
    } catch(e){ /* offline / file:// — leave the table as-is */ }
  }
  function reset(){ offset = 0; load(); }               // filter/sort change → back to page 1
  const debouncedReset = () => { clearTimeout(timer); timer = setTimeout(reset, 250); };

  document.querySelectorAll("#nodes-table th").forEach(th=>{
    th.addEventListener("click", ()=>{
      const k = th.dataset.k;
      if (sortKey===k) sortDir = sortDir==="asc" ? "desc" : "asc";
      else { sortKey = k; sortDir = "asc"; }
      reset();
    });
  });
  search.addEventListener("input", debouncedReset);
  [fImpl,fBip].forEach(el=>el.addEventListener("change", reset));
  if (prevBtn) prevBtn.addEventListener("click", ()=>{ if (offset>0){ offset=Math.max(0,offset-PAGE); load(); } });
  if (nextBtn) nextBtn.addEventListener("click", ()=>{ if (offset+PAGE<total){ offset+=PAGE; load(); } });

  // On each live refresh, keep the filter options current and re-load the current page so
  // the totals track the growing crawl (preserves the user's filters/sort/offset).
  return { refresh(){ syncOptions(); load(); } };
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
  renderTimeline();
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