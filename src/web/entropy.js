// Entropy generator: mixes the browser's CSPRNG (crypto.getRandomValues) with hashed user
// interaction (pointer + keyboard timing) into a BIP-39 recovery phrase and raw hex. Everything
// happens in page memory — no fetch, no storage, nothing sent anywhere.
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

if (!(window.crypto && window.crypto.subtle)) {
  document.querySelector(".wrap").innerHTML =
    '<div class="callout"><b>Not available.</b> This page needs the Web Crypto API '
    + "(crypto.subtle), which requires a modern browser and a secure context (HTTPS, or "
    + "localhost). Reload over HTTPS or use an up-to-date browser.</div>";
  throw new Error("Web Crypto unavailable");
}

// The full BIP-39 English wordlist (2048 entries), injected at render time from the
// server's copy of assets/bip39-english.txt — see report.rs::render_entropy_html, which
// also re-validates it (length, uniqueness, sort order) on every request.
const WORDLIST = /*__WORDLIST__*/null;

// ---- byte/bit helpers ----
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}
function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}
function bytesToBinary(bytes) {
  return [...bytes].map(b => b.toString(2).padStart(8, "0")).join("");
}
function bitsToBytes(bits) {
  const out = new Uint8Array(bits.length / 8);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return out;
}

// ---- BIP-39 ----
// Standard algorithm: append a checksum (the first ENT/32 bits of SHA-256(entropy)) to the
// entropy, then read it off in 11-bit chunks, each an index into the 2048-word list.
async function entropyToMnemonic(entropyBytes) {
  const entBits = bytesToBinary(entropyBytes);
  const csLen = entropyBytes.length * 8 / 32;
  const hashBits = bytesToBinary(await sha256(entropyBytes)).slice(0, csLen);
  const allBits = entBits + hashBits;
  const words = [];
  for (let i = 0; i < allBits.length; i += 11) {
    words.push(WORDLIST[parseInt(allBits.slice(i, i + 11), 2)]);
  }
  return words;
}
// Reverses the above and re-derives the checksum, so a generated phrase can be checked against
// its own entropy before it's ever shown — this only proves OUR bit-manipulation is internally
// consistent, not that the embedded wordlist matches the canonical one word-for-word.
async function verifyMnemonic(words, entropyBytes) {
  const idxBits = words.map(w => WORDLIST.indexOf(w).toString(2).padStart(11, "0")).join("");
  const entBitLen = entropyBytes.length * 8;
  const reconstructed = bitsToBytes(idxBits.slice(0, entBitLen));
  const csBits = idxBits.slice(entBitLen);
  const hashBits = bytesToBinary(await sha256(reconstructed)).slice(0, csBits.length);
  return hashBits === csBits && bytesToHex(reconstructed) === bytesToHex(entropyBytes);
}

// ---- entropy pool ----
// poolHash is re-hashed continuously: every mix folds in a FRESH crypto.getRandomValues() pull
// (the dominant, always-present entropy source) together with whatever pointer/keyboard samples
// arrived since the last mix. User input matters as a hedge against a compromised or flawed
// CSPRNG, not because mouse movement itself is highly random — it's an extra ingredient, not
// the main one.
let poolHash = crypto.getRandomValues(new Uint8Array(32));
let sampleQueue = [];
let mixing = false;

// ---- interaction-entropy estimate (deliberately conservative and clearly separate from the
// final key space) ----
// The FINAL secret is always exactly 128 or 256 bits, chosen by the radio buttons below and
// guaranteed by the browser's CSPRNG on its own — that number never changes no matter how long
// you interact, and it genuinely CANNOT exceed 256 bits: a 256-bit value can't hold more than
// 256 bits of entropy, full stop, no matter how much goes into producing it.
//
// `interactionBits` tracks something different, and is deliberately NOT capped at 256: a
// running, order-of-magnitude estimate of how much UNPREDICTABLE input your pointer/keyboard
// has contributed IN TOTAL this session, as the extra/independent ingredient described above.
// Unlike the final output, this total keeps meaning something past 256 — every additional
// independent round mixed in (each with its own fresh CSPRNG pull) is one more hedge against
// any single one of those rounds being predictable, so more is never wasted even once the
// nominal pool width is "full". It is not a rigorous measurement (that would need to account
// for screen size, sampling correlation, an attacker's viewing angle, and more) — treat it as
// illustrative, not a precise security guarantee.
const BITS_PER_POINTER_SAMPLE = 2; // quantised position + high-res timing jitter
const BITS_PER_KEY_SAMPLE = 1;     // timing jitter only — no key identity is ever read
const MIN_INTERACTION_BITS = 128;  // gate before "Generate" unlocks
let interactionBits = 0;

function queueSample(x, y, bits) {
  const buf = new Uint8Array(12);
  new DataView(buf.buffer).setUint16(0, x & 0xffff);
  new DataView(buf.buffer).setUint16(2, y & 0xffff);
  new DataView(buf.buffer).setFloat64(4, performance.now());
  sampleQueue.push(buf);
  interactionBits += bits;
}

// Drains the queue into the pool hash. Guarded by `mixing` so overlapping calls (a new
// animation frame firing before the previous digest resolves) can't race on poolHash.
async function drainPool() {
  if (mixing || !sampleQueue.length) return;
  mixing = true;
  try {
    const batch = sampleQueue;
    sampleQueue = [];
    const fresh = crypto.getRandomValues(new Uint8Array(32));
    poolHash = await sha256(concatBytes(poolHash, fresh, ...batch));
    updateProgress();
  } finally {
    mixing = false;
  }
}

function updateProgress() {
  const pct = Math.min(100, (interactionBits / MIN_INTERACTION_BITS) * 100);
  document.getElementById("progress-fill").style.width = pct.toFixed(1) + "%";
  document.getElementById("progress-note").textContent = interactionBits >= MIN_INTERACTION_BITS
    ? `~${interactionBits} bits of interaction entropy (conservative estimate) — enough to generate.`
    : `~${interactionBits} of ${MIN_INTERACTION_BITS} bits (conservative estimate) — keep moving, clicking, typing…`;
  document.getElementById("generate").disabled = interactionBits < MIN_INTERACTION_BITS;
}
updateProgress();

(function tick() { drainPool(); requestAnimationFrame(tick); })();

// ---- interaction pad: captures samples, draws a fading trail for feedback ----
const pad = document.getElementById("pad");
const padCtx = pad.getContext("2d");
let trail = [];

function resizePad() {
  const r = pad.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  pad.width = r.width * dpr;
  pad.height = r.height * dpr;
}
window.addEventListener("resize", resizePad);
resizePad();

function padPoint(e) {
  const r = pad.getBoundingClientRect();
  return { x: e.clientX - r.left, y: e.clientY - r.top };
}
pad.addEventListener("pointermove", e => {
  const p = padPoint(e);
  queueSample(p.x | 0, p.y | 0, BITS_PER_POINTER_SAMPLE);
  trail.push({ ...p, t: performance.now() });
});
pad.addEventListener("pointerdown", e => {
  const p = padPoint(e);
  queueSample(p.x | 0, p.y | 0, BITS_PER_POINTER_SAMPLE);
  trail.push({ ...p, t: performance.now() });
});
// Only timing (a high-resolution timestamp), never which key — this page has nothing worth
// logging keystrokes for, and there's no reason to give it the ability to.
window.addEventListener("keydown", e => queueSample(e.timeStamp | 0, 0, BITS_PER_KEY_SAMPLE));

function drawPad() {
  requestAnimationFrame(drawPad);
  const r = pad.getBoundingClientRect();
  if (!r.width || !r.height) return;
  const dpr = window.devicePixelRatio || 1;
  padCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
  padCtx.clearRect(0, 0, r.width, r.height);
  const now = performance.now();
  trail = trail.filter(p => now - p.t < 1200);
  const col = getComputedStyle(document.documentElement).getPropertyValue("--neon").trim() || "#0ff";
  padCtx.fillStyle = col;
  for (const p of trail) {
    padCtx.globalAlpha = Math.max(0, 1 - (now - p.t) / 1200);
    padCtx.beginPath();
    padCtx.arc(p.x, p.y, 3, 0, Math.PI * 2);
    padCtx.fill();
  }
  padCtx.globalAlpha = 1;
}
requestAnimationFrame(drawPad);

// ---- generate / reveal / wipe ----
function renderOutput(entropyBytes, words, verified) {
  document.getElementById("output").style.display = "";
  document.getElementById("reveal-wrap").classList.remove("revealed");
  document.getElementById("mnemonic-grid").innerHTML = words
    .map((w, i) => `<div class="w"><b>${i + 1}</b>${esc(w)}</div>`)
    .join("");
  document.getElementById("checksum-note").textContent = verified
    ? "✓ internal checksum verified — the phrase decodes back to the exact same entropy."
    : "⚠ internal checksum check FAILED — do not use this output. Reload the page and try again.";
  const hexEl = document.getElementById("hexbox");
  hexEl.textContent = bytesToHex(entropyBytes);
  hexEl.classList.remove("revealed");
}

document.getElementById("generate").addEventListener("click", async () => {
  const bitLength = Number(document.querySelector('input[name="len"]:checked').value);
  await drainPool();
  // One last mix, folding in this very click, before deriving the output — and ratchet the
  // pool forward afterward so a second click never reuses the same material.
  const fresh = crypto.getRandomValues(new Uint8Array(32));
  poolHash = await sha256(concatBytes(poolHash, fresh));
  const entropyBytes = poolHash.slice(0, bitLength / 8);

  const words = await entropyToMnemonic(entropyBytes);
  const verified = await verifyMnemonic(words, entropyBytes);
  renderOutput(entropyBytes, words, verified);
});

document.getElementById("wipe").addEventListener("click", () => {
  poolHash = crypto.getRandomValues(new Uint8Array(32));
  sampleQueue = [];
  interactionBits = 0;
  trail = [];
  updateProgress();
  document.getElementById("output").style.display = "none";
  document.getElementById("mnemonic-grid").innerHTML = "";
  document.getElementById("hexbox").textContent = "";
  document.getElementById("checksum-note").textContent = "";
});

document.getElementById("reveal-veil").addEventListener("click", () => {
  document.getElementById("reveal-wrap").classList.add("revealed");
});
document.getElementById("hexbox").addEventListener("click", function () {
  this.classList.toggle("revealed");
});
document.getElementById("copy-hex").addEventListener("click", async () => {
  const hex = document.getElementById("hexbox").textContent;
  const btn = document.getElementById("copy-hex");
  if (!hex) return;
  try {
    await navigator.clipboard.writeText(hex);
    const old = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = old; }, 1500);
  } catch (e) {
    alert("Copy failed — click the hex box to reveal it, then select and copy manually.");
  }
});

document.getElementById("disclaimer").textContent =
  "How this works: your browser's Web Crypto API (a CSPRNG) supplies the primary randomness; "
  + "your pointer/keyboard input is hashed (SHA-256) on top of it as a second, independent "
  + "ingredient, mixed continuously while you interact together with a fresh CSPRNG pull every "
  + "cycle, so a compromised or flawed CSPRNG alone can't fully determine the result. Nothing "
  + "here is transmitted anywhere or written to storage — it all lives in page memory and is "
  + "gone when you close or reload the tab. That said, JavaScript cannot guarantee secrets are "
  + "wiped from memory (there's no secure-erase in a garbage-collected language) — closing the "
  + "tab or browser is the real reset, not just the Wipe button.";
