//! Bitcoin Core JSON-RPC client (only the calls the crawler needs).
//!
//! Supports either explicit `--rpc-user/--rpc-pass` or a `.cookie` file written by
//! bitcoind (`__cookie__:<hex>`), passed as user:pass.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

use crate::node::SignalStats;
use crate::p2p::Peer;

/// Data-payload breakdown for one block.
///
/// Detection is by well-known byte signatures, so it is a *heuristic*: it finds the
/// protocols below reliably, but "carries a data payload" is not the same as
/// "non-monetary" — these transactions usually move real value too. `weight` fields are
/// whole-transaction weight (a tx is counted once per category it matches), whereas
/// `*_bytes` is the payload itself, which is the tighter measure of data carried.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockPayload {
    /// Non-coinbase transactions in the block.
    pub tx_total: u32,
    /// Ordinals/inscription envelopes (`OP_FALSE OP_IF "ord"` in a tapscript witness).
    pub insc_count: u32,
    pub insc_weight: i64,
    pub insc_bytes: i64,
    /// Runestones (`OP_RETURN OP_13`).
    pub rune_count: u32,
    pub rune_weight: i64,
    pub rune_bytes: i64,
    /// Other `OP_RETURN` data carriers.
    pub data_count: u32,
    pub data_weight: i64,
    pub data_bytes: i64,
    /// Transactions carrying any of the above.
    pub payload_tx_count: u32,
    pub payload_weight: i64,
    /// Transactions BIP-110 would have rejected — i.e. an inscription envelope (rule 7
    /// bans OP_IF in tapscript) or a witness item over 256 bytes (rule 2). Runestones are
    /// deliberately excluded: a small OP_RETURN stays valid under rule 1's 83-byte
    /// allowance, so BIP-110 would not have stopped them.
    pub bip110_reject_count: u32,
    pub bip110_reject_weight: i64,
}

/// Fee/economic summary for one block, straight from `getblockstats`.
/// All amounts are satoshis; feerates are sat/vB.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockStats {
    pub total_fee: i64,
    pub subsidy: i64,
    pub avg_feerate: i64,
    pub median_feerate: i64,
    pub min_feerate: i64,
    pub max_feerate: i64,
    /// 10th/25th/50th/75th/90th percentile feerates.
    pub feerate_percentiles: Vec<i64>,
    pub total_out: i64,
    pub avg_tx_size: i64,
    pub ins: i64,
    pub outs: i64,
}

/// One chain tip reported by `getchaintips`.
#[derive(Debug, Clone, Serialize)]
pub struct ChainTip {
    pub height: i64,
    pub hash: String,
    /// 0 for the active chain; >0 means a branch diverging that many blocks back.
    pub branchlen: i64,
    /// `active` | `valid-fork` | `valid-headers` | `headers-only` | `invalid`.
    /// `invalid` means THIS node rejected the branch — under BIP-110 enforcement that is the
    /// split signature rather than a mere orphan.
    pub status: String,
}

/// One block as shown by the explorer page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub height: i64,
    pub hash: String,
    /// Unix timestamp from the block header.
    pub time: i64,
    pub version: i64,
    /// True when the header sets the BIP-110 signalling bit.
    pub signals: bool,
    pub tx_count: u32,
    pub size: i64,
    pub weight: i64,
    /// Best-effort miner/pool tag from the coinbase; empty when unknown.
    pub miner: String,
}

/// One band of the mempool fee-rate histogram: pending transactions whose feerate falls in
/// `[min_feerate, max_feerate)` sat/vB. `max_feerate` is `None` for the open-ended top band.
/// Empty bands are omitted, so this list is only as long as the mempool actually spans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeBucket {
    pub min_feerate: f64,
    pub max_feerate: Option<f64>,
    pub count: u32,
    pub vsize: i64,
}

/// A snapshot of the node's mempool: aggregate stats plus a fee-rate histogram, taken from
/// `getmempoolinfo` + `getrawmempool(true)`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MempoolSnapshot {
    pub pending: u32,
    /// Total virtual size of pending transactions (vbytes).
    pub vsize: i64,
    pub usage_bytes: i64,
    /// Sum of fees waiting to be mined, in BTC.
    pub total_fee: f64,
    /// The node's current minimum accepted feerate, in sat/vB.
    pub min_relay_feerate: f64,
    pub histogram: Vec<FeeBucket>,
    /// Feerate (sat/vB) of the transaction that would be the last one to fit in a
    /// block-sized (1,000,000 vbyte) slice of the mempool, taken highest-feerate-first —
    /// i.e. roughly what a transaction needs to pay to clear in the next block. `None`
    /// when the whole mempool is smaller than one block.
    pub next_block_feerate: Option<f64>,
}

/// Fee-rate band edges (sat/vB) for the histogram, Fibonacci-ish so low-fee spam and
/// high-fee spikes both get their own bands instead of being flattened into one bucket.
const FEE_BUCKET_EDGES: &[f64] = &[
    1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 12.0, 15.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0,
    100.0, 120.0, 150.0, 200.0, 300.0, 400.0, 500.0, 600.0, 700.0, 800.0, 900.0, 1000.0,
];

/// A standard block's vsize capacity (4,000,000 weight units / 4).
const BLOCK_VSIZE: i64 = 1_000_000;

/// Bucket `(feerate, vsize)` pairs into the fixed fee bands, dropping empty bands.
fn bucket_histogram(rates: &[(f64, i64)]) -> Vec<FeeBucket> {
    let n = FEE_BUCKET_EDGES.len();
    let mut counts = vec![0u32; n + 1];
    let mut vsizes = vec![0i64; n + 1];
    for &(rate, vs) in rates {
        let idx = FEE_BUCKET_EDGES.iter().position(|&e| rate < e).unwrap_or(n);
        counts[idx] += 1;
        vsizes[idx] += vs;
    }
    let mut out = Vec::new();
    let mut lo = 0.0;
    for i in 0..=n {
        let hi = FEE_BUCKET_EDGES.get(i).copied();
        if counts[i] > 0 {
            out.push(FeeBucket { min_feerate: lo, max_feerate: hi, count: counts[i], vsize: vsizes[i] });
        }
        if let Some(h) = hi {
            lo = h;
        }
    }
    out
}

/// The feerate needed to land in roughly the next block: walk pending transactions
/// highest-feerate-first, accumulating vsize until a block's worth is covered.
fn next_block_feerate(rates: &[(f64, i64)]) -> Option<f64> {
    let mut sorted = rates.to_vec();
    sorted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut acc = 0i64;
    for (rate, vs) in sorted {
        acc += vs;
        if acc >= BLOCK_VSIZE {
            return Some(rate);
        }
    }
    None
}

pub struct RpcClient {
    url: String,
    user: String,
    pass: String,
    agent: ureq::Agent,
}

impl RpcClient {
    pub fn new(url: String, user: String, pass: String) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build();
        RpcClient {
            url,
            user,
            pass,
            agent,
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "bip110-crawler",
            "method": method,
            "params": params,
        });
        let resp = self
            .agent
            .post(&self.url)
            .set(
                "Authorization",
                &basic_auth_header(&self.user, &self.pass),
            )
            .send_json(body)
            .with_context(|| format!("RPC {method} request failed"))?;
        let value: Value = resp
            .into_json()
            .with_context(|| format!("RPC {method} bad JSON"))?;
        if let Some(err) = value.get("error") {
            if !err.is_null() {
                bail!("RPC {method} error: {err}");
            }
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("RPC {method}: no result"))
    }

    /// Own node's version + subversion + best-known public IP (from `localaddresses`,
    /// highest score; may be None if the node doesn't know its external address).
    pub fn network_info(&self) -> Result<(i64, String, u64, Option<String>)> {
        let r = self.call("getnetworkinfo", json!([]))?;
        let version = r.get("version").and_then(Value::as_i64).unwrap_or(0);
        let subversion = r
            .get("subversion")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let services = r
            .get("localservices")
            .and_then(Value::as_str)
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .unwrap_or(0);
        // Pick the highest-scored non-onion local address as our public IP.
        let local_addr = r
            .get("localaddresses")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| {
                        let addr = a.get("address").and_then(Value::as_str)?;
                        if addr.ends_with(".onion") {
                            return None;
                        }
                        let score = a.get("score").and_then(Value::as_i64).unwrap_or(0);
                        Some((score, addr.to_string()))
                    })
                    .max_by_key(|(s, _)| *s)
                    .map(|(_, a)| a)
            })
            .flatten();
        Ok((version, subversion, services, local_addr))
    }

    /// Directly connected peers: returns `(Peer, subver, protocol_version, startingheight)`.
    pub fn peer_info(&self) -> Result<Vec<(Peer, String, i32, i32)>> {
        let r = self.call("getpeerinfo", json!([]))?;
        let arr = r.as_array().cloned().unwrap_or_default();
        let mut peers = Vec::new();
        for p in arr {
            let addr_str = p.get("addr").and_then(Value::as_str).unwrap_or("");
            let subver = p
                .get("subver")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let version = p.get("version").and_then(Value::as_i64).unwrap_or(0) as i32;
            let height = p.get("startingheight").and_then(Value::as_i64).unwrap_or(0) as i32;
            // getpeerinfo returns clearnet and onion addresses; keep both.
            if let Some(peer) = Peer::parse(addr_str, 8333) {
                peers.push((peer, subver, version, height));
            }
        }
        Ok(peers)
    }

    /// Scan the last `window` block headers and count how many signal BIP-110 (bit `bit`,
    /// default 4). This is the authoritative, network-wide miner signalling figure.
    /// Returns the period tally plus the heights of every signalling block found in it. The
    /// walk already visits each header, so collecting the heights is free — and it's what
    /// lets the explorer show an authoritative list of the period's BIP-110 blocks rather
    /// than only the ones that happen to be in the recent window.
    pub fn signalling(&self, window: u32, bit: u8) -> Result<(SignalStats, Vec<i64>)> {
        let chaininfo = self.call("getblockchaininfo", json!([]))?;
        let tip = chaininfo
            .get("blocks")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("getblockchaininfo: no height"))?;

        let mask: i64 = 1 << bit;
        let mut signalling_heights: Vec<i64> = Vec::new();
        let mut scanned = 0u32;
        // Count within the CURRENT difficulty adjustment period (retarget-aligned), not a
        // rolling "last `window` blocks" window. BIP9/BIP8 tally signalling per 2016-block
        // period and evaluate lock-in at the retarget boundary, so we scan from the first
        // block of the current period (height divisible by the period) up to the tip.
        let period = (window as i64).max(1);
        let start = (tip / period) * period;
        for h in start..=tip {
            let hash = self.call("getblockhash", json!([h]))?;
            let hash = hash.as_str().ok_or_else(|| anyhow!("getblockhash: not str"))?;
            // verbosity 1 header is enough; avoids pulling full blocks.
            let header = self.call("getblockheader", json!([hash, true]))?;
            let ver = header.get("version").and_then(Value::as_i64).unwrap_or(0);
            // A BIP9-style deployment also sets the top bits (0x20000000). We just test
            // the deployment bit itself, matching how signalling is normally counted.
            if ver & mask != 0 {
                signalling_heights.push(h);
            }
            scanned += 1;
        }
        let signalling = signalling_heights.len() as u32;
        let percent = if scanned > 0 {
            signalling as f64 / scanned as f64 * 100.0
        } else {
            0.0
        };
        Ok((
            SignalStats {
                window,
                blocks_scanned: scanned,
                blocks_signalling: signalling,
                percent,
                bit,
                threshold_percent: 55.0, // BIP-110: 1109/2016
                tip_height: tip,
            },
            signalling_heights,
        ))
    }

    /// Our block hash at `height`, in **internal (wire) byte order** — the RPC returns it in
    /// display order, which is byte-reversed, and the P2P locator needs the wire form.
    pub fn block_hash_at(&self, height: i64) -> Result<[u8; 32]> {
        let v = self.call("getblockhash", json!([height]))?;
        let s = v.as_str().ok_or_else(|| anyhow!("getblockhash: not a string"))?;
        if s.len() != 64 {
            bail!("getblockhash: expected 64 hex chars, got {}", s.len());
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[31 - i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow!("getblockhash: bad hex"))?;
        }
        Ok(out)
    }

    /// Every chain tip the node knows about (`getchaintips`).
    ///
    /// This is how a consensus split is seen from the inside. A node enforcing BIP-110 that
    /// rejects a non-signalling branch reports that branch with `status: "invalid"` and a
    /// `branchlen` that grows as the other side keeps building — exactly the signature of a
    /// mandatory-signalling split. Ordinary orphan races also show up here, but only as
    /// 1–2 block branches that resolve, which is why the caller applies a length threshold.
    pub fn chain_tips(&self) -> Result<Vec<ChainTip>> {
        let v = self.call("getchaintips", json!([]))?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .map(|t| ChainTip {
                        height: t.get("height").and_then(Value::as_i64).unwrap_or(0),
                        hash: t.get("hash").and_then(Value::as_str).unwrap_or("").to_string(),
                        branchlen: t.get("branchlen").and_then(Value::as_i64).unwrap_or(0),
                        status: t.get("status").and_then(Value::as_str).unwrap_or("").to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// A snapshot of the node's mempool: aggregate stats from `getmempoolinfo` plus a
    /// fee-rate histogram and next-block feerate estimate built from `getrawmempool(true)`.
    ///
    /// The verbose mempool listing is the expensive part — one entry per pending
    /// transaction — so callers should poll this on its own cadence rather than on every
    /// block (the mempool changes continuously, unlike blocks).
    pub fn mempool_snapshot(&self) -> Result<MempoolSnapshot> {
        let info = self.call("getmempoolinfo", json!([]))?;
        let pending = info.get("size").and_then(Value::as_u64).unwrap_or(0) as u32;
        let vsize = info.get("bytes").and_then(Value::as_i64).unwrap_or(0);
        let usage_bytes = info.get("usage").and_then(Value::as_i64).unwrap_or(0);
        let total_fee = info.get("total_fee").and_then(Value::as_f64).unwrap_or(0.0);
        // mempoolminfee is BTC/kvB; sat/vB = btc * 1e8 sats/BTC / 1000 vB/kvB.
        let min_relay_feerate =
            info.get("mempoolminfee").and_then(Value::as_f64).unwrap_or(0.0) * 1e8 / 1000.0;

        let raw = self.call("getrawmempool", json!([true]))?;
        let entries = raw.as_object().cloned().unwrap_or_default();
        let mut rates: Vec<(f64, i64)> = Vec::with_capacity(entries.len());
        for e in entries.values() {
            let vs = e.get("vsize").and_then(Value::as_i64).unwrap_or(0);
            if vs <= 0 {
                continue;
            }
            let fee_btc = e
                .get("fees")
                .and_then(|f| f.get("base"))
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            rates.push((fee_btc * 1e8 / vs as f64, vs));
        }

        Ok(MempoolSnapshot {
            pending,
            vsize,
            usage_bytes,
            total_fee,
            min_relay_feerate,
            histogram: bucket_histogram(&rates),
            next_block_feerate: next_block_feerate(&rates),
        })
    }

    /// Current best-block height (`getblockcount`) — a cheap tip check used to decide
    /// whether a fresh (expensive) signalling scan is warranted.
    pub fn block_count(&self) -> Result<i64> {
        let v = self.call("getblockcount", json!([]))?;
        v.as_i64().ok_or_else(|| anyhow!("getblockcount: not an integer"))
    }

    /// The newest `count` blocks (newest first) with the details the explorer shows, and
    /// whether each signals BIP-110 on `bit`.
    ///
    /// Uses `getblock` verbosity 1 (header + txids, no tx bodies) so a screenful of blocks
    /// is cheap. The coinbase's scriptSig is fetched separately for the miner tag, since
    /// verbosity 1 gives only txids.
    pub fn recent_blocks(&self, count: u32, bit: u8) -> Result<Vec<BlockInfo>> {
        let tip = self.block_count()?;
        let mask: i64 = 1 << bit;
        let mut out = Vec::new();
        for h in (0..count as i64).map(|i| tip - i).take_while(|h| *h >= 0) {
            out.push(self.block_info(h, mask)?);
        }
        Ok(out)
    }

    /// Full explorer detail for a specific list of heights, in the order given. Used to
    /// backfill the current period's signalling blocks that fall outside the recent window,
    /// so the "signalling this period" list is complete rather than limited to recent blocks.
    pub fn blocks_at_heights(&self, heights: &[i64], bit: u8) -> Result<Vec<BlockInfo>> {
        let mask: i64 = 1 << bit;
        heights.iter().map(|&h| self.block_info(h, mask)).collect()
    }

    /// Assemble the explorer's `BlockInfo` for one height: `getblock` verbosity 1 (header +
    /// txids, no tx bodies) plus a separate coinbase fetch for the miner tag.
    fn block_info(&self, height: i64, mask: i64) -> Result<BlockInfo> {
        let hash = self.call("getblockhash", json!([height]))?;
        let hash = hash.as_str().ok_or_else(|| anyhow!("getblockhash: not str"))?;
        let b = self.call("getblock", json!([hash, 1]))?;
        let version = b.get("version").and_then(Value::as_i64).unwrap_or(0);
        let txids: Vec<&str> = b
            .get("tx")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        // Miner tag: the coinbase scriptSig traditionally carries a pool identifier.
        let miner = match txids.first() {
            Some(txid) => self.coinbase_tag(txid, hash).unwrap_or_default(),
            None => String::new(),
        };
        Ok(BlockInfo {
            height,
            hash: hash.to_string(),
            time: b.get("time").and_then(Value::as_i64).unwrap_or(0),
            version,
            signals: version & mask != 0,
            tx_count: txids.len() as u32,
            size: b.get("size").and_then(Value::as_i64).unwrap_or(0),
            weight: b.get("weight").and_then(Value::as_i64).unwrap_or(0),
            miner,
        })
    }

    /// Fee/economic stats for a block (`getblockstats`).
    ///
    /// One cheap call — Core computes this from the block plus its undo data, so we don't
    /// have to fetch previous outputs ourselves to work out fees. Needs the block to still
    /// be on disk, so on a pruned node this fails for blocks past the prune horizon.
    pub fn block_stats(&self, height: i64) -> Result<BlockStats> {
        let v = self.call("getblockstats", json!([height]))?;
        let g = |k: &str| v.get(k).and_then(Value::as_i64).unwrap_or(0);
        Ok(BlockStats {
            total_fee: g("totalfee"),
            subsidy: g("subsidy"),
            avg_feerate: g("avgfeerate"),
            median_feerate: g("medianfeerate"),
            min_feerate: g("minfeerate"),
            max_feerate: g("maxfeerate"),
            feerate_percentiles: v
                .get("feerate_percentiles")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_i64).collect())
                .unwrap_or_default(),
            total_out: g("total_out"),
            avg_tx_size: g("avgtxsize"),
            ins: g("ins"),
            outs: g("outs"),
        })
    }

    /// Scan a block's transactions for data payloads (inscriptions, runes, OP_RETURN).
    ///
    /// Uses `getblock` verbosity 2, which returns every transaction decoded — the only way
    /// to see witness contents. That's a large response (tens of MB on a full block), so
    /// callers should analyse each block once, not repeatedly.
    pub fn analyze_block(&self, hash: &str) -> Result<BlockPayload> {
        // Byte signatures.
        //  * Inscription envelope: OP_FALSE OP_IF, then a 3-byte push of "ord".
        //    00 63 03 6f 72 64
        //  * Runestone output: OP_RETURN OP_13 -> scriptPubKey begins 6a 5d.
        const ORD_ENVELOPE: &str = "0063036f7264";
        const MAX_WITNESS_ITEM: usize = 256; // BIP-110 rule 2 reduced push limit
        const MAX_OP_RETURN_SPK: usize = 83; // BIP-110 rule 1 data-carrier scriptPubKey limit
        const MAX_OUTPUT_SPK: usize = 34; // BIP-110 rule 1 non-OP_RETURN output limit

        let block = self.call("getblock", json!([hash, 2]))?;
        let txs = block.get("tx").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut p = BlockPayload::default();

        for tx in &txs {
            let vin = tx.get("vin").and_then(Value::as_array);
            // Skip the coinbase: its scriptSig is miner tag data, not a user payload.
            if vin.and_then(|v| v.first()).map_or(false, |v| v.get("coinbase").is_some()) {
                continue;
            }
            p.tx_total += 1;
            let weight = tx.get("weight").and_then(Value::as_i64).unwrap_or(0);

            // --- witness: inscriptions, oversized pushes, Taproot annex ---
            let (mut has_insc, mut insc_bytes, mut oversized, mut has_annex) =
                (false, 0i64, false, false);
            if let Some(vin) = vin {
                for input in vin {
                    if let Some(w) = input.get("txinwitness").and_then(Value::as_array) {
                        // Rule 4: a Taproot annex. Per BIP341 the annex is the last witness
                        // element when there are >= 2 elements and it begins with 0x50. We
                        // only flag it on a script-path spend — the preceding element is a
                        // control block (leaf version 0xc0/0xc1) — which is unambiguous and
                        // avoids false positives on non-Taproot witnesses. (A key-path annex
                        // is far rarer and not distinguishable here, so it isn't counted.)
                        if w.len() >= 2 {
                            let last = w[w.len() - 1].as_str().unwrap_or("");
                            let prev = w[w.len() - 2].as_str().unwrap_or("");
                            if last.starts_with("50") && (prev.starts_with("c0") || prev.starts_with("c1")) {
                                has_annex = true;
                            }
                        }
                        for item in w.iter().filter_map(Value::as_str) {
                            let bytes = (item.len() / 2) as i64;
                            if bytes as usize > MAX_WITNESS_ITEM {
                                oversized = true;
                            }
                            if item.contains(ORD_ENVELOPE) {
                                has_insc = true;
                                insc_bytes += bytes;
                            }
                        }
                    }
                }
            }

            // --- outputs: runestones, OP_RETURN carriers, and rule-1 size violations ---
            let (mut has_rune, mut has_data, mut oversized_output) = (false, false, false);
            let (mut rune_bytes, mut data_bytes) = (0i64, 0i64);
            if let Some(vout) = tx.get("vout").and_then(Value::as_array) {
                for out in vout {
                    let spk = out
                        .get("scriptPubKey")
                        .and_then(|s| s.get("hex"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let bytes = (spk.len() / 2) as i64;
                    if spk.starts_with("6a") {
                        // OP_RETURN data carrier — rule 1 allows up to 83 bytes. Applies to
                        // any OP_RETURN, runestones included: only *small* ones stay valid.
                        // (Bitcoin Core v30 lifted the datacarrier relay cap, so >83-byte
                        // OP_RETURNs now appear on-chain.)
                        if bytes as usize > MAX_OP_RETURN_SPK {
                            oversized_output = true;
                        }
                        if spk.starts_with("6a5d") {
                            has_rune = true;
                            rune_bytes += bytes;
                        } else {
                            has_data = true;
                            data_bytes += bytes;
                        }
                    } else if bytes as usize > MAX_OUTPUT_SPK {
                        // Any other output — rule 1 allows up to 34 bytes, which covers every
                        // standard type. Larger ones (bare P2PK, bare multisig, oddball
                        // scripts) would be invalid under BIP-110.
                        oversized_output = true;
                    }
                }
            }

            if has_insc {
                p.insc_count += 1;
                p.insc_weight += weight;
                p.insc_bytes += insc_bytes;
            }
            if has_rune {
                p.rune_count += 1;
                p.rune_weight += weight;
                p.rune_bytes += rune_bytes;
            }
            if has_data {
                p.data_count += 1;
                p.data_weight += weight;
                p.data_bytes += data_bytes;
            }
            if has_insc || has_rune || has_data {
                p.payload_tx_count += 1;
                p.payload_weight += weight;
            }
            // BIP-110 rejects, by rule: an inscription (rule 7, executes OP_IF), an oversized
            // witness push (rule 2), an output over its rule-1 size limit (34B, or 83B for
            // OP_RETURN), or a Taproot annex (rule 4). A runestone/OP_RETURN within 83 bytes
            // is valid, so it is not a reject on its own.
            if has_insc || oversized || oversized_output || has_annex {
                p.bip110_reject_count += 1;
                p.bip110_reject_weight += weight;
            }
        }
        Ok(p)
    }

    /// Best-effort miner name from the coinbase scriptSig's ASCII run. Returns an empty
    /// string when the node has no tx index for the lookup or nothing legible is found.
    fn coinbase_tag(&self, txid: &str, block_hash: &str) -> Result<String> {
        let tx = self.call("getrawtransaction", json!([txid, true, block_hash]))?;
        let sig = tx
            .get("vin")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|v| v.get("coinbase"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        Ok(parse_coinbase_tag(sig))
    }
}

/// Pull a display-ready `pool` or `pool · miner` tag out of a coinbase scriptSig (hex).
///
/// First collect every printable-ASCII run in the scriptSig — the pool tag lives amongst the
/// height push, extranonce and witness commitment, which is noise around it, not part of it.
/// The pool name comes from the longest such run: that noise is almost always shorter than a
/// deliberate tag. The run is then unwrapped, since tags are conventionally slash-delimited
/// (`/Foundry USA Pool #dropgold/`) — and the pool name is the first *substantial* segment
/// there (>= 3 chars), not simply the first non-empty one: a stray printable byte from the
/// extranonce often lands right against the tag with no delimiter of its own (`k/Foundry USA
/// Pool #dropgold/`), which would otherwise be mistaken for the whole pool name.
///
/// An individual miner's own tag, appended after the pool name when present, is real for
/// exactly one pool we've seen: Ocean's DATUM software lets each miner set their own identity,
/// surfaced as either a later slash segment or (Ocean's actual convention) a wholly separate
/// ASCII run elsewhere in the scriptSig (its own tag is stored as `< OCEAN.XYZ >`, alongside a
/// lone `Roughnecks`- or `Peak Mining`-style run). Other pools' extra segments/runs are just
/// extranonce noise that happens to be printable — appending those as if they were a deliberate
/// tag was tried and confirmed (against this project's own crawled blocks) to mostly produce
/// garbage, so the lookup is scoped to Ocean rather than attempted for every pool.
fn parse_coinbase_tag(sig_hex: &str) -> String {
    let bytes: Vec<u8> = (0..sig_hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).ok())
        .collect();

    // Every printable-ASCII run, in the order each appears in the scriptSig.
    let mut runs: Vec<String> = Vec::new();
    let mut cur = String::new();
    for b in bytes {
        if (0x20..0x7f).contains(&b) {
            cur.push(b as char);
        } else if !cur.is_empty() {
            runs.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        runs.push(cur);
    }
    if runs.is_empty() {
        return String::new();
    }

    let mut best_idx = 0;
    for (i, r) in runs.iter().enumerate() {
        if r.len() > runs[best_idx].len() {
            best_idx = i;
        }
    }
    let best = &runs[best_idx];

    let segments: Vec<&str> = best.split('/').map(clean_tag).filter(|s| !s.is_empty()).collect();
    let pool_pos = segments.iter().position(|s| s.len() >= 3).unwrap_or(0);
    let pool: String = segments
        .get(pool_pos)
        .copied()
        .unwrap_or_else(|| clean_tag(best))
        .chars()
        .take(32)
        .collect();

    let miner = if pool.eq_ignore_ascii_case("OCEAN.XYZ") || pool.eq_ignore_ascii_case("OCEAN") {
        segments
            .get(pool_pos.saturating_add(1)..)
            .and_then(|rest| rest.iter().find(|s| s.len() >= 4))
            .map(|s| s.to_string())
            .or_else(|| {
                runs.iter()
                    .enumerate()
                    .filter(|(i, r)| *i != best_idx && clean_tag(r).len() >= 4)
                    .map(|(_, r)| clean_tag(r).to_string())
                    .next()
            })
    } else {
        None
    };

    match miner {
        Some(m) if !m.is_empty() && !m.eq_ignore_ascii_case(&pool) => {
            let m: String = m.chars().take(32).collect();
            format!("{pool} · {m}")
        }
        _ => pool,
    }
}

/// Trim whitespace and the decorative wrapper punctuation some pools pad their tag with
/// (Ocean's is stored as `< OCEAN.XYZ >`), without touching punctuation inside the tag itself.
fn clean_tag(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '<' || c == '>')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hex-encode an ASCII coinbase tag with the binary noise that surrounds it in a real
    /// scriptSig: a height push in front, an extranonce behind.
    fn coinbase_hex(tag: &str) -> String {
        let mut s = String::from("03a1b2c300");
        for b in tag.bytes() {
            s.push_str(&format!("{b:02x}"));
        }
        s.push_str("00deadbeef");
        s
    }

    #[test]
    fn coinbase_tag_is_unwrapped_from_its_slash_delimiters() {
        let t = |tag: &str| parse_coinbase_tag(&coinbase_hex(tag));

        // The common case: the whole tag is wrapped, so both delimiters must come off.
        assert_eq!(t("/Foundry USA Pool #dropgold/"), "Foundry USA Pool #dropgold");
        // Long tags are still capped, but the cap now clears the real pool names.
        assert_eq!(t(&format!("/{}/", "x".repeat(50))), "x".repeat(32));
        assert_eq!(t("/slush/"), "slush");
        // Multi-segment tags are only enriched with a miner sub-tag for Ocean (see the test
        // below) — for every other pool the trailing segment is real-world extranonce noise
        // more often than a deliberate tag, so it's dropped just like before.
        assert_eq!(t("/ViaBTC/Mined by someminer123/"), "ViaBTC");
        assert_eq!(t("/F2Pool/Mined by user/"), "F2Pool");
        // Unwrapped and unslashed tags must survive untouched.
        assert_eq!(t("Mined by AntPool"), "Mined by AntPool");
        assert_eq!(t("BTC.COM"), "BTC.COM");
        // Nothing legible in the scriptSig at all.
        assert_eq!(parse_coinbase_tag("03a1b2c300ff"), "");
        assert_eq!(parse_coinbase_tag(""), "");
    }

    #[test]
    fn a_stray_leading_byte_glued_onto_the_tag_is_not_mistaken_for_the_pool_name() {
        // Real Foundry blocks often have a lone printable extranonce byte land directly
        // against the leading `/`, with no non-printable byte separating them, e.g. this
        // block's actual scriptSig ASCII run: "k/Foundry USA Pool #dropgold/`R". Naively
        // taking the first non-empty `/`-segment would name the pool "k".
        let hex = coinbase_hex("k/Foundry USA Pool #dropgold/`R");
        assert_eq!(parse_coinbase_tag(&hex), "Foundry USA Pool #dropgold");
    }

    #[test]
    fn coinbase_tag_picks_up_a_separate_run_as_the_miner_tag_for_ocean_only() {
        // Ocean's DATUM software writes the pool's own tag and the individual miner's tag as
        // two distinct ASCII runs with no shared `/` delimiter — unlike the wrapped-segment
        // convention above — and pads its own tag (`< OCEAN.XYZ >`) wide enough that it, not
        // the miner's name, is still the longest run and so is picked as the pool.
        let two_runs = |pool: &str, miner: &str| {
            let mut hex = String::from("03a1b2c300");
            for b in pool.bytes() {
                hex.push_str(&format!("{b:02x}"));
            }
            hex.push_str("00");
            for b in miner.bytes() {
                hex.push_str(&format!("{b:02x}"));
            }
            hex.push_str("00deadbeef");
            hex
        };

        assert_eq!(
            parse_coinbase_tag(&two_runs("< OCEAN.XYZ >", "Roughnecks")),
            "OCEAN.XYZ · Roughnecks"
        );
        // Same layout for a pool this project has no special knowledge of: the second run is
        // left alone rather than guessed at, because for every other pool we've actually seen
        // crawled, that second run turns out to be extranonce noise, not a deliberate tag.
        assert_eq!(
            parse_coinbase_tag(&two_runs("< SomeOtherPool >", "Roughnecks")),
            "SomeOtherPool"
        );
    }

    /// Build a fake `getblock` verbosity-2 response so the classifier can be exercised
    /// against real byte signatures without a node.
    fn block(txs: Vec<Value>) -> Value {
        let mut all = vec![json!({ "weight": 800, "vin": [{ "coinbase": "03abcdef" }], "vout": [] })];
        all.extend(txs);
        json!({ "tx": all })
    }

    fn tx(weight: i64, witness: Vec<&str>, spks: Vec<&str>) -> Value {
        json!({
            "weight": weight,
            "vin": [{ "txinwitness": witness }],
            "vout": spks.iter().map(|h| json!({ "scriptPubKey": { "hex": h } })).collect::<Vec<_>>(),
        })
    }

    /// The classifier, run directly on a parsed block (mirrors `analyze_block`'s body).
    fn classify(v: &Value) -> BlockPayload {
        const ORD_ENVELOPE: &str = "0063036f7264";
        const MAX_WITNESS_ITEM: usize = 256;
        const MAX_OP_RETURN_SPK: usize = 83;
        const MAX_OUTPUT_SPK: usize = 34;
        let mut p = BlockPayload::default();
        for tx in v.get("tx").and_then(Value::as_array).unwrap() {
            let vin = tx.get("vin").and_then(Value::as_array);
            if vin.and_then(|x| x.first()).map_or(false, |x| x.get("coinbase").is_some()) {
                continue;
            }
            p.tx_total += 1;
            let weight = tx.get("weight").and_then(Value::as_i64).unwrap_or(0);
            let (mut has_insc, mut insc_bytes, mut oversized, mut has_annex) =
                (false, 0i64, false, false);
            if let Some(vin) = vin {
                for i in vin {
                    if let Some(w) = i.get("txinwitness").and_then(Value::as_array) {
                        if w.len() >= 2 {
                            let last = w[w.len() - 1].as_str().unwrap_or("");
                            let prev = w[w.len() - 2].as_str().unwrap_or("");
                            if last.starts_with("50") && (prev.starts_with("c0") || prev.starts_with("c1")) {
                                has_annex = true;
                            }
                        }
                        for item in w.iter().filter_map(Value::as_str) {
                            let b = (item.len() / 2) as i64;
                            if b as usize > MAX_WITNESS_ITEM { oversized = true; }
                            if item.contains(ORD_ENVELOPE) { has_insc = true; insc_bytes += b; }
                        }
                    }
                }
            }
            let (mut has_rune, mut has_data, mut oversized_output) = (false, false, false);
            if let Some(vout) = tx.get("vout").and_then(Value::as_array) {
                for o in vout {
                    let spk = o.get("scriptPubKey").and_then(|s| s.get("hex")).and_then(Value::as_str).unwrap_or("");
                    let bytes = spk.len() / 2;
                    if spk.starts_with("6a") {
                        if bytes > MAX_OP_RETURN_SPK { oversized_output = true; }
                        if spk.starts_with("6a5d") { has_rune = true; } else { has_data = true; }
                    } else if bytes > MAX_OUTPUT_SPK {
                        oversized_output = true;
                    }
                }
            }
            if has_insc { p.insc_count += 1; p.insc_weight += weight; p.insc_bytes += insc_bytes; }
            if has_rune { p.rune_count += 1; p.rune_weight += weight; }
            if has_data { p.data_count += 1; p.data_weight += weight; }
            if has_insc || has_rune || has_data { p.payload_tx_count += 1; p.payload_weight += weight; }
            if has_insc || oversized || oversized_output || has_annex { p.bip110_reject_count += 1; p.bip110_reject_weight += weight; }
        }
        p
    }

    #[test]
    fn detects_inscriptions_runes_and_opreturn() {
        // Inscription: OP_FALSE OP_IF <push "ord"> ... inside a tapscript witness.
        let insc_witness = format!("20{}0063036f7264510b48656c6c6f21", "ab".repeat(32));
        let b = block(vec![
            tx(1200, vec![&insc_witness], vec!["0014abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"]),
            // Runestone: OP_RETURN OP_13 ...
            tx(600, vec![], vec!["6a5d0714c0a233c0843d"]),
            // Plain OP_RETURN data carrier (not a runestone).
            tx(700, vec![], vec!["6a4c50", "0014ffffffffffffffffffffffffffffffffffffffff"]),
            // Ordinary payment: no payload at all.
            tx(560, vec!["3045022100"], vec!["0014deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]),
        ]);
        let p = classify(&b);

        assert_eq!(p.tx_total, 4, "coinbase excluded");
        assert_eq!(p.insc_count, 1);
        assert_eq!(p.rune_count, 1, "6a5d is a runestone, not generic OP_RETURN");
        assert_eq!(p.data_count, 1, "6a4c50 is a plain data carrier, not a rune");
        assert_eq!(p.payload_tx_count, 3, "the plain payment carries nothing");
        assert_eq!(p.payload_weight, 1200 + 600 + 700);

        // BIP-110 rejects the inscription but NOT the runestone: a small OP_RETURN stays
        // valid under rule 1's 83-byte allowance.
        assert_eq!(p.bip110_reject_count, 1);
        assert_eq!(p.bip110_reject_weight, 1200);
    }

    #[test]
    fn oversized_witness_push_counts_as_a_bip110_reject() {
        // 300 bytes > the 256-byte reduced push limit (rule 2), with no "ord" envelope.
        let big = "cd".repeat(300);
        let p = classify(&block(vec![tx(2000, vec![&big], vec![])]));
        assert_eq!(p.insc_count, 0, "no envelope, so not an inscription");
        assert_eq!(p.payload_tx_count, 0, "an oversized push is not a 'data payload' category");
        assert_eq!(p.bip110_reject_count, 1, "but rule 2 would still reject it");

        // A 200-byte item is under the limit and must not be flagged.
        let ok = "cd".repeat(200);
        assert_eq!(classify(&block(vec![tx(900, vec![&ok], vec![])])).bip110_reject_count, 0);
    }

    #[test]
    fn op_return_over_83_bytes_counts_as_a_rule_1_reject() {
        // 6a 4c <89 bytes> = a 91-byte OP_RETURN scriptPubKey, over rule 1's 83-byte limit.
        let big = |lead: &str| format!("{lead}{}", "ab".repeat(89));
        let b = block(vec![
            tx(800, vec![], vec![&big("6a4c")]),            // generic OP_RETURN, oversized
            tx(900, vec![], vec![&big("6a5d")]),            // runestone, oversized
            tx(600, vec![], vec!["6a5d0714c0a233c0843d"]),  // small runestone, valid
            tx(560, vec![], vec!["6a4c50"]),                // small OP_RETURN, valid
        ]);
        let p = classify(&b);
        // Both oversized OP_RETURNs are rule-1 rejects; the small ones are not — a runestone
        // is exempt only by size, not unconditionally.
        assert_eq!(p.bip110_reject_count, 2);
        assert_eq!(p.bip110_reject_weight, 800 + 900);
        assert_eq!(p.rune_count, 2, "both runestones are still classified as runestones");
    }

    #[test]
    fn non_op_return_output_over_34_bytes_is_a_rule_1_reject() {
        // A 40-byte non-OP_RETURN output (bare/oddball script) exceeds rule 1's 34-byte
        // output limit; a 34-byte P2WSH is exactly at the limit and stays valid.
        let big_spk = "ab".repeat(40); // 40 bytes, not OP_RETURN
        let p2wsh = format!("0020{}", "cd".repeat(32)); // 34 bytes — the standard maximum
        let p = classify(&block(vec![
            tx(700, vec![], vec![&big_spk]),
            tx(600, vec![], vec![&p2wsh]),
        ]));
        assert_eq!(p.bip110_reject_count, 1, "only the >34-byte output is a rule-1 reject");
        assert_eq!(p.bip110_reject_weight, 700);
    }

    #[test]
    fn taproot_annex_is_a_rule_4_reject() {
        // Taproot script-path spend WITH annex: [tapscript, control_block(0xc0…), annex(0x50…)].
        let script = format!("20{}ac", "ab".repeat(32));
        let control = format!("c0{}", "cd".repeat(32)); // 33-byte control block, leaf ver 0xc0
        let annex = "50aabbcc"; // annex marker byte 0x50
        let p = classify(&block(vec![
            tx(1000, vec![&script, &control, annex], vec![]), // with annex → reject
            tx(900, vec![&script, &control], vec![]),         // no annex → valid
        ]));
        assert_eq!(p.bip110_reject_count, 1, "only the annex-carrying spend is a rule-4 reject");
        assert_eq!(p.bip110_reject_weight, 1000);
    }

    #[test]
    fn histogram_buckets_by_feerate_and_drops_empty_bands() {
        let rates = vec![(0.5, 100), (0.9, 50), (5.5, 200), (5.7, 300), (5000.0, 10)];
        let hist = bucket_histogram(&rates);
        // Bands with no transactions (e.g. 2–3 sat/vB) are omitted entirely, so the list is
        // far shorter than the full edge table.
        assert_eq!(hist.len(), 3);

        let below_one = &hist[0];
        assert_eq!(below_one.min_feerate, 0.0);
        assert_eq!(below_one.max_feerate, Some(1.0));
        assert_eq!(below_one.count, 2);
        assert_eq!(below_one.vsize, 150);

        let five_to_six = &hist[1];
        assert_eq!(five_to_six.min_feerate, 5.0);
        assert_eq!(five_to_six.max_feerate, Some(6.0));
        assert_eq!(five_to_six.count, 2);
        assert_eq!(five_to_six.vsize, 500);

        let top = &hist[2];
        assert_eq!(top.min_feerate, 1000.0);
        assert_eq!(top.max_feerate, None, "the top band is open-ended");
        assert_eq!(top.count, 1);
    }

    #[test]
    fn next_block_feerate_walks_highest_first_until_a_block_fills() {
        // Two transactions of 600,000 vsize each: the higher-feerate one alone doesn't fill
        // a block, but combined with the second it crosses the 1,000,000 vsize line — so the
        // reported feerate is the SECOND (lower) transaction's, not the first.
        let rates = vec![(50.0, 600_000), (10.0, 600_000)];
        assert_eq!(next_block_feerate(&rates), Some(10.0));
    }

    #[test]
    fn next_block_feerate_is_none_when_mempool_is_smaller_than_a_block() {
        let rates = vec![(50.0, 1_000), (10.0, 2_000)];
        assert_eq!(next_block_feerate(&rates), None);
    }
}

fn basic_auth_header(user: &str, pass: &str) -> String {
    let raw = format!("{user}:{pass}");
    format!("Basic {}", base64_encode(raw.as_bytes()))
}

/// Small self-contained base64 encoder (avoids pulling in a crate just for auth).
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
