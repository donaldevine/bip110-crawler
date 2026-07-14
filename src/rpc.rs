//! Bitcoin Core JSON-RPC client (only the calls the crawler needs).
//!
//! Supports either explicit `--rpc-user/--rpc-pass` or a `.cookie` file written by
//! bitcoind (`__cookie__:<hex>`), passed as user:pass.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

use crate::node::SignalStats;
use crate::p2p::Peer;

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
    pub fn signalling(&self, window: u32, bit: u8) -> Result<SignalStats> {
        let chaininfo = self.call("getblockchaininfo", json!([]))?;
        let tip = chaininfo
            .get("blocks")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("getblockchaininfo: no height"))?;

        let mask: i64 = 1 << bit;
        let mut signalling = 0u32;
        let mut scanned = 0u32;
        let start = (tip - window as i64 + 1).max(0);
        for h in start..=tip {
            let hash = self.call("getblockhash", json!([h]))?;
            let hash = hash.as_str().ok_or_else(|| anyhow!("getblockhash: not str"))?;
            // verbosity 1 header is enough; avoids pulling full blocks.
            let header = self.call("getblockheader", json!([hash, true]))?;
            let ver = header.get("version").and_then(Value::as_i64).unwrap_or(0);
            // A BIP9-style deployment also sets the top bits (0x20000000). We just test
            // the deployment bit itself, matching how signalling is normally counted.
            if ver & mask != 0 {
                signalling += 1;
            }
            scanned += 1;
        }
        let percent = if scanned > 0 {
            signalling as f64 / scanned as f64 * 100.0
        } else {
            0.0
        };
        Ok(SignalStats {
            window,
            blocks_scanned: scanned,
            blocks_signalling: signalling,
            percent,
            bit,
            threshold_percent: 55.0, // BIP-110: 1109/2016
            tip_height: tip,
        })
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
