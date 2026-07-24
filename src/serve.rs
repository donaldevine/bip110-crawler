//! Tiny embedded HTTP API (`serve` mode). Reads the SQLite DB the crawler writes and
//! serves the page plus JSON endpoints. No async runtime — a small fixed thread pool of
//! blocking workers, each with its own read connection.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::{db, report};

/// Social-preview image, embedded so it's served with no external file dependency.
const OG_IMAGE: &[u8] = include_bytes!("../assets/summary_large_image.png");

/// Donation details for the `/support` page. Loaded at startup from gitignored files
/// (`assets/support.json` + the QR PNGs) so they are served live but never committed.
/// The page HTML is prerendered once; missing files yield a "not configured" page.
struct Support {
    html: String,
    btc_qr: Option<Vec<u8>>,
    ln_qr: Option<Vec<u8>>,
}

#[derive(serde::Deserialize, Default)]
struct SupportConfig {
    #[serde(default)]
    bitcoin_address: String,
    #[serde(default)]
    lightning_address: String,
}

fn load_support() -> Support {
    let cfg: SupportConfig = std::fs::read_to_string("assets/support.json")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let btc_qr = std::fs::read("assets/bitcoin.png").ok();
    let ln_qr = std::fs::read("assets/lightning.png").ok();
    let html = report::render_support_html(
        &cfg.bitcoin_address,
        &cfg.lightning_address,
        btc_qr.is_some(),
        ln_qr.is_some(),
    );
    Support { html, btc_qr, ln_qr }
}

/// Serve the pages + API from `db_path`. `max_age_secs` is the freshness window: nodes
/// not confirmed reachable within it are treated as gone (0 disables aging).
pub fn serve(db_path: &Path, port: u16, max_age_secs: u64) -> Result<()> {
    let server = tiny_http::Server::http(("127.0.0.1", port))
        .map_err(|e| anyhow!("binding 127.0.0.1:{port}: {e}"))?;
    let server = Arc::new(server);
    let page = Arc::new(report::render_api_html());
    let support = Arc::new(load_support());
    eprintln!("[serve] http://127.0.0.1:{port}  (db: {})", db_path.display());
    eprintln!(
        "[serve] /support: bitcoin={} lightning={}",
        if support.html.contains("bitcoin:") { "yes" } else { "no" },
        if support.html.contains("lightning:") { "yes" } else { "no" },
    );
    eprintln!("[serve] point your Cloudflare tunnel at this port.");

    let mut handles = Vec::new();
    for _ in 0..4 {
        let server = Arc::clone(&server);
        let page = Arc::clone(&page);
        let support = Arc::clone(&support);
        let db_path = db_path.to_path_buf();
        handles.push(std::thread::spawn(move || {
            // Each worker gets its own connection (rusqlite Connection isn't Sync).
            let conn = match db::open(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[serve] worker db open failed: {e:#}");
                    return;
                }
            };
            loop {
                match server.recv() {
                    Ok(req) => handle(&conn, &page, &support, max_age_secs, req),
                    Err(_) => break,
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn json_header() -> tiny_http::Header {
    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}
fn html_header() -> tiny_http::Header {
    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap()
}

fn handle(
    conn: &rusqlite::Connection,
    page: &str,
    support: &Support,
    max_age_secs: u64,
    req: tiny_http::Request,
) {
    let url = req.url().to_string();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p, parse_query(q)),
        None => (url.as_str(), HashMap::new()),
    };

    // Binary asset: the social-preview image (served straight from the embedded bytes).
    if path == "/summary_large_image.png" {
        let hdr = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"image/png"[..]).unwrap();
        let _ = req.respond(tiny_http::Response::from_data(OG_IMAGE).with_header(hdr));
        return;
    }

    // "Why support BIP-110?" explainer (static content + live charts via /api/report).
    if path == "/why" || path == "/why.html" {
        let _ = req.respond(
            tiny_http::Response::from_string(report::render_why_html()).with_header(html_header()),
        );
        return;
    }

    // "BIP-110 code walkthrough" — the seven consensus rules and how they're implemented.
    if path == "/code" || path == "/code.html" {
        let _ = req.respond(
            tiny_http::Response::from_string(report::render_code_html()).with_header(html_header()),
        );
        return;
    }

    // Crawl stats + history graphs.
    if path == "/stats" || path == "/stats.html" {
        let _ = req.respond(
            tiny_http::Response::from_string(report::render_stats_html()).with_header(html_header()),
        );
        return;
    }

    // Chain view: which chain each crawled peer is on.
    if path == "/chains" || path == "/chains.html" {
        let _ = req.respond(
            tiny_http::Response::from_string(report::render_chains_html())
                .with_header(html_header()),
        );
        return;
    }

    // Block explorer.
    if path == "/blocks" || path == "/blocks.html" {
        let _ = req.respond(
            tiny_http::Response::from_string(report::render_blocks_html())
                .with_header(html_header()),
        );
        return;
    }

    // "Support" page + its QR images (donation details loaded from gitignored files).
    if path == "/support" || path == "/support.html" {
        let _ = req.respond(
            tiny_http::Response::from_string(support.html.clone()).with_header(html_header()),
        );
        return;
    }
    if path == "/support/bitcoin.png" || path == "/support/lightning.png" {
        let bytes = if path.ends_with("bitcoin.png") { &support.btc_qr } else { &support.ln_qr };
        match bytes {
            Some(b) => {
                let hdr =
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"image/png"[..]).unwrap();
                let _ = req.respond(tiny_http::Response::from_data(b.clone()).with_header(hdr));
            }
            None => {
                let _ = req
                    .respond(tiny_http::Response::from_string("not found").with_status_code(404));
            }
        }
        return;
    }

    let result: Result<(String, tiny_http::Header)> = match path {
        "/" | "/index.html" => Ok((page.to_string(), html_header())),
        "/api/report" => {
            let max = query.get("max").and_then(|s| s.parse().ok()).unwrap_or(3000);
            db::read_report(conn, max, max_age_secs)
                .and_then(|r| Ok(serde_json::to_string(&r)?))
                .map(|s| (s, json_header()))
        }
        "/api/blocks" => {
            let limit = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50).min(500);
            // The current retarget period's signalling blocks, with full detail. 2016 is the
            // Bitcoin difficulty-adjustment period; capped so a fully-signalling period can't
            // return thousands of rows.
            const RETARGET_PERIOD: i64 = 2016;
            db::read_blocks(conn, limit)
                .and_then(|b| {
                    let (start, tip, sig) =
                        db::read_period_signalling_blocks(conn, RETARGET_PERIOD, 200)?;
                    // Authoritative tally from the crawler's full header scan. It can exceed the
                    // detailed list above while the per-block backfill is still catching up, so
                    // the page can show the true "N of M" instead of only the fetched subset.
                    let stats = db::read_signalling(conn);
                    // Payload/fee aggregates across the whole period, so the page's cards are
                    // scoped to the signalling period rather than the loaded block window.
                    let pstats = db::read_period_block_stats(conn, RETARGET_PERIOD)?;
                    Ok(serde_json::to_string(&serde_json::json!({
                        "blocks": b,
                        "period": {
                            "start": start, "tip": tip, "length": RETARGET_PERIOD,
                            "signalling": sig,
                            "signalled": stats.as_ref().map(|s| s.blocks_signalling),
                            "scanned": stats.as_ref().map(|s| s.blocks_scanned),
                            "stats": pstats,
                        },
                    }))?)
                })
                .map(|s| (s, json_header()))
        }
        // Small payload for the live ticker on every page.
        "/api/ticker" => db::read_ticker(conn, max_age_secs)
            .and_then(|v| Ok(serde_json::to_string(&v)?))
            .map(|s| (s, json_header())),
        // Peer chain clustering + the split assessment, for /chains.
        "/api/chains" => {
            let body = serde_json::json!({
                "clusters": db::read_chain_clusters(conn),
                "split": db::read_chain_split(conn),
            });
            serde_json::to_string(&body)
                .map_err(anyhow::Error::from)
                .map(|s| (s, json_header()))
        }
        "/api/stats" => db::read_stats(conn, max_age_secs)
            .and_then(|v| Ok(serde_json::to_string(&v)?))
            .map(|s| (s, json_header())),
        "/api/nodes" => {
            let q = query.get("q").map(String::as_str).unwrap_or("");
            let impl_ = query.get("impl").map(String::as_str).unwrap_or("");
            let bip = query.get("bip").map(String::as_str).unwrap_or("");
            let sort = query.get("sort").map(String::as_str).unwrap_or("depth");
            // Default direction is ascending (natural for depth); ?dir=desc flips it.
            let dir_desc = query.get("dir").map(|s| s == "desc").unwrap_or(false);
            let limit = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(100).min(1000);
            let offset = query.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);
            db::read_nodes(conn, q, impl_, bip, sort, dir_desc, limit, offset, max_age_secs)
                .and_then(|(rows, total)| {
                    Ok(serde_json::to_string(&serde_json::json!({
                        "total": total, "rows": rows
                    }))?)
                })
                .map(|s| (s, json_header()))
        }
        _ => {
            let _ = req.respond(tiny_http::Response::from_string("not found").with_status_code(404));
            return;
        }
    };

    match result {
        Ok((body, header)) => {
            let _ = req.respond(tiny_http::Response::from_string(body).with_header(header));
        }
        Err(e) => {
            let _ = req.respond(
                tiny_http::Response::from_string(format!("error: {e:#}")).with_status_code(500),
            );
        }
    }
}

/// Parse a `k=v&k2=v2` query string with minimal percent-decoding.
fn parse_query(q: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            m.insert(pct_decode(k), pct_decode(v));
        } else if !pair.is_empty() {
            m.insert(pct_decode(pair), String::new());
        }
    }
    m
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
