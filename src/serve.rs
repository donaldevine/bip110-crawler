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

pub fn serve(db_path: &Path, port: u16) -> Result<()> {
    let server = tiny_http::Server::http(("127.0.0.1", port))
        .map_err(|e| anyhow!("binding 127.0.0.1:{port}: {e}"))?;
    let server = Arc::new(server);
    let page = Arc::new(report::render_api_html());
    eprintln!("[serve] http://127.0.0.1:{port}  (db: {})", db_path.display());
    eprintln!("[serve] point your Cloudflare tunnel at this port.");

    let mut handles = Vec::new();
    for _ in 0..4 {
        let server = Arc::clone(&server);
        let page = Arc::clone(&page);
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
                    Ok(req) => handle(&conn, &page, req),
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

fn handle(conn: &rusqlite::Connection, page: &str, req: tiny_http::Request) {
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

    let result: Result<(String, tiny_http::Header)> = match path {
        "/" | "/index.html" => Ok((page.to_string(), html_header())),
        "/api/report" => {
            let max = query.get("max").and_then(|s| s.parse().ok()).unwrap_or(3000);
            db::read_report(conn, max)
                .and_then(|r| Ok(serde_json::to_string(&r)?))
                .map(|s| (s, json_header()))
        }
        "/api/nodes" => {
            let q = query.get("q").map(String::as_str).unwrap_or("");
            let impl_ = query.get("impl").map(String::as_str).unwrap_or("");
            let reachable = query.get("reachable").map(|s| s == "1").unwrap_or(false);
            let sort = query.get("sort").map(String::as_str).unwrap_or("last_seen");
            let limit = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(100).min(1000);
            let offset = query.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);
            db::read_nodes(conn, q, impl_, reachable, sort, limit, offset)
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
