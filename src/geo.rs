//! IP geolocation via the free ip-api.com batch endpoint.
//!
//! PRIVACY: this sends peer IP addresses to ip-api.com (a third party). It only runs
//! when the user passes `--geolocate`. The free endpoint is HTTP-only and rate-limited
//! to ~45 requests/min; we batch up to 100 IPs per request and pace ourselves.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub lat: f64,
    pub lon: f64,
    pub country: String,
    pub country_code: String,
    pub city: String,
}

/// Load the on-disk geolocation cache (`ip -> GeoInfo`), or empty if absent.
pub fn load_cache(path: &Path) -> HashMap<String, GeoInfo> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

pub fn save_cache(path: &Path, cache: &HashMap<String, GeoInfo>) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string(cache)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Geolocate `ips`, using `cache_path` as a persistent store: only IPs not already in
/// the cache hit the API; results are merged back and saved. Returns the geo data for
/// the requested IPs (from cache + freshly resolved).
pub fn geolocate_cached(ips: &[IpAddr], cache_path: &Path) -> HashMap<String, GeoInfo> {
    let mut cache = load_cache(cache_path);
    let missing: Vec<IpAddr> = ips
        .iter()
        .filter(|ip| !cache.contains_key(&ip.to_string()))
        .copied()
        .collect();

    eprintln!(
        "[geo] {} IPs total, {} cached, {} to look up",
        ips.len(),
        ips.len() - missing.len(),
        missing.len()
    );

    if !missing.is_empty() {
        let fresh = geolocate(&missing);
        for (k, v) in fresh {
            cache.insert(k, v);
        }
        if let Err(e) = save_cache(cache_path, &cache) {
            eprintln!("[geo] failed to write cache {}: {e:#}", cache_path.display());
        }
    }

    // Return just the entries for the requested IPs.
    let mut out = HashMap::new();
    for ip in ips {
        if let Some(g) = cache.get(&ip.to_string()) {
            out.insert(ip.to_string(), g.clone());
        }
    }
    out
}

#[derive(Deserialize)]
struct ApiEntry {
    status: String,
    #[serde(default)]
    country: String,
    #[serde(rename = "countryCode", default)]
    country_code: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    query: String,
}

/// Geolocate a set of IPs. Returns a map keyed by the IP's string form.
/// Failures (rate limits, unresolved IPs, private ranges) are simply omitted.
pub fn geolocate(ips: &[IpAddr]) -> HashMap<String, GeoInfo> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build();
    let mut out = HashMap::new();
    let total = ips.len();
    let batches = ips.chunks(100);
    let batch_count = batches.len();
    for (i, chunk) in ips.chunks(100).enumerate() {
        match geolocate_batch(&agent, chunk) {
            Ok(part) => {
                for (k, v) in part {
                    out.insert(k, v);
                }
            }
            Err(e) => eprintln!("[geo] batch {}/{} failed: {e:#}", i + 1, batch_count),
        }
        eprintln!("[geo] {}/{} IPs located", out.len().min(total), total);
        // ip-api free tier allows ~45 requests/min; pace to stay comfortably under.
        if i + 1 < batch_count {
            std::thread::sleep(Duration::from_millis(1500));
        }
    }
    out
}

fn geolocate_batch(agent: &ureq::Agent, ips: &[IpAddr]) -> Result<HashMap<String, GeoInfo>> {
    let query: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
    // HTTP only on the free tier.
    let resp = agent
        .post("http://ip-api.com/batch?fields=status,message,country,countryCode,city,lat,lon,query")
        .send_json(&query)?;
    let entries: Vec<ApiEntry> = resp.into_json()?;
    let mut out = HashMap::new();
    for e in entries {
        if e.status == "success" {
            if let (Some(lat), Some(lon)) = (e.lat, e.lon) {
                out.insert(
                    e.query.clone(),
                    GeoInfo {
                        lat,
                        lon,
                        country: e.country,
                        country_code: e.country_code,
                        city: e.city,
                    },
                );
            }
        }
    }
    Ok(out)
}

/// Best-effort: pull the IP out of an `ip:port` (or `[ipv6]:port`) node address.
pub fn ip_of(addr: &str) -> Option<IpAddr> {
    addr.parse::<std::net::SocketAddr>().ok().map(|sa| sa.ip())
}
