//! SQLite storage + read queries powering the API (`serve` mode).
//!
//! The crawler writes the node/edge/geo set here; the API server reads it. Each write is a
//! per-row **upsert** (INSERT … ON CONFLICT by address), so the DB *accumulates* across
//! snapshots and restarts and never drops rows. This means multiple crawlers (e.g. a
//! clearnet and a Tor-focused one, each with its own state file) can write to the same DB
//! concurrently without wiping each other. It's a single file (`crawl.db`), no server needed.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::collections::BTreeMap;
use std::path::Path;

use crate::geo::GeoInfo;
use crate::node::{assess_bip110, Aggregates, Bip110Stance, Edge, NodeInfo, SignalStats};
use crate::report::{OwnNode, ReportData};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS nodes (
  addr TEXT PRIMARY KEY, depth INTEGER, protocol_version INTEGER, user_agent TEXT,
  services INTEGER, start_height INTEGER, handshaked INTEGER, implementation TEXT,
  version TEXT, bip110 TEXT, first_seen TEXT, last_seen TEXT, times_seen INTEGER,
  online INTEGER, lat REAL, lon REAL, country TEXT, country_code TEXT, city TEXT
);
CREATE TABLE IF NOT EXISTS edges (from_addr TEXT, to_addr TEXT);
-- Hourly points of the reachable population, so /stats can graph how the client mix
-- shifts over time. One row per hour (upserted until the hour rolls over); two crawlers
-- writing the same hour is idempotent since both compute from this same shared DB.
CREATE TABLE IF NOT EXISTS history (hour TEXT PRIMARY KEY, snapshot TEXT);
-- Recent blocks for the /blocks explorer. The crawler (which holds the RPC connection)
-- fills this whenever a new block arrives; the API server only reads it, so serve mode
-- still needs nothing but the DB file. Blocks are immutable, so height is the key and
-- re-fetching the same block is a harmless no-op.
-- `payload` holds the JSON data-payload breakdown (inscriptions/runes/OP_RETURN), filled
-- in lazily after the block row exists: scanning a block needs the full verbose block from
-- RPC, so it's done once per block rather than on every refresh. NULL = not yet analysed.
CREATE TABLE IF NOT EXISTS blocks (
  height INTEGER PRIMARY KEY, hash TEXT, time INTEGER, version INTEGER,
  signals INTEGER, tx_count INTEGER, size INTEGER, weight INTEGER, miner TEXT,
  payload TEXT, stats TEXT
);
CREATE INDEX IF NOT EXISTS idx_nodes_online ON nodes(online);
CREATE INDEX IF NOT EXISTS idx_nodes_impl ON nodes(implementation);
CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_addr);
-- Nodes can't duplicate (addr is the PRIMARY KEY); this keeps edges unique too.
CREATE UNIQUE INDEX IF NOT EXISTS idx_edges_uniq ON edges(from_addr, to_addr);
";

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("opening db {}", path.display()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .ok();
    conn.execute_batch(SCHEMA).context("creating schema")?;
    // CREATE TABLE IF NOT EXISTS won't add a column to a table that already exists, so
    // bring older DBs up to date. Erroring means the column is already there.
    let _ = conn.execute("ALTER TABLE blocks ADD COLUMN payload TEXT", []);
    let _ = conn.execute("ALTER TABLE blocks ADD COLUMN stats TEXT", []);
    Ok(conn)
}

/// Window used when recording history points: a node counts toward an hour's population
/// if it was confirmed reachable within this long of that hour. Matches the serve-side
/// `--max-age-hours` default so the graph lines up with what the site showed.
/// Must track the serve-side `--max-age-hours` default, or the graph records a different
/// population than the site displays. It also has to exceed a full re-crawl cycle: with a
/// window that expires nodes faster than they can be re-confirmed, every recorded point is
/// dragged downwards and that artifact is baked into the history permanently.
const HISTORY_WINDOW_SECS: u64 = 336 * 3600;

/// How many client versions to track individually per hour. The network runs ~100 distinct
/// versions, almost all of them a long tail; keeping only the biggest N bounds each hourly
/// row so `/api/stats` stays small over months of history. The tail isn't bucketed — a
/// lumped "other" line is meaningless on a per-version chart. `total` still carries the
/// full population, and `distinct_versions` reports how many exist.
const HISTORY_TOP_VERSIONS: usize = 12;

/// Append/refresh this hour's population point (reachable count per client version).
/// Cheap: it groups the ~20k reachable rows, not the whole address book.
fn record_history(tx: &rusqlite::Transaction, now: &str) -> Result<()> {
    let hour: String = now.chars().take(13).collect(); // YYYY-MM-DDTHH
    let cutoff = crate::time::iso_secs_ago(HISTORY_WINDOW_SECS);

    let mut counts: Vec<(String, i64)> = Vec::new();
    {
        let mut st = tx.prepare(
            "SELECT implementation, version, COUNT(*) FROM nodes
             WHERE online=1 AND last_seen >= ?1 GROUP BY implementation, version",
        )?;
        let rows = st.query_map(params![cutoff], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (im, ver, c) = row?;
            // Same key shape as the dashboard's version chart: "Bitcoin Knots 29.3.0".
            let key = if ver.is_empty() { im } else { format!("{im} {ver}") };
            counts.push((key, c));
        }
    }
    let total: i64 = counts.iter().map(|(_, c)| *c).sum();
    let distinct_versions = counts.len() as i64;
    counts.sort_by(|a, b| b.1.cmp(&a.1));
    let versions: BTreeMap<String, i64> =
        counts.into_iter().take(HISTORY_TOP_VERSIONS).collect();

    let onion: i64 = tx.query_row(
        "SELECT COUNT(*) FROM nodes WHERE online=1 AND last_seen >= ?1 AND addr LIKE '%.onion%'",
        params![cutoff],
        |r| r.get(0),
    )?;
    let snapshot = serde_json::json!({
        "total": total, "onion": onion,
        "distinct_versions": distinct_versions, "versions": versions,
    })
    .to_string();
    tx.execute(
        "INSERT OR REPLACE INTO history (hour, snapshot) VALUES (?1, ?2)",
        params![hour, snapshot],
    )?;
    Ok(())
}

fn stance_str(s: &Bip110Stance) -> &'static str {
    match s {
        Bip110Stance::Enforcing => "enforcing",
        Bip110Stance::NotEnforcing => "not_enforcing",
        Bip110Stance::Unknown => "unknown",
    }
}
/// Merge the current crawl snapshot into the DB (one transaction). Rows are upserted by
/// address, not wiped — the DB accumulates across snapshots/restarts and tolerates
/// multiple concurrent crawlers writing to it. `last_seen` carries the crawler's
/// probe-time stamp (when the peer was last confirmed reachable), which the API uses to
/// age out rows that stopped being re-confirmed.
#[allow(clippy::too_many_arguments)]
pub fn write_snapshot(
    conn: &mut Connection,
    generated_at: &str,
    network: &str,
    own_node: &OwnNode,
    signalling: &Option<SignalStats>,
    nodes: &[NodeInfo],
    edges: &[Edge],
    geo: &BTreeMap<String, GeoInfo>,
) -> Result<()> {
    let tx = conn.transaction()?;
    // Upsert (no DELETE): rows accumulate and multiple crawlers can share the DB.
    {
        // Upsert by address. Two rules keep concurrent crawlers from fighting:
        //  * The trailing WHERE means a write that did NOT handshake the peer (a failed
        //    probe: online=false, implementation="Unreachable") can never overwrite a row
        //    another crawler successfully handshook. Without this, a Tor-focused crawler
        //    that skips/fails clearnet peers would flip them offline every snapshot and the
        //    totals would oscillate. Better information always wins; a failed probe only
        //    updates a row that was itself never handshook.
        //  * COALESCE keeps existing geolocation when the incoming write has none, so a
        //    crawler that isn't geolocating can't blank coordinates another one resolved.
        let mut ins = tx.prepare(
            "INSERT INTO nodes
             (addr,depth,protocol_version,user_agent,services,start_height,handshaked,
              implementation,version,bip110,first_seen,last_seen,times_seen,online,
              lat,lon,country,country_code,city)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)
             ON CONFLICT(addr) DO UPDATE SET
               depth=excluded.depth, protocol_version=excluded.protocol_version,
               user_agent=excluded.user_agent, services=excluded.services,
               start_height=excluded.start_height, handshaked=excluded.handshaked,
               implementation=excluded.implementation, version=excluded.version,
               bip110=excluded.bip110, first_seen=excluded.first_seen,
               last_seen=excluded.last_seen, times_seen=excluded.times_seen,
               online=excluded.online,
               lat=COALESCE(excluded.lat, lat), lon=COALESCE(excluded.lon, lon),
               country=COALESCE(excluded.country, country),
               country_code=COALESCE(excluded.country_code, country_code),
               city=COALESCE(excluded.city, city)
             WHERE excluded.handshaked=1 OR nodes.handshaked=0",
        )?;
        for n in nodes {
            let g = geo.get(&n.addr);
            // last_seen must mean "last CONFIRMED reachable", so we keep the crawler's
            // probe-time stamp verbatim — stamping it at write time would refresh every
            // row on every snapshot and nothing would ever age out. The fallback only
            // covers online rows with no stamp of their own (e.g. the spliced own node).
            let last_seen: &str = if n.last_seen.is_empty() && n.online {
                generated_at
            } else {
                &n.last_seen
            };
            ins.execute(params![
                n.addr, n.depth, n.protocol_version, n.user_agent, n.services as i64,
                n.start_height, n.handshaked as i64, n.implementation, n.version,
                stance_str(&n.bip110), n.first_seen, last_seen, n.times_seen, n.online as i64,
                g.map(|x| x.lat), g.map(|x| x.lon),
                g.map(|x| x.country.clone()), g.map(|x| x.country_code.clone()),
                g.map(|x| x.city.clone()),
            ])?;
        }
        let mut ei = tx.prepare("INSERT OR IGNORE INTO edges (from_addr,to_addr) VALUES (?1,?2)")?;
        for e in edges {
            ei.execute(params![e.from, e.to])?;
        }
    }
    let set_meta = |k: &str, v: String| -> Result<()> {
        tx.execute(
            "INSERT OR REPLACE INTO meta (key,value) VALUES (?1,?2)",
            params![k, v],
        )?;
        Ok(())
    };
    set_meta("generated_at", generated_at.to_string())?;
    set_meta("network", network.to_string())?;
    set_meta("own_node", serde_json::to_string(own_node)?)?;
    set_meta("signalling", serde_json::to_string(signalling)?)?;
    set_meta("discovered_total", nodes.len().to_string())?;
    record_history(&tx, generated_at)?;
    tx.commit()?;
    Ok(())
}

fn meta_get(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| {
        r.get::<_, String>(0)
    })
    .ok()
}

fn row_to_node(r: &rusqlite::Row) -> rusqlite::Result<(NodeInfo, Option<GeoInfo>)> {
    let node = NodeInfo {
        addr: r.get("addr")?,
        depth: r.get("depth")?,
        protocol_version: r.get("protocol_version")?,
        user_agent: r.get("user_agent")?,
        services: r.get::<_, i64>("services")? as u64,
        start_height: r.get("start_height")?,
        // Not persisted: it is a per-crawl measurement, aggregated at snapshot time.
        chain_hash: String::new(),
        handshaked: r.get::<_, i64>("handshaked")? != 0,
        implementation: r.get("implementation")?,
        version: r.get("version")?,
        // Derive readiness from the stored user agent on read, so the current rule
        // (see node::assess_bip110) always applies — even to nodes classified by an
        // older crawler build. The stored `bip110` column is ignored for display.
        bip110: assess_bip110(
            &r.get::<_, String>("implementation")?,
            &r.get::<_, String>("user_agent")?,
            &[],
        ),
        first_seen: r.get("first_seen")?,
        last_seen: r.get("last_seen")?,
        times_seen: r.get("times_seen")?,
        online: r.get::<_, i64>("online")? != 0,
    };
    let geo = match (r.get::<_, Option<f64>>("lat")?, r.get::<_, Option<f64>>("lon")?) {
        (Some(lat), Some(lon)) => Some(GeoInfo {
            lat,
            lon,
            country: r.get::<_, Option<String>>("country")?.unwrap_or_default(),
            country_code: r.get::<_, Option<String>>("country_code")?.unwrap_or_default(),
            city: r.get::<_, Option<String>>("city")?.unwrap_or_default(),
        }),
        _ => None,
    };
    Ok((node, geo))
}

/// SQL predicate for "currently reachable": online, and — unless aging is disabled with
/// `max_age_secs = 0` — confirmed reachable within that window.
///
/// Because the crawler never re-probes a peer inside one pass, and a failed probe can't
/// overwrite a successful one, `online` alone is effectively sticky: without aging, dead
/// nodes would linger forever and the totals would only ever grow. Aging is what keeps
/// them honest — a re-crawl refreshes `last_seen` for peers that are still up, and peers
/// that stop answering simply fall out of the window.
///
/// The cutoff is generated internally by `time::iso_secs_ago` (fixed-width, digits and
/// `-:TZ` only), so inlining it carries no injection risk and keeps the callers simple.
fn fresh_clause(max_age_secs: u64) -> String {
    if max_age_secs == 0 {
        "online=1".to_string()
    } else {
        format!(
            "online=1 AND last_seen >= '{}'",
            crate::time::iso_secs_ago(max_age_secs)
        )
    }
}

/// Build a bounded ReportData for the maps/charts/summary: all reachable nodes plus a
/// sample of the rest up to `max`, their edges, geo, and full aggregate counts.
/// `max_age_secs` drops nodes not confirmed reachable recently (0 = keep everything).
pub fn read_report(conn: &Connection, max: usize, max_age_secs: u64) -> Result<ReportData> {
    // The website only exposes reachable (online) nodes, recently confirmed.
    let fresh = fresh_clause(max_age_secs);
    let reachable_total: usize = conn
        .query_row(&format!("SELECT count(*) FROM nodes WHERE {fresh}"), [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize;
    let discovered_total = reachable_total;
    let own_node: OwnNode = meta_get(conn, "own_node")
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(OwnNode {
            addr: "self".into(),
            version: 0,
            subversion: "(unknown)".into(),
            implementation: "Unknown".into(),
            network: "main".into(),
        });
    let signalling: Option<SignalStats> = meta_get(conn, "signalling")
        .and_then(|s| serde_json::from_str(&s).ok())
        .flatten();
    let network = meta_get(conn, "network").unwrap_or_else(|| "main".into());
    let generated_at = meta_get(conn, "generated_at").unwrap_or_default();

    // Aggregates over reachable nodes only.
    let mut agg = Aggregates::default();
    agg.total_nodes = reachable_total;
    {
        let mut st = conn.prepare(&format!(
            "SELECT implementation, version, user_agent, online, handshaked, addr FROM nodes WHERE {fresh}"
        ))?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)? != 0,
                r.get::<_, i64>(4)? != 0,
                r.get::<_, String>(5)?,
            ))
        })?;
        for row in rows {
            let (impl_, version, user_agent, online, handshaked, addr) = row?;
            *agg.by_implementation.entry(impl_.clone()).or_default() += 1;
            let vkey = if version.is_empty() { impl_.clone() } else { format!("{impl_} {version}") };
            *agg.by_version.entry(vkey).or_default() += 1;
            // Recompute readiness from the user agent (current rule), not the stored label.
            let label = match assess_bip110(&impl_, &user_agent, &[]) {
                Bip110Stance::Enforcing => "BIP-110 ready",
                Bip110Stance::NotEnforcing => "Not ready",
                Bip110Stance::Unknown => "Unknown",
            };
            *agg.by_bip110.entry(label.to_string()).or_default() += 1;
            if handshaked { agg.handshaked_nodes += 1; }
            if online { agg.online_nodes += 1; }
            // Count Tor nodes over the FULL reachable set (not the size-capped node list),
            // so the dashboard's "Tor nodes" figure is exact even when the report is capped.
            if addr.contains(".onion") { agg.onion_nodes += 1; }
        }
    }

    // Bounded node set: reachable first, then the rest, up to `max`.
    let mut nodes = Vec::new();
    let mut geo = BTreeMap::new();
    {
        let mut st = conn.prepare(&format!(
            // depth=0 (the own node) is pinned first so it always survives the cap and
            // shows on the maps, not just the uncapped table.
            "SELECT * FROM nodes WHERE {fresh} ORDER BY (depth=0) DESC, times_seen DESC LIMIT ?1"
        ))?;
        let rows = st.query_map(params![max as i64], row_to_node)?;
        for row in rows {
            let (n, g) = row?;
            if let Some(g) = g {
                geo.insert(n.addr.clone(), g);
            }
            nodes.push(n);
        }
    }

    // Edges among the shown nodes only.
    let shown: std::collections::HashSet<&str> = nodes.iter().map(|n| n.addr.as_str()).collect();
    let mut edges = Vec::new();
    {
        let mut st = conn.prepare("SELECT from_addr, to_addr FROM edges")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (from, to) = row?;
            if shown.contains(from.as_str()) && shown.contains(to.as_str()) {
                edges.push(Edge { from, to });
            }
        }
    }

    Ok(ReportData {
        generated_at,
        network,
        own_node,
        signalling,
        chain_split: read_chain_split(conn),
        aggregates: agg,
        discovered_total,
        nodes,
        edges,
        geo: if geo.is_empty() { None } else { Some(geo) },
        live: true,
        refresh_seconds: 10,
    })
}

/// A single row for the paginated node table (`/api/nodes`).
#[derive(serde::Serialize)]
pub struct NodeRow {
    pub addr: String,
    pub implementation: String,
    pub version: String,
    pub protocol_version: i32,
    pub depth: u32,
    pub bip110: String,
    pub online: bool,
    pub last_seen: String,
    pub city: Option<String>,
    pub country: Option<String>,
}

/// Store blocks for the explorer (upsert by height; blocks are immutable so re-storing
/// the same height is a no-op). Called by the crawler, which owns the RPC connection.
pub fn write_blocks(conn: &mut Connection, blocks: &[crate::rpc::BlockInfo]) -> Result<()> {
    let tx = conn.transaction()?;
    {
        // Upsert, NOT INSERT OR REPLACE. Every new block re-fetches the recent window, so
        // most of these rows already exist and many have been analysed. REPLACE deletes the
        // old row and re-inserts with no payload/stats, wiping the analysis and leaving the
        // newest blocks — the ones the page shows — perpetually "scan pending". So update
        // only the cheap metadata that recent_blocks provides and leave payload/stats intact.
        let mut ins = tx.prepare(
            "INSERT INTO blocks
             (height,hash,time,version,signals,tx_count,size,weight,miner)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(height) DO UPDATE SET
               hash=excluded.hash, time=excluded.time, version=excluded.version,
               signals=excluded.signals, tx_count=excluded.tx_count, size=excluded.size,
               weight=excluded.weight, miner=excluded.miner",
        )?;
        for b in blocks {
            ins.execute(params![
                b.height, b.hash, b.time, b.version, b.signals as i64,
                b.tx_count, b.size, b.weight, b.miner
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// The columns every block view selects, in the order `block_row` expects.
const BLOCK_COLS: &str = "height,hash,time,version,signals,tx_count,size,weight,miner,payload,stats";

/// Map one `BLOCK_COLS` row to the JSON the explorer consumes. Shared by every block query
/// so they can't drift apart in shape.
fn block_row(r: &rusqlite::Row) -> rusqlite::Result<serde_json::Value> {
    let payload: Option<String> = r.get(9)?;
    let stats: Option<String> = r.get(10)?;
    let parse = |s: Option<String>| s.and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
    Ok(serde_json::json!({
        "height": r.get::<_, i64>(0)?,
        "hash": r.get::<_, String>(1)?,
        "time": r.get::<_, i64>(2)?,
        "version": r.get::<_, i64>(3)?,
        "signals": r.get::<_, i64>(4)? != 0,
        "tx_count": r.get::<_, i64>(5)?,
        "size": r.get::<_, i64>(6)?,
        "weight": r.get::<_, i64>(7)?,
        "miner": r.get::<_, String>(8)?,
        "payload": parse(payload),
        "stats": parse(stats),
    }))
}

/// Newest `limit` blocks, newest first, for the explorer page. Each row carries its
/// data-payload breakdown when one has been computed (`payload` is null until then).
pub fn read_blocks(conn: &Connection, limit: usize) -> Result<Vec<serde_json::Value>> {
    let mut st = conn.prepare(&format!(
        "SELECT {BLOCK_COLS} FROM blocks ORDER BY height DESC LIMIT ?1"
    ))?;
    let rows = st.query_map(params![limit as i64], block_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Blocks in the CURRENT difficulty period that signal BIP-110, newest first, with full
/// detail. The period is retarget-aligned (`[start, tip]`, start divisible by `period_len`)
/// to match how BIP8 tallies signalling — the same window the crawler's signalling scan uses.
///
/// Returns `(period_start, tip, blocks)`. The tip is taken as the highest stored block, which
/// equals the chain tip because the crawler always stores up to the tip. Note the list only
/// covers blocks the crawler has actually recorded (the explorer accumulates these as it
/// runs); it is not a re-scan of every header in the period.
pub fn read_period_signalling_blocks(
    conn: &Connection,
    period_len: i64,
    limit: usize,
) -> Result<(i64, i64, Vec<serde_json::Value>)> {
    let period_len = period_len.max(1);
    // MAX() always returns one row — NULL (→ None) when the table is empty. No blocks yet:
    // report an empty current period rather than erroring.
    let tip: Option<i64> = conn.query_row("SELECT MAX(height) FROM blocks", [], |r| r.get(0))?;
    let Some(tip) = tip else {
        return Ok((0, 0, Vec::new()));
    };
    let start = (tip / period_len) * period_len;
    let mut st = conn.prepare(&format!(
        "SELECT {BLOCK_COLS} FROM blocks
         WHERE signals=1 AND height>=?1 ORDER BY height DESC LIMIT ?2"
    ))?;
    let rows = st.query_map(params![start, limit as i64], block_row)?;
    let blocks = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((start, tip, blocks))
}

/// The authoritative period signalling tally the crawler last recorded from its full header
/// scan (the same figure the dashboard shows), or None if no scan has run. Lets the explorer
/// report the true "N of M signalled" even before the per-block backfill has fetched detail
/// for every signalling block — otherwise the count and the detailed list disagree.
pub fn read_signalling(conn: &Connection) -> Option<SignalStats> {
    meta_get(conn, "signalling")
        .and_then(|s| serde_json::from_str::<Option<SignalStats>>(&s).ok())
        .flatten()
}

/// Record the latest chain-split assessment. Written by the crawler (the only process with an
/// RPC connection) and read back by the report, so `serve` can render it without RPC.
pub fn write_chain_split(conn: &Connection, split: &crate::node::ChainSplit) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO meta (key,value) VALUES ('chain_split', ?1)",
        params![serde_json::to_string(split)?],
    )?;
    Ok(())
}

/// Record how the crawled peers cluster onto chains (from their `headers` replies).
pub fn write_chain_clusters(conn: &Connection, v: &serde_json::Value) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO meta (key,value) VALUES ('chain_clusters', ?1)",
        params![serde_json::to_string(v)?],
    )?;
    Ok(())
}

/// The stored peer chain clustering, or None before a crawl has produced one.
pub fn read_chain_clusters(conn: &Connection) -> Option<serde_json::Value> {
    meta_get(conn, "chain_clusters").and_then(|s| serde_json::from_str(&s).ok())
}

/// The stored chain-split assessment, or None before the crawler has made one.
pub fn read_chain_split(conn: &Connection) -> Option<crate::node::ChainSplit> {
    meta_get(conn, "chain_split").and_then(|s| serde_json::from_str(&s).ok())
}

/// Payload/fee aggregates over every analysed block in the CURRENT difficulty period.
///
/// The explorer's headline cards used to be derived from whatever handful of blocks the page
/// happened to load, which made their denominator "the last 200 blocks" rather than the period
/// the signalling tally is measured over — two different scopes on one screen. This aggregates
/// across the period in the DB instead, so every figure shares one denominator.
///
/// `analysed` is the number of period blocks whose payload scan has completed; it climbs toward
/// the full period as the crawler works through it, so the percentages are a growing sample of
/// the period rather than of an arbitrary recent window.
///
/// Summing in Rust rather than via SQL `json_extract` keeps this independent of whether the
/// bundled SQLite ships the JSON1 extension.
pub fn read_period_block_stats(conn: &Connection, period_len: i64) -> Result<serde_json::Value> {
    let period_len = period_len.max(1);
    let tip: Option<i64> = conn.query_row("SELECT MAX(height) FROM blocks", [], |r| r.get(0))?;
    let Some(tip) = tip else {
        return Ok(serde_json::json!({ "analysed": 0, "with_stats": 0 }));
    };
    let start = (tip / period_len) * period_len;

    let mut st = conn
        .prepare("SELECT payload, stats FROM blocks WHERE height >= ?1 AND payload IS NOT NULL")?;
    let rows = st.query_map(params![start], |r| {
        Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?))
    })?;

    let g = |v: &serde_json::Value, k: &str| v.get(k).and_then(serde_json::Value::as_i64).unwrap_or(0);
    let (mut analysed, mut with_stats) = (0i64, 0i64);
    let (mut insc, mut runes) = (0i64, 0i64);
    let (mut payload_weight, mut reject_weight, mut total_fee) = (0i64, 0i64, 0i64);
    let mut rates: Vec<i64> = Vec::new();
    for row in rows {
        let (p, s) = row?;
        let Some(p) = p.and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()) else {
            continue;
        };
        analysed += 1;
        insc += g(&p, "insc_count");
        runes += g(&p, "rune_count");
        payload_weight += g(&p, "payload_weight");
        reject_weight += g(&p, "bip110_reject_weight");
        if let Some(s) = s.and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()) {
            with_stats += 1;
            total_fee += g(&s, "total_fee");
            rates.push(g(&s, "median_feerate"));
        }
    }
    rates.sort_unstable();
    let median_feerate = rates.get(rates.len() / 2).copied().unwrap_or(0);
    Ok(serde_json::json!({
        "start": start,
        "analysed": analysed,
        "with_stats": with_stats,
        "insc_count": insc,
        "rune_count": runes,
        "payload_weight": payload_weight,
        "reject_weight": reject_weight,
        "total_fee": total_fee,
        "median_feerate": median_feerate,
    }))
}

/// Heights of stored blocks that haven't been analysed yet, newest first.
pub fn blocks_needing_analysis(conn: &Connection, limit: usize) -> Result<Vec<(i64, String)>> {
    let mut st = conn.prepare(
        "SELECT height, hash FROM blocks WHERE payload IS NULL ORDER BY height DESC LIMIT ?1",
    )?;
    let rows = st.query_map(params![limit as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Of `heights`, the ones not yet in the blocks table — the signalling blocks the period
/// scan found that still need their full detail fetched and stored. Preserves input order.
pub fn unstored_heights(conn: &Connection, heights: &[i64]) -> Result<Vec<i64>> {
    let mut st = conn.prepare("SELECT 1 FROM blocks WHERE height=?1")?;
    let mut missing = Vec::new();
    for &h in heights {
        if !st.exists(params![h])? {
            missing.push(h);
        }
    }
    Ok(missing)
}

/// Attach the computed data-payload breakdown and fee stats to a stored block.
/// `stats` is optional: `getblockstats` can legitimately fail (e.g. a pruned node), and
/// the payload scan is still worth keeping when it does.
pub fn write_block_analysis(
    conn: &Connection,
    height: i64,
    payload: &crate::rpc::BlockPayload,
    stats: Option<&crate::rpc::BlockStats>,
) -> Result<()> {
    conn.execute(
        "UPDATE blocks SET payload=?2, stats=?3 WHERE height=?1",
        params![
            height,
            serde_json::to_string(payload)?,
            stats.map(serde_json::to_string).transpose()?,
        ],
    )?;
    Ok(())
}

/// Addresses of nodes we have previously handshaked, most-recently-confirmed first.
///
/// Used to seed a re-crawl. Without this, every cycle restarts from the RPC peers and
/// rediscovers the network from scratch, grinding through a ~97%-dead address book before
/// it revisits any known-good node — so re-confirmation crawls at a trickle and nodes
/// expire from the freshness window faster than they can be refreshed. Seeding from the
/// known-good set puts the live network at the FRONT of the queue, so a cycle refreshes
/// `last_seen` for real peers within minutes instead of days.
pub fn read_known_good(conn: &Connection, limit: usize) -> Result<Vec<String>> {
    let mut st = conn.prepare(
        "SELECT addr FROM nodes WHERE online=1 AND handshaked=1
         ORDER BY last_seen DESC LIMIT ?1",
    )?;
    let rows = st.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Crawl-health stats + history for the `/stats` page.
///
/// Everything here is derived from the same DB the site serves: how much of the gossiped
/// address book is actually reachable, and the hourly population series (client mix over time).
pub fn read_stats(conn: &Connection, max_age_secs: u64) -> Result<serde_json::Value> {
    let fresh = fresh_clause(max_age_secs);

    let total_addresses: i64 = conn.query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get(0))?;
    let online_raw: i64 =
        conn.query_row("SELECT COUNT(*) FROM nodes WHERE online=1", [], |r| r.get(0))?;
    let unreachable: i64 =
        conn.query_row("SELECT COUNT(*) FROM nodes WHERE online=0", [], |r| r.get(0))?;
    let reachable: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM nodes WHERE {fresh}"),
        [],
        |r| r.get(0),
    )?;
    let onion: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM nodes WHERE {fresh} AND addr LIKE '%.onion%'"),
        [],
        |r| r.get(0),
    )?;
    let edges: i64 = conn.query_row("SELECT COUNT(*) FROM edges", [], |r| r.get(0))?;
    let distinct_versions: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(DISTINCT implementation || ' ' || version) FROM nodes WHERE {fresh}"
        ),
        [],
        |r| r.get(0),
    )?;

    // Hourly population series (client versions over time), newest 30 days, returned
    // chronologically. Capped so the payload stays small as history accumulates.
    let mut history = Vec::new();
    {
        let mut st =
            conn.prepare("SELECT hour, snapshot FROM history ORDER BY hour DESC LIMIT 720")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (hour, snap) = row?;
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&snap) {
                history.push(serde_json::json!({ "hour": hour, "snapshot": v }));
            }
        }
        history.reverse(); // oldest -> newest for the chart
    }

    Ok(serde_json::json!({
        "total_addresses": total_addresses,
        "reachable": reachable,
        "onion": onion,
        "unreachable": unreachable,
        "online_raw": online_raw,
        "aged_out": online_raw - reachable,
        "edges": edges,
        "distinct_versions": distinct_versions,
        "max_age_hours": max_age_secs / 3600,
        "history": history,
    }))
}

/// Paginated + filtered node list for the table (all reachable nodes, not the capped
/// report set). Returns (page-of-rows, total-matching). Filtering by `q`/`implementation`
/// happens in SQL; BIP-110 readiness is derived from the user agent, so the `bip` filter,
/// sort, and pagination are applied in memory — the reachable set is a few thousand rows,
/// so this is cheap and keeps the counts exact.
#[allow(clippy::too_many_arguments)]
pub fn read_nodes(
    conn: &Connection,
    q: &str,
    implementation: &str,
    bip: &str,
    sort: &str,
    dir_desc: bool,
    limit: usize,
    offset: usize,
    max_age_secs: u64,
) -> Result<(Vec<NodeRow>, usize)> {
    let mut where_clauses = vec![fresh_clause(max_age_secs)];
    let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if !implementation.is_empty() {
        where_clauses.push(format!("implementation=?{}", args.len() + 1));
        args.push(Box::new(implementation.to_string()));
    }
    if !q.is_empty() {
        let like = format!("%{q}%");
        where_clauses.push(format!(
            "(addr LIKE ?{0} OR implementation LIKE ?{0} OR version LIKE ?{0} OR country LIKE ?{0} OR city LIKE ?{0})",
            args.len() + 1
        ));
        args.push(Box::new(like));
    }
    let where_sql = format!("WHERE {}", where_clauses.join(" AND "));
    let arg_refs: Vec<&dyn rusqlite::types::ToSql> = args.iter().map(|b| b.as_ref()).collect();

    let sql = format!(
        "SELECT addr,implementation,version,protocol_version,depth,user_agent,online,last_seen,city,country
         FROM nodes {where_sql}"
    );
    let mut st = conn.prepare(&sql)?;
    let mut rows: Vec<NodeRow> = st
        .query_map(arg_refs.as_slice(), |r| {
            let implementation: String = r.get(1)?;
            let user_agent: String = r.get(5)?;
            Ok(NodeRow {
                addr: r.get(0)?,
                implementation: implementation.clone(),
                version: r.get(2)?,
                protocol_version: r.get(3)?,
                depth: r.get(4)?,
                // Readiness derived from the user agent (current rule), not the stored label.
                bip110: stance_str(&assess_bip110(&implementation, &user_agent, &[])).to_string(),
                online: r.get::<_, i64>(6)? != 0,
                last_seen: r.get(7)?,
                city: r.get(8)?,
                country: r.get(9)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    if !bip.is_empty() {
        rows.retain(|r| r.bip110 == bip);
    }
    let total = rows.len();

    // Sort ascending by the requested column, then reverse for descending.
    match sort {
        "implementation" => rows.sort_by(|a, b| a.implementation.cmp(&b.implementation)),
        "version" => rows.sort_by(|a, b| a.version.cmp(&b.version)),
        "protocol_version" => rows.sort_by(|a, b| a.protocol_version.cmp(&b.protocol_version)),
        "bip110" => rows.sort_by(|a, b| a.bip110.cmp(&b.bip110)),
        "location" | "country" => rows.sort_by(|a, b| a.country.cmp(&b.country)),
        _ => rows.sort_by(|a, b| a.depth.cmp(&b.depth)),
    }
    if dir_desc {
        rows.reverse();
    }

    let page = rows.into_iter().skip(offset).take(limit).collect();
    Ok((page, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Bip110Stance;

    fn node(addr: &str, online: bool) -> NodeInfo {
        NodeInfo {
            addr: addr.into(), depth: 1, protocol_version: 70016,
            user_agent: "/Satoshi:27.0.0/".into(), services: 0, start_height: 0,
            chain_hash: String::new(), handshaked: online, implementation: "Bitcoin Core".into(),
            version: "27.0.0".into(), bip110: Bip110Stance::NotEnforcing,
            first_seen: String::new(), last_seen: String::new(), times_seen: 0, online,
        }
    }

    /// What a crawler records when it fails to reach a peer (see crawler.rs).
    fn unreachable(addr: &str) -> NodeInfo {
        NodeInfo {
            addr: addr.into(), depth: 9, protocol_version: 0, user_agent: String::new(),
            services: 0, start_height: 0, chain_hash: String::new(), handshaked: false,
            implementation: "Unreachable".into(), version: String::new(),
            bip110: Bip110Stance::Unknown, first_seen: String::new(),
            last_seen: String::new(), times_seen: 0, online: false,
        }
    }

    fn own_stub() -> OwnNode {
        OwnNode {
            addr: "self".into(), version: 0, subversion: "x".into(),
            implementation: "Bitcoin Core".into(), network: "main".into(),
        }
    }

    #[test]
    fn known_good_reseed_prefers_recent_handshaked_peers() {
        let path = std::env::temp_dir().join(format!("bip110_db_reseed_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut conn = open(&path).unwrap();
        let own = own_stub();

        let mut older = node("1.1.1.1:8333", true);
        older.last_seen = "2026-01-01T00:00:00Z".into();
        let mut newer = node("2.2.2.2:8333", true);
        newer.last_seen = "2026-06-01T00:00:00Z".into();
        // Never handshaked -> must not be re-seeded (nothing to re-confirm).
        let dead = unreachable("3.3.3.3:8333");
        write_snapshot(&mut conn, "t1", "main", &own, &None, &[older, newer, dead], &[], &BTreeMap::new()).unwrap();

        let got = read_known_good(&conn, 10).unwrap();
        assert_eq!(got, vec!["2.2.2.2:8333".to_string(), "1.1.1.1:8333".to_string()],
                   "most-recently-confirmed first, unreachable excluded");
        // The limit caps the queue.
        assert_eq!(read_known_good(&conn, 1).unwrap(), vec!["2.2.2.2:8333".to_string()]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn aging_drops_nodes_not_confirmed_recently() {
        let path = std::env::temp_dir().join(format!("bip110_db_age_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut conn = open(&path).unwrap();
        let own = own_stub();

        // One peer confirmed just now, one confirmed 10 days ago.
        let mut fresh = node("5.5.5.5:8333", true);
        fresh.last_seen = crate::time::now_iso();
        let mut stale = node("6.6.6.6:8333", true);
        stale.last_seen = crate::time::iso_secs_ago(10 * 24 * 3600);
        write_snapshot(&mut conn, "t1", "main", &own, &None, &[fresh, stale], &[], &BTreeMap::new()).unwrap();

        // No aging: both are reachable.
        let r = read_report(&conn, 100, 0).unwrap();
        assert_eq!(r.aggregates.total_nodes, 2, "aging disabled keeps everything");

        // 48h window: the 10-day-old node ages out, the fresh one stays.
        let r = read_report(&conn, 100, 48 * 3600).unwrap();
        assert_eq!(r.aggregates.total_nodes, 1, "stale node should age out");
        assert_eq!(r.nodes.len(), 1);
        assert_eq!(r.nodes[0].addr, "5.5.5.5:8333");

        // The table endpoint agrees.
        let (rows, total) = read_nodes(&conn, "", "", "", "depth", false, 100, 0, 48 * 3600).unwrap();
        assert_eq!(total, 1, "read_nodes should apply the same window");
        assert_eq!(rows[0].addr, "5.5.5.5:8333");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn failed_probe_never_clobbers_a_successful_one() {
        let path = std::env::temp_dir()
            .join(format!("bip110_db_clobber_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut conn = open(&path).unwrap();
        let own = own_stub();
        let addr = "9.9.9.9:8333";

        // Crawler A handshakes the peer: online.
        write_snapshot(&mut conn, "t1", "main", &own, &None, &[node(addr, true)], &[], &BTreeMap::new()).unwrap();
        // Crawler B (e.g. Tor-focused) fails to reach the same peer and would mark it
        // Unreachable/offline. It must NOT overwrite A's successful handshake.
        write_snapshot(&mut conn, "t2", "main", &own, &None, &[unreachable(addr)], &[], &BTreeMap::new()).unwrap();

        let (online, impl_): (i64, String) = conn.query_row(
            "SELECT online, implementation FROM nodes WHERE addr=?1", params![addr],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(online, 1, "a failed probe must not flip a handshaked node offline");
        assert_eq!(impl_, "Bitcoin Core", "a failed probe must not overwrite the client name");

        // But a later SUCCESSFUL probe is better information and does win.
        write_snapshot(&mut conn, "t3", "main", &own, &None, &[node(addr, true)], &[], &BTreeMap::new()).unwrap();
        let ls: String = conn.query_row(
            "SELECT last_seen FROM nodes WHERE addr=?1", params![addr], |r| r.get(0)).unwrap();
        assert_eq!(ls, "t3", "a handshaked write should refresh the row");

        // And an unreachable peer nobody has handshaked is still recorded.
        write_snapshot(&mut conn, "t4", "main", &own, &None, &[unreachable("8.8.8.8:8333")], &[], &BTreeMap::new()).unwrap();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM nodes WHERE addr='8.8.8.8:8333'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn re_storing_a_block_preserves_its_analysis() {
        use crate::rpc::{BlockInfo, BlockPayload};
        let path = std::env::temp_dir()
            .join(format!("bip110_db_blocks_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut conn = open(&path).unwrap();

        let blk = |h: i64| BlockInfo {
            height: h, hash: format!("{h:064x}"), time: 100, version: 0x2000_0000,
            signals: false, tx_count: 2000, size: 1_500_000, weight: 3_990_000,
            miner: "Foundry USA".into(),
        };

        // Store the block, then analyse it (payload gets filled in).
        write_blocks(&mut conn, &[blk(900_000)]).unwrap();
        let mut payload = BlockPayload::default();
        payload.insc_count = 42;
        write_block_analysis(&conn, 900_000, &payload, None).unwrap();

        // A later new-block event re-fetches the recent window and re-stores this same
        // height. That must NOT wipe the analysis — the regression that made almost every
        // recent block read "scan pending".
        write_blocks(&mut conn, &[blk(900_000)]).unwrap();

        assert!(
            blocks_needing_analysis(&conn, 10).unwrap().is_empty(),
            "re-storing an analysed block must leave its payload intact"
        );
        let out = read_blocks(&conn, 10).unwrap();
        assert_eq!(out[0]["payload"]["insc_count"], 42, "payload must survive the re-store");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn snapshots_accumulate_and_preserve_geo() {
        let path = std::env::temp_dir().join(format!("bip110_db_test_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut conn = open(&path).unwrap();
        let own = OwnNode {
            addr: "self".into(), version: 0, subversion: "x".into(),
            implementation: "Bitcoin Core".into(), network: "main".into(),
        };

        // Snapshot 1: node A, with geolocation.
        let mut geo = BTreeMap::new();
        geo.insert("1.1.1.1:8333".to_string(), GeoInfo {
            lat: 1.0, lon: 2.0, country: "Testland".into(),
            country_code: "TL".into(), city: "Testville".into(),
        });
        write_snapshot(&mut conn, "t1", "main", &own, &None, &[node("1.1.1.1:8333", true)], &[], &geo).unwrap();

        // Snapshot 2: a DIFFERENT node, no geo (simulating a second crawler). A must survive.
        write_snapshot(&mut conn, "t2", "main", &own, &None, &[node("2.2.2.2:8333", true)], &[], &BTreeMap::new()).unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM nodes WHERE online=1", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2, "both nodes should accumulate (no wipe)");

        // Snapshot 3: re-write A WITHOUT geo — the geo must be preserved via COALESCE.
        write_snapshot(&mut conn, "t3", "main", &own, &None, &[node("1.1.1.1:8333", true)], &[], &BTreeMap::new()).unwrap();
        let city: Option<String> = conn.query_row(
            "SELECT city FROM nodes WHERE addr='1.1.1.1:8333'", [], |r| r.get(0)).unwrap();
        assert_eq!(city.as_deref(), Some("Testville"), "geo preserved on geo-less re-write");
        // last_seen stamped for the online node.
        let ls: String = conn.query_row(
            "SELECT last_seen FROM nodes WHERE addr='1.1.1.1:8333'", [], |r| r.get(0)).unwrap();
        assert_eq!(ls, "t3");

        let _ = std::fs::remove_file(&path);
    }
}
