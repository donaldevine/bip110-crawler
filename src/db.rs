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
    Ok(conn)
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
/// multiple concurrent crawlers writing to it. Online nodes get their `last_seen` stamped
/// with `generated_at`; offline (historical) nodes keep their prior `last_seen`.
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
            // Stamp last_seen with this crawl's time for nodes seen now (online); offline
            // history rows keep their prior last_seen so aging stays meaningful.
            let last_seen: &str = if n.online { generated_at } else { &n.last_seen };
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

/// Build a bounded ReportData for the maps/charts/summary: all reachable nodes plus a
/// sample of the rest up to `max`, their edges, geo, and full aggregate counts.
pub fn read_report(conn: &Connection, max: usize) -> Result<ReportData> {
    // The website only exposes reachable (online) nodes.
    let reachable_total: usize = conn
        .query_row("SELECT count(*) FROM nodes WHERE online=1", [], |r| {
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
        let mut st = conn.prepare(
            "SELECT implementation, version, user_agent, online, handshaked, addr FROM nodes WHERE online=1",
        )?;
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
        let mut st = conn.prepare(
            // depth=0 (the own node) is pinned first so it always survives the cap and
            // shows on the maps, not just the uncapped table.
            "SELECT * FROM nodes WHERE online=1 ORDER BY (depth=0) DESC, times_seen DESC LIMIT ?1",
        )?;
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

/// Paginated + filtered node list for the table (all reachable nodes, not the capped
/// report set). Returns (page-of-rows, total-matching). Filtering by `q`/`implementation`
/// happens in SQL; BIP-110 readiness is derived from the user agent, so the `bip` filter,
/// sort, and pagination are applied in memory — the reachable set is a few thousand rows,
/// so this is cheap and keeps the counts exact.
pub fn read_nodes(
    conn: &Connection,
    q: &str,
    implementation: &str,
    bip: &str,
    sort: &str,
    dir_desc: bool,
    limit: usize,
    offset: usize,
) -> Result<(Vec<NodeRow>, usize)> {
    let mut where_clauses = vec!["online=1".to_string()];
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
            handshaked: online, implementation: "Bitcoin Core".into(),
            version: "27.0.0".into(), bip110: Bip110Stance::NotEnforcing,
            first_seen: String::new(), last_seen: String::new(), times_seen: 0, online,
        }
    }

    /// What a crawler records when it fails to reach a peer (see crawler.rs).
    fn unreachable(addr: &str) -> NodeInfo {
        NodeInfo {
            addr: addr.into(), depth: 9, protocol_version: 0, user_agent: String::new(),
            services: 0, start_height: 0, handshaked: false,
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
