//! bip110-crawler — interrogate your Bitcoin node, depth-first crawl its peers,
//! and render an interactive report of implementations, versions, and BIP-110 status.

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bip110_crawler::{crawler, db, geo, history, node, p2p, report, rpc, serve, state};
use crawler::CrawlConfig;
use node::{assess_bip110, classify_user_agent, Bip110Rule, Edge, NodeInfo};
use p2p::{NetworkParams, Peer};

#[derive(Parser, Debug)]
#[command(
    name = "bip110-crawler",
    about = "Crawl the Bitcoin P2P network from your own node and report BIP-110 status."
)]
struct Args {
    /// Network to crawl.
    #[arg(long, default_value = "main")]
    network: String,

    /// Bitcoin Core JSON-RPC URL (e.g. http://127.0.0.1:8332). Omit to skip RPC.
    #[arg(long)]
    rpc_url: Option<String>,

    /// RPC username (or `__cookie__` when using a cookie file value).
    #[arg(long)]
    rpc_user: Option<String>,

    /// RPC password (or the hex from bitcoind's .cookie file).
    #[arg(long)]
    rpc_pass: Option<String>,

    /// Path to bitcoind's `.cookie` file (alternative to --rpc-user/--rpc-pass).
    #[arg(long)]
    rpc_cookie: Option<PathBuf>,

    /// Extra seed peers (`ip:port`) to crawl from, in addition to (or instead of) RPC peers.
    #[arg(long = "seed")]
    seeds: Vec<String>,

    /// Maximum crawl depth. Use 0 for unlimited (crawl the whole reachable network).
    #[arg(long, default_value_t = 2)]
    max_depth: u32,

    /// Stop after discovering this many nodes. Use 0 for unlimited.
    #[arg(long, default_value_t = 500)]
    max_nodes: usize,

    /// Crawl exhaustively: unlimited depth and unlimited nodes (overrides the two above).
    /// Warning: visits the entire reachable network — this can take a long time.
    #[arg(long)]
    exhaustive: bool,

    /// Extra connection attempts before marking a peer unreachable (reduces false negatives).
    #[arg(long, default_value_t = 1)]
    retries: usize,

    /// Max edges recorded per node (keeps data.json manageable on huge crawls; 0 = unlimited).
    #[arg(long, default_value_t = 64)]
    edges_per_node: usize,

    /// Geolocate node IPs for the world map. PRIVACY: sends peer IPs to ip-api.com.
    #[arg(long)]
    geolocate: bool,

    /// Geolocation cache file. Only IPs missing from it are looked up (saves API calls).
    #[arg(long, default_value = "geo-cache.json")]
    geo_cache: PathBuf,

    /// Accumulate results across crawls in this file (nodes persist even when offline).
    #[arg(long)]
    history_file: Option<PathBuf>,

    /// SOCKS5 proxy for crawling Tor onion peers, e.g. 127.0.0.1:9050 (Tor daemon) or
    /// 127.0.0.1:9150 (Tor Browser). Without it, onion peers are skipped.
    #[arg(long)]
    tor_proxy: Option<String>,

    /// Write the report every N seconds *during* the crawl so a long run can be watched
    /// live (0 = only write once at the end). Ideal with --exhaustive.
    #[arg(long, default_value_t = 0)]
    snapshot_interval: u64,

    /// Persist resumable crawl state here (frontier + nodes + edges). Restarting with
    /// the same file continues where it left off instead of starting over.
    #[arg(long)]
    state_file: Option<PathBuf>,

    /// Max nodes to include in the report (0 = unlimited). Keeps the page loadable on
    /// huge crawls — all reachable nodes are kept plus a sample of the rest. The full
    /// dataset still lives in --state-file.
    #[arg(long, default_value_t = 3000)]
    report_max_nodes: usize,

    /// SQLite database to write the full crawl into (enables the `--serve` API).
    #[arg(long)]
    db: Option<PathBuf>,

    /// Run the web/API server (reads --db) instead of crawling. Host this behind your
    /// tunnel; the page fetches /api/report and /api/nodes.
    #[arg(long)]
    serve: bool,

    /// Port for --serve.
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// Freshness window for --serve, in hours: a node counts as reachable only if it was
    /// confirmed within this long. Because the DB accumulates and a failed probe never
    /// overwrites a good one, this is what stops long-dead nodes inflating the totals —
    /// re-crawls refresh living peers, dead ones fall out. Set 0 to disable aging.
    ///
    /// MUST be longer than a full re-crawl cycle, or nodes expire faster than the crawler
    /// can re-confirm them and the count bleeds downwards. A cycle is slow because ~97% of
    /// the gossiped address book is dead and every one costs a connection timeout, so
    /// re-confirmation runs at only ~75 nodes/hour — revisiting ~23k nodes takes well over
    /// a week. Hence the 14-day default; raise it further if you ever see totals sagging.
    #[arg(long, default_value_t = 336)]
    max_age_hours: u64,

    /// Max known-good peers to re-seed each crawl cycle from `--db` (0 = don't re-seed).
    /// These go to the front of the queue so a re-crawl refreshes the live network before
    /// grinding the mostly-dead address book.
    #[arg(long, default_value_t = 50_000)]
    reseed_max: usize,

    /// Number of concurrent clearnet probing workers. Probing is I/O-bound (mostly
    /// waiting on connect/handshake timeouts), so this can far exceed the CPU core count.
    #[arg(long, default_value_t = 64)]
    threads: usize,

    /// Number of concurrent onion probing workers (a separate pool used only with
    /// --tor-proxy, so slow Tor dials never hold up clearnet workers).
    #[arg(long, default_value_t = 48)]
    tor_threads: usize,

    /// TCP connect timeout (seconds). Higher = fewer slow-but-alive nodes marked
    /// unreachable, at the cost of a slower crawl on dead addresses.
    #[arg(long, default_value_t = 8)]
    connect_timeout: u64,

    /// Per-read/write socket timeout (seconds).
    #[arg(long, default_value_t = 10)]
    io_timeout: u64,

    /// How long to collect `addr` gossip from each peer (seconds).
    #[arg(long, default_value_t = 3)]
    addr_collect: u64,

    /// Ask every handshaked peer which chain it is on (P2P `getheaders`), and group peers by
    /// their block hash — the definitive chain-split test. Needs `--rpc-*` (the block locator
    /// is built from your own chain) and `--db` (to store the result).
    ///
    /// Enable this on ONE crawler only. The cluster summary is a single record keyed on the
    /// whole surveyed population, so two crawlers writing it would overwrite each other and
    /// the page would flip between their two different samples.
    #[arg(long)]
    chain_check: bool,

    /// Number of recent blocks to scan for BIP-110 (bit 4) signalling.
    #[arg(long, default_value_t = 2016)]
    signal_window: u32,

    /// Block version bit that BIP-110 signals on.
    #[arg(long, default_value_t = 4)]
    signal_bit: u8,

    /// Optional JSON file of BIP-110 classification rules
    /// (`[{"user_agent_contains":"knots","stance":"enforcing"}, ...]`).
    #[arg(long)]
    rules: Option<PathBuf>,

    /// Output directory for the report.
    #[arg(long, default_value = "report")]
    out: PathBuf,

    /// Keep running: re-crawl on a loop and rewrite the report each cycle.
    #[arg(long)]
    watch: bool,

    /// Seconds to wait between crawls in --watch mode.
    #[arg(long, default_value_t = 300)]
    interval: u64,

    /// How often (seconds) the report page re-fetches data.json in --watch mode.
    #[arg(long, default_value_t = 10)]
    page_refresh: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Server mode: serve the API/page from the DB instead of crawling.
    if args.serve {
        let db_path = args
            .db
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--serve requires --db <path>"))?;
        return serve::serve(&db_path, args.port, args.max_age_hours * 3600);
    }

    let net = NetworkParams::from_name(&args.network)?;
    let rules = Arc::new(load_rules(&args)?);

    if args.watch {
        eprintln!(
            "[watch] live mode: re-crawling every {}s; report at {}/index.html",
            args.interval,
            args.out.display()
        );
        let mut cycle = 1u64;
        loop {
            eprintln!("[watch] === crawl #{cycle} ===");
            if let Err(e) = run_cycle(&args, net, &rules) {
                eprintln!("[watch] crawl #{cycle} failed: {e:#}");
            }
            eprintln!("[watch] sleeping {}s before next crawl…", args.interval);
            std::thread::sleep(Duration::from_secs(args.interval));
            cycle += 1;
        }
    } else {
        run_cycle(&args, net, &rules)
    }
}

/// Compare peers' block hashes this far below our tip. Far enough that peers a few blocks
/// behind still report it, close enough to catch a fork the moment it matters.
const CHAIN_REF_LAG: i64 = 6;
/// Newest locator entry, below the reference height so the peer's reply covers it.
const LOCATOR_START_LAG: i64 = 12;

/// Build a BIP-style block locator from our own chain: ten consecutive hashes then
/// exponentially spaced ones, walking back from just below the tip.
///
/// The spacing is what makes this a fork detector. A peer walks the locator, finds the most
/// recent hash it recognises, and answers from *that* block forward along its own chain — so
/// even a peer on a chain that diverged thousands of blocks ago still shares an ancestor with
/// us and tells us exactly where it went its own way.
fn build_locator(client: &rpc::RpcClient, tip: i64) -> Vec<([u8; 32], i64)> {
    let mut heights = Vec::new();
    let (mut h, mut step, mut n) = (tip - LOCATOR_START_LAG, 1i64, 0);
    while h > 0 && heights.len() < 24 {
        heights.push(h);
        n += 1;
        if n > 10 {
            step *= 2;
        }
        h -= step;
    }
    let mut out = Vec::with_capacity(heights.len());
    for ht in heights {
        match client.block_hash_at(ht) {
            Ok(hash) => out.push((hash, ht)),
            // A gap just shortens the locator; it stays valid as long as one entry matches.
            Err(e) => eprintln!("[chain] locator: getblockhash {ht} failed: {e:#}"),
        }
    }
    out
}

/// Perform one full crawl (RPC interrogation + P2P DFS) and write the report.
fn run_cycle(args: &Args, net: NetworkParams, rules: &Arc<Vec<Bip110Rule>>) -> Result<()> {
    let rules = rules.clone();

    // Parse the optional Tor SOCKS5 proxy up front.
    let tor_proxy: Option<SocketAddr> = match &args.tor_proxy {
        Some(s) => Some(
            s.parse::<SocketAddr>()
                .with_context(|| format!("invalid --tor-proxy '{s}' (want host:port)"))?,
        ),
        None => None,
    };

    // ---- Interrogate own node over RPC (optional) ----
    let mut own_node = None;
    let mut signalling = None;
    let mut own_ip: Option<std::net::IpAddr> = None; // our public IP, for geolocating self
    let mut seeds: Vec<(Peer, u32, Option<NodeInfo>)> = Vec::new();
    let mut own_edges: Vec<Edge> = Vec::new();
    let mut own_label = String::from("self");

    if let Some(client) = build_rpc(args)? {
        eprintln!("[rpc] querying own node…");
        let (version, subversion, services, local_addr) = client
            .network_info()
            .context("getnetworkinfo failed — check --rpc-* credentials")?;
        own_ip = local_addr.as_deref().and_then(|a| a.parse().ok());
        if let Some(ip) = own_ip {
            eprintln!("[rpc] own node public IP: {ip} (will geolocate for the map)");
        }
        let (impl_name, ver) = classify_user_agent(&subversion);
        own_label = format!("self ({})", subversion);
        own_node = Some(report::OwnNode {
            addr: own_label.clone(),
            version,
            subversion: subversion.clone(),
            implementation: impl_name.clone(),
            network: net.name.to_string(),
        });
        // Own node appears in the graph at depth 0.
        seeds.push((
            // A placeholder loopback addr; the own node is not probed over P2P.
            Peer::Clearnet("127.0.0.1:0".parse().unwrap()),
            0,
            None,
        ));
        // Direct peers (ground truth: real live connections + their subvers).
        let peers = client.peer_info().unwrap_or_default();
        eprintln!("[rpc] {} directly connected peers", peers.len());
        for (sa, subver, protover, height) in peers {
            let (impl_name, ver) = classify_user_agent(&subver);
            let bip110 = assess_bip110(&impl_name, &subver, &rules);
            let info = NodeInfo {
                addr: sa.to_string(),
                depth: 1,
                protocol_version: protover,
                user_agent: subver.clone(),
                services: 0,
                start_height: height,
                chain_hash: String::new(),
                handshaked: false, // becomes true if the crawler also handshakes it
                implementation: impl_name,
                version: ver,
                bip110,
                first_seen: String::new(),
                last_seen: String::new(),
                times_seen: 0,
                online: false,
            };
            own_edges.push(Edge {
                from: own_label.clone(),
                to: sa.to_string(),
            });
            seeds.push((sa, 1, Some(info)));
        }
        // Authoritative miner signalling scan.
        if args.signal_window > 0 {
            eprintln!(
                "[rpc] scanning last {} blocks for bit-{} signalling…",
                args.signal_window, args.signal_bit
            );
            match client.signalling(args.signal_window, args.signal_bit) {
                Ok((s, _heights)) => {
                    eprintln!(
                        "[rpc] signalling: {}/{} blocks ({:.1}%)",
                        s.blocks_signalling, s.blocks_scanned, s.percent
                    );
                    signalling = Some(s);
                }
                Err(e) => eprintln!("[rpc] signalling scan failed: {e:#}"),
            }
        }
        // Placeholder own-node record; folded in after the crawl.
        let _ = (version, services, ver, impl_name);
    }

    // ---- Re-seed from known-good peers in the DB ----
    // On a re-crawl this is what keeps the site's numbers alive. Seeding only from the RPC
    // peers means the cycle rediscovers everything from scratch and spends most of its time
    // on the ~97%-dead address book, so known-good nodes get re-confirmed far too slowly and
    // age out of the freshness window. Queuing them up front refreshes the live network
    // first. They're depth-1 and deduped against the seeds we already have.
    if let Some(dbpath) = &args.db {
        match db::open(dbpath).and_then(|c| db::read_known_good(&c, args.reseed_max)) {
            Ok(known) if !known.is_empty() => {
                let have: std::collections::HashSet<String> =
                    seeds.iter().map(|(p, _, _)| p.to_string()).collect();
                let mut added = 0usize;
                for addr in known {
                    if have.contains(&addr) {
                        continue;
                    }
                    // Peer::parse (not parse_seed) — these are stored ip:port/onion
                    // literals, so this stays a pure parse with no DNS lookups.
                    if let Some(peer) = Peer::parse(&addr, net.default_port) {
                        seeds.push((peer, 1, None));
                        added += 1;
                    }
                }
                eprintln!("[reseed] queued {added} known-good peers from {}", dbpath.display());
            }
            Ok(_) => {}
            Err(e) => eprintln!("[reseed] skipped ({e:#})"),
        }
    }

    // ---- Extra CLI seeds ----
    for s in &args.seeds {
        let sa = parse_seed(s, net.default_port)?;
        seeds.push((sa, 0, None));
    }

    // The only non-crawlable seed is the depth-0 loopback placeholder (port 0).
    let has_real_seed = seeds
        .iter()
        .any(|(p, _, _)| !matches!(p, Peer::Clearnet(sa) if sa.port() == 0));
    if !has_real_seed {
        bail!("no crawlable seeds — provide --rpc-* (to read your node's peers) or --seed ip:port");
    }

    // ---- Run the depth-first crawl ----
    let (max_depth, max_nodes) = if args.exhaustive {
        (0, 0) // unlimited depth and nodes
    } else {
        (args.max_depth, args.max_nodes)
    };
    let fmt = |v: usize| if v == 0 { "unlimited".to_string() } else { v.to_string() };
    let tor_desc = match tor_proxy {
        Some(p) => format!("{p} ({} workers)", args.tor_threads),
        None => "off".to_string(),
    };
    eprintln!(
        "[crawl] starting: max_depth={} max_nodes={} clearnet_workers={} retries={} tor={}",
        fmt(max_depth as usize),
        fmt(max_nodes),
        args.threads,
        args.retries,
        tor_desc
    );
    // Chain check: ask every peer we handshake which chain it is on. Needs RPC (to build the
    // locator from our own chain); without it the locator is empty and peers aren't asked for
    // headers at all, leaving the crawl byte-for-byte as it was.
    let locator_rpc = if args.chain_check { build_rpc(args)? } else { None };
    let (locator, chain_ref_height) = match (&locator_rpc, signalling.as_ref()) {
        (Some(client), Some(sig)) if sig.tip_height > LOCATOR_START_LAG => {
            let loc = build_locator(client, sig.tip_height);
            eprintln!(
                "[chain] locator built: {} entries, comparing peer hashes at height {}",
                loc.len(),
                sig.tip_height - CHAIN_REF_LAG
            );
            (loc, sig.tip_height - CHAIN_REF_LAG)
        }
        _ => (Vec::new(), 0),
    };

    let cfg = CrawlConfig {
        net,
        locator: Arc::new(locator),
        chain_ref_height,
        max_depth,
        max_nodes,
        threads: args.threads,
        tor_threads: args.tor_threads,
        connect_timeout: Duration::from_secs(args.connect_timeout),
        io_timeout: Duration::from_secs(args.io_timeout),
        addr_collect: Duration::from_secs(args.addr_collect),
        retries: args.retries,
        edges_per_node: args.edges_per_node,
        tor_proxy,
        rules: Arc::clone(&rules),
    };
    // Precompute the own-node records so both live snapshots and the final report can
    // splice them in. `report_own` is the OwnNode shown in the header; `own_node_info`
    // is its depth-0 graph record.
    let report_own = own_node.clone().unwrap_or_else(|| report::OwnNode {
        addr: own_label,
        version: 0,
        subversion: String::from("(no RPC)"),
        implementation: String::from("Unknown"),
        network: net.name.to_string(),
    });
    let own_node_info: Option<NodeInfo> = own_node.as_ref().map(|o| own_node_record(o, &rules));
    let live = args.watch || args.snapshot_interval > 0;
    let refresh = if args.page_refresh > 0 { args.page_refresh } else { 15 };

    // How many recent blocks to (re-)fetch each time a new block arrives. Blocks are
    // upserted by height, so this only needs to cover the newest few — the table keeps
    // everything fetched before, and the explorer's history grows as the crawler runs.
    const BLOCKS_PER_REFRESH: u32 = 30;
    // Data-payload scans per new block. Each pulls a full verbose block over RPC, so keep
    // the batch small: one new block arrives every ~10 minutes, and this still drains an
    // initial backlog of 30 within a few hours.
    const ANALYZE_PER_REFRESH: usize = 4;
    // Per-refresh cap on backfilling the period's older signalling blocks (those outside the
    // recent window). Each is one getblock+coinbase fetch. Before mandatory signalling (block
    // 961632) only a handful of blocks per period signal, so this clears the whole backlog in
    // a refresh or two and the explorer's detailed list quickly matches the header-scan count.
    // Once the mandatory window is reached most/all of the period signals (up to ~2016 blocks);
    // the cap then paces the backfill so a full period drains across refreshes, not one snapshot.
    const STORE_SIGNALLING_PER_REFRESH: usize = 64;

    // Shared, refreshable signalling (incl. chain tip). Seeded with the startup scan and
    // re-measured from the node during the crawl (see the snapshot callback) so the
    // report's tip height + lock-in countdown track the chain instead of freezing.
    let signal_cache: Arc<Mutex<Option<node::SignalStats>>> = Arc::new(Mutex::new(signalling.clone()));

    // Live snapshots: rewrite the report every N seconds *during* the crawl, so a long
    // run can be watched as the DFS expands.
    let snapshot: Option<(Duration, crawler::SnapshotFn)> = if args.snapshot_interval > 0 {
        let out = args.out.clone();
        let own_info = own_node_info.clone();
        let own_edges = own_edges.clone();
        let report_own = report_own.clone();
        let network = net.name.to_string();
        let geolocate = args.geolocate;
        let geo_cache = args.geo_cache.clone();
        let own_ip = own_ip;
        let own_addr = report_own.addr.clone();
        let report_max = args.report_max_nodes;
        let db_path = args.db.clone();
        let network2 = net.name.to_string();
        // A dedicated RPC client + the shared cache, so snapshots can re-scan signalling.
        let rpc = build_rpc(args)?;
        let signal_window = args.signal_window;
        let signal_bit = args.signal_bit;
        let signal_cache_cb = Arc::clone(&signal_cache);
        let cb: crawler::SnapshotFn = Arc::new(move |mut nodes: Vec<NodeInfo>, mut edges: Vec<Edge>| {
            let discovered_total = nodes.len();
            // Re-measure signalling when the node has a NEW block, so the tip height and
            // countdown stay live. A cheap getblockcount gates the expensive window scan.
            if let (Some(client), true) = (&rpc, signal_window > 0) {
                if let Ok(tip) = client.block_count() {
                    let cached_tip = signal_cache_cb.lock().unwrap().as_ref().map(|s| s.tip_height);
                    if cached_tip != Some(tip) {
                        // The period scan returns the heights of every signalling block it
                        // found; used below to backfill any that fall outside the recent
                        // window, so the explorer's "signalling this period" list is
                        // authoritative from the node, not just the recent blocks.
                        let mut signalling_heights: Vec<i64> = Vec::new();
                        match client.signalling(signal_window, signal_bit) {
                            Ok((s, heights)) => {
                                *signal_cache_cb.lock().unwrap() = Some(s);
                                signalling_heights = heights;
                            }
                            Err(e) => eprintln!("[snapshot] signalling refresh failed: {e:#}"),
                        }
                        // Cluster the crawled peers onto chains by the block hash each
                        // reported at the reference height. Unlike heights (which drift with
                        // probe timing) a hash is identity: two peers with different hashes at
                        // the same height are provably on different chains.
                        if let (Some(dbpath), true) = (&db_path, chain_ref_height > 0) {
                            let mut clusters: std::collections::BTreeMap<
                                String,
                                (u32, std::collections::BTreeMap<String, u32>),
                            > = Default::default();
                            for n in nodes.iter().filter(|n| n.handshaked && !n.chain_hash.is_empty()) {
                                let e = clusters.entry(n.chain_hash.clone()).or_default();
                                e.0 += 1;
                                *e.1.entry(n.implementation.clone()).or_insert(0) += 1;
                            }
                            let ours = client
                                .block_hash_at(chain_ref_height)
                                .map(|h| p2p::hash_hex(&h))
                                .unwrap_or_default();
                            let responded: u32 = clusters.values().map(|(c, _)| *c).sum();
                            let mut list: Vec<serde_json::Value> = clusters
                                .iter()
                                .map(|(hash, (count, by_impl))| {
                                    serde_json::json!({
                                        "hash": hash, "nodes": count,
                                        "ours": !ours.is_empty() && *hash == ours,
                                        "by_implementation": by_impl,
                                    })
                                })
                                .collect();
                            list.sort_by_key(|c| {
                                std::cmp::Reverse(c["nodes"].as_u64().unwrap_or(0))
                            });
                            let summary = serde_json::json!({
                                "ref_height": chain_ref_height,
                                "our_hash": ours,
                                "responded": responded,
                                "clusters": list,
                            });
                            if let Ok(c) = db::open(dbpath) {
                                if let Err(e) = db::write_chain_clusters(&c, &summary) {
                                    eprintln!("[chain] cluster store failed: {e:#}");
                                }
                            }
                            if responded > 0 && summary["clusters"].as_array().map_or(0, |a| a.len()) > 1 {
                                eprintln!(
                                    "[chain] {} distinct chains seen across {responded} responding peers at height {chain_ref_height}",
                                    summary["clusters"].as_array().unwrap().len()
                                );
                            }
                        }
                        // Chain-split check, on the same new-block trigger. `getchaintips` is
                        // one cheap call and is the only authoritative view of what THIS node
                        // rejects — which is exactly what a mandatory-signalling split looks
                        // like from the inside. Peers supply corroboration from their tips.
                        if let Some(dbpath) = &db_path {
                            match client.chain_tips() {
                                Ok(tips) => {
                                    let peers: Vec<&NodeInfo> = nodes.iter().collect();
                                    let split = node::assess_chain_split(&tips, &peers);
                                    if split.split {
                                        eprintln!(
                                            "[split] CHAIN SPLIT SUSPECTED: active={} longest_fork={} rejected={} ready_median={} other_median={}",
                                            split.active_height, split.longest_fork,
                                            split.rejected_branches, split.ready_median_height,
                                            split.other_median_height
                                        );
                                    }
                                    match db::open(dbpath) {
                                        Ok(c) => {
                                            if let Err(e) = db::write_chain_split(&c, &split) {
                                                eprintln!("[split] store failed: {e:#}");
                                            }
                                        }
                                        Err(e) => eprintln!("[split] db open failed: {e:#}"),
                                    }
                                }
                                Err(e) => eprintln!("[split] getchaintips failed: {e:#}"),
                            }
                        }
                        // Same new-block trigger feeds the /blocks explorer. Only the
                        // crawler holds an RPC connection, so it stores blocks and the API
                        // server just reads them. Blocks are immutable → upsert by height,
                        // so the table accumulates without ever re-fetching old ones.
                        if let Some(dbpath) = &db_path {
                            match client.recent_blocks(BLOCKS_PER_REFRESH, signal_bit) {
                                Ok(blocks) => match db::open(dbpath) {
                                    Ok(mut c) => {
                                        if let Err(e) = db::write_blocks(&mut c, &blocks) {
                                            eprintln!("[blocks] store failed: {e:#}");
                                        }
                                        // Backfill the period's signalling blocks that aren't
                                        // stored yet (those older than the recent window). The
                                        // scan already found their heights for free; fetch full
                                        // detail for a capped batch and upsert, so the list is
                                        // authoritative and any backlog drains over refreshes.
                                        // The payload/fee analysis below then enriches them.
                                        match db::unstored_heights(&c, &signalling_heights) {
                                            Ok(mut missing) => {
                                                missing.sort_unstable_by(|a, b| b.cmp(a)); // newest first
                                                missing.truncate(STORE_SIGNALLING_PER_REFRESH);
                                                if !missing.is_empty() {
                                                    match client.blocks_at_heights(&missing, signal_bit) {
                                                        Ok(sb) => {
                                                            if let Err(e) = db::write_blocks(&mut c, &sb) {
                                                                eprintln!("[blocks] signalling store failed: {e:#}");
                                                            }
                                                        }
                                                        Err(e) => eprintln!("[blocks] signalling backfill failed: {e:#}"),
                                                    }
                                                }
                                            }
                                            Err(e) => eprintln!("[blocks] unstored-heights query failed: {e:#}"),
                                        }
                                        // Scan a few not-yet-analysed blocks for data
                                        // payloads. Each needs the full verbose block from
                                        // RPC (tens of MB), so cap the batch — any backlog
                                        // drains over subsequent blocks rather than
                                        // stalling this snapshot.
                                        match db::blocks_needing_analysis(&c, ANALYZE_PER_REFRESH) {
                                            Ok(pending) => {
                                                for (height, hash) in pending {
                                                    match client.analyze_block(&hash) {
                                                        Ok(p) => {
                                                            // Fees are a bonus: keep the
                                                            // payload scan even if
                                                            // getblockstats is unavailable.
                                                            let s = client.block_stats(height).ok();
                                                            if let Err(e) = db::write_block_analysis(
                                                                &c, height, &p, s.as_ref(),
                                                            ) {
                                                                eprintln!("[blocks] analysis store failed at {height}: {e:#}");
                                                            }
                                                        }
                                                        Err(e) => {
                                                            eprintln!("[blocks] analyse {height} failed: {e:#}");
                                                            break; // pruned/unavailable — stop for now
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => eprintln!("[blocks] pending query failed: {e:#}"),
                                        }
                                    }
                                    Err(e) => eprintln!("[blocks] db open failed: {e:#}"),
                                },
                                Err(e) => eprintln!("[blocks] fetch failed: {e:#}"),
                            }
                        }
                    }
                }
            }
            let signalling = signal_cache_cb.lock().unwrap().clone();
            // Splice the own node (+ its edges) into the snapshot so the DB the live site
            // reads actually contains it. The post-crawl splice never fires during a
            // continuous crawl, so without this your own node is absent from serve mode.
            // Drop the depth-0 placeholder seed first.
            nodes.retain(|n| n.addr != "127.0.0.1:0");
            if let Some(oni) = &own_info {
                nodes.push(oni.clone());
                edges.extend(own_edges.iter().cloned());
            }
            // Geolocate reachable nodes only (for map + DB).
            let geo = if geolocate {
                let reachable: Vec<NodeInfo> = nodes.iter().filter(|n| n.online).cloned().collect();
                let mut g = geolocate_map(&reachable, &geo_cache);
                attach_own_geo(&mut g, &own_addr, own_ip, &geo_cache);
                Some(g)
            } else {
                None
            };
            // Write the full set to the DB, then show only reachable on the site.
            if let Some(dbpath) = &db_path {
                write_db(dbpath, &now_iso(), &network2, &report_own, &signalling, &nodes, &edges, &geo);
            }
            let _ = discovered_total;
            reachable_only(&mut nodes, &mut edges);
            let reachable_total = nodes.len();
            cap_report(&mut nodes, &mut edges, report_max);
            let data = assemble_report(
                nodes, edges, &None, &[], &report_own, &signalling, geo, &network,
                now_iso(), true, refresh, reachable_total,
            );
            match report::write_report(&out, &data) {
                Ok(()) => eprintln!("[snapshot] report updated ({} nodes)", data.aggregates.total_nodes),
                Err(e) => eprintln!("[snapshot] write failed: {e:#}"),
            }
        });
        Some((Duration::from_secs(args.snapshot_interval), cb))
    } else {
        None
    };

    // Resume from prior state + persist state, if a state file is configured.
    let resume = match &args.state_file {
        Some(path) => match state::CrawlState::load(path) {
            Ok(st) => {
                if st.is_some() {
                    eprintln!("[resume] loading prior state from {}", path.display());
                }
                st
            }
            Err(e) => {
                eprintln!("[resume] could not load {}: {e:#} — starting fresh", path.display());
                None
            }
        },
        None => None,
    };
    let persist = args.state_file.as_ref().map(|p| {
        // Persist at the snapshot cadence when set, otherwise every 60s.
        let secs = if args.snapshot_interval > 0 { args.snapshot_interval } else { 60 };
        (Duration::from_secs(secs), p.clone())
    });

    let io = crawler::CrawlIo { snapshot, resume, persist };
    let mut result = crawler::crawl(seeds, cfg, io);

    // Splice the own node + its edges into the crawl result.
    result.nodes.retain(|n| n.addr != "127.0.0.1:0");
    if let Some(oni) = &own_node_info {
        result.nodes.push(oni.clone());
        result.edges.extend(own_edges.clone());
    }

    // Single timestamp for this run — used for both history bookkeeping and the report.
    let now = now_iso();

    // ---- Accumulate into history (optional): grows over time, keeps offline nodes ----
    if let Some(hpath) = &args.history_file {
        match history::History::load(hpath) {
            Ok(mut hist) => {
                hist.merge(std::mem::take(&mut result.nodes), &now);
                if let Err(e) = hist.save(hpath) {
                    eprintln!("[history] save failed: {e:#}");
                }
                eprintln!(
                    "[history] {} known nodes total ({} online now) in {}",
                    hist.nodes.len(),
                    hist.online_count(),
                    hpath.display()
                );
                result.nodes = hist.into_nodes();
            }
            Err(e) => eprintln!("[history] load failed, continuing without history: {e:#}"),
        }
    }

    let known_total = result.nodes.len(); // full, including unreachable (for logging + DB)

    // ---- Geolocate reachable nodes (for the world map + DB), not the 100k+ stubs ----
    let geo = if args.geolocate {
        eprintln!("[geo] geolocating reachable node IPs (cache: {})…", args.geo_cache.display());
        let reachable: Vec<NodeInfo> = result.nodes.iter().filter(|n| n.online).cloned().collect();
        let mut g = geolocate_map(&reachable, &args.geo_cache);
        attach_own_geo(&mut g, &report_own.addr, own_ip, &args.geo_cache);
        Some(g)
    } else {
        None
    };

    // Use the freshest signalling the snapshots re-measured (falls back to the startup
    // scan when snapshots are off).
    let signalling = signal_cache.lock().unwrap().clone();

    // ---- Write the FULL dataset to SQLite (the store keeps everything) ----
    if let Some(dbpath) = &args.db {
        write_db(dbpath, &now, net.name, &report_own, &signalling, &result.nodes, &result.edges, &geo);
    }

    // ---- The website shows ONLY reachable nodes: drop unreachable + their edges ----
    reachable_only(&mut result.nodes, &mut result.edges);
    let reachable_total = result.nodes.len();
    cap_report(&mut result.nodes, &mut result.edges, args.report_max_nodes); // safety for huge nets

    let data = assemble_report(
        result.nodes,
        result.edges,
        &None, // own node already spliced above
        &[],
        &report_own,
        &signalling,
        geo,
        net.name,
        now,
        live,
        if live { refresh } else { 0 },
        reachable_total,
    );
    eprintln!(
        "[done] {} known ({} reachable, shown on the site)",
        known_total, reachable_total
    );
    report::write_report(&args.out, &data)?;
    println!(
        "Report written to {}/index.html — open it in a browser.",
        args.out.display()
    );
    Ok(())
}

/// Build the depth-0 NodeInfo record for our own node.
fn own_node_record(own: &report::OwnNode, rules: &[Bip110Rule]) -> NodeInfo {
    NodeInfo {
        addr: own.addr.clone(),
        depth: 0,
        protocol_version: 0,
        user_agent: own.subversion.clone(),
        services: 0,
        start_height: 0,
        chain_hash: String::new(),
        handshaked: true,
        implementation: own.implementation.clone(),
        version: classify_user_agent(&own.subversion).1,
        bip110: assess_bip110(&own.implementation, &own.subversion, rules),
        first_seen: String::new(),
        last_seen: String::new(),
        times_seen: 0,
        online: true,
    }
}

/// Geolocate the IP-bearing nodes and return a `addr -> GeoInfo` map (cache-aware:
/// only IPs missing from the cache hit the API).
fn geolocate_map(
    nodes: &[NodeInfo],
    cache: &std::path::Path,
) -> std::collections::BTreeMap<String, geo::GeoInfo> {
    let mut ips = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for n in nodes {
        if let Some(ip) = geo::ip_of(&n.addr) {
            if seen.insert(ip) {
                ips.push(ip);
            }
        }
    }
    let by_ip = geo::geolocate_cached(&ips, cache);
    let mut by_addr = std::collections::BTreeMap::new();
    for n in nodes {
        if let Some(ip) = geo::ip_of(&n.addr) {
            if let Some(g) = by_ip.get(&ip.to_string()) {
                by_addr.insert(n.addr.clone(), g.clone());
            }
        }
    }
    by_addr
}

/// Write the full crawl snapshot to SQLite (errors are logged, never fatal).
#[allow(clippy::too_many_arguments)]
fn write_db(
    path: &std::path::Path,
    generated_at: &str,
    network: &str,
    own_node: &report::OwnNode,
    signalling: &Option<node::SignalStats>,
    nodes: &[NodeInfo],
    edges: &[Edge],
    geo: &Option<std::collections::BTreeMap<String, geo::GeoInfo>>,
) {
    let empty = std::collections::BTreeMap::new();
    let geo = geo.as_ref().unwrap_or(&empty);
    match db::open(path) {
        Ok(mut conn) => match db::write_snapshot(
            &mut conn, generated_at, network, own_node, signalling, nodes, edges, geo,
        ) {
            Ok(()) => eprintln!(
                "[db] wrote {} nodes, {} edges -> {}",
                nodes.len(),
                edges.len(),
                path.display()
            ),
            Err(e) => eprintln!("[db] write failed: {e:#}"),
        },
        Err(e) => eprintln!("[db] open failed: {e:#}"),
    }
}

/// Geolocate our own node's public IP and file it under the own-node address, so the
/// map/table can place "this node" (e.g. in Ireland) instead of showing no location.
fn attach_own_geo(
    geo: &mut std::collections::BTreeMap<String, geo::GeoInfo>,
    own_addr: &str,
    own_ip: Option<std::net::IpAddr>,
    cache: &std::path::Path,
) {
    if let Some(ip) = own_ip {
        let m = geo::geolocate_cached(&[ip], cache);
        if let Some(g) = m.get(&ip.to_string()) {
            geo.insert(own_addr.to_string(), g.clone());
        }
    }
}

/// Splice the own node + its edges into a crawl result and package it as ReportData.
/// (History merge and the "[done]" logging are handled by the caller for the final
/// write; snapshots call this directly with `live = true`.)
#[allow(clippy::too_many_arguments)]
fn assemble_report(
    mut nodes: Vec<NodeInfo>,
    mut edges: Vec<Edge>,
    own_info: &Option<NodeInfo>,
    own_edges: &[Edge],
    report_own: &report::OwnNode,
    signalling: &Option<node::SignalStats>,
    geo: Option<std::collections::BTreeMap<String, geo::GeoInfo>>,
    network: &str,
    generated_at: String,
    live: bool,
    refresh_seconds: u32,
    discovered_total: usize,
) -> report::ReportData {
    nodes.retain(|n| n.addr != "127.0.0.1:0");
    if let Some(oni) = own_info {
        nodes.push(oni.clone());
        edges.extend_from_slice(own_edges);
    }
    let aggregates = node::Aggregates::from_nodes(&nodes);
    report::ReportData {
        generated_at,
        network: network.to_string(),
        own_node: report_own.clone(),
        signalling: signalling.clone(),
        // The live assessment is written straight to the DB on each new block; this
        // in-memory report (static/--watch output) carries none.
        chain_split: None,
        aggregates,
        discovered_total,
        nodes,
        edges,
        geo,
        live,
        refresh_seconds,
    }
}

/// Bound the report to a viewable size: keep all reachable (online) nodes plus a sample
/// of the rest up to `max`, and drop edges whose endpoints fall outside the kept set.
/// An exhaustive crawl finds 100k+ mostly-unreachable gossip addresses — far more than a
/// browser can render — while the full set stays in the state file.
/// Keep only reachable (online) nodes and edges between them — the website never shows
/// unreachable nodes. (The full set is still written to the DB / state file.)
fn reachable_only(nodes: &mut Vec<NodeInfo>, edges: &mut Vec<Edge>) {
    nodes.retain(|n| n.online);
    let keep: std::collections::HashSet<String> = nodes.iter().map(|n| n.addr.clone()).collect();
    edges.retain(|e| keep.contains(&e.from) && keep.contains(&e.to));
}

fn cap_report(nodes: &mut Vec<NodeInfo>, edges: &mut Vec<Edge>, max: usize) {
    if max == 0 || nodes.len() <= max {
        return;
    }
    nodes.sort_by_key(|n| !n.online); // online first (false sorts before true)
    nodes.truncate(max);
    let keep: std::collections::HashSet<String> = nodes.iter().map(|n| n.addr.clone()).collect();
    edges.retain(|e| keep.contains(&e.from) && keep.contains(&e.to));
}

fn build_rpc(args: &Args) -> Result<Option<rpc::RpcClient>> {
    let url = match &args.rpc_url {
        Some(u) => u.clone(),
        None => return Ok(None),
    };
    let (user, pass) = if let Some(cookie) = &args.rpc_cookie {
        let raw = std::fs::read_to_string(cookie)
            .with_context(|| format!("reading cookie {}", cookie.display()))?;
        let raw = raw.trim();
        let (u, p) = raw
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("cookie file not in user:pass form"))?;
        (u.to_string(), p.to_string())
    } else {
        (
            args.rpc_user.clone().unwrap_or_default(),
            args.rpc_pass.clone().unwrap_or_default(),
        )
    };
    Ok(Some(rpc::RpcClient::new(url, user, pass)))
}

fn load_rules(args: &Args) -> Result<Vec<Bip110Rule>> {
    match &args.rules {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading rules {}", path.display()))?;
            let rules: Vec<Bip110Rule> =
                serde_json::from_str(&raw).context("parsing BIP-110 rules JSON")?;
            Ok(rules)
        }
        None => Ok(Vec::new()),
    }
}

/// Parse a seed: clearnet `ip:port` / `host` (DNS-resolved), or a `.onion` address.
fn parse_seed(s: &str, default_port: u16) -> Result<Peer> {
    // Onion (or clearnet ip:port) handled directly by Peer::parse.
    if let Some(peer) = Peer::parse(s, default_port) {
        return Ok(peer);
    }
    // Otherwise treat as a clearnet hostname and DNS-resolve it.
    let with_port = if s.contains(':') {
        s.to_string()
    } else {
        format!("{s}:{default_port}")
    };
    use std::net::ToSocketAddrs;
    let sa = with_port
        .to_socket_addrs()
        .with_context(|| format!("resolving seed {s}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address for seed {s}"))?;
    Ok(Peer::Clearnet(sa))
}

// UTC timestamps live in the shared `time` module so the crawler, DB writer, and the
// API's freshness cutoff all use the identical (string-comparable) format.
use bip110_crawler::time::now_iso;
