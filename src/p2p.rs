//! Minimal, dependency-light implementation of the Bitcoin P2P wire protocol.
//!
//! We only implement what the crawler needs:
//!   - the message header framing (magic / command / length / checksum)
//!   - the `version` / `verack` handshake (to learn the peer's user agent + version)
//!   - `sendaddrv2`, `getaddr`, and parsing of `addr` / `addrv2` (to discover peers)
//!
//! Reference: https://en.bitcoin.it/wiki/Protocol_documentation and BIP155 (addrv2).

use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// A peer we can dial: either a clearnet socket or a Tor v3 onion service.
/// (I2P/CJDNS could be added the same way, each needing its own proxy.)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Peer {
    Clearnet(SocketAddr),
    Onion(String, u16), // host ("<56 chars>.onion"), port
}

impl Peer {
    pub fn is_onion(&self) -> bool {
        matches!(self, Peer::Onion(..))
    }

    /// Parse a `host:port` string: clearnet `ip:port` / `[ipv6]:port`, or `*.onion:port`.
    pub fn parse(s: &str, default_port: u16) -> Option<Peer> {
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return Some(Peer::Clearnet(sa));
        }
        // Onion (and other hostname) forms: split host:port from the right.
        if let Some((host, port)) = s.rsplit_once(':') {
            if host.ends_with(".onion") {
                if let Ok(p) = port.parse::<u16>() {
                    return Some(Peer::Onion(host.to_string(), p));
                }
            }
        }
        if s.ends_with(".onion") {
            return Some(Peer::Onion(s.to_string(), default_port));
        }
        None
    }
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Peer::Clearnet(sa) => write!(f, "{sa}"),
            Peer::Onion(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

/// Reconstruct a Tor v3 `.onion` hostname from the 32-byte ed25519 public key carried
/// in a BIP155 addrv2 record: base32(pubkey ‖ checksum ‖ version) + ".onion", where
/// checksum = SHA3-256(".onion checksum" ‖ pubkey ‖ 0x03)[..2] and version = 0x03.
fn onion_v3_host(pubkey: &[u8]) -> Option<String> {
    if pubkey.len() != 32 {
        return None;
    }
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pubkey);
    h.update([0x03u8]);
    let checksum = h.finalize();
    let mut data = Vec::with_capacity(35);
    data.extend_from_slice(pubkey);
    data.extend_from_slice(&checksum[..2]);
    data.push(0x03);
    Some(format!("{}.onion", base32_lower(&data)))
}

/// RFC 4648 base32, lowercase, no padding (as used by Tor onion addresses).
fn base32_lower(data: &[u8]) -> String {
    const ALPH: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPH[((bits >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPH[((bits << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

/// Open a TCP stream to `host:port` through a SOCKS5 proxy (e.g. Tor). Uses the
/// domain-name address type so the proxy resolves/routes the `.onion` itself.
fn socks5_connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream> {
    let mut s = TcpStream::connect_timeout(&proxy, timeout)
        .with_context(|| format!("connecting to SOCKS5 proxy {proxy}"))?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    // Greeting: VER=5, 1 method, method 0 (no auth).
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet)?;
    if greet[0] != 0x05 || greet[1] != 0x00 {
        bail!("SOCKS5 proxy refused no-auth");
    }
    // CONNECT: VER=5, CMD=1, RSV=0, ATYP=3 (domain), len, host, port(BE).
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        bail!("onion host too long");
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        bail!("SOCKS5 connect failed (reply code {})", head[1]);
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        other => bail!("SOCKS5 unexpected ATYP {other}"),
    };
    let mut rest = vec![0u8; addr_len + 2];
    s.read_exact(&mut rest)?;
    Ok(s)
}

/// Network magic + default port for the networks we support.
#[derive(Clone, Copy, Debug)]
pub struct NetworkParams {
    pub magic: [u8; 4],
    pub default_port: u16,
    pub name: &'static str,
}

impl NetworkParams {
    pub fn from_name(name: &str) -> Result<Self> {
        Ok(match name {
            "main" | "mainnet" => NetworkParams {
                magic: [0xF9, 0xBE, 0xB4, 0xD9],
                default_port: 8333,
                name: "main",
            },
            "test" | "testnet" | "testnet3" => NetworkParams {
                magic: [0x0B, 0x11, 0x09, 0x07],
                default_port: 18333,
                name: "test",
            },
            "signet" => NetworkParams {
                magic: [0x0A, 0x03, 0xCF, 0x40],
                default_port: 38333,
                name: "signet",
            },
            "regtest" => NetworkParams {
                magic: [0xFA, 0xBF, 0xB5, 0xDA],
                default_port: 18444,
                name: "regtest",
            },
            other => bail!("unknown network: {other}"),
        })
    }
}

/// Result of a successful handshake.
#[derive(Debug, Clone)]
pub struct PeerVersion {
    pub protocol_version: i32,
    pub services: u64,
    pub user_agent: String,
    pub start_height: i32,
}

// ---- CompactSize (varint) helpers -------------------------------------------

fn write_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xFD {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Read a CompactSize from a byte cursor, advancing `pos`.
fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let first = *data.get(*pos).ok_or_else(|| anyhow!("varint: eof"))?;
    *pos += 1;
    Ok(match first {
        0xFF => {
            let v = read_array::<8>(data, pos)?;
            u64::from_le_bytes(v)
        }
        0xFE => {
            let v = read_array::<4>(data, pos)?;
            u32::from_le_bytes(v) as u64
        }
        0xFD => {
            let v = read_array::<2>(data, pos)?;
            u16::from_le_bytes(v) as u64
        }
        n => n as u64,
    })
}

fn read_array<const N: usize>(data: &[u8], pos: &mut usize) -> Result<[u8; N]> {
    let end = *pos + N;
    let slice = data.get(*pos..end).ok_or_else(|| anyhow!("read: eof"))?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    *pos = end;
    Ok(out)
}

// ---- Message framing --------------------------------------------------------

fn checksum(payload: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

fn build_message(magic: [u8; 4], command: &str, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(24 + payload.len());
    msg.extend_from_slice(&magic);
    let mut cmd = [0u8; 12];
    for (i, b) in command.bytes().take(12).enumerate() {
        cmd[i] = b;
    }
    msg.extend_from_slice(&cmd);
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(&checksum(payload));
    msg.extend_from_slice(payload);
    msg
}

fn read_exact_timeout(stream: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
    stream.read_exact(buf).context("reading from peer")?;
    Ok(())
}

/// A parsed inbound message: (command, payload).
struct RawMessage {
    command: String,
    payload: Vec<u8>,
}

fn read_message(stream: &mut TcpStream, magic: [u8; 4]) -> Result<RawMessage> {
    let mut header = [0u8; 24];
    read_exact_timeout(stream, &mut header)?;
    if header[0..4] != magic {
        bail!("bad network magic");
    }
    let command_bytes = &header[4..16];
    let command = command_bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect::<String>();
    let len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    // Guard against absurd frame sizes (protocol max is 32 MiB; keep well under).
    if len > 4 * 1024 * 1024 {
        bail!("oversized message: {len} bytes");
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact_timeout(stream, &mut payload)?;
    }
    Ok(RawMessage { command, payload })
}

// ---- version payload --------------------------------------------------------

fn encode_netaddr_no_time(services: u64, ip: IpAddr, port: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(26);
    b.extend_from_slice(&services.to_le_bytes());
    b.extend_from_slice(&ip_to_16(ip));
    b.extend_from_slice(&port.to_be_bytes()); // port is big-endian on the wire
    b
}

fn ip_to_16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn build_version_payload(recv_ip: IpAddr, recv_port: u16, start_height: i32) -> Vec<u8> {
    const PROTOCOL_VERSION: i32 = 70016; // supports wtxid relay / addrv2 negotiation
    const SERVICE_NONE: u64 = 0;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut p = Vec::new();
    p.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    p.extend_from_slice(&SERVICE_NONE.to_le_bytes());
    p.extend_from_slice(&now.to_le_bytes());
    // addr_recv (the peer). For onion peers we have no IP, so this is left unspecified;
    // Bitcoin nodes don't validate addr_recv contents.
    p.extend_from_slice(&encode_netaddr_no_time(0, recv_ip, recv_port));
    // addr_from (us) — we advertise nothing meaningful
    p.extend_from_slice(&encode_netaddr_no_time(
        0,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    ));
    let nonce: u64 = rand::thread_rng().gen();
    p.extend_from_slice(&nonce.to_le_bytes());
    // user agent
    let ua = b"/bip110-crawler:0.1.0/";
    write_varint(&mut p, ua.len() as u64);
    p.extend_from_slice(ua);
    p.extend_from_slice(&start_height.to_le_bytes());
    p.push(0x00); // relay = false: we don't want tx flooding
    p
}

fn parse_version_payload(payload: &[u8]) -> Result<PeerVersion> {
    let mut pos = 0usize;
    let protocol_version = i32::from_le_bytes(read_array::<4>(payload, &mut pos)?);
    let services = u64::from_le_bytes(read_array::<8>(payload, &mut pos)?);
    // timestamp(8) + addr_recv(26) + addr_from(26) + nonce(8) = 68 bytes to skip
    pos += 8 + 26 + 26 + 8;
    let ua_len = read_varint(payload, &mut pos)? as usize;
    let ua_bytes = payload
        .get(pos..pos + ua_len)
        .ok_or_else(|| anyhow!("version: truncated user agent"))?;
    let user_agent = String::from_utf8_lossy(ua_bytes).to_string();
    pos += ua_len;
    let start_height = i32::from_le_bytes(read_array::<4>(payload, &mut pos)?);
    Ok(PeerVersion {
        protocol_version,
        services,
        user_agent,
        start_height,
    })
}

// ---- addr / addrv2 parsing --------------------------------------------------

fn parse_addr(payload: &[u8], default_port: u16) -> Vec<Peer> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let count = match read_varint(payload, &mut pos) {
        Ok(c) => c.min(1000),
        Err(_) => return out,
    };
    for _ in 0..count {
        // Each entry: time(4) + services(8) + ip(16) + port(2) = 30 bytes.
        let entry = match payload.get(pos..pos + 30) {
            Some(e) => e,
            None => break,
        };
        pos += 30;
        let ip = ip16_to_addr(&entry[12..28]);
        let port = u16::from_be_bytes([entry[28], entry[29]]);
        if let Some(ip) = ip {
            let port = if port == 0 { default_port } else { port };
            out.push(Peer::Clearnet(SocketAddr::new(ip, port)));
        }
    }
    out
}

fn parse_addrv2(payload: &[u8], default_port: u16) -> Vec<Peer> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let count = match read_varint(payload, &mut pos) {
        Ok(c) => c.min(1000),
        Err(_) => return out,
    };
    for _ in 0..count {
        // time(4) + services(varint) + network(1) + addr(varlen) + port(2)
        if read_array::<4>(payload, &mut pos).is_err() {
            break;
        }
        if read_varint(payload, &mut pos).is_err() {
            break; // services
        }
        let network = match payload.get(pos) {
            Some(&n) => n,
            None => break,
        };
        pos += 1;
        // Cap the field length: every real addrv2 address is <= 32 bytes (Tor v3 / I2P), so
        // anything larger is a malformed or hostile record. This also guards the
        // `pos + addr_len` slice below from overflowing on an absurd varint.
        let addr_len = match read_varint(payload, &mut pos) {
            Ok(l) if l <= 512 => l as usize,
            _ => break,
        };
        let addr_bytes = match payload.get(pos..pos + addr_len) {
            Some(b) => b.to_vec(),
            None => break,
        };
        pos += addr_len;
        let port = match read_array::<2>(payload, &mut pos) {
            Ok(b) => u16::from_be_bytes(b),
            Err(_) => break,
        };
        let port = if port == 0 { default_port } else { port };
        // network IDs per BIP155: 1=IPv4, 2=IPv6, 3=TorV2 (dead), 4=TorV3, 5=I2P,
        // 6=CJDNS. We decode IPv4/IPv6 and Tor v3; I2P/CJDNS need their own proxies.
        match (network, addr_len) {
            (1, 4) => out.push(Peer::Clearnet(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3])),
                port,
            ))),
            (2, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&addr_bytes);
                out.push(Peer::Clearnet(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port)));
            }
            (4, 32) => {
                if let Some(host) = onion_v3_host(&addr_bytes) {
                    out.push(Peer::Onion(host, port));
                }
            }
            _ => {} // TorV2 / I2P / CJDNS — not dialable here
        }
    }
    out
}

fn ip16_to_addr(bytes: &[u8]) -> Option<IpAddr> {
    if bytes.len() != 16 {
        return None;
    }
    let mut o = [0u8; 16];
    o.copy_from_slice(bytes);
    let v6 = Ipv6Addr::from(o);
    // Unmap IPv4-in-IPv6 addresses back to plain IPv4.
    if let Some(v4) = v6.to_ipv4_mapped() {
        Some(IpAddr::V4(v4))
    } else {
        Some(IpAddr::V6(v6))
    }
}

// ---- Public entry point -----------------------------------------------------

/// Connect to `peer`, complete the handshake, ask for addresses, and return
/// `(version, discovered_peers)`. Onion peers are dialed through `tor_proxy`.
pub fn probe_peer(
    peer: &Peer,
    net: NetworkParams,
    connect_timeout: Duration,
    io_timeout: Duration,
    addr_collect: Duration,
    tor_proxy: Option<SocketAddr>,
) -> Result<(PeerVersion, Vec<Peer>)> {
    // Tor circuits are slow to build, so give onion connections a lot more time.
    let (ct, iot, act) = if peer.is_onion() {
        (
            connect_timeout.max(Duration::from_secs(20)),
            io_timeout.max(Duration::from_secs(20)),
            addr_collect.max(Duration::from_secs(8)),
        )
    } else {
        (connect_timeout, io_timeout, addr_collect)
    };

    let (mut stream, recv_ip, recv_port) = match peer {
        Peer::Clearnet(sa) => {
            let s = TcpStream::connect_timeout(sa, ct).with_context(|| format!("connect {sa}"))?;
            (s, sa.ip(), sa.port())
        }
        Peer::Onion(host, port) => {
            let proxy = tor_proxy
                .ok_or_else(|| anyhow!("onion peer {host} requires --tor-proxy"))?;
            let s = socks5_connect(proxy, host, *port, ct)?;
            (s, IpAddr::V4(Ipv4Addr::UNSPECIFIED), *port)
        }
    };
    stream.set_read_timeout(Some(iot))?;
    stream.set_write_timeout(Some(iot))?;

    // 1. Send our version.
    let version_msg =
        build_message(net.magic, "version", &build_version_payload(recv_ip, recv_port, 0));
    stream.write_all(&version_msg)?;

    // 2. Read until we have the peer's version, then reply verack (+ sendaddrv2).
    let mut peer_version: Option<PeerVersion> = None;
    let mut got_verack = false;
    for _ in 0..20 {
        let msg = read_message(&mut stream, net.magic)?;
        match msg.command.as_str() {
            "version" => {
                peer_version = Some(parse_version_payload(&msg.payload)?);
                // Negotiate addrv2 before verack, then ack.
                stream.write_all(&build_message(net.magic, "sendaddrv2", &[]))?;
                stream.write_all(&build_message(net.magic, "verack", &[]))?;
            }
            "verack" => got_verack = true,
            "ping" => {
                // Reply with the same nonce so the peer keeps the link alive.
                stream.write_all(&build_message(net.magic, "pong", &msg.payload))?;
            }
            _ => {}
        }
        if peer_version.is_some() && got_verack {
            break;
        }
    }
    let peer_version = peer_version.ok_or_else(|| anyhow!("peer never sent version"))?;

    // 3. Ask for addresses and collect for a bounded window.
    stream.write_all(&build_message(net.magic, "getaddr", &[]))?;
    let deadline = std::time::Instant::now() + act;
    let mut discovered = Vec::new();
    // Shorten the read timeout so we don't block past the collect window.
    stream.set_read_timeout(Some(iot.min(act)))?;
    while std::time::Instant::now() < deadline {
        match read_message(&mut stream, net.magic) {
            Ok(msg) => match msg.command.as_str() {
                "addr" => discovered.extend(parse_addr(&msg.payload, net.default_port)),
                "addrv2" => discovered.extend(parse_addrv2(&msg.payload, net.default_port)),
                "ping" => {
                    let _ = stream.write_all(&build_message(net.magic, "pong", &msg.payload));
                }
                _ => {}
            },
            Err(_) => break, // timeout or closed — stop collecting
        }
        // A single big addr message (up to 1000) is usually enough for the graph.
        if discovered.len() >= 1000 {
            break;
        }
    }

    Ok((peer_version, discovered))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 base32 decode (lowercase, no padding) — test helper only.
    fn b32_decode(s: &str) -> Vec<u8> {
        const ALPH: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let (mut bits, mut nbits, mut out) = (0u32, 0u32, Vec::new());
        for c in s.bytes() {
            let v = ALPH.iter().position(|&a| a == c).expect("valid base32") as u32;
            bits = (bits << 5) | v;
            nbits += 5;
            if nbits >= 8 {
                nbits -= 8;
                out.push((bits >> nbits) as u8);
            }
        }
        out
    }

    // Reconstructing the hostname from the 32-byte key must reproduce a real onion
    // address (validates the SHA3-256 checksum, version byte, and base32 encoding).
    #[test]
    fn onion_v3_matches_known_address() {
        let addr = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
        let b32 = &addr[..addr.len() - ".onion".len()];
        let decoded = b32_decode(b32); // 32 pubkey + 2 checksum + 1 version
        assert_eq!(decoded.len(), 35);
        let host = onion_v3_host(&decoded[..32]).expect("32-byte key");
        assert_eq!(host, addr);
    }

    #[test]
    fn peer_parse_handles_onion_and_clearnet() {
        assert!(matches!(Peer::parse("1.2.3.4:8333", 8333), Some(Peer::Clearnet(_))));
        match Peer::parse("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:8333", 8333) {
            Some(Peer::Onion(h, p)) => { assert!(h.ends_with(".onion")); assert_eq!(p, 8333); }
            other => panic!("expected onion, got {other:?}"),
        }
    }

    // Prove parse_addrv2 decodes a network-4 (Tor v3) record into the right hostname,
    // alongside a normal IPv4 entry.
    #[test]
    fn parse_addrv2_decodes_onion() {
        let addr = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
        let key = b32_decode(&addr[..addr.len() - ".onion".len()])[..32].to_vec();

        let mut payload = Vec::new();
        write_varint(&mut payload, 2); // 2 entries
        // IPv4 entry: time, services=0, net=1, len=4, 1.2.3.4, port 8333
        payload.extend_from_slice(&0u32.to_le_bytes());
        write_varint(&mut payload, 0);
        payload.push(0x01);
        write_varint(&mut payload, 4);
        payload.extend_from_slice(&[1, 2, 3, 4]);
        payload.extend_from_slice(&8333u16.to_be_bytes());
        // Onion v3 entry: time, services=0, net=4, len=32, key, port 8333
        payload.extend_from_slice(&0u32.to_le_bytes());
        write_varint(&mut payload, 0);
        payload.push(0x04);
        write_varint(&mut payload, 32);
        payload.extend_from_slice(&key);
        payload.extend_from_slice(&8333u16.to_be_bytes());

        let peers = parse_addrv2(&payload, 8333);
        assert_eq!(peers.len(), 2);
        assert!(peers.iter().any(|p| matches!(p, Peer::Clearnet(_))));
        assert!(peers.iter().any(|p| matches!(p, Peer::Onion(h, _) if h == addr)));
    }
}
