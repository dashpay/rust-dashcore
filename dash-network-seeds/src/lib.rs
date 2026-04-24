//! Hardcoded masternode seed lists for Dash mainnet and testnet.
//!
//! The seed lists are regenerated weekly by CI from the live Dash P2P network
//! using the `masternode-seeds-fetcher` tool. Alongside each masternode
//! address the file records the type (regular / evo) and best-effort probe
//! results captured at the moment the list was refreshed:
//!
//! * **Core reachability** — TCP + P2P handshake to the advertised Core port.
//! * **Core sync** — the peer's `start_height` compared to a reference tip.
//! * **Platform reachability** — TCP + TLS to the advertised platform HTTP
//!   port (Evo nodes only).
//! * **Platform liveness** — whether the platform HTTP endpoint responds to a
//!   baseline HTTP request (Evo nodes only).
//! * **Platform SSL** — the health of the presented X.509 certificate
//!   (Evo nodes only).
//!
//! Consumers that just need a bootstrap peer list can still ignore the
//! probe fields and treat this crate as a plain `Vec<SocketAddr>` source
//! via [`addresses`] or [`reachable_addresses`].
//!
//! # Example
//!
//! ```rust
//! use dash_network_seeds::{MasternodeType, Reachability, reachable_seeds, seeds};
//! use dash_network::Network;
//!
//! let all = seeds(Network::Mainnet);
//! assert!(!all.is_empty());
//! // Only entries whose Core port answered our last probe:
//! let live = reachable_seeds(Network::Mainnet);
//! assert!(live.len() <= all.len());
//! # let _ = (live, MasternodeType::Evo, Reachability::Ok);
//! ```
//!
//! # File format
//!
//! Plain text, one seed per line. Lines beginning with `#` and blank lines
//! are ignored. Each data line is space-separated with fixed columns:
//!
//! ```text
//! <type> <addr> <platform_http_port|-> <core_reach> <core_sync> <plat_reach> <plat_live> <plat_ssl>
//! ```
//!
//! where:
//!
//! | column | values |
//! |--------|--------|
//! | `type` | `regular`, `evo` |
//! | `addr` | `ip:port` for the Core P2P port |
//! | `platform_http_port` | `u16` for Evo; `-` for regular |
//! | `core_reach`, `plat_reach` | `ok`, `timeout`, `refused`, `error`, `?` |
//! | `core_sync` | `sync`, `-N` (behind), `+N` (ahead), `?` |
//! | `plat_live` | `ok`, `none`, `?`, `-` (regular) |
//! | `plat_ssl` | `valid`, `expired`, `self-signed`, `untrusted`, `no-handshake`, `?`, `-` (regular) |
//!
//! Backwards-compatible legacy formats are still accepted on parse: lines
//! with just `<addr>` default to regular + unknown status, lines with just
//! `<type> <addr>` default to unknown status.

#![forbid(unsafe_code)]

use dash_network::Network;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Raw embedded seed file contents, as a `&'static str`.
pub const fn raw_seed_file(network: &Network) -> &'static str {
    match network {
        Network::Mainnet => MAINNET_SEED_FILE,
        Network::Testnet => TESTNET_SEED_FILE,
        _ => "",
    }
}

// ---------- MasternodeType ----------

/// Masternode type as encoded in a seed entry.
///
/// The underlying protocol uses `EntryMasternodeType::HighPerformance` for
/// what Dash Platform documentation, users, and the Dash Core RPC all refer
/// to as an "Evo" or "HPMN". This crate uses "Evo" because that's the
/// ecosystem-facing name.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum MasternodeType {
    /// Regular masternode.
    Regular,
    /// Evo (a.k.a. HPMN) masternode — runs Dash Platform alongside Core.
    Evo,
}

impl MasternodeType {
    /// Parse the seed-file token (`"regular"` or `"evo"`, case-insensitive).
    pub fn parse(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "regular" => Some(MasternodeType::Regular),
            "evo" | "hpmn" | "highperformance" => Some(MasternodeType::Evo),
            _ => None,
        }
    }

    /// The seed-file token for this type.
    pub const fn as_str(self) -> &'static str {
        match self {
            MasternodeType::Regular => "regular",
            MasternodeType::Evo => "evo",
        }
    }
}

// ---------- Status enums ----------

/// Result of a reachability probe.
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub enum Reachability {
    /// Not probed.
    #[default]
    Unknown,
    /// TCP (and, where applicable, handshake/TLS) completed successfully.
    Ok,
    /// Connect attempt did not finish in time.
    Timeout,
    /// Peer actively refused the connection.
    Refused,
    /// Other error (protocol, I/O) while probing.
    Error,
}

impl Reachability {
    /// Short token used in the seed file.
    pub const fn as_str(self) -> &'static str {
        match self {
            Reachability::Unknown => "?",
            Reachability::Ok => "ok",
            Reachability::Timeout => "timeout",
            Reachability::Refused => "refused",
            Reachability::Error => "error",
        }
    }

    fn parse(token: &str) -> Option<Self> {
        Some(match token {
            "?" => Reachability::Unknown,
            "ok" => Reachability::Ok,
            "timeout" => Reachability::Timeout,
            "refused" => Reachability::Refused,
            "error" => Reachability::Error,
            _ => return None,
        })
    }
}

/// A peer's chain-tip relationship to a reference height captured during the
/// same run.
///
/// Only meaningful for Core (we have a reliable tip height from the primary
/// `mnlistdiff` exchange). Platform does not currently support this level
/// of detail in the seed file.
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub enum SyncStatus {
    /// Not probed.
    #[default]
    Unknown,
    /// Within a small delta (default ±10 blocks) of the reference tip.
    Synced,
    /// `n` blocks behind the reference tip.
    Behind(u32),
    /// `n` blocks ahead of the reference tip (unusual; peer had a fresher
    /// block than our reference).
    Ahead(u32),
}

impl SyncStatus {
    /// Short token used in the seed file.
    pub fn as_string(self) -> String {
        match self {
            SyncStatus::Unknown => "?".to_string(),
            SyncStatus::Synced => "sync".to_string(),
            SyncStatus::Behind(n) => format!("-{}", n),
            SyncStatus::Ahead(n) => format!("+{}", n),
        }
    }

    fn parse(token: &str) -> Option<Self> {
        if token == "?" {
            return Some(SyncStatus::Unknown);
        }
        if token == "sync" {
            return Some(SyncStatus::Synced);
        }
        if let Some(rest) = token.strip_prefix('-') {
            return rest.parse().ok().map(SyncStatus::Behind);
        }
        if let Some(rest) = token.strip_prefix('+') {
            return rest.parse().ok().map(SyncStatus::Ahead);
        }
        None
    }
}

/// Whether the platform HTTP port served *any* HTTP response during the
/// probe.
///
/// We do not parse the response body. `Ok` just means the server answered
/// with an HTTP status line (2xx/3xx/4xx/5xx); `None` means the TLS layer
/// came up but no HTTP response arrived before the timeout.
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub enum PlatformLiveness {
    /// Not probed.
    #[default]
    Unknown,
    /// Server answered with an HTTP status line.
    Ok,
    /// No HTTP response received.
    None,
}

impl PlatformLiveness {
    /// Short token used in the seed file.
    pub const fn as_str(self) -> &'static str {
        match self {
            PlatformLiveness::Unknown => "?",
            PlatformLiveness::Ok => "ok",
            PlatformLiveness::None => "none",
        }
    }

    fn parse(token: &str) -> Option<Self> {
        Some(match token {
            "?" => PlatformLiveness::Unknown,
            "ok" => PlatformLiveness::Ok,
            "none" => PlatformLiveness::None,
            _ => return None,
        })
    }
}

/// Platform TLS certificate health.
///
/// Hostname verification is deliberately **not** performed: seed entries are
/// keyed by IP address, so the presented cert's Subject/SAN almost always
/// doesn't match. The probe instead checks the certificate's self-described
/// validity (expiration, self-signedness, chain trust).
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub enum SslStatus {
    /// Not probed.
    #[default]
    Unknown,
    /// Chain verified, not expired.
    Valid,
    /// Cert is past its `notAfter` timestamp.
    Expired,
    /// Leaf cert is its own issuer.
    SelfSigned,
    /// Chain did not verify against the system root store (and is not
    /// self-signed).
    Untrusted,
    /// TLS handshake failed before we could see a certificate.
    NoHandshake,
}

impl SslStatus {
    /// Short token used in the seed file.
    pub const fn as_str(self) -> &'static str {
        match self {
            SslStatus::Unknown => "?",
            SslStatus::Valid => "valid",
            SslStatus::Expired => "expired",
            SslStatus::SelfSigned => "self-signed",
            SslStatus::Untrusted => "untrusted",
            SslStatus::NoHandshake => "no-handshake",
        }
    }

    fn parse(token: &str) -> Option<Self> {
        Some(match token {
            "?" => SslStatus::Unknown,
            "valid" => SslStatus::Valid,
            "expired" => SslStatus::Expired,
            "self-signed" => SslStatus::SelfSigned,
            "untrusted" => SslStatus::Untrusted,
            "no-handshake" => SslStatus::NoHandshake,
            _ => return None,
        })
    }
}

// ---------- Core / Platform status composites ----------

/// Core probe summary.
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct CoreStatus {
    pub reachable: Reachability,
    pub synced: SyncStatus,
}

/// Platform probe summary (Evo masternodes only).
#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct PlatformStatus {
    pub reachable: Reachability,
    pub live: PlatformLiveness,
    pub ssl: SslStatus,
}

// ---------- MasternodeSeed ----------

/// A single masternode seed entry.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct MasternodeSeed {
    /// The masternode's advertised Core P2P service address.
    pub address: SocketAddr,
    /// Whether this masternode is a regular or Evo (HPMN) node.
    pub mn_type: MasternodeType,
    /// Evo masternodes advertise a platform HTTP port. `None` for regular.
    pub platform_http_port: Option<u16>,
    /// Result of the most recent Core probe (or all-`Unknown` if not probed).
    pub core: CoreStatus,
    /// Result of the most recent Platform probe. `None` for regular nodes.
    pub platform: Option<PlatformStatus>,
}

impl MasternodeSeed {
    /// Format this seed as a single seed-file line (no trailing newline).
    pub fn to_line(&self) -> String {
        let http = match self.platform_http_port {
            Some(p) => p.to_string(),
            None => "-".to_string(),
        };
        let (plat_reach, plat_live, plat_ssl) = match self.platform {
            Some(p) => (
                p.reachable.as_str().to_string(),
                p.live.as_str().to_string(),
                p.ssl.as_str().to_string(),
            ),
            None => ("-".to_string(), "-".to_string(), "-".to_string()),
        };
        format!(
            "{} {} {} {} {} {} {} {}",
            self.mn_type.as_str(),
            self.address,
            http,
            self.core.reachable.as_str(),
            self.core.synced.as_string(),
            plat_reach,
            plat_live,
            plat_ssl,
        )
    }
}

impl fmt::Display for MasternodeSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_line())
    }
}

impl PartialOrd for MasternodeSeed {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MasternodeSeed {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Sort primarily by address (stable across probe-result churn) then
        // type. Probe fields are deliberately *not* part of the sort so that
        // seed-file diffs are dominated by membership churn, not status.
        self.address.cmp(&other.address).then_with(|| self.mn_type.cmp(&other.mn_type))
    }
}

// ---------- Embedded files ----------

const MAINNET_SEED_FILE: &str = include_str!("../seeds/mainnet.txt");
const TESTNET_SEED_FILE: &str = include_str!("../seeds/testnet.txt");

// ---------- Public API ----------

/// Return all hardcoded masternode seeds for the given network.
pub fn seeds(network: Network) -> Vec<MasternodeSeed> {
    parse(raw_seed_file(&network), network.default_p2p_port())
}

/// Return just the socket addresses for all hardcoded masternode seeds,
/// dropping type and probe information.
pub fn addresses(network: Network) -> Vec<SocketAddr> {
    seeds(network).into_iter().map(|s| s.address).collect()
}

/// Return only Evo (HPMN) masternode seeds.
pub fn evo_seeds(network: Network) -> Vec<MasternodeSeed> {
    seeds(network).into_iter().filter(|s| s.mn_type == MasternodeType::Evo).collect()
}

/// Return only regular masternode seeds.
pub fn regular_seeds(network: Network) -> Vec<MasternodeSeed> {
    seeds(network).into_iter().filter(|s| s.mn_type == MasternodeType::Regular).collect()
}

/// Return seeds whose last Core probe reported the node reachable. Useful
/// as a "liveliest" bootstrap list.
pub fn reachable_seeds(network: Network) -> Vec<MasternodeSeed> {
    seeds(network).into_iter().filter(|s| s.core.reachable == Reachability::Ok).collect()
}

/// Return just the Core socket addresses of seeds whose last probe reported
/// the node reachable.
pub fn reachable_addresses(network: Network) -> Vec<SocketAddr> {
    reachable_seeds(network).into_iter().map(|s| s.address).collect()
}

/// Parse a seed-file body (as produced by `masternode-seeds-fetcher`) into a
/// list of entries. Exposed for tooling — library consumers should usually
/// call [`seeds`] instead.
///
/// Accepts the current rich format *and* legacy 1- or 2-column formats.
/// Unparsable lines are silently skipped so a single malformed line never
/// prevents the rest of the list from loading.
pub fn parse(raw: &str, default_port: u16) -> Vec<MasternodeSeed> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(seed) = parse_line(line, default_port) {
            out.push(seed);
        }
    }
    out
}

fn parse_line(line: &str, default_port: u16) -> Option<MasternodeSeed> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    match toks.len() {
        1 => parse_bare(toks[0], default_port),
        2 => parse_typed(toks[0], toks[1], default_port),
        8 => parse_full(&toks, default_port),
        _ => None,
    }
}

fn parse_bare(addr: &str, default_port: u16) -> Option<MasternodeSeed> {
    let address = parse_address(addr, default_port)?;
    Some(MasternodeSeed {
        address,
        mn_type: MasternodeType::Regular,
        platform_http_port: None,
        core: CoreStatus::default(),
        platform: None,
    })
}

fn parse_typed(type_tok: &str, addr_tok: &str, default_port: u16) -> Option<MasternodeSeed> {
    let mn_type = MasternodeType::parse(type_tok)?;
    let address = parse_address(addr_tok, default_port)?;
    Some(MasternodeSeed {
        address,
        mn_type,
        platform_http_port: None,
        core: CoreStatus::default(),
        platform: match mn_type {
            MasternodeType::Evo => Some(PlatformStatus::default()),
            MasternodeType::Regular => None,
        },
    })
}

fn parse_full(toks: &[&str], default_port: u16) -> Option<MasternodeSeed> {
    let mn_type = MasternodeType::parse(toks[0])?;
    let address = parse_address(toks[1], default_port)?;
    let platform_http_port = match toks[2] {
        "-" => None,
        n => Some(n.parse::<u16>().ok()?),
    };
    let core = CoreStatus {
        reachable: Reachability::parse(toks[3])?,
        synced: SyncStatus::parse(toks[4])?,
    };
    let platform = match (mn_type, toks[5], toks[6], toks[7]) {
        (MasternodeType::Regular, "-", "-", "-") => None,
        (MasternodeType::Evo, r, l, s) => Some(PlatformStatus {
            reachable: Reachability::parse(r)?,
            live: PlatformLiveness::parse(l)?,
            ssl: SslStatus::parse(s)?,
        }),
        _ => return None,
    };
    Some(MasternodeSeed {
        address,
        mn_type,
        platform_http_port,
        core,
        platform,
    })
}

fn parse_address(tok: &str, default_port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = tok.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = tok.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    None
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_seed_peers_contains_hp_mn_ips() {
        let peers = addresses(Network::Testnet);
        // The HP-MN range at 68.67.122.1-29 should be present; later runs may
        // extend it but never shrink below 29.
        let hp_mn = peers.iter().filter(|a| a.ip().to_string().starts_with("68.67.122.")).count();
        assert!(hp_mn >= 29, "expected >=29 HP-MN testnet seeds, got {}", hp_mn);
        assert!(peers.iter().all(|a| a.port() == Network::Testnet.default_p2p_port()));
    }

    #[test]
    fn mainnet_seed_peers_non_empty() {
        let peers = addresses(Network::Mainnet);
        assert!(!peers.is_empty(), "mainnet seeds must not be empty");
        assert!(peers.iter().all(|a| a.port() == Network::Mainnet.default_p2p_port()));
    }

    fn mk_full(addr: &str, mn_type: MasternodeType) -> MasternodeSeed {
        MasternodeSeed {
            address: addr.parse().unwrap(),
            mn_type,
            platform_http_port: if mn_type == MasternodeType::Evo {
                Some(443)
            } else {
                None
            },
            core: CoreStatus {
                reachable: Reachability::Ok,
                synced: SyncStatus::Synced,
            },
            platform: if mn_type == MasternodeType::Evo {
                Some(PlatformStatus {
                    reachable: Reachability::Ok,
                    live: PlatformLiveness::Ok,
                    ssl: SslStatus::Valid,
                })
            } else {
                None
            },
        }
    }

    #[test]
    fn round_trip_full_evo() {
        let seed = mk_full("68.67.122.1:19999", MasternodeType::Evo);
        let line = seed.to_line();
        assert_eq!(line, "evo 68.67.122.1:19999 443 ok sync ok ok valid");
        let parsed = parse_line(&line, 19999).unwrap();
        assert_eq!(parsed, seed);
    }

    #[test]
    fn round_trip_full_regular() {
        let seed = mk_full("1.2.3.4:9999", MasternodeType::Regular);
        let line = seed.to_line();
        assert_eq!(line, "regular 1.2.3.4:9999 - ok sync - - -");
        let parsed = parse_line(&line, 9999).unwrap();
        assert_eq!(parsed, seed);
    }

    #[test]
    fn legacy_bare_ip_is_regular_with_unknown_status() {
        let p = parse_line("1.2.3.4:9999", 9999).unwrap();
        assert_eq!(p.mn_type, MasternodeType::Regular);
        assert_eq!(p.core.reachable, Reachability::Unknown);
        assert_eq!(p.core.synced, SyncStatus::Unknown);
        assert!(p.platform.is_none());
    }

    #[test]
    fn legacy_typed_no_status() {
        let p = parse_line("evo 68.67.122.1:19999", 19999).unwrap();
        assert_eq!(p.mn_type, MasternodeType::Evo);
        assert_eq!(p.core.reachable, Reachability::Unknown);
        let plat = p.platform.unwrap();
        assert_eq!(plat.reachable, Reachability::Unknown);
        assert_eq!(plat.ssl, SslStatus::Unknown);
    }

    #[test]
    fn parse_sync_status_variants() {
        assert_eq!(SyncStatus::parse("sync"), Some(SyncStatus::Synced));
        assert_eq!(SyncStatus::parse("-123"), Some(SyncStatus::Behind(123)));
        assert_eq!(SyncStatus::parse("+5"), Some(SyncStatus::Ahead(5)));
        assert_eq!(SyncStatus::parse("?"), Some(SyncStatus::Unknown));
        assert_eq!(SyncStatus::parse("weird"), None);
    }

    #[test]
    fn parse_skips_invalid_and_short_lines() {
        // 3 columns is not a valid length.
        let raw = "evo 1.2.3.4 invalid\nregular 5.6.7.8:9999 - ok sync - - -\n";
        let list = parse(raw, 9999);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn masternode_type_parse_case_insensitive() {
        assert_eq!(MasternodeType::parse("EVO"), Some(MasternodeType::Evo));
        assert_eq!(MasternodeType::parse("Regular"), Some(MasternodeType::Regular));
        assert_eq!(MasternodeType::parse("hpmn"), Some(MasternodeType::Evo));
        assert_eq!(MasternodeType::parse("Nope"), None);
    }

    #[test]
    fn testnet_seeds_contain_expected_evo_ips() {
        let list = seeds(Network::Testnet);
        let hpmn_count = list
            .iter()
            .filter(|s| s.mn_type == MasternodeType::Evo)
            .filter(|s| s.address.ip().to_string().starts_with("68.67.122."))
            .count();
        assert!(hpmn_count >= 29, "expected >=29 HP-MN seeds at 68.67.122.x, got {}", hpmn_count);
    }

    #[test]
    fn mainnet_seeds_non_empty_and_well_formed() {
        let list = seeds(Network::Mainnet);
        assert!(!list.is_empty(), "mainnet seeds must not be empty");
        for s in &list {
            assert_eq!(s.address.port(), Network::Mainnet.default_p2p_port());
        }
    }

    #[test]
    fn evo_seeds_all_have_platform_status() {
        // Post-probe, evo entries carry a platform field regardless of
        // whether individual probes succeeded.
        for s in evo_seeds(Network::Testnet) {
            assert!(s.platform.is_some());
        }
    }

    #[test]
    fn regular_seeds_never_have_platform_status() {
        for s in regular_seeds(Network::Mainnet) {
            assert!(s.platform.is_none());
        }
    }
}
