//! Fetch the current masternode list from the Dash P2P network and write it
//! to a seed file consumed by the `dash-network-seeds` crate.
//!
//! The fetcher does **not** require RPC credentials. It:
//!
//! 1. Resolves candidate peer addresses from the network's DNS seeds and the
//!    existing seed file (the very file it will overwrite).
//! 2. Connects to one peer at a time and runs the Dash P2P handshake.
//! 3. Sends `sendheaders` and waits for the peer's next new-block
//!    announcement (via a `headers` or `inv` message) to obtain a fresh,
//!    valid chain tip hash. Block times of ~2.5 minutes mean this usually
//!    returns within a couple of minutes and always within ~6 minutes.
//! 4. Sends `getmnlistd` with `base_block_hash = 0` (full list) and
//!    `block_hash = tip` to receive a `mnlistdiff` containing every
//!    registered masternode as of that block.
//! 5. Filters to valid masternodes and writes a deterministic, sorted,
//!    comment-headed seed file.
//!
//! If a peer fails at any step (connect, handshake, timeout, malformed
//! response) the fetcher tries the next candidate. It refuses to overwrite
//! the output file unless it actually obtained a non-empty mnlistdiff.
//!
//! Typical usage (e.g. from CI):
//!
//! ```bash
//! masternode-seeds-fetcher --network mainnet --out dash-network-seeds/seeds/mainnet.txt
//! ```

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use dash_network_seeds::{
    CoreStatus, MasternodeSeed, MasternodeType, PlatformStatus, Reachability,
};
use dash_spv::network::Peer;
use dashcore::hashes::Hash;
use dashcore::network::Address;
use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use dashcore::network::message_network::VersionMessage;
use dashcore::network::message_sml::{GetMnListDiff, MnListDiff};
use dashcore::sml::masternode_list_entry::EntryMasternodeType;
use dashcore::{BlockHash, Network};
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::Instant;

mod probe;

// ---------- CLI ----------
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Fetch masternode IPs via the Dash P2P network and write a dash-network-seeds seed file"
)]
struct Args {
    /// Target network.
    #[arg(long, value_enum)]
    network: Network,

    /// Output file path. Defaults to `dash-network-seeds/seeds/<network>.txt`
    /// relative to the current directory.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Extra peer addresses (in `ip:port` form) to try in addition to DNS
    /// seeds and the existing seed file. May be repeated.
    #[arg(long = "peer")]
    extra_peers: Vec<SocketAddr>,

    /// Maximum number of peers to try before giving up.
    #[arg(long, default_value_t = 8)]
    max_peers: usize,

    /// Also keep masternodes flagged `is_valid = false`. Default is to keep
    /// only valid entries so that the resulting list reflects peers that are
    /// actually reachable.
    #[arg(long, default_value_t = false)]
    include_invalid: bool,

    /// Skip the per-masternode reachability probes entirely and write the
    /// seed file with all status columns set to unknown. Useful for quick
    /// local runs.
    #[arg(long, default_value_t = false)]
    skip_probes: bool,

    /// Maximum number of probes running concurrently.
    #[arg(long, default_value_t = 64)]
    probe_concurrency: usize,
}

// ---------- main ----------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let out_path = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("dash-network-seeds/seeds/{}.txt", args.network)));

    let candidates =
        gather_candidate_peers(args.network, &args.extra_peers, &out_path, args.max_peers).await;
    if candidates.is_empty() {
        return Err(anyhow!(
            "no candidate peers to contact (DNS seeds resolved 0, existing seed file empty, \
             and --peer not set)"
        ));
    }
    tracing::info!(
        "Trying up to {} of {} candidate peer(s) on {}",
        args.max_peers,
        candidates.len(),
        args.network
    );

    let mut last_error: Option<anyhow::Error> = None;
    let mut diff_and_source: Option<(MnListDiff, SocketAddr)> = None;
    for peer_addr in candidates.iter().take(args.max_peers) {
        tracing::info!("Contacting peer {}", peer_addr);
        match fetch_from_peer(*peer_addr, args.network).await {
            Ok(diff) => {
                diff_and_source = Some((diff, *peer_addr));
                break;
            }
            Err(e) => {
                tracing::warn!("Peer {} failed: {:#}", peer_addr, e);
                last_error = Some(e);
            }
        }
    }

    let (diff, peer_addr) = diff_and_source.ok_or_else(|| {
        anyhow!(
            "exhausted all {} candidate peer(s); last error: {}",
            args.max_peers.min(candidates.len()),
            last_error.map(|e| format!("{:#}", e)).unwrap_or_else(|| "<none>".to_string())
        )
    })?;

    let tip_height = reference_tip_height(&diff);
    tracing::info!("Reference tip height: {:?}", tip_height);

    let collected = collect_seeds(&diff, &args);
    if collected.entries.is_empty() {
        return Err(anyhow!(
            "peer {} returned {} masternodes but none were usable; refusing to overwrite {}",
            peer_addr,
            collected.total,
            out_path.display()
        ));
    }

    let mut entries = collected.entries;
    if !args.skip_probes {
        probe_all(&mut entries, args.network, tip_height, args.probe_concurrency).await;
    }

    let summary = summarize(&entries);
    write_seed_file(
        &out_path,
        args.network,
        peer_addr,
        &diff,
        tip_height,
        &entries,
        collected.total,
        &summary,
    )?;
    eprintln!(
        "wrote {} seeds ({} regular + {} evo) for {} to {} — core_ok={} plat_ok={} ssl_valid={} (from peer {}, tip {})",
        entries.len(),
        summary.regular,
        summary.evo,
        args.network,
        out_path.display(),
        summary.core_reachable,
        summary.platform_reachable,
        summary.ssl_valid,
        peer_addr,
        diff.block_hash
    );
    Ok(())
}

// ---------- peer discovery ----------

async fn gather_candidate_peers(
    network: Network,
    extra: &[SocketAddr],
    existing_seeds: &std::path::Path,
    max: usize,
) -> Vec<SocketAddr> {
    let mut out: BTreeSet<SocketAddr> = BTreeSet::new();
    out.extend(extra.iter().copied());

    // Existing seed file — the file we are about to overwrite. Gives us a fast
    // local starting set even if DNS is unavailable.
    if let Ok(raw) = fs::read_to_string(existing_seeds) {
        for seed in dash_network_seeds::parse(&raw, network.default_p2p_port()) {
            out.insert(seed.address);
        }
    }

    // DNS seeds.
    let port = network.default_p2p_port();
    for seed in network.dns_seeds() {
        match tokio::net::lookup_host((*seed, port)).await {
            Ok(iter) => out.extend(iter),
            Err(e) => tracing::warn!("DNS seed {} failed: {}", seed, e),
        }
    }

    let mut list: Vec<SocketAddr> = out.into_iter().collect();
    // Shuffle so we do not always hit the same peer first across runs.
    use rand::seq::SliceRandom;
    list.shuffle(&mut rand::thread_rng());
    list.truncate(max.saturating_mul(4).max(max));
    list
}

// ---------- per-peer P2P flow ----------

async fn fetch_from_peer(peer_addr: SocketAddr, network: Network) -> Result<MnListDiff> {
    let mut peer = Peer::connect(peer_addr, 15, network)
        .await
        .with_context(|| format!("connecting to {}", peer_addr))?;

    handshake(&mut peer, peer_addr).await.context("handshake")?;

    let tip = discover_tip(&mut peer).await.context("tip discovery")?;
    tracing::info!("Peer {} tip: {}", peer_addr, tip);

    peer.send_message(NetworkMessage::GetMnListD(GetMnListDiff {
        base_block_hash: BlockHash::all_zeros(),
        block_hash: tip,
    }))
    .await
    .with_context(|| format!("sending getmnlistd to {}", peer_addr))?;

    let diff = wait_for_message(&mut peer, Duration::from_secs(120), |m| match m {
        NetworkMessage::MnListDiff(d) => Some(d.clone()),
        _ => None,
    })
    .await
    .with_context(|| format!("waiting for mnlistdiff from {}", peer_addr))?;

    Ok(diff)
}

async fn handshake(peer: &mut Peer, peer_addr: SocketAddr) -> Result<()> {
    let our_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0);
    // `VersionMessage::new` picks up `PROTOCOL_VERSION` internally.
    let version = VersionMessage::new(
        ServiceFlags::NONE,
        chrono::Utc::now().timestamp(),
        Address::new(&peer_addr, ServiceFlags::NETWORK),
        Address::new(&our_addr, ServiceFlags::NONE),
        rand::random::<u64>(),
        format!("/masternode-seeds-fetcher:{}/", env!("CARGO_PKG_VERSION")),
        0,
        false,
        [0u8; 32],
    );
    peer.send_message(NetworkMessage::Version(version)).await?;

    let mut got_version = false;
    let mut got_verack = false;
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(15) {
            return Err(anyhow!(
                "handshake timeout (version={}, verack={})",
                got_version,
                got_verack
            ));
        }
        match tokio::time::timeout(Duration::from_millis(300), peer.receive_message()).await {
            Ok(Ok(Some(msg))) => match msg.inner() {
                NetworkMessage::Version(_v) => {
                    got_version = true;
                    peer.send_message(NetworkMessage::SendAddrV2).await.ok();
                    peer.send_message(NetworkMessage::Verack).await?;
                    if got_verack {
                        return Ok(());
                    }
                }
                NetworkMessage::Verack => {
                    got_verack = true;
                    if got_version {
                        return Ok(());
                    }
                }
                NetworkMessage::Ping(n) => {
                    peer.send_message(NetworkMessage::Pong(*n)).await.ok();
                }
                _ => { /* ignore during handshake */ }
            },
            Ok(Ok(None)) => { /* nothing buffered yet */ }
            Ok(Err(e)) => return Err(anyhow!("receive failed: {}", e)),
            Err(_) => { /* poll interval timeout; keep looping */ }
        }
    }
}

/// Discover a recent chain tip by asking the peer to announce via `headers`
/// and then waiting for the next block the peer hears about.
///
/// This is dramatically faster than walking `getheaders` from genesis: Dash
/// mainnet & testnet target ~2.5 minute block times, so the expected wait is
/// ~75s with an absolute cap of a few minutes. Using a *fresh* block as the
/// `getmnlistd.block_hash` also means each weekly CI run produces a different
/// output file, which is what we want.
async fn discover_tip(peer: &mut Peer) -> Result<BlockHash> {
    // Request header-style new-block announcements.
    peer.send_message(NetworkMessage::SendHeaders).await.ok();

    const TIP_WAIT: Duration = Duration::from_secs(360); // 6 minutes: comfortably above max inter-block time.
    tracing::info!("Waiting up to {:?} for a new-block announcement from peer", TIP_WAIT);

    wait_for_message(peer, TIP_WAIT, |m| match m {
        NetworkMessage::Headers(hs) => hs.last().map(|h| h.block_hash()),
        NetworkMessage::Inv(items) => items.iter().rev().find_map(|inv| match inv {
            Inventory::Block(hash) | Inventory::CompactBlock(hash) => Some(*hash),
            _ => None,
        }),
        _ => None,
    })
    .await
}

async fn wait_for_message<T, F>(
    peer: &mut Peer,
    total_timeout: Duration,
    mut extract: F,
) -> Result<T>
where
    F: FnMut(&NetworkMessage) -> Option<T>,
{
    let start = Instant::now();
    loop {
        if start.elapsed() > total_timeout {
            return Err(anyhow!("timed out after {:?} waiting for target message", total_timeout));
        }
        match tokio::time::timeout(Duration::from_millis(300), peer.receive_message()).await {
            Ok(Ok(Some(msg))) => {
                match msg.inner() {
                    NetworkMessage::Ping(n) => {
                        peer.send_message(NetworkMessage::Pong(*n)).await.ok();
                        continue;
                    }
                    NetworkMessage::GetHeaders(_)
                    | NetworkMessage::GetHeaders2(_)
                    | NetworkMessage::Inv(_)
                    | NetworkMessage::Addr(_)
                    | NetworkMessage::AddrV2(_)
                    | NetworkMessage::SendHeaders
                    | NetworkMessage::SendHeaders2
                    | NetworkMessage::SendCmpct(_)
                    | NetworkMessage::SendAddrV2
                    | NetworkMessage::WtxidRelay
                    | NetworkMessage::FeeFilter(_)
                    | NetworkMessage::SendDsq(_) => { /* ignore */ }
                    _ => {}
                }
                if let Some(v) = extract(msg.inner()) {
                    return Ok(v);
                }
            }
            Ok(Ok(None)) => { /* buffer empty, keep looping */ }
            Ok(Err(e)) => return Err(anyhow!("receive failed: {}", e)),
            Err(_) => { /* poll timeout */ }
        }
    }
}

// ---------- output ----------

struct CollectedSeeds {
    total: usize,
    entries: Vec<MasternodeSeed>,
}

struct Summary {
    regular: usize,
    evo: usize,
    core_reachable: usize,
    platform_reachable: usize,
    ssl_valid: usize,
}

fn collect_seeds(diff: &MnListDiff, args: &Args) -> CollectedSeeds {
    let total = diff.new_masternodes.len();
    // Dedupe by (addr, type). If a given address appears as both regular and
    // evo (should never happen on-chain) we keep only the evo variant.
    let mut by_addr: BTreeSet<(SocketAddr, MasternodeType, Option<u16>)> = BTreeSet::new();
    for mn in &diff.new_masternodes {
        if !args.include_invalid && !mn.is_valid {
            continue;
        }
        let Some(addr) = mn.service_address.primary_service_address() else {
            continue;
        };
        if addr.port() == 0 {
            continue;
        }
        match addr.ip() {
            IpAddr::V4(v4) if v4.is_unspecified() => continue,
            IpAddr::V6(v6) if v6.is_unspecified() => continue,
            _ => {}
        }
        let (mn_type, platform_port) = match mn.mn_type {
            EntryMasternodeType::Regular => (MasternodeType::Regular, None),
            EntryMasternodeType::HighPerformance {
                platform_http_port,
                ..
            } => (MasternodeType::Evo, Some(platform_http_port)),
        };
        by_addr.insert((addr, mn_type, platform_port));
    }
    let entries: Vec<MasternodeSeed> = by_addr
        .into_iter()
        .map(|(address, mn_type, platform_http_port)| MasternodeSeed {
            address,
            mn_type,
            platform_http_port,
            core: CoreStatus::default(),
            platform: match mn_type {
                MasternodeType::Evo => Some(PlatformStatus::default()),
                MasternodeType::Regular => None,
            },
        })
        .collect();
    CollectedSeeds {
        total,
        entries,
    }
}

fn reference_tip_height(diff: &MnListDiff) -> Option<u32> {
    use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
    match diff.coinbase_tx.special_transaction_payload.as_ref()? {
        TransactionPayload::CoinbasePayloadType(cb) => Some(cb.height),
        _ => None,
    }
}

async fn probe_all(
    entries: &mut [MasternodeSeed],
    network: Network,
    tip_height: Option<u32>,
    concurrency: usize,
) {
    let total = entries.len();
    tracing::info!(
        "Probing {} seeds with concurrency={} (tip_height={:?})",
        total,
        concurrency,
        tip_height
    );
    let permits = Arc::new(Semaphore::new(concurrency.max(1)));
    let start = Instant::now();
    let mut tasks = FuturesUnordered::new();
    for (idx, seed) in entries.iter().enumerate() {
        let permits = permits.clone();
        let addr = seed.address;
        let mn_type = seed.mn_type;
        let platform_port = seed.platform_http_port;
        tasks.push(tokio::spawn(async move {
            let _permit = permits.acquire_owned().await.ok()?;
            let (reach, peer_h) = probe::probe_core(addr, network).await;
            let sync = probe::classify_sync(peer_h, tip_height);
            let core = probe::core_status(reach, sync);
            let platform = match (mn_type, platform_port) {
                (MasternodeType::Evo, Some(port)) if port != 0 => {
                    Some(probe::probe_platform(addr.ip(), port).await)
                }
                _ => None,
            };
            Some((idx, core, platform))
        }));
    }

    let mut done = 0usize;
    while let Some(res) = tasks.next().await {
        done += 1;
        if let Ok(Some((idx, core, platform))) = res {
            entries[idx].core = core;
            if let Some(p) = platform {
                entries[idx].platform = Some(p);
            }
        }
        if done.is_multiple_of(200) || done == total {
            tracing::info!("Probed {} / {} in {:.1}s", done, total, start.elapsed().as_secs_f64());
        }
    }
    tracing::info!("Probing complete in {:.1}s", start.elapsed().as_secs_f64());
}

fn summarize(entries: &[MasternodeSeed]) -> Summary {
    let regular = entries.iter().filter(|s| s.mn_type == MasternodeType::Regular).count();
    let evo = entries.iter().filter(|s| s.mn_type == MasternodeType::Evo).count();
    let core_reachable = entries.iter().filter(|s| s.core.reachable == Reachability::Ok).count();
    let platform_reachable = entries
        .iter()
        .filter(|s| s.platform.map(|p| p.reachable == Reachability::Ok).unwrap_or(false))
        .count();
    let ssl_valid = entries
        .iter()
        .filter(|s| {
            s.platform.map(|p| p.ssl == dash_network_seeds::SslStatus::Valid).unwrap_or(false)
        })
        .count();
    Summary {
        regular,
        evo,
        core_reachable,
        platform_reachable,
        ssl_valid,
    }
}

#[allow(clippy::too_many_arguments)]
fn write_seed_file(
    path: &std::path::Path,
    network: Network,
    peer: SocketAddr,
    diff: &MnListDiff,
    tip_height: Option<u32>,
    entries: &[MasternodeSeed],
    total: usize,
    summary: &Summary,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir for {}", path.display()))?;
    }
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let mut file =
        fs::File::create(path).with_context(|| format!("opening {} for write", path.display()))?;
    writeln!(
        file,
        "# Auto-generated by masternode-seeds-fetcher on {} for {}",
        timestamp, network
    )?;
    writeln!(file, "# Source: Dash P2P network (mnlistdiff)")?;
    writeln!(file, "# Primary peer: {}", peer)?;
    writeln!(file, "# Tip block hash: {}", diff.block_hash)?;
    if let Some(h) = tip_height {
        writeln!(file, "# Tip block height: {}", h)?;
    }
    writeln!(
        file,
        "# {} seeds ({} regular + {} evo) of {} total masternodes, valid-only",
        entries.len(),
        summary.regular,
        summary.evo,
        total
    )?;
    writeln!(
        file,
        "# Probe summary: core_reachable={}/{} platform_reachable={}/{} ssl_valid={}/{}",
        summary.core_reachable,
        entries.len(),
        summary.platform_reachable,
        summary.evo,
        summary.ssl_valid,
        summary.evo,
    )?;
    writeln!(
        file,
        "# Columns: <type> <addr> <platform_http_port|-> <core_reach> <core_sync> <plat_reach> <plat_live> <plat_ssl>"
    )?;
    writeln!(
        file,
        "# Values: core_reach/plat_reach=ok|timeout|refused|error|?, core_sync=sync|-N|+N|?, plat_live=ok|none|?|-, plat_ssl=valid|expired|self-signed|untrusted|no-handshake|?|-"
    )?;
    writeln!(
        file,
        "# Do not edit manually — refreshed weekly by .github/workflows/update-masternode-seeds.yml"
    )?;
    // Sort by address so the file is deterministic and diffs stay minimal
    // when only membership changes.
    let mut sorted: Vec<&MasternodeSeed> = entries.iter().collect();
    sorted.sort_by_key(|s| (s.address, s.mn_type));
    for seed in sorted {
        writeln!(file, "{}", seed.to_line())?;
    }
    Ok(())
}
