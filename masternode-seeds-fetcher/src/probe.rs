//! Per-masternode reachability probes.
//!
//! Given a masternode's advertised Core address (and, for Evo nodes, a
//! platform HTTP port), this module produces a [`CoreStatus`] /
//! [`PlatformStatus`] suitable for embedding in the seed file. All probes are
//! bounded by short timeouts so that even a fully-unresponsive peer costs
//! the fetcher only a few seconds.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dash_network_seeds::{
    CoreStatus, PlatformLiveness, PlatformStatus, Reachability, SslStatus, SyncStatus,
};
use dashcore::Network as DashNetwork;
use dashcore::network::Address;
use dashcore::network::constants::ServiceFlags;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_network::VersionMessage;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Version;

use dash_spv::network::Peer;

/// How long to give a single TCP connect before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Budget for the whole Core probe (connect + handshake).
const CORE_PROBE_BUDGET: Duration = Duration::from_secs(10);
/// Budget for the whole Platform probe (connect + TLS handshake + baseline HTTP).
const PLATFORM_PROBE_BUDGET: Duration = Duration::from_secs(10);

/// Number of blocks within which a peer's `start_height` is considered
/// "synced" relative to the reference tip.
const SYNC_TOLERANCE: u32 = 10;

/// Probe a Core peer: TCP + P2P handshake. Returns reachability and the
/// peer's reported `start_height` (for caller-side sync classification).
pub async fn probe_core(
    peer_addr: SocketAddr,
    _network: DashNetwork,
) -> (Reachability, Option<u32>) {
    match tokio::time::timeout(CORE_PROBE_BUDGET, probe_core_inner(peer_addr, _network)).await {
        Ok(Ok(h)) => (Reachability::Ok, h),
        Ok(Err(e)) => (classify_io(e), None),
        Err(_) => (Reachability::Timeout, None),
    }
}

async fn probe_core_inner(peer_addr: SocketAddr, network: DashNetwork) -> Result<Option<u32>> {
    let mut peer = Peer::connect(peer_addr, CONNECT_TIMEOUT.as_secs(), network).await?;

    let version = VersionMessage::new(
        ServiceFlags::NONE,
        chrono::Utc::now().timestamp(),
        Address::new(&peer_addr, ServiceFlags::NETWORK),
        Address::new(
            &SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0),
            ServiceFlags::NONE,
        ),
        rand::random::<u64>(),
        format!("/masternode-seeds-fetcher:{}/probe", env!("CARGO_PKG_VERSION")),
        0,
        false,
        [0u8; 32],
    );
    peer.send_message(NetworkMessage::Version(version)).await?;

    let start = tokio::time::Instant::now();
    let mut got_version = false;
    let mut got_verack = false;
    let mut start_height: Option<u32> = None;

    while start.elapsed() < CORE_PROBE_BUDGET {
        match tokio::time::timeout(Duration::from_millis(300), peer.receive_message()).await {
            Ok(Ok(Some(msg))) => match msg.inner() {
                NetworkMessage::Version(v) => {
                    got_version = true;
                    start_height = Some(v.start_height.max(0) as u32);
                    peer.send_message(NetworkMessage::SendAddrV2).await.ok();
                    peer.send_message(NetworkMessage::Verack).await?;
                    if got_verack {
                        return Ok(start_height);
                    }
                }
                NetworkMessage::Verack => {
                    got_verack = true;
                    if got_version {
                        return Ok(start_height);
                    }
                }
                NetworkMessage::Ping(n) => {
                    peer.send_message(NetworkMessage::Pong(*n)).await.ok();
                }
                _ => { /* ignore */ }
            },
            Ok(Ok(None)) | Err(_) => { /* poll tick */ }
            Ok(Err(e)) => return Err(anyhow::anyhow!("{}", e)),
        }
    }
    Err(anyhow::anyhow!("handshake incomplete within budget"))
}

/// Classify a `SyncStatus` given a peer's reported `start_height` and a
/// reference tip height captured from the primary fetch.
pub fn classify_sync(peer_height: Option<u32>, reference_tip: Option<u32>) -> SyncStatus {
    let (Some(peer), Some(reference)) = (peer_height, reference_tip) else {
        return SyncStatus::Unknown;
    };
    if peer >= reference {
        let ahead = peer - reference;
        if ahead <= SYNC_TOLERANCE {
            SyncStatus::Synced
        } else {
            SyncStatus::Ahead(ahead)
        }
    } else {
        let behind = reference - peer;
        if behind <= SYNC_TOLERANCE {
            SyncStatus::Synced
        } else {
            SyncStatus::Behind(behind)
        }
    }
}

/// Probe a Platform HTTP port: TCP connect, TLS handshake (chain check +
/// cert introspection), and a minimal HTTP `GET /` to gauge liveness.
pub async fn probe_platform(ip: std::net::IpAddr, http_port: u16) -> PlatformStatus {
    let addr = SocketAddr::new(ip, http_port);
    match tokio::time::timeout(PLATFORM_PROBE_BUDGET, probe_platform_inner(addr)).await {
        Ok(result) => result,
        Err(_) => PlatformStatus {
            reachable: Reachability::Timeout,
            live: PlatformLiveness::None,
            ssl: SslStatus::NoHandshake,
        },
    }
}

async fn probe_platform_inner(addr: SocketAddr) -> PlatformStatus {
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return PlatformStatus {
                reachable: classify_io(anyhow::Error::from(e)),
                live: PlatformLiveness::None,
                ssl: SslStatus::NoHandshake,
            };
        }
        Err(_) => {
            return PlatformStatus {
                reachable: Reachability::Timeout,
                live: PlatformLiveness::None,
                ssl: SslStatus::NoHandshake,
            };
        }
    };

    // TLS handshake. We use a custom verifier that accepts *any* certificate
    // chain, then inspect the end-entity cert ourselves — this gives us
    // "valid" / "expired" / "self-signed" / "untrusted" classifications
    // without having to pin to a hostname (which is pointless when connecting
    // by IP).
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    // ServerName::try_from requires a DNS name; we don't have one. Use a
    // dummy "no-hostname" marker — the custom verifier ignores it.
    let dummy_name: ServerName<'static> = ServerName::try_from("example.invalid").unwrap();

    let mut tls = match connector.connect(dummy_name, tcp).await {
        Ok(s) => s,
        Err(_) => {
            return PlatformStatus {
                reachable: Reachability::Ok,
                live: PlatformLiveness::None,
                ssl: SslStatus::NoHandshake,
            };
        }
    };

    let ssl = {
        let (_, conn) = tls.get_ref();
        classify_cert(conn.peer_certificates())
    };

    // Minimal HTTP probe. We send `GET / HTTP/1.1` and check for *any* HTTP
    // status line. Platform nodes running gRPC-over-HTTP/2 will usually
    // reject this with a 4xx or 5xx — which still counts as "live".
    let live = match http_liveness(&mut tls).await {
        true => PlatformLiveness::Ok,
        false => PlatformLiveness::None,
    };

    PlatformStatus {
        reachable: Reachability::Ok,
        live,
        ssl,
    }
}

async fn http_liveness(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) -> bool {
    let req = b"GET / HTTP/1.1\r\nHost: dash-platform\r\nUser-Agent: masternode-seeds-fetcher\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    if stream.write_all(req).await.is_err() {
        return false;
    }
    if stream.flush().await.is_err() {
        return false;
    }
    let mut buf = [0u8; 16];
    match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n >= 5 => buf.starts_with(b"HTTP/"),
        _ => false,
    }
}

fn classify_cert(chain: Option<&[CertificateDer<'_>]>) -> SslStatus {
    let Some(chain) = chain else {
        return SslStatus::NoHandshake;
    };
    let Some(leaf_der) = chain.first() else {
        return SslStatus::NoHandshake;
    };
    let Ok((_, leaf)) = x509_parser::certificate::X509Certificate::from_der(leaf_der.as_ref())
    else {
        return SslStatus::Untrusted;
    };
    if leaf.tbs_certificate.version != X509Version::V3 {
        // V1 / V2 certs in the wild are almost always dodgy.
        return SslStatus::Untrusted;
    }
    let not_after = leaf.tbs_certificate.validity.not_after;
    let now = chrono::Utc::now().timestamp();
    if not_after.timestamp() < now {
        return SslStatus::Expired;
    }
    // Self-signed: Issuer == Subject and only one cert in the chain.
    let self_signed_hint =
        leaf.tbs_certificate.issuer == leaf.tbs_certificate.subject && chain.len() == 1;
    if self_signed_hint {
        return SslStatus::SelfSigned;
    }
    // We don't do a full PKI walk (that's what rustls's default verifier is
    // for, but it'd reject based on hostname mismatch). Lacking full chain
    // verification, the best we can say is "looks valid enough".
    SslStatus::Valid
}

fn classify_io(err: anyhow::Error) -> Reachability {
    // Walk the source chain for an io::Error kind.
    let mut src: Option<&dyn std::error::Error> = Some(err.as_ref());
    while let Some(current) = src {
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                ErrorKind::TimedOut => Reachability::Timeout,
                ErrorKind::ConnectionRefused => Reachability::Refused,
                _ => Reachability::Error,
            };
        }
        src = current.source();
    }
    Reachability::Error
}

/// Convenience: turn a pair of probes into a fully-populated [`CoreStatus`].
pub fn core_status(reachable: Reachability, synced: SyncStatus) -> CoreStatus {
    CoreStatus {
        reachable,
        synced,
    }
}

// ---------- rustls custom verifier ----------

#[derive(Debug)]
struct AcceptAllVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
