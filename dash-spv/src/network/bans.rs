use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

const MAX_DIAL_BACKOFF: Duration = Duration::from_secs(60);
const KICK_BAN: Duration = Duration::from_secs(10 * 60);
const MISBEHAVIOUR_BAN: Duration = Duration::from_secs(24 * 60 * 60);

pub enum Ban {
    DialFailed,
    Kicked,
    /// Lacks a service the client needs, which does not change within a session.
    MissingServices,
    Misbehaved,
}

/// The dial backoff and the ban of one address, apart so a handshake can clear the backoff
/// alone.
struct Entry {
    fails: u32,
    backoff_until: Instant,
    banned_until: Instant,
}

pub struct Bans {
    entries: Mutex<HashMap<SocketAddr, Entry>>,
    /// The configured peers: never kicked out of the dial set, only backed off on a
    /// failed dial. Banning one can leave a restricted client with nothing to dial.
    configured: HashSet<SocketAddr>,
}

impl Bans {
    pub fn new(configured: impl IntoIterator<Item = SocketAddr>) -> Self {
        Self {
            entries: Mutex::default(),
            configured: configured.into_iter().collect(),
        }
    }

    pub async fn ban(&self, addr: SocketAddr, ban: Ban) {
        if self.configured.contains(&addr) && !matches!(ban, Ban::DialFailed) {
            return;
        }
        let mut entries = self.entries.lock().await;
        let now = Instant::now();
        let entry = entries.entry(addr).or_insert(Entry {
            fails: 0,
            backoff_until: now,
            banned_until: now,
        });
        let (until, duration) = match ban {
            Ban::DialFailed => {
                entry.fails += 1;
                let backoff = Duration::from_secs(1 << entry.fails.min(6));
                (&mut entry.backoff_until, MAX_DIAL_BACKOFF.min(backoff))
            }
            Ban::Kicked => (&mut entry.banned_until, KICK_BAN),
            Ban::MissingServices => (&mut entry.banned_until, MISBEHAVIOUR_BAN),
            Ban::Misbehaved => {
                tracing::warn!(target: "dash_spv::network", "banning {} for misbehaving", addr);
                (&mut entry.banned_until, MISBEHAVIOUR_BAN)
            }
        };
        *until = (*until).max(now + duration);
    }

    /// Clears the dial backoff of `addr` after a handshake. A ban recorded while the dial was
    /// in flight survives the handshake.
    pub async fn dialed(&self, addr: SocketAddr) {
        let mut entries = self.entries.lock().await;
        let now = Instant::now();
        match entries.get_mut(&addr) {
            Some(entry) if entry.banned_until > now => {
                entry.fails = 0;
                entry.backoff_until = now;
            }
            _ => {
                entries.remove(&addr);
            }
        }
    }

    /// Whether `addr` is banned, leaving out its dial backoff.
    pub async fn is_banned(&self, addr: SocketAddr) -> bool {
        let entries = self.entries.lock().await;
        entries.get(&addr).is_some_and(|entry| entry.banned_until > Instant::now())
    }

    /// Locks the table until the returned guard drops. A test holds it to stop a task at its
    /// next ban.
    #[cfg(test)]
    pub(super) async fn hold(&self) -> impl Sized + '_ {
        self.entries.lock().await
    }

    pub async fn banned(&self) -> HashSet<SocketAddr> {
        let now = Instant::now();
        self.entries
            .lock()
            .await
            .iter()
            .filter(|(_, entry)| entry.backoff_until.max(entry.banned_until) > now)
            .map(|(addr, _)| *addr)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;
    use tokio::time::advance;

    /// A node lacking a service the client needs stays banned past the longest dial
    /// backoff.
    #[tokio::test(start_paused = true)]
    async fn missing_services_outlast_the_dial_backoff() {
        let bans = Bans::new([]);
        let addr: SocketAddr = "46.224.41.173:19999".parse().expect("an address");
        bans.ban(addr, Ban::MissingServices).await;

        tokio::time::advance(MAX_DIAL_BACKOFF * 10).await;

        assert!(bans.banned().await.contains(&addr));
    }

    /// A handshake clears the dial backoff and the fail count, even ones a parallel dial just
    /// set, but keeps a ban recorded during the dial. Only the ban counts for `is_banned`.
    #[test_case(Ban::Kicked, KICK_BAN; "kicked")]
    #[test_case(Ban::MissingServices, MISBEHAVIOUR_BAN; "missing services")]
    #[test_case(Ban::Misbehaved, MISBEHAVIOUR_BAN; "misbehaved")]
    #[tokio::test(start_paused = true)]
    async fn a_handshake_clears_the_dial_backoff_but_keeps_a_ban(ban: Ban, duration: Duration) {
        let bans = Bans::new([]);
        let addr: SocketAddr = "46.224.41.173:19999".parse().expect("an address");
        bans.ban(addr, Ban::DialFailed).await;
        assert!(bans.banned().await.contains(&addr));
        assert!(!bans.is_banned(addr).await, "a dial backoff counted as a ban");
        bans.dialed(addr).await;
        assert!(bans.banned().await.is_empty(), "the handshake kept a live dial backoff");

        // The dial backoff set in the ban's last second outlives the ban.
        bans.ban(addr, ban).await;
        advance(duration - Duration::from_secs(1)).await;
        for _ in 0..6 {
            bans.ban(addr, Ban::DialFailed).await;
        }
        bans.dialed(addr).await;
        assert!(bans.is_banned(addr).await, "the handshake erased the ban");
        advance(Duration::from_secs(2)).await;
        assert!(!bans.is_banned(addr).await, "an expired ban still counted");
        assert!(bans.banned().await.is_empty(), "the handshake kept the dial backoff");

        bans.ban(addr, Ban::DialFailed).await;
        advance(Duration::from_secs(2)).await;
        assert!(bans.banned().await.is_empty(), "the handshake kept the fail count");
    }
}
