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
    Misbehaved,
}

#[derive(Default)]
pub struct Bans {
    entries: Mutex<HashMap<SocketAddr, (u32, Instant)>>,
}

impl Bans {
    pub async fn ban(&self, addr: SocketAddr, ban: Ban) {
        let mut entries = self.entries.lock().await;
        let now = Instant::now();
        let (fails, until) = entries.entry(addr).or_insert((0, now));
        let duration = match ban {
            Ban::DialFailed => {
                *fails += 1;
                MAX_DIAL_BACKOFF.min(Duration::from_secs(1 << (*fails).min(6)))
            }
            Ban::Kicked => KICK_BAN,
            Ban::Misbehaved => {
                tracing::warn!(target: "dash_spv::network", "banning {} for misbehaving", addr);
                MISBEHAVIOUR_BAN
            }
        };
        *until = (*until).max(now + duration);
    }

    pub async fn dialed(&self, addr: SocketAddr) {
        self.entries.lock().await.remove(&addr);
    }

    pub async fn banned(&self) -> HashSet<SocketAddr> {
        let now = Instant::now();
        self.entries
            .lock()
            .await
            .iter()
            .filter(|(_, (_, until))| *until > now)
            .map(|(addr, _)| *addr)
            .collect()
    }
}
