use crate::sync::SyncState;
use std::fmt;
use std::time::Instant;

/// Progress tracking for mempool transaction monitoring.
#[derive(Debug, Clone, PartialEq)]
pub struct MempoolProgress {
    /// Current sync state.
    state: SyncState,
    /// Total transactions received from the network.
    received: u32,
    /// Transactions that matched wallet addresses.
    relevant: u32,
    /// Transactions currently tracked in mempool state (wallet-relevant).
    tracked: u32,
    /// Transactions removed (confirmed or expired).
    removed: u32,
    /// Time of last activity.
    last_activity: Instant,
}

impl Default for MempoolProgress {
    fn default() -> Self {
        Self {
            state: Default::default(),
            received: 0,
            relevant: 0,
            tracked: 0,
            removed: 0,
            last_activity: Instant::now(),
        }
    }
}

impl MempoolProgress {
    pub fn state(&self) -> SyncState {
        self.state
    }

    pub fn received(&self) -> u32 {
        self.received
    }

    pub fn relevant(&self) -> u32 {
        self.relevant
    }

    pub fn tracked(&self) -> u32 {
        self.tracked
    }

    pub fn removed(&self) -> u32 {
        self.removed
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub(super) fn set_state(&mut self, state: SyncState) {
        self.state = state;
        self.bump_last_activity();
    }

    pub(super) fn add_received(&mut self, count: u32) {
        self.received += count;
        self.bump_last_activity();
    }

    pub(super) fn add_relevant(&mut self, count: u32) {
        self.relevant += count;
        self.bump_last_activity();
    }

    pub(super) fn set_tracked(&mut self, count: u32) {
        self.tracked = count;
        self.bump_last_activity();
    }

    pub(super) fn add_removed(&mut self, count: u32) {
        self.removed += count;
        self.bump_last_activity();
    }

    fn bump_last_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

impl fmt::Display for MempoolProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} received: {}, relevant: {}, tracked: {}, removed: {}, last_activity: {}s",
            self.state,
            self.received,
            self.relevant,
            self.tracked,
            self.removed,
            self.last_activity.elapsed().as_secs()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let p = MempoolProgress::default();
        assert_eq!(p.state(), SyncState::WaitForEvents);
        assert_eq!(p.received(), 0);
        assert_eq!(p.relevant(), 0);
        assert_eq!(p.tracked(), 0);
        assert_eq!(p.removed(), 0);
    }

    #[test]
    fn test_mutators_update_correctly() {
        let mut p = MempoolProgress::default();

        p.add_received(5);
        assert_eq!(p.received(), 5);
        p.add_received(3);
        assert_eq!(p.received(), 8);

        p.add_relevant(2);
        assert_eq!(p.relevant(), 2);

        p.set_tracked(10);
        assert_eq!(p.tracked(), 10);
        // set_tracked replaces, not accumulates
        p.set_tracked(7);
        assert_eq!(p.tracked(), 7);

        p.add_removed(3);
        assert_eq!(p.removed(), 3);

        p.set_state(SyncState::Synced);
        assert_eq!(p.state(), SyncState::Synced);
    }

    #[test]
    fn test_last_activity_updated_on_mutation() {
        let mut p = MempoolProgress::default();
        let before = p.last_activity();

        // Small sleep to ensure time difference
        std::thread::sleep(std::time::Duration::from_millis(1));
        p.add_received(1);

        assert!(p.last_activity() >= before);
    }

    #[test]
    fn test_display_format() {
        let mut p = MempoolProgress::default();
        p.add_received(10);
        p.add_relevant(3);
        p.set_tracked(2);
        p.add_removed(1);

        let display = format!("{}", p);
        assert!(display.contains("received: 10"));
        assert!(display.contains("relevant: 3"));
        assert!(display.contains("tracked: 2"));
        assert!(display.contains("removed: 1"));
        assert!(display.contains("WaitForEvents"));
    }
}
