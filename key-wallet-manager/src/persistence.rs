//! Wallet persistence trait.
//!
//! [`WalletPersistence`] is the single hook point through which
//! [`WalletManager`](crate::WalletManager) writes core wallet state
//! (UTXOs, transactions, balances, address watermarks) to durable storage.
//!
//! Implementations supply their own backend (SQLite, SwiftData, memory, …).
//! The no-op default [`NoWalletPersistence`] is used when persistence is not
//! needed (e.g. standalone tests or in-process wallets without a DB).
//!
//! ## Contract
//!
//! - `store` is called once per wallet per block with an accumulated changeset
//!   containing all transaction state plus the synced height.
//! - The implementation decides its own flush strategy — it may write
//!   immediately (like SQLite) or buffer for later.

use crate::WalletId;
use key_wallet::changeset::WalletChangeSet;

/// Persistence backend for wallet state.
pub trait WalletPersistence: Send + Sync {
    /// Persist a changeset for `wallet_id`.
    ///
    /// Called once per wallet per block with the accumulated changeset.
    /// Implementations decide their own flush strategy — they may write
    /// inline or buffer for a later batch write.
    fn store(
        &self,
        wallet_id: WalletId,
        cs: WalletChangeSet,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// No-op persistence — discards all changesets silently.
///
/// Default used by [`WalletManager::new`](crate::WalletManager::new).
pub struct NoWalletPersistence;

impl WalletPersistence for NoWalletPersistence {
    fn store(
        &self,
        _wallet_id: WalletId,
        _cs: WalletChangeSet,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}
