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
//! - `store` is called once per wallet per block for any wallet that had
//!   relevant transactions in that block.
//! - `flush` is called once per block after all `store` calls, signalling
//!   that the buffered changeset may be written atomically.
//! - Both calls receive the same `wallet_id` so a single shared implementation
//!   can manage multiple wallets.

use crate::WalletId;
use key_wallet::changeset::WalletChangeSet;

/// Persistence backend for wallet state.
pub trait WalletPersistence: Send + Sync {
    /// Buffer a changeset for `wallet_id`.
    ///
    /// Implementations may write immediately or accumulate for a later [`flush`].
    fn store(
        &self,
        wallet_id: WalletId,
        cs: WalletChangeSet,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Flush all buffered state for `wallet_id` to durable storage.
    fn flush(
        &self,
        wallet_id: WalletId,
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

    fn flush(
        &self,
        _wallet_id: WalletId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}
