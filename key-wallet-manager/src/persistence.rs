//! Persistence layer for wallet state changes.
//!
//! The [`WalletPersistence`] trait allows `ManagedWalletState` to persist
//! changesets produced by transaction checking and other state mutations.
//! [`NoPersistence`] is a no-op implementation used when persistence is
//! not required (e.g. in tests or the default `WalletManager`).

use key_wallet::changeset::WalletChangeSet;

/// Trait for persisting wallet state changes.
///
/// Implementations receive changesets produced by transaction processing
/// and are responsible for durably storing them.
pub trait WalletPersistence: Send + Sync + 'static {
    /// Queue a changeset for persistence.
    fn store(&self, changeset: WalletChangeSet) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Flush any pending changesets to durable storage.
    fn flush(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// No-op persistence implementation.
///
/// Discards all changesets silently. Used as the default persistence
/// layer when no external storage is configured.
#[derive(Debug, Default)]
pub struct NoPersistence;

impl WalletPersistence for NoPersistence {
    fn store(&self, _changeset: WalletChangeSet) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn flush(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}
