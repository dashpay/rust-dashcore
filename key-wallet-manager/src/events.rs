//! Wallet events for notifying consumers of wallet state changes.
//!
//! Each variant is self-contained: it carries the transaction record(s) that
//! triggered it and the wallet's new balance after the change. Consumers can
//! persist the transaction(s) and balance atomically off a single event.

use std::collections::BTreeMap;

use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::Txid;
use key_wallet::account::{AccountType, StandardAccountType};
use key_wallet::managed_account::transaction_record::TransactionRecord;
use key_wallet::WalletCoreBalance;

use crate::WalletId;

/// Compact label for an [`AccountType`] suitable for log lines. Avoids
/// printing 32-byte identity hashes from the Dashpay variants.
fn format_account_type(account_type: &AccountType) -> String {
    match account_type {
        AccountType::Standard {
            index,
            standard_account_type,
        } => {
            let kind = match standard_account_type {
                StandardAccountType::BIP44Account => "BIP44",
                StandardAccountType::BIP32Account => "BIP32",
            };
            format!("Standard{{idx:{},{}}}", index, kind)
        }
        AccountType::CoinJoin {
            index,
        } => {
            format!("CoinJoin{{idx:{}}}", index)
        }
        AccountType::IdentityRegistration => "IdentityRegistration".to_string(),
        AccountType::IdentityTopUp {
            registration_index,
        } => {
            format!("IdentityTopUp{{reg:{}}}", registration_index)
        }
        AccountType::IdentityTopUpNotBoundToIdentity => "IdentityTopUpNotBound".to_string(),
        AccountType::IdentityInvitation => "IdentityInvitation".to_string(),
        AccountType::AssetLockAddressTopUp => "AssetLockAddressTopUp".to_string(),
        AccountType::AssetLockShieldedAddressTopUp => "AssetLockShieldedAddressTopUp".to_string(),
        AccountType::ProviderVotingKeys => "ProviderVotingKeys".to_string(),
        AccountType::ProviderOwnerKeys => "ProviderOwnerKeys".to_string(),
        AccountType::ProviderOperatorKeys => "ProviderOperatorKeys".to_string(),
        AccountType::ProviderPlatformKeys => "ProviderPlatformKeys".to_string(),
        AccountType::DashpayReceivingFunds {
            index,
            ..
        } => {
            format!("DashpayReceiving{{idx:{}}}", index)
        }
        AccountType::DashpayExternalAccount {
            index,
            ..
        } => {
            format!("DashpayExternal{{idx:{}}}", index)
        }
        AccountType::PlatformPayment {
            account,
            key_class,
        } => {
            format!("PlatformPayment{{acct:{},class:{}}}", account, key_class)
        }
    }
}

/// Render the changed-account balance map as a short bracketed list
/// suitable for log lines, e.g. `[Standard{idx:0,BIP44}=>1.5 DASH]`.
fn format_account_balances(map: &BTreeMap<AccountType, WalletCoreBalance>) -> String {
    if map.is_empty() {
        return "[]".to_string();
    }
    let parts: Vec<String> = map
        .iter()
        .map(|(account_type, balance)| {
            format!(
                "{}=>{}",
                format_account_type(account_type),
                dashcore::Amount::from_sat(balance.total())
            )
        })
        .collect();
    format!("[{}]", parts.join(", "))
}

/// Events emitted by the wallet manager.
///
/// Each event represents a meaningful wallet state change. Events that
/// modify balance carry the wallet's balance *after* the change so
/// consumers can persist the record(s) and balance atomically.
#[derive(Debug, Clone)]
pub enum WalletEvent {
    /// First time the wallet sees an off-chain wallet-relevant transaction
    /// (mempool, or directly via an InstantSend lock — in that case
    /// `record.context` is `InstantSend(..)`).
    TransactionDetected {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// The full transaction record with all details.
        record: Box<TransactionRecord>,
        /// Wallet balance after the transaction was recorded.
        balance: WalletCoreBalance,
        /// Post-event balance **snapshots** for accounts whose balance
        /// changed as a result of this event. Each value is the account's
        /// full balance after the change — not a delta. Accounts whose
        /// balance was unchanged are omitted to keep the payload small
        /// (most transactions touch only 1–2 accounts).
        account_balances: BTreeMap<AccountType, WalletCoreBalance>,
    },
    /// An InstantSend lock was applied to a previously-seen off-chain
    /// wallet-relevant transaction.
    TransactionInstantLocked {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// Transaction ID.
        txid: Txid,
        /// The InstantSend lock now applied to the transaction.
        instant_lock: InstantLock,
        /// Wallet balance after the status change.
        balance: WalletCoreBalance,
        /// Post-event balance **snapshots** for accounts whose balance
        /// changed as a result of this event. Each value is the account's
        /// full balance after the change — not a delta.
        account_balances: BTreeMap<AccountType, WalletCoreBalance>,
    },
    /// A block was processed for a wallet. Carries records bucketed by what
    /// happened to them in this block, plus the post-block balance.
    /// `inserted` is records first stored in this block, `updated` is
    /// previously-known records that just confirmed, `matured` is older
    /// coinbase records that crossed the maturity threshold as the scanned
    /// height advanced.
    BlockProcessed {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// Height of the block that was processed.
        height: CoreBlockHeight,
        /// Records first stored for this wallet in this block.
        inserted: Vec<TransactionRecord>,
        /// Previously-known records confirmed by this block.
        updated: Vec<TransactionRecord>,
        /// Older coinbase records whose maturity threshold was crossed by
        /// this height advance.
        matured: Vec<TransactionRecord>,
        /// Wallet balance after the block was processed.
        balance: WalletCoreBalance,
        /// Post-event balance **snapshots** for accounts whose balance
        /// changed during processing of this block. Each value is the
        /// account's full balance after the change — not a delta. Accounts
        /// whose balance was unchanged are omitted.
        account_balances: BTreeMap<AccountType, WalletCoreBalance>,
    },
    /// The wallet's scan cursor advanced because the filter pipeline
    /// committed a batch covering blocks up to `height`. No records or
    /// balance — consumers persist this as a checkpoint atomically with
    /// any records/balance from prior `BlockProcessed` events in the batch.
    SyncHeightAdvanced {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// New scanned height for the wallet.
        height: CoreBlockHeight,
    },
}

impl WalletEvent {
    /// ID of the wallet this event pertains to.
    pub fn wallet_id(&self) -> WalletId {
        match self {
            WalletEvent::TransactionDetected {
                wallet_id,
                ..
            }
            | WalletEvent::TransactionInstantLocked {
                wallet_id,
                ..
            }
            | WalletEvent::BlockProcessed {
                wallet_id,
                ..
            }
            | WalletEvent::SyncHeightAdvanced {
                wallet_id,
                ..
            } => *wallet_id,
        }
    }

    /// Short description for logging.
    pub fn description(&self) -> String {
        match self {
            WalletEvent::TransactionDetected {
                record,
                balance,
                account_balances,
                ..
            } => {
                format!(
                    "TransactionDetected(txid={}, context={}, balance={}, account_balances={})",
                    record.txid,
                    record.context,
                    balance,
                    format_account_balances(account_balances),
                )
            }
            WalletEvent::TransactionInstantLocked {
                txid,
                balance,
                account_balances,
                ..
            } => {
                format!(
                    "TransactionInstantLocked(txid={}, balance={}, account_balances={})",
                    txid,
                    balance,
                    format_account_balances(account_balances),
                )
            }
            WalletEvent::BlockProcessed {
                height,
                inserted,
                updated,
                matured,
                balance,
                account_balances,
                ..
            } => {
                format!(
                    "BlockProcessed(height={}, inserted={}, updated={}, matured={}, balance={}, account_balances={})",
                    height,
                    inserted.len(),
                    updated.len(),
                    matured.len(),
                    balance,
                    format_account_balances(account_balances),
                )
            }
            WalletEvent::SyncHeightAdvanced {
                height,
                ..
            } => {
                format!("SyncHeightAdvanced(height={})", height)
            }
        }
    }
}
