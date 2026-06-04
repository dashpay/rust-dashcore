//! Transaction routing based on transaction type
//!
//! This module determines which account types should be checked
//! for different transaction types.

mod tests;

use crate::managed_account::managed_account_type::ManagedAccountType;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::Transaction;

/// Classification of transaction types for routing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TransactionType {
    /// Standard payment transaction
    Standard,
    /// CoinJoin mixing transaction
    CoinJoin,
    /// Provider registration transaction
    ProviderRegistration,
    /// Provider update registrar transaction
    ProviderUpdateRegistrar,
    /// Provider update service transaction
    ProviderUpdateService,
    /// Provider update revocation transaction
    ProviderUpdateRevocation,
    /// Asset lock transaction
    AssetLock,
    /// Asset unlock transaction
    AssetUnlock,
    /// Coinbase transaction
    Coinbase,
    /// Ignored special transaction
    Ignored,
}

/// Router for determining which accounts to check for a transaction
pub struct TransactionRouter;

impl TransactionRouter {
    /// Classify a transaction based on its type and payload
    pub fn classify_transaction(tx: &Transaction) -> TransactionType {
        // Check if it's a special transaction
        let special_classification = tx.special_transaction_payload.as_ref().and_then(|payload| {
            match payload {
                TransactionPayload::ProviderRegistrationPayloadType(_) => {
                    Some(TransactionType::ProviderRegistration)
                }
                TransactionPayload::ProviderUpdateRegistrarPayloadType(_) => {
                    Some(TransactionType::ProviderUpdateRegistrar)
                }
                TransactionPayload::ProviderUpdateServicePayloadType(_) => {
                    Some(TransactionType::ProviderUpdateService)
                }
                TransactionPayload::ProviderUpdateRevocationPayloadType(_) => {
                    Some(TransactionType::ProviderUpdateRevocation)
                }
                TransactionPayload::AssetLockPayloadType(_) => Some(TransactionType::AssetLock),
                TransactionPayload::AssetUnlockPayloadType(_) => Some(TransactionType::AssetUnlock),
                TransactionPayload::CoinbasePayloadType(_) => Some(TransactionType::Coinbase),
                TransactionPayload::QuorumCommitmentPayloadType(_) => {
                    Some(TransactionType::Ignored)
                }
                TransactionPayload::MnhfSignalPayloadType(_) => Some(TransactionType::Ignored),
                // Pre-DIP-0002 transactions are logically Classic — fall through to the
                // standard / coinbase / coinjoin classification below.
                TransactionPayload::ClassicalWithNonStandardVersionTypeBytesPayloadType(_) => None,
            }
        });
        if let Some(classification) = special_classification {
            classification
        } else if tx.is_coin_base() {
            TransactionType::Coinbase
        } else if Self::is_coinjoin_transaction(tx) {
            TransactionType::CoinJoin
        } else {
            TransactionType::Standard
        }
    }

    /// All account types that hold spendable funds on the Core chain.
    ///
    /// Ownership of a transaction is membership-based across every keychain, exactly like
    /// Dash Core's `IsMine`, which tests each scriptPubKey against all script-pubkey managers
    /// uniformly (regular external, internal, and the CoinJoin descriptor). A transaction's
    /// shape (`TransactionType::Standard` vs `TransactionType::CoinJoin`) is only a downstream
    /// label, never a precondition for discovery, so both shapes must consult the full set of
    /// fund-bearing accounts. An account only matches when a scriptPubKey or spent UTXO actually
    /// belongs to it, so checking extra accounts never produces false positives.
    fn fund_bearing_account_types() -> Vec<AccountTypeToCheck> {
        vec![
            AccountTypeToCheck::StandardBIP44,
            AccountTypeToCheck::StandardBIP32,
            AccountTypeToCheck::CoinJoin,
            AccountTypeToCheck::DashpayReceivingFunds,
            AccountTypeToCheck::DashpayExternalAccount,
        ]
    }

    /// Determine which account types should be checked for a given transaction type
    pub fn get_relevant_account_types(tx_type: &TransactionType) -> Vec<AccountTypeToCheck> {
        match tx_type {
            // Standard and CoinJoin transactions are distinguished only by their stored label;
            // discovery is membership-based, so both check every fund-bearing account.
            TransactionType::Standard | TransactionType::CoinJoin => {
                Self::fund_bearing_account_types()
            }
            TransactionType::ProviderRegistration => vec![
                AccountTypeToCheck::ProviderOwnerKeys,
                AccountTypeToCheck::ProviderOperatorKeys,
                AccountTypeToCheck::ProviderVotingKeys,
                AccountTypeToCheck::ProviderPlatformKeys,
                AccountTypeToCheck::StandardBIP44,
                AccountTypeToCheck::StandardBIP32,
                AccountTypeToCheck::CoinJoin,
            ],
            TransactionType::ProviderUpdateRegistrar => vec![
                AccountTypeToCheck::ProviderVotingKeys,
                AccountTypeToCheck::ProviderOperatorKeys,
                AccountTypeToCheck::StandardBIP44,
                AccountTypeToCheck::StandardBIP32,
                AccountTypeToCheck::CoinJoin,
            ],
            TransactionType::ProviderUpdateService => vec![
                AccountTypeToCheck::ProviderOperatorKeys,
                AccountTypeToCheck::ProviderPlatformKeys,
                AccountTypeToCheck::StandardBIP44,
                AccountTypeToCheck::StandardBIP32,
                AccountTypeToCheck::CoinJoin,
            ],
            TransactionType::ProviderUpdateRevocation => vec![
                AccountTypeToCheck::StandardBIP44,
                AccountTypeToCheck::StandardBIP32,
                AccountTypeToCheck::CoinJoin,
            ],
            TransactionType::AssetLock => vec![
                AccountTypeToCheck::StandardBIP44,
                AccountTypeToCheck::StandardBIP32,
                AccountTypeToCheck::IdentityRegistration,
                AccountTypeToCheck::IdentityTopUp,
                AccountTypeToCheck::IdentityTopUpNotBound,
                AccountTypeToCheck::IdentityInvitation,
                AccountTypeToCheck::AssetLockAddressTopUp,
                AccountTypeToCheck::AssetLockShieldedAddressTopUp,
            ],
            TransactionType::AssetUnlock => {
                vec![AccountTypeToCheck::StandardBIP44, AccountTypeToCheck::StandardBIP32]
            }
            TransactionType::Coinbase => vec![
                // Check all account types for unknown special transactions
                AccountTypeToCheck::StandardBIP44,
                AccountTypeToCheck::StandardBIP32,
            ],
            TransactionType::Ignored => vec![],
        }
    }

    /// Check if a transaction appears to be a CoinJoin transaction.
    ///
    /// This heuristic only determines the stored [`TransactionType`] label; it never gates which
    /// accounts are consulted for ownership (that is membership-based across all keychains, like
    /// Dash Core). A small denomination spend that fails this heuristic is still discovered by the
    /// CoinJoin account because that account owns the relevant scriptPubKeys.
    fn is_coinjoin_transaction(tx: &Transaction) -> bool {
        // CoinJoin transactions typically have:
        // - Multiple inputs from different addresses
        // - Multiple outputs with same denominations
        // - Specific version flags

        // Simplified check - real implementation would be more sophisticated
        tx.input.len() >= 3 && tx.output.len() >= 3 && Self::has_denomination_outputs(tx)
    }

    /// Check if transaction has denomination outputs typical of CoinJoin
    fn has_denomination_outputs(tx: &Transaction) -> bool {
        // Standard CoinJoin denominations, each including the per-round fee
        // (Dash Core `coinjoin/common.h`): denom + denom/1000 + 1, with COIN = 100_000_000.
        const COINJOIN_DENOMINATIONS: [u64; 5] = [
            1_000_010_000, // 10 DASH + fee
            100_001_000,   // 1 DASH + fee
            10_000_100,    // 0.1 DASH + fee
            1_000_010,     // 0.01 DASH + fee
            100_001,       // 0.001 DASH + fee
        ];

        let mut denomination_count = 0;
        for output in &tx.output {
            if COINJOIN_DENOMINATIONS.contains(&output.value) {
                denomination_count += 1;
            }
        }

        // If most outputs are denominations, likely CoinJoin
        denomination_count >= tx.output.len() / 2
    }
}

/// Core account types that can be checked for transactions
///
/// Note: Platform Payment accounts (DIP-17) are NOT included here as they
/// operate on Dash Platform, not the Core chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountTypeToCheck {
    StandardBIP44,
    StandardBIP32,
    CoinJoin,
    IdentityRegistration,
    IdentityTopUp,
    IdentityTopUpNotBound,
    IdentityInvitation,
    AssetLockAddressTopUp,
    AssetLockShieldedAddressTopUp,
    ProviderVotingKeys,
    ProviderOwnerKeys,
    ProviderOperatorKeys,
    ProviderPlatformKeys,
    DashpayReceivingFunds,
    DashpayExternalAccount,
}

/// Error returned when trying to convert a Platform Payment account to AccountTypeToCheck
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformAccountConversionError;

impl core::fmt::Display for PlatformAccountConversionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PlatformPayment accounts cannot be converted to AccountTypeToCheck")
    }
}

impl TryFrom<ManagedAccountType> for AccountTypeToCheck {
    type Error = PlatformAccountConversionError;

    fn try_from(value: ManagedAccountType) -> Result<Self, Self::Error> {
        match value {
            ManagedAccountType::Standard {
                standard_account_type,
                ..
            } => match standard_account_type {
                crate::account::account_type::StandardAccountType::BIP44Account => {
                    Ok(AccountTypeToCheck::StandardBIP44)
                }
                crate::account::account_type::StandardAccountType::BIP32Account => {
                    Ok(AccountTypeToCheck::StandardBIP32)
                }
            },
            ManagedAccountType::CoinJoin {
                ..
            } => Ok(AccountTypeToCheck::CoinJoin),
            ManagedAccountType::IdentityRegistration {
                ..
            } => Ok(AccountTypeToCheck::IdentityRegistration),
            ManagedAccountType::IdentityTopUp {
                ..
            } => Ok(AccountTypeToCheck::IdentityTopUp),
            ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                ..
            } => Ok(AccountTypeToCheck::IdentityTopUpNotBound),
            ManagedAccountType::IdentityInvitation {
                ..
            } => Ok(AccountTypeToCheck::IdentityInvitation),
            ManagedAccountType::AssetLockAddressTopUp {
                ..
            } => Ok(AccountTypeToCheck::AssetLockAddressTopUp),
            ManagedAccountType::AssetLockShieldedAddressTopUp {
                ..
            } => Ok(AccountTypeToCheck::AssetLockShieldedAddressTopUp),
            ManagedAccountType::ProviderVotingKeys {
                ..
            } => Ok(AccountTypeToCheck::ProviderVotingKeys),
            ManagedAccountType::ProviderOwnerKeys {
                ..
            } => Ok(AccountTypeToCheck::ProviderOwnerKeys),
            ManagedAccountType::ProviderOperatorKeys {
                ..
            } => Ok(AccountTypeToCheck::ProviderOperatorKeys),
            ManagedAccountType::ProviderPlatformKeys {
                ..
            } => Ok(AccountTypeToCheck::ProviderPlatformKeys),
            ManagedAccountType::DashpayReceivingFunds {
                ..
            } => Ok(AccountTypeToCheck::DashpayReceivingFunds),
            ManagedAccountType::DashpayExternalAccount {
                ..
            } => Ok(AccountTypeToCheck::DashpayExternalAccount),
            ManagedAccountType::PlatformPayment {
                ..
            } => {
                // Platform Payment accounts (DIP-17) operate on Dash Platform, not the Core chain.
                Err(PlatformAccountConversionError)
            }
        }
    }
}

impl TryFrom<&ManagedAccountType> for AccountTypeToCheck {
    type Error = PlatformAccountConversionError;

    fn try_from(value: &ManagedAccountType) -> Result<Self, Self::Error> {
        match value {
            ManagedAccountType::Standard {
                standard_account_type,
                ..
            } => match standard_account_type {
                crate::account::account_type::StandardAccountType::BIP44Account => {
                    Ok(AccountTypeToCheck::StandardBIP44)
                }
                crate::account::account_type::StandardAccountType::BIP32Account => {
                    Ok(AccountTypeToCheck::StandardBIP32)
                }
            },
            ManagedAccountType::CoinJoin {
                ..
            } => Ok(AccountTypeToCheck::CoinJoin),
            ManagedAccountType::IdentityRegistration {
                ..
            } => Ok(AccountTypeToCheck::IdentityRegistration),
            ManagedAccountType::IdentityTopUp {
                ..
            } => Ok(AccountTypeToCheck::IdentityTopUp),
            ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                ..
            } => Ok(AccountTypeToCheck::IdentityTopUpNotBound),
            ManagedAccountType::IdentityInvitation {
                ..
            } => Ok(AccountTypeToCheck::IdentityInvitation),
            ManagedAccountType::AssetLockAddressTopUp {
                ..
            } => Ok(AccountTypeToCheck::AssetLockAddressTopUp),
            ManagedAccountType::AssetLockShieldedAddressTopUp {
                ..
            } => Ok(AccountTypeToCheck::AssetLockShieldedAddressTopUp),
            ManagedAccountType::ProviderVotingKeys {
                ..
            } => Ok(AccountTypeToCheck::ProviderVotingKeys),
            ManagedAccountType::ProviderOwnerKeys {
                ..
            } => Ok(AccountTypeToCheck::ProviderOwnerKeys),
            ManagedAccountType::ProviderOperatorKeys {
                ..
            } => Ok(AccountTypeToCheck::ProviderOperatorKeys),
            ManagedAccountType::ProviderPlatformKeys {
                ..
            } => Ok(AccountTypeToCheck::ProviderPlatformKeys),
            ManagedAccountType::DashpayReceivingFunds {
                ..
            } => Ok(AccountTypeToCheck::DashpayReceivingFunds),
            ManagedAccountType::DashpayExternalAccount {
                ..
            } => Ok(AccountTypeToCheck::DashpayExternalAccount),
            ManagedAccountType::PlatformPayment {
                ..
            } => {
                // Platform Payment accounts (DIP-17) operate on Dash Platform, not the Core chain.
                Err(PlatformAccountConversionError)
            }
        }
    }
}
