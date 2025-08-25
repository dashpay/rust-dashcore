//! Transaction routing based on transaction type
//!
//! This module determines which account types should be checked
//! for different transaction types.

use crate::managed_account::managed_account_type::ManagedAccountType;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::Transaction;

/// Classification of transaction types for routing
#[derive(Debug, Clone, PartialEq, Eq)]
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
        if let Some(ref payload) = tx.special_transaction_payload {
            match payload {
                TransactionPayload::ProviderRegistrationPayloadType(_) => {
                    TransactionType::ProviderRegistration
                }
                TransactionPayload::ProviderUpdateRegistrarPayloadType(_) => {
                    TransactionType::ProviderUpdateRegistrar
                }
                TransactionPayload::ProviderUpdateServicePayloadType(_) => {
                    TransactionType::ProviderUpdateService
                }
                TransactionPayload::ProviderUpdateRevocationPayloadType(_) => {
                    TransactionType::ProviderUpdateRevocation
                }
                TransactionPayload::AssetLockPayloadType(_) => TransactionType::AssetLock,
                TransactionPayload::AssetUnlockPayloadType(_) => TransactionType::AssetUnlock,
                TransactionPayload::CoinbasePayloadType(_) => TransactionType::Coinbase,
                TransactionPayload::QuorumCommitmentPayloadType(_) => TransactionType::Ignored,
                TransactionPayload::MnhfSignalPayloadType(_) => TransactionType::Ignored,
            }
        } else if Self::is_coinjoin_transaction(tx) {
            TransactionType::CoinJoin
        } else {
            TransactionType::Standard
        }
    }

    /// Determine which account types should be checked for a given transaction type
    pub fn get_relevant_account_types(tx_type: &TransactionType) -> Vec<AccountTypeToCheck> {
        match tx_type {
            TransactionType::Standard => {
                vec![AccountTypeToCheck::StandardBIP44, AccountTypeToCheck::StandardBIP32]
            }
            TransactionType::CoinJoin => vec![AccountTypeToCheck::CoinJoin],
            TransactionType::ProviderRegistration => vec![
                AccountTypeToCheck::ProviderOwnerKeys,
                AccountTypeToCheck::ProviderOperatorKeys,
                AccountTypeToCheck::ProviderVotingKeys,
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

    /// Check if a transaction appears to be a CoinJoin transaction
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
        // Check for standard CoinJoin denominations
        const COINJOIN_DENOMINATIONS: [u64; 5] = [
            100_000_000, // 1 DASH
            10_000_000,  // 0.1 DASH
            1_000_000,   // 0.01 DASH
            100_000,     // 0.001 DASH
            10_000,      // 0.0001 DASH
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

/// Account types that can be checked for transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountTypeToCheck {
    StandardBIP44,
    StandardBIP32,
    CoinJoin,
    IdentityRegistration,
    IdentityTopUp,
    IdentityTopUpNotBound,
    IdentityInvitation,
    ProviderVotingKeys,
    ProviderOwnerKeys,
    ProviderOperatorKeys,
    ProviderPlatformKeys,
}

impl From<ManagedAccountType> for AccountTypeToCheck {
    fn from(value: ManagedAccountType) -> Self {
        match value {
            ManagedAccountType::Standard {
                standard_account_type,
                ..
            } => match standard_account_type {
                crate::account::account_type::StandardAccountType::BIP44Account => {
                    AccountTypeToCheck::StandardBIP44
                }
                crate::account::account_type::StandardAccountType::BIP32Account => {
                    AccountTypeToCheck::StandardBIP32
                }
            },
            ManagedAccountType::CoinJoin {
                ..
            } => AccountTypeToCheck::CoinJoin,
            ManagedAccountType::IdentityRegistration {
                ..
            } => AccountTypeToCheck::IdentityRegistration,
            ManagedAccountType::IdentityTopUp {
                ..
            } => AccountTypeToCheck::IdentityTopUp,
            ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                ..
            } => AccountTypeToCheck::IdentityTopUpNotBound,
            ManagedAccountType::IdentityInvitation {
                ..
            } => AccountTypeToCheck::IdentityInvitation,
            ManagedAccountType::ProviderVotingKeys {
                ..
            } => AccountTypeToCheck::ProviderVotingKeys,
            ManagedAccountType::ProviderOwnerKeys {
                ..
            } => AccountTypeToCheck::ProviderOwnerKeys,
            ManagedAccountType::ProviderOperatorKeys {
                ..
            } => AccountTypeToCheck::ProviderOperatorKeys,
            ManagedAccountType::ProviderPlatformKeys {
                ..
            } => AccountTypeToCheck::ProviderPlatformKeys,
        }
    }
}

impl From<&ManagedAccountType> for AccountTypeToCheck {
    fn from(value: &ManagedAccountType) -> Self {
        match value {
            ManagedAccountType::Standard {
                standard_account_type,
                ..
            } => match standard_account_type {
                crate::account::account_type::StandardAccountType::BIP44Account => {
                    AccountTypeToCheck::StandardBIP44
                }
                crate::account::account_type::StandardAccountType::BIP32Account => {
                    AccountTypeToCheck::StandardBIP32
                }
            },
            ManagedAccountType::CoinJoin {
                ..
            } => AccountTypeToCheck::CoinJoin,
            ManagedAccountType::IdentityRegistration {
                ..
            } => AccountTypeToCheck::IdentityRegistration,
            ManagedAccountType::IdentityTopUp {
                ..
            } => AccountTypeToCheck::IdentityTopUp,
            ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                ..
            } => AccountTypeToCheck::IdentityTopUpNotBound,
            ManagedAccountType::IdentityInvitation {
                ..
            } => AccountTypeToCheck::IdentityInvitation,
            ManagedAccountType::ProviderVotingKeys {
                ..
            } => AccountTypeToCheck::ProviderVotingKeys,
            ManagedAccountType::ProviderOwnerKeys {
                ..
            } => AccountTypeToCheck::ProviderOwnerKeys,
            ManagedAccountType::ProviderOperatorKeys {
                ..
            } => AccountTypeToCheck::ProviderOperatorKeys,
            ManagedAccountType::ProviderPlatformKeys {
                ..
            } => AccountTypeToCheck::ProviderPlatformKeys,
        }
    }
}
