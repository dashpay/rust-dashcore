//! Transaction routing based on transaction type
//!
//! This module determines which account types should be checked
//! for different transaction types.

mod tests;

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

/// Specific CoinJoin transaction types
#[derive(Debug, Clone, PartialEq, Eq)]
enum CoinJoinTransactionType {
    /// Transaction is not a CoinJoin transaction
    None,
    /// CoinJoin mixing transaction (equal inputs/outputs, zero net value)
    Mixing,
    /// Fee payment for mixing
    MixingFee,
    /// Transaction that creates collateral inputs
    MakeCollateralInputs,
    /// Transaction that creates denomination outputs
    CreateDenomination,
    /// Transaction that combines dust outputs
    CombineDust,
    /// CoinJoin send transaction (not considered a mixing transaction)
    Send,
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
                vec![
                    AccountTypeToCheck::StandardBIP44,
                    AccountTypeToCheck::StandardBIP32,
                    AccountTypeToCheck::DashpayReceivingFunds,
                    AccountTypeToCheck::DashpayExternalAccount,
                ]
            }
            TransactionType::CoinJoin => vec![
                AccountTypeToCheck::CoinJoin,
                AccountTypeToCheck::StandardBIP44,
                AccountTypeToCheck::StandardBIP32
            ],
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
    pub fn is_coinjoin_transaction(tx: &Transaction) -> bool {
        let coinjoin_type = Self::classify_coinjoin_transaction(tx);
        matches!(
            coinjoin_type,
            CoinJoinTransactionType::Mixing
                | CoinJoinTransactionType::MixingFee
                | CoinJoinTransactionType::MakeCollateralInputs
                | CoinJoinTransactionType::CreateDenomination
                | CoinJoinTransactionType::CombineDust
        )
    }

    /// Classify the specific type of CoinJoin transaction
    fn classify_coinjoin_transaction(tx: &Transaction) -> CoinJoinTransactionType {
        // Check for mixing transaction: equal inputs/outputs with zero net value
        if tx.input.len() == tx.output.len() && Self::has_zero_net_value(tx) {
            return CoinJoinTransactionType::Mixing;
        }

        // Check for mixing fee transaction
        if Self::is_mixing_fee(tx) {
            return CoinJoinTransactionType::MixingFee;
        }

        // Check for collateral creation
        let mut make_collateral = false;
        if tx.output.len() == 2 {
            let amount0 = tx.output[0].value;
            let amount1 = tx.output[1].value;
            
            // Case 1: One output is collateral amount, other is larger (change)
            make_collateral = (Self::is_collateral_amount(amount0) && amount1 > amount0)
                || (Self::is_collateral_amount(amount1) && amount0 > amount1)
                // Case 2: Both outputs equal and are collateral amounts
                || (amount0 == amount1 && Self::is_collateral_amount(amount0));
        } else if tx.output.len() == 1 {
            let first_output = &tx.output[0];
            
            if Self::is_collateral_amount(first_output.value) {
                // Case 3: Single collateral output
                make_collateral = true;
            } else if tx.input.len() > 1 {
                // Check for dust combining transaction
                // Note: We can't check the fee or spending transaction without additional context
                // This is a simplified check
                if Self::is_small_amount(first_output.value) {
                    return CoinJoinTransactionType::CombineDust;
                }
            }
        }

        if make_collateral {
            return CoinJoinTransactionType::MakeCollateralInputs;
        } else if Self::is_denomination(tx) {
            return CoinJoinTransactionType::CreateDenomination;
        }

        // Check for CoinJoin send transaction
        if Self::is_coinjoin_send(tx) {
            return CoinJoinTransactionType::Send;
        }

        CoinJoinTransactionType::None
    }

    /// Check if transaction has zero net value (mixing transaction characteristic)
    fn has_zero_net_value(tx: &Transaction) -> bool {
        // This is a simplified check - in reality we'd need access to input values
        // which requires the UTXO set or transaction bag
        tx.input.len() >= 3 && tx.output.len() >= 3 && Self::has_denomination_outputs(tx)
    }

    /// Check if this is a mixing fee transaction
    fn is_mixing_fee(_tx: &Transaction) -> bool {
        // Simplified implementation - would need more context to determine mixing fees
        false
    }

    /// Check if this is a CoinJoin send transaction
    fn is_coinjoin_send(_tx: &Transaction) -> bool {
        // Simplified implementation - would need more sophisticated analysis
        false
    }

    /// Check if transaction creates denominations
    fn is_denomination(tx: &Transaction) -> bool {
        Self::has_denomination_outputs(tx)
    }

    /// Check if transaction has denomination outputs typical of CoinJoin
    fn has_denomination_outputs(tx: &Transaction) -> bool {
        // Check for standard CoinJoin denominations
        const COINJOIN_DENOMINATIONS: [u64; 5] = [
            1_000_010_000, // 10.00010000 DASH
              100_001_000, //  1.00001000 DASH
               10_000_100, //  0.10000100 DASH
                1_000_010, //  0.01000010 DASH
                  100_001, //  0.00100001 DASH
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

    /// Check if an amount is a valid collateral amount
    fn is_collateral_amount(amount: u64) -> bool {
        // Collateral amounts are typically small, non-denominated amounts
        amount >= Self::get_collateral_amount() && amount <= Self::get_max_collateral_amount()
    }

    /// Get the minimum collateral amount
    fn get_collateral_amount() -> u64 {
        1000 // 0.00001 DASH in satoshis
    }

    /// Get the maximum collateral amount
    fn get_max_collateral_amount() -> u64 {
        100000 // 0.001 DASH in satoshis
    }

    /// Check if an amount is considered small (dust-like)
    fn is_small_amount(amount: u64) -> bool {
        amount < 10000 // Less than 0.0001 DASH
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
    DashpayReceivingFunds,
    DashpayExternalAccount,
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
            ManagedAccountType::DashpayReceivingFunds {
                ..
            } => AccountTypeToCheck::DashpayReceivingFunds,
            ManagedAccountType::DashpayExternalAccount {
                ..
            } => AccountTypeToCheck::DashpayExternalAccount,
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
            ManagedAccountType::DashpayReceivingFunds {
                ..
            } => AccountTypeToCheck::DashpayReceivingFunds,
            ManagedAccountType::DashpayExternalAccount {
                ..
            } => AccountTypeToCheck::DashpayExternalAccount,
        }
    }
}
