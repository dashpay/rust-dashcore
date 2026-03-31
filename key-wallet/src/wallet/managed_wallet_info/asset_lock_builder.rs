//! Asset lock transaction builder.
//!
//! Builds a Core special transaction (type 8) with `AssetLockPayload` that
//! locks Dash for Platform credits.

use dashcore::{Address, Transaction, TxOut};
use std::collections::HashMap;
use std::fmt;

use crate::managed_account::ManagedCoreAccount;
use crate::wallet::managed_wallet_info::coin_selection::SelectionStrategy;
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::wallet::managed_wallet_info::transaction_builder::{BuilderError, TransactionBuilder};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::wallet::Wallet;
use crate::{DerivationPath, Utxo};

/// Which funding account to derive the one-time key from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetLockFundingType {
    /// Identity registration: m/9'/coinType'/5'/0'/index'
    IdentityRegistration,
    /// Identity top-up (bound to a specific identity): m/9'/coinType'/5'/1'/reg_index'/index'
    IdentityTopUp,
    /// Identity top-up (not bound to identity): m/9'/coinType'/5'/1'/index'
    IdentityTopUpNotBound,
    /// Identity invitation: m/9'/coinType'/5'/3'/index'
    IdentityInvitation,
    /// Asset lock address top-up: m/9'/coinType'/5'/4'/index'
    AssetLockAddressTopUp,
    /// Asset lock shielded address top-up: m/9'/coinType'/5'/5'/index'
    AssetLockShieldedAddressTopUp,
}

/// Per-credit-output funding specification.
pub struct CreditOutputFunding {
    /// The credit output (script + amount).
    pub output: TxOut,
    /// Which funding account type to derive the one-time key from.
    pub funding_type: AssetLockFundingType,
    /// Identity index (only used for `IdentityTopUp`, ignored otherwise).
    pub identity_index: u32,
}

/// Result of building an asset lock transaction.
pub struct AssetLockResult {
    /// The signed transaction.
    pub transaction: Transaction,
    /// The fee paid in duffs.
    pub fee: u64,
    /// One-time private keys, one per credit output (in order).
    /// `keys[i]` corresponds to the credit output at index `i` in the
    /// payload's `credit_outputs` vector (not affected by BIP-69 sorting
    /// of the transaction's output list).
    pub keys: Vec<[u8; 32]>,
}

/// Errors specific to asset lock transaction building.
#[derive(Debug, Clone)]
pub enum AssetLockError {
    /// No credit outputs provided.
    NoCreditOutputs,
    /// The funding account was not found in the wallet.
    FundingAccountNotFound(String),
    /// No unused address index available in the funding key account.
    NoUnusedKeyIndex,
    /// No address available in the funding account's address pool.
    NoAddressAvailable,
    /// The funding account has no address pool.
    NoAddressPool,
    /// Key derivation failed.
    KeyDerivation(String),
    /// The wallet does not have a private key (watch-only).
    WatchOnlyWallet,
    /// The specified BIP44 account was not found.
    AccountNotFound(u32),
    /// No change address available.
    NoChangeAddress,
    /// Underlying transaction builder error.
    Builder(BuilderError),
}

impl fmt::Display for AssetLockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCreditOutputs => write!(f, "At least one credit output required"),
            Self::FundingAccountNotFound(msg) => write!(f, "Funding account not found: {msg}"),
            Self::NoUnusedKeyIndex => {
                write!(f, "No unused address index available in funding key account")
            }
            Self::NoAddressAvailable => write!(f, "No address available in funding account"),
            Self::NoAddressPool => write!(f, "Funding account has no address pool"),
            Self::KeyDerivation(msg) => write!(f, "Key derivation failed: {msg}"),
            Self::WatchOnlyWallet => write!(f, "Cannot sign with watch-only wallet"),
            Self::AccountNotFound(idx) => write!(f, "BIP44 account {} not found", idx),
            Self::NoChangeAddress => write!(f, "No change address available"),
            Self::Builder(e) => write!(f, "Transaction builder error: {e}"),
        }
    }
}

impl From<BuilderError> for AssetLockError {
    fn from(e: BuilderError) -> Self {
        Self::Builder(e)
    }
}

/// Resolve a funding key account from the managed account collection.
fn resolve_funding_account(
    accounts: &mut crate::account::ManagedAccountCollection,
    funding_type: AssetLockFundingType,
    identity_index: u32,
) -> Result<&mut ManagedCoreAccount, AssetLockError> {
    match funding_type {
        AssetLockFundingType::IdentityRegistration => accounts
            .identity_registration
            .as_mut()
            .ok_or_else(|| AssetLockError::FundingAccountNotFound("identity registration".into())),
        AssetLockFundingType::IdentityTopUp => {
            accounts.identity_topup.get_mut(&identity_index).ok_or_else(|| {
                AssetLockError::FundingAccountNotFound(format!(
                    "identity top-up index {}",
                    identity_index
                ))
            })
        }
        AssetLockFundingType::IdentityTopUpNotBound => {
            accounts.identity_topup_not_bound.as_mut().ok_or_else(|| {
                AssetLockError::FundingAccountNotFound("identity top-up (unbound)".into())
            })
        }
        AssetLockFundingType::IdentityInvitation => accounts
            .identity_invitation
            .as_mut()
            .ok_or_else(|| AssetLockError::FundingAccountNotFound("identity invitation".into())),
        AssetLockFundingType::AssetLockAddressTopUp => {
            accounts.asset_lock_address_topup.as_mut().ok_or_else(|| {
                AssetLockError::FundingAccountNotFound("asset lock address top-up".into())
            })
        }
        AssetLockFundingType::AssetLockShieldedAddressTopUp => {
            accounts.asset_lock_shielded_address_topup.as_mut().ok_or_else(|| {
                AssetLockError::FundingAccountNotFound("asset lock shielded address top-up".into())
            })
        }
    }
}

impl ManagedWalletInfo {
    /// Build and sign an asset lock transaction.
    ///
    /// Creates a special transaction (type 8) with `AssetLockPayload` that locks
    /// Dash for Platform credits. Derives one unique private key per credit output.
    ///
    /// The transaction is built first, and keys are only derived after a successful
    /// build — so no addresses are consumed if the build fails.
    pub fn build_asset_lock(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        credit_output_fundings: Vec<CreditOutputFunding>,
        fee_per_kb: u64,
    ) -> Result<AssetLockResult, AssetLockError> {
        use crate::wallet::WalletType;

        if credit_output_fundings.is_empty() {
            return Err(AssetLockError::NoCreditOutputs);
        }

        let network = self.network;

        // Get root extended private key
        let root_xpriv = match &wallet.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            }
            | WalletType::Seed {
                root_extended_private_key,
                ..
            } => root_extended_private_key,
            WalletType::ExtendedPrivKey(root_extended_private_key) => root_extended_private_key,
            _ => return Err(AssetLockError::WatchOnlyWallet),
        };

        // Get the BIP44 funding account for UTXOs and signing
        let funding_account = self
            .accounts
            .standard_bip44_accounts
            .get(&account_index)
            .ok_or(AssetLockError::AccountNotFound(account_index))?;

        let utxos: Vec<Utxo> = funding_account.utxos.values().cloned().collect();
        let mut address_to_path: HashMap<Address, DerivationPath> = HashMap::new();
        for pool in funding_account.account_type.address_pools() {
            for addr_info in pool.addresses.values() {
                address_to_path.insert(addr_info.address.clone(), addr_info.path.clone());
            }
        }

        // Get change address from the funding account
        let xpub = wallet.get_bip44_account(account_index).map(|a| a.account_xpub);
        let change_address = self
            .accounts
            .standard_bip44_accounts
            .get_mut(&account_index)
            .and_then(|account| account.next_change_address(xpub.as_ref(), true).ok())
            .ok_or(AssetLockError::NoChangeAddress)?;

        let synced_height = self.synced_height();

        // Separate credit outputs from funding specs
        let credit_outputs: Vec<TxOut> =
            credit_output_fundings.iter().map(|f| f.output.clone()).collect();

        // Build the transaction FIRST — before deriving keys.
        // This ensures no addresses are consumed if the build fails.
        let mut tx_builder = TransactionBuilder::new()
            .set_change_address(change_address)
            .set_fee_rate(FeeRate::new(fee_per_kb));

        for credit_out in &credit_outputs {
            tx_builder = tx_builder.add_raw_output(credit_out.clone());
        }

        let tx_builder_with_inputs = tx_builder.select_inputs(
            &utxos,
            SelectionStrategy::BranchAndBound,
            synced_height,
            |utxo| {
                let path = address_to_path.get(&utxo.address)?;
                let root_ext_priv = root_xpriv.to_extended_priv_key(network);
                let secp = secp256k1::Secp256k1::new();
                let derived_xpriv = root_ext_priv.derive_priv(&secp, path).ok()?;
                Some(derived_xpriv.private_key)
            },
        )?;

        let outputs_count_before = tx_builder_with_inputs.outputs().len();
        let fee = tx_builder_with_inputs.calculate_fee();
        let fee_with_extra = tx_builder_with_inputs.calculate_fee_with_extra_output();

        let transaction = tx_builder_with_inputs.build_asset_lock(credit_outputs)?;

        let actual_fee = if transaction.output.len() > outputs_count_before {
            fee_with_extra
        } else {
            fee
        };

        // Transaction built successfully — now derive keys.
        let mut keys = Vec::with_capacity(credit_output_fundings.len());
        for funding in &credit_output_fundings {
            let funding_key_account = resolve_funding_account(
                &mut self.accounts,
                funding.funding_type,
                funding.identity_index,
            )?;
            let key = funding_key_account
                .next_private_key(root_xpriv, network)
                .map_err(|e| AssetLockError::KeyDerivation(e.to_string()))?;
            keys.push(key);
        }

        Ok(AssetLockResult {
            transaction,
            fee: actual_fee,
            keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::Network;
    use dashcore::ScriptBuf;

    fn test_credit_outputs(amounts: &[u64]) -> Vec<CreditOutputFunding> {
        amounts
            .iter()
            .map(|&amount| CreditOutputFunding {
                output: TxOut {
                    value: amount,
                    script_pubkey: ScriptBuf::from(vec![
                        0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88,
                        0xac,
                    ]),
                },
                funding_type: AssetLockFundingType::AssetLockAddressTopUp,
                identity_index: 0,
            })
            .collect()
    }

    fn test_wallet_and_info() -> (Wallet, ManagedWalletInfo) {
        let wallet =
            Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default).unwrap();
        let info = ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());
        (wallet, info)
    }

    // -- Error type tests --

    #[test]
    fn test_error_display() {
        assert_eq!(
            AssetLockError::NoCreditOutputs.to_string(),
            "At least one credit output required"
        );
        assert_eq!(
            AssetLockError::WatchOnlyWallet.to_string(),
            "Cannot sign with watch-only wallet"
        );
        assert_eq!(AssetLockError::AccountNotFound(5).to_string(), "BIP44 account 5 not found");
        assert_eq!(AssetLockError::NoChangeAddress.to_string(), "No change address available");
    }

    #[test]
    fn test_builder_error_conversion() {
        let builder_err = BuilderError::NoInputs;
        let asset_err: AssetLockError = builder_err.into();
        assert!(matches!(asset_err, AssetLockError::Builder(BuilderError::NoInputs)));
    }

    // -- Builder logic tests --

    #[test]
    fn test_empty_credit_outputs_rejected() {
        let (wallet, mut info) = test_wallet_and_info();
        let result = info.build_asset_lock(&wallet, 0, vec![], 1000);
        assert!(matches!(result, Err(AssetLockError::NoCreditOutputs)));
    }

    #[test]
    fn test_invalid_account_index() {
        let (wallet, mut info) = test_wallet_and_info();
        let result = info.build_asset_lock(&wallet, 99, test_credit_outputs(&[100_000]), 1000);
        assert!(matches!(result, Err(AssetLockError::AccountNotFound(99))));
    }

    #[test]
    fn test_insufficient_funds() {
        // Wallet has no UTXOs, so coin selection should fail
        let (wallet, mut info) = test_wallet_and_info();
        let result = info.build_asset_lock(&wallet, 0, test_credit_outputs(&[500_000]), 1000);
        assert!(
            matches!(result, Err(AssetLockError::Builder(_))),
            "Expected Builder error for insufficient funds, got: {:?}",
            result.err()
        );
    }
}
