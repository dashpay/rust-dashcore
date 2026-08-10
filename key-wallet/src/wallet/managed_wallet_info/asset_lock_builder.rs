//! Asset lock transaction builder.
//!
//! Builds a Core special transaction (type 8) with `AssetLockPayload` that
//! locks Dash for Platform credits.

use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::{OutPoint, Transaction, TxOut};
use secp256k1::PublicKey;
use std::fmt;

use crate::account::AccountType;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::reservation::ReservationSet;
use crate::managed_account::{ManagedCoreKeysAccount, ReservationToken};
use crate::signer::Signer;
use crate::wallet::managed_wallet_info::coin_selection::SelectionStrategy;
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::wallet::managed_wallet_info::transaction_builder::{BuilderError, TransactionBuilder};
use crate::wallet::managed_wallet_info::transaction_building::{
    AccountTypePreference, PooledFunding,
};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::wallet::Wallet;
use crate::DerivationPath;
use std::collections::HashSet;

/// Which funding account to derive the one-time key from.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

/// A single wallet account that supplies the funding UTXOs (and signs the
/// inputs) of a whole-balance **drain** asset lock.
///
/// The asset-lock builders take a *list* of [`AccountTypePreference`] sources
/// and pool them; this is the narrower vocabulary of the drain flows, which
/// name exactly one account by construction (a drain has no change output, so
/// "which account supplies change" — the thing a pooled list decides — does not
/// arise). `Bip44` is the standard spendable balance; `CoinJoin` lets mixed
/// coins fund an asset lock directly, without first sweeping them through a
/// transparent BIP44 address (which would link the mixed UTXOs to a reusable
/// transparent address for an extra hop).
///
/// Convert with [`AccountTypePreference::from`] to hand one to a builder.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetLockFundingAccount {
    /// Standard BIP44 account (`m/44'/coinType'/index'`).
    Bip44 {
        /// BIP44 account index.
        account_index: u32,
    },
    /// CoinJoin account (`m/9'/coinType'/4'/index'`).
    CoinJoin {
        /// CoinJoin account index.
        account_index: u32,
    },
}

impl AssetLockFundingAccount {
    /// The account index within its family.
    pub fn account_index(&self) -> u32 {
        match self {
            Self::Bip44 {
                account_index,
            }
            | Self::CoinJoin {
                account_index,
            } => *account_index,
        }
    }
}

impl From<AssetLockFundingAccount> for AccountTypePreference {
    fn from(account: AssetLockFundingAccount) -> Self {
        match account {
            AssetLockFundingAccount::Bip44 {
                ..
            } => Self::BIP44,
            AssetLockFundingAccount::CoinJoin {
                ..
            } => Self::CoinJoin,
        }
    }
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

/// One-time credit-output keys carried back from an asset-lock build.
///
/// For each credit output (in payload order, unaffected by BIP-69 sorting of
/// the transaction's output list), either the raw private key — when the host
/// holds signing material — or the public key + derivation path, when signing
/// was delegated to an external [`Signer`].
pub enum AssetLockCreditKeys {
    /// Raw private keys, one per credit output. Produced by
    /// [`ManagedWalletInfo::build_asset_lock`] on soft wallets.
    Private(Vec<[u8; 32]>),
    /// Public key + derivation path per credit output. Produced by
    /// [`ManagedWalletInfo::build_asset_lock_with_signer`] when the
    /// private keys never leave the signing device.
    Public(Vec<(PublicKey, DerivationPath)>),
}

/// Result of building an asset lock transaction.
pub struct AssetLockResult {
    /// The signed transaction.
    pub transaction: Transaction,
    /// The fee paid in duffs.
    pub fee: u64,
    /// Per-credit-output key material. See [`AssetLockCreditKeys`] for
    /// ordering and variant semantics.
    pub keys: AssetLockCreditKeys,
    /// Owner token for the reservation this build took on the funding inputs,
    /// or `None` if no funding account carried a reservation set.
    ///
    /// The caller broadcasts `transaction` and, on a rejected broadcast, must
    /// release the reserved inputs with
    /// [`ManagedCoreFundsAccount::release_reservation_if_owner`] passing this
    /// token — never the unconditional `release_reservation` — on **every**
    /// account in [`Self::funding_accounts`]. See
    /// `ReservationSet::release_if_owner` for why owner-guarded release is
    /// required here (`dashpay/platform#4185`).
    ///
    /// [`ManagedCoreFundsAccount::release_reservation_if_owner`]: crate::managed_account::ManagedCoreFundsAccount::release_reservation_if_owner
    pub reservation_token: Option<ReservationToken>,
    /// The accounts that actually contributed inputs to `transaction`, and so
    /// the accounts holding a share of this build's reservation — a pooled
    /// build reserves in each contributing account's own set, all under the one
    /// [`Self::reservation_token`].
    ///
    /// This is the *contributor* list, not everything the source list offered:
    /// coin selection routinely takes nothing from most offered accounts, and a
    /// list naming every DashPay contact would make the caller's release and
    /// bookkeeping scale with the address book while claiming contributions
    /// that never happened.
    pub funding_accounts: Vec<AccountType>,
}

/// Errors specific to asset lock transaction building.
#[derive(Debug, Clone)]
pub enum AssetLockError {
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
    /// The external signer reported an error.
    Signer(String),
    /// Signing produced an unexpected state (e.g. input without a known path).
    SigningFailed(String),
    /// The wallet does not have a private key (watch-only).
    WatchOnlyWallet,
    /// No change address available.
    NoChangeAddress,
    /// Underlying transaction builder error.
    Builder(BuilderError),
}

impl fmt::Display for AssetLockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FundingAccountNotFound(msg) => write!(f, "Funding account not found: {msg}"),
            Self::NoUnusedKeyIndex => {
                write!(f, "No unused address index available in funding key account")
            }
            Self::NoAddressAvailable => write!(f, "No address available in funding account"),
            Self::NoAddressPool => write!(f, "Funding account has no address pool"),
            Self::KeyDerivation(msg) => write!(f, "Key derivation failed: {msg}"),
            Self::Signer(msg) => write!(f, "Signer error: {msg}"),
            Self::SigningFailed(msg) => write!(f, "Signing failed: {msg}"),
            Self::WatchOnlyWallet => write!(f, "Cannot sign with watch-only wallet"),
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
) -> Result<&mut ManagedCoreKeysAccount, AssetLockError> {
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

/// Shared guard for both asset-lock builders, run before any wallet state is
/// touched.
///
/// * A drain rewrites exactly one credit output, so it requires exactly one.
/// * CoinJoin funding is drain-only and must be the *sole* source. CoinJoin
///   accounts have no change-address pool semantics for asset locks (change
///   would need re-denomination), and pooling mixed coins with transparent ones
///   in a single transaction links them and undoes the mixing — the same
///   reasoning that keeps CoinJoin out of [`AccountTypePreference::DEFAULT`].
fn validate_funding_sources(
    sources: &[AccountTypePreference],
    credit_output_count: usize,
    drain: bool,
) -> Result<(), AssetLockError> {
    if drain && credit_output_count != 1 {
        return Err(AssetLockError::Builder(BuilderError::InvalidData(
            "drain asset lock requires exactly one credit output".into(),
        )));
    }
    let has_coinjoin = sources.contains(&AccountTypePreference::CoinJoin);
    if has_coinjoin && !drain {
        return Err(AssetLockError::Builder(BuilderError::InvalidData(
            "CoinJoin-funded asset locks support drain mode only".into(),
        )));
    }
    if has_coinjoin && sources.len() > 1 {
        return Err(AssetLockError::Builder(BuilderError::InvalidData(
            "CoinJoin funding cannot be pooled with other sources: spending mixed outputs \
             alongside transparent ones in one transaction links them and undoes the mixing"
                .into(),
        )));
    }
    Ok(())
}

/// The accounts among `offered` that contributed an input to `transaction`.
///
/// Only these hold a share of the build's reservation, so this is what the
/// caller must reconcile on a rejected broadcast. An outpoint is attributed to
/// an account when that account still holds it as a UTXO — a build reserves its
/// inputs but does not remove them, so this is exact right after the build.
fn contributing_accounts(
    accounts: &crate::account::ManagedAccountCollection,
    offered: &[AccountType],
    transaction: &Transaction,
) -> Vec<AccountType> {
    let spent: HashSet<OutPoint> =
        transaction.input.iter().map(|input| input.previous_output).collect();
    offered
        .iter()
        .copied()
        .filter(|account_type| {
            accounts.funds_account(account_type).is_some_and(|account| {
                account.utxos.keys().any(|outpoint| spent.contains(outpoint))
            })
        })
        .collect()
}

impl ManagedWalletInfo {
    /// Build and sign an asset lock transaction.
    ///
    /// Creates a special transaction (type 8) with `AssetLockPayload` that locks
    /// Dash for Platform credits. Derives one unique private key per credit output.
    ///
    /// The transaction is built first, and keys are only derived after a successful
    /// build — so no addresses are consumed if the build fails.
    ///
    /// `funding_sources` picks which account families supply (and sign) the
    /// funding UTXOs; coin selection draws from the union of their UTXOs and
    /// the first source supplies the change address. A single source is an
    /// explicit request for that one account and errors if it is absent; a
    /// pooled list skips the sources this wallet has nothing for. `source_index`
    /// addresses the standard families (BIP44/BIP32/CoinJoin); DashPay set
    /// selectors span their own indices. See
    /// [`ManagedWalletInfo::build_and_sign_transaction`] for the shared
    /// source-list semantics.
    ///
    /// `drain` locks the sourced accounts' whole spendable balance: every final
    /// UTXO is consumed and the single credit output's value is rewritten to
    /// `Σ inputs − fee` (the caller's credit-output value is ignored; exactly
    /// one credit output is required). CoinJoin funding is drain-only and must
    /// be the sole source: pooling mixed outputs with transparent ones in one
    /// transaction links them and undoes the mixing.
    pub async fn build_asset_lock(
        &mut self,
        wallet: &Wallet,
        funding_sources: &[AccountTypePreference],
        source_index: u32,
        credit_output_fundings: Vec<CreditOutputFunding>,
        fee_per_kb: u64,
        drain: bool,
    ) -> Result<AssetLockResult, AssetLockError> {
        // Surface watch-only / no-private-key wallets here so we don't reserve
        // a change index before the build can possibly succeed.
        let root_xpriv =
            wallet.root_extended_priv_key().map_err(|_| AssetLockError::WatchOnlyWallet)?.clone();

        let network = self.network;
        let height = self.last_processed_height();

        validate_funding_sources(funding_sources, credit_output_fundings.len(), drain)?;

        let credit_outputs: Vec<TxOut> =
            credit_output_fundings.iter().map(|f| f.output.clone()).collect();

        // Build first, derive credit keys after — a build failure must not
        // consume any funding-key indices.
        let mut builder = TransactionBuilder::new()
            .set_fee_rate(FeeRate::new(fee_per_kb))
            .set_current_height(height)
            .set_special_payload(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(
                credit_outputs,
            )))
            .require_final_inputs();
        if drain {
            builder = builder.set_selection_strategy(SelectionStrategy::All);
        }
        let PooledFunding {
            builder,
            paths,
            accounts: offered,
        } = self.fund(wallet, funding_sources, source_index, builder)?;

        // The build below reserves the funding inputs in each contributing
        // account's own set. Clone every offered account's reservation handle
        // (a shared `Arc` view of the same set) now, before the loop further
        // down re-borrows `self.accounts`: a mid-loop failure can no longer
        // reach those accounts to release, and the caller never received the
        // token to release with either, so a leaked reservation would strand
        // the already-signed inputs until the 24-block TTL sweep. Offered
        // rather than contributing, because the set is captured before the
        // build tells us who contributed; releasing against an account that
        // reserved nothing is a no-op. Owner-guarded release only (see
        // `ReservationSet::release_if_owner`, `dashpay/platform#4185`).
        let reservations: Vec<ReservationSet> = offered
            .iter()
            .filter_map(|account_type| self.accounts.funds_account(account_type))
            .map(|account| account.reservations().clone())
            .collect();

        let (transaction, fee, reservation_token) =
            builder.build_signed_reserved(wallet, move |addr| paths.get(&addr).cloned()).await?;

        let reserved: Vec<OutPoint> =
            transaction.input.iter().map(|input| input.previous_output).collect();
        let release_reservations = || {
            if let Some(token) = reservation_token {
                for set in &reservations {
                    set.release_if_owner(&reserved, token);
                }
            }
        };

        // Derive one private key per credit output. On any failure, release
        // this build's own reservation before returning.
        let keys = match (|| -> Result<Vec<[u8; 32]>, AssetLockError> {
            let mut keys = Vec::with_capacity(credit_output_fundings.len());
            for funding in &credit_output_fundings {
                let funding_key_account = resolve_funding_account(
                    &mut self.accounts,
                    funding.funding_type,
                    funding.identity_index,
                )?;
                let key = funding_key_account
                    .next_private_key(&root_xpriv, network)
                    .map_err(|e| AssetLockError::KeyDerivation(e.to_string()))?;
                keys.push(key);
            }
            Ok(keys)
        })() {
            Ok(keys) => keys,
            Err(e) => {
                release_reservations();
                return Err(e);
            }
        };

        let funding_accounts = contributing_accounts(&self.accounts, &offered, &transaction);
        Ok(AssetLockResult {
            transaction,
            fee,
            keys: AssetLockCreditKeys::Private(keys),
            reservation_token,
            funding_accounts,
        })
    }

    /// Build and sign an asset lock transaction via an external [`Signer`].
    ///
    /// Same shape and semantics as [`Self::build_asset_lock`], but every
    /// signing operation — both the P2PKH input signatures and the public
    /// keys recorded for credit outputs — is delegated to `signer`. The host
    /// never sees the underlying private keys, so this is the entry point for
    /// hardware wallets and remote signers backing a
    /// [`WalletType::ExternalSignable`](crate::wallet::WalletType::ExternalSignable)
    /// wallet.
    ///
    /// The returned [`AssetLockResult::keys`] is
    /// [`AssetLockCreditKeys::Public`]: public keys plus derivation paths,
    /// one per credit output in payload order. The caller uses the paths to
    /// request signatures from the same signer when later consuming the
    /// credits on Platform.
    ///
    /// `funding_sources` / `source_index` / `drain` — see
    /// [`Self::build_asset_lock`].
    #[allow(clippy::too_many_arguments)]
    pub async fn build_asset_lock_with_signer<S: Signer>(
        &mut self,
        wallet: &Wallet,
        funding_sources: &[AccountTypePreference],
        source_index: u32,
        credit_output_fundings: Vec<CreditOutputFunding>,
        fee_per_kb: u64,
        drain: bool,
        signer: &S,
    ) -> Result<AssetLockResult, AssetLockError> {
        let height = self.last_processed_height();

        validate_funding_sources(funding_sources, credit_output_fundings.len(), drain)?;

        let credit_outputs: Vec<TxOut> =
            credit_output_fundings.iter().map(|f| f.output.clone()).collect();

        let mut builder = TransactionBuilder::new()
            .set_fee_rate(FeeRate::new(fee_per_kb))
            .set_current_height(height)
            .set_special_payload(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(
                credit_outputs,
            )))
            .require_final_inputs();
        if drain {
            builder = builder.set_selection_strategy(SelectionStrategy::All);
        }
        let PooledFunding {
            builder,
            paths,
            accounts: offered,
        } = self.fund(wallet, funding_sources, source_index, builder)?;

        // The build below reserves the funding inputs in each contributing
        // account's own set. Clone every offered account's reservation handle
        // (a shared `Arc` view of the same set) before the bookkeeping loop
        // further down re-borrows `self.accounts`, so a failure during Phase
        // 1–3 — which runs after the transaction is already signed — can still
        // release THIS build's reservation instead of stranding the signed
        // inputs until the 24-block TTL sweep. Owner-guarded release only (see
        // `ReservationSet::release_if_owner`, `dashpay/platform#4185`).
        let reservations: Vec<ReservationSet> = offered
            .iter()
            .filter_map(|account_type| self.accounts.funds_account(account_type))
            .map(|account| account.reservations().clone())
            .collect();

        let (transaction, fee, reservation_token) =
            builder.build_signed_reserved(signer, move |addr| paths.get(&addr).cloned()).await?;

        let reserved: Vec<OutPoint> =
            transaction.input.iter().map(|input| input.previous_output).collect();
        let release_reservations = || {
            if let Some(token) = reservation_token {
                for set in &reservations {
                    set.release_if_owner(&reserved, token);
                }
            }
        };

        // Credit-output bookkeeping: for each funding, peek the next unused
        // path on its account, ask the signer for the matching pubkey, and
        // only mark the index used once the signer has succeeded.
        //
        // This protects against a signer failure mid-loop leaving earlier
        // fundings' pool indices irreversibly consumed: if `public_key`
        // errors, the current funding's index is still free, and no
        // subsequent fundings have touched their pools yet. On any failure we
        // also release this build's own reservation before returning.
        let credit_output_keys = match async {
            let mut credit_output_keys = Vec::with_capacity(credit_output_fundings.len());
            for funding in &credit_output_fundings {
                // Phase 1 (sync): peek without marking used. Borrow is scoped
                // to the block so we can re-resolve the account after the
                // signer await.
                let (path, index) = {
                    let funding_key_account = resolve_funding_account(
                        &mut self.accounts,
                        funding.funding_type,
                        funding.identity_index,
                    )?;
                    funding_key_account
                        .peek_next_path()
                        .map_err(|e| AssetLockError::KeyDerivation(e.to_string()))?
                };

                // Phase 2 (async): signer round-trip. If this errors, we return
                // without ever calling mark_first_pool_index_used — index stays
                // free for a retry.
                let pubkey = signer
                    .public_key(&path)
                    .await
                    .map_err(|e| AssetLockError::Signer(e.to_string()))?;

                // Phase 3 (sync): signer succeeded, commit the index.
                {
                    let funding_key_account = resolve_funding_account(
                        &mut self.accounts,
                        funding.funding_type,
                        funding.identity_index,
                    )?;
                    funding_key_account
                        .mark_first_pool_index_used(index)
                        .map_err(|e| AssetLockError::KeyDerivation(e.to_string()))?;
                }

                credit_output_keys.push((pubkey, path));
            }
            Ok::<_, AssetLockError>(credit_output_keys)
        }
        .await
        {
            Ok(keys) => keys,
            Err(e) => {
                release_reservations();
                return Err(e);
            }
        };

        let funding_accounts = contributing_accounts(&self.accounts, &offered, &transaction);
        Ok(AssetLockResult {
            transaction,
            fee,
            keys: AssetLockCreditKeys::Public(credit_output_keys),
            reservation_token,
            funding_accounts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{ExtendedPubKeySigner, SignerMethod};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::{Network, Utxo};
    use dashcore::{OutPoint, ScriptBuf, Txid};
    use dashcore_hashes::Hash;
    use test_case::test_case;

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
        let info = ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);
        (wallet, info)
    }

    /// Fund account 0 with a UTXO at a fresh receive address and return its
    /// outpoint.
    fn insert_funded_utxo(
        info: &mut ManagedWalletInfo,
        wallet: &Wallet,
        txid_byte: u8,
        value: u64,
        is_confirmed: bool,
    ) -> OutPoint {
        let account_xpub = wallet.get_bip44_account(0).unwrap().account_xpub;
        let account = info.accounts.standard_bip44_accounts.get_mut(&0).unwrap();
        let funding_address = account.next_receive_address(Some(&account_xpub), true).unwrap();
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([txid_byte; 32]),
            vout: 0,
        };
        let utxo = Utxo {
            outpoint,
            txout: TxOut {
                value,
                script_pubkey: funding_address.script_pubkey(),
            },
            address: funding_address,
            height: 1000,
            is_coinbase: false,
            is_confirmed,
            is_instantlocked: false,
            is_locked: false,
            is_trusted: false,
        };
        account.utxos.insert(outpoint, utxo);
        outpoint
    }

    /// CoinJoin-account sibling of [`insert_funded_utxo`]: fund CoinJoin
    /// account 0 with a UTXO at a fresh receive address.
    fn insert_funded_coinjoin_utxo(
        info: &mut ManagedWalletInfo,
        wallet: &Wallet,
        txid_byte: u8,
        value: u64,
        is_confirmed: bool,
    ) -> OutPoint {
        let account_xpub = wallet.get_coinjoin_account(0).unwrap().account_xpub;
        let account = info.accounts.coinjoin_accounts.get_mut(&0).unwrap();
        // CoinJoin accounts have no `next_receive_address` wrapper (that is
        // Standard-only); draw from the external (mixed-coin) pool directly.
        let funding_address = match account.managed_account_type_mut() {
            crate::ManagedAccountType::CoinJoin {
                external_addresses,
                ..
            } => external_addresses
                .next_unused(&crate::KeySource::Public(account_xpub), true)
                .unwrap(),
            _ => unreachable!("coinjoin account must carry the CoinJoin managed type"),
        };
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([txid_byte; 32]),
            vout: 0,
        };
        let utxo = Utxo {
            outpoint,
            txout: TxOut {
                value,
                script_pubkey: funding_address.script_pubkey(),
            },
            address: funding_address,
            height: 1000,
            is_coinbase: false,
            is_confirmed,
            is_instantlocked: false,
            is_locked: false,
            is_trusted: false,
        };
        account.utxos.insert(outpoint, utxo);
        outpoint
    }

    /// Drain from the CoinJoin account: every CoinJoin UTXO is consumed, the
    /// single credit output's value is rewritten to `Σ inputs − fee`, the
    /// on-chain burn mirrors it exactly, and there is no change output.
    #[tokio::test]
    async fn test_drain_coinjoin_asset_lock() {
        let (wallet, mut info) = test_wallet_and_info();
        insert_funded_coinjoin_utxo(&mut info, &wallet, 0x41, 400_000, true);
        insert_funded_coinjoin_utxo(&mut info, &wallet, 0x42, 300_000, true);
        insert_funded_coinjoin_utxo(&mut info, &wallet, 0x43, 300_000, true);
        info.update_last_processed_height(1100);

        // The caller's credit amount (0) is ignored — drain rewrites it.
        let result = info
            .build_asset_lock(
                &wallet,
                &[AccountTypePreference::CoinJoin],
                0,
                test_credit_outputs(&[0]),
                1000,
                true,
            )
            .await
            .expect("drain from a funded CoinJoin account should succeed");

        assert_eq!(result.transaction.input.len(), 3, "drain must consume every CoinJoin UTXO");
        assert_eq!(result.transaction.output.len(), 1, "drain emits no change output");
        let burn = &result.transaction.output[0];
        assert!(burn.script_pubkey.is_op_return(), "single output must be the OP_RETURN burn");
        assert_eq!(burn.value, 1_000_000 - result.fee, "burn must carry Σ inputs − fee");

        let payload = match &result.transaction.special_transaction_payload {
            Some(TransactionPayload::AssetLockPayloadType(p)) => p,
            other => panic!("expected asset-lock payload, got {:?}", other),
        };
        assert_eq!(payload.credit_outputs.len(), 1);
        assert_eq!(
            payload.credit_outputs[0].value, burn.value,
            "payload credit output must mirror the burn value"
        );

        for (i, txin) in result.transaction.input.iter().enumerate() {
            assert!(!txin.script_sig.is_empty(), "input {i} not signed");
        }
    }

    /// A drain build requires exactly one credit output — anything else is
    /// rejected before any wallet state is touched.
    #[tokio::test]
    async fn test_drain_requires_single_credit_output() {
        let (wallet, mut info) = test_wallet_and_info();
        insert_funded_coinjoin_utxo(&mut info, &wallet, 0x44, 500_000, true);
        info.update_last_processed_height(1100);

        let result = info
            .build_asset_lock(
                &wallet,
                &[AccountTypePreference::CoinJoin],
                0,
                test_credit_outputs(&[0, 0]),
                1000,
                true,
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::Builder(BuilderError::InvalidData(_)))),
            "two credit outputs must be rejected in drain mode, got: {:?}",
            result.err()
        );
    }

    /// CoinJoin funding is drain-only: a partial (non-drain) CoinJoin-funded
    /// build is rejected before any wallet state is touched (change would
    /// need CoinJoin re-denomination, which the builder does not do).
    #[tokio::test]
    async fn test_coinjoin_funding_requires_drain() {
        let (wallet, mut info) = test_wallet_and_info();
        insert_funded_coinjoin_utxo(&mut info, &wallet, 0x45, 1_000_000, true);
        info.update_last_processed_height(1100);

        let result = info
            .build_asset_lock(
                &wallet,
                &[AccountTypePreference::CoinJoin],
                0,
                test_credit_outputs(&[200_000]),
                1000,
                false,
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::Builder(BuilderError::InvalidData(_)))),
            "non-drain CoinJoin funding must be rejected, got: {:?}",
            result.err()
        );
    }

    // -- Error type tests --

    #[test]
    fn test_error_display() {
        assert_eq!(
            AssetLockError::WatchOnlyWallet.to_string(),
            "Cannot sign with watch-only wallet"
        );
        assert_eq!(AssetLockError::NoChangeAddress.to_string(), "No change address available");
    }

    #[test]
    fn test_builder_error_conversion() {
        let builder_err = BuilderError::NoInputs;
        let asset_err: AssetLockError = builder_err.into();
        assert!(matches!(asset_err, AssetLockError::Builder(BuilderError::NoInputs)));
    }

    // -- Builder logic tests --

    #[tokio::test]
    async fn test_empty_credit_outputs_rejected() {
        let (wallet, mut info) = test_wallet_and_info();
        let result = info
            .build_asset_lock(&wallet, &[AccountTypePreference::BIP44], 0, vec![], 1000, false)
            .await;
        assert!(matches!(result, Err(AssetLockError::Builder(BuilderError::NoOutputs))));
    }

    #[tokio::test]
    async fn test_invalid_account_index() {
        let (wallet, mut info) = test_wallet_and_info();
        let result = info
            .build_asset_lock(
                &wallet,
                &[AccountTypePreference::BIP44],
                99,
                test_credit_outputs(&[100_000]),
                1000,
                false,
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::Builder(BuilderError::AccountNotFound(_)))),
            "a single named source is strict: the absent account must be an error"
        );
    }

    #[tokio::test]
    async fn test_insufficient_funds() {
        // Wallet has no UTXOs, so coin selection should fail
        let (wallet, mut info) = test_wallet_and_info();
        let result = info
            .build_asset_lock(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                test_credit_outputs(&[500_000]),
                1000,
                false,
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::Builder(_))),
            "Expected Builder error for insufficient funds, got: {:?}",
            result.err()
        );
    }

    /// An account whose only funds are an unconfirmed mempool UTXO must not
    /// produce an asset lock: a non-final input is not InstantSend-eligible
    /// per DIP-0010, so the funding transaction could never receive the lock
    /// Platform requires.
    #[tokio::test]
    async fn test_rejects_non_final_funding() {
        let (wallet, mut info) = test_wallet_and_info();
        insert_funded_utxo(&mut info, &wallet, 0x11, 1_000_000, false);
        info.update_last_processed_height(1100);

        let result = info
            .build_asset_lock(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                test_credit_outputs(&[200_000]),
                1000,
                false,
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::Builder(_))),
            "asset lock must not be built on unconfirmed funds, got: {:?}",
            result.err()
        );
    }

    /// With a mix of confirmed and unconfirmed funds, coin selection must only
    /// spend the confirmed UTXO, even though the unconfirmed one is larger.
    #[tokio::test]
    async fn test_selects_only_final_funding() {
        let (wallet, mut info) = test_wallet_and_info();
        let confirmed_outpoint = insert_funded_utxo(&mut info, &wallet, 0x22, 1_000_000, true);
        insert_funded_utxo(&mut info, &wallet, 0x33, 5_000_000, false);
        info.update_last_processed_height(1100);

        let result = info
            .build_asset_lock(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                test_credit_outputs(&[200_000]),
                1000,
                false,
            )
            .await
            .expect("confirmed funds should cover the asset lock");
        assert!(!result.transaction.input.is_empty());
        for txin in &result.transaction.input {
            assert_eq!(
                txin.previous_output, confirmed_outpoint,
                "asset lock spent a non-final input"
            );
        }
    }

    // -- Signer-variant tests --

    /// Signer implementation backed by a real [`RootExtendedPrivKey`]. Models
    /// the same derive-and-sign the soft-wallet path performs internally, so
    /// `build_asset_lock_with_signer` can be exercised end-to-end without a
    /// hardware device in the loop.
    struct InMemorySigner {
        root: crate::wallet::root_extended_keys::RootExtendedPrivKey,
        network: Network,
    }

    const IN_MEMORY_METHODS: &[SignerMethod] = &[SignerMethod::Digest];

    #[async_trait::async_trait]
    impl Signer for InMemorySigner {
        type Error = String;

        fn supported_methods(&self) -> &[SignerMethod] {
            IN_MEMORY_METHODS
        }

        async fn sign_ecdsa(
            &self,
            path: &DerivationPath,
            sighash: [u8; 32],
        ) -> Result<(secp256k1::ecdsa::Signature, PublicKey), Self::Error> {
            let secp = secp256k1::Secp256k1::new();
            let xpriv = self
                .root
                .to_extended_priv_key(self.network)
                .derive_priv(&secp, path)
                .map_err(|e| e.to_string())?;
            let msg = secp256k1::Message::from_digest(sighash);
            let sig = secp.sign_ecdsa(&msg, &xpriv.private_key);
            let pk = secp256k1::PublicKey::from_secret_key(&secp, &xpriv.private_key);
            Ok((sig, pk))
        }

        async fn public_key(&self, path: &DerivationPath) -> Result<PublicKey, Self::Error> {
            let secp = secp256k1::Secp256k1::new();
            let xpriv = self
                .root
                .to_extended_priv_key(self.network)
                .derive_priv(&secp, path)
                .map_err(|e| e.to_string())?;
            Ok(secp256k1::PublicKey::from_secret_key(&secp, &xpriv.private_key))
        }
    }

    #[async_trait::async_trait]
    impl ExtendedPubKeySigner for InMemorySigner {
        async fn extended_public_key(
            &self,
            path: &DerivationPath,
        ) -> Result<crate::bip32::ExtendedPubKey, Self::Error> {
            let secp = secp256k1::Secp256k1::new();
            let xpriv = self
                .root
                .to_extended_priv_key(self.network)
                .derive_priv(&secp, path)
                .map_err(|e| e.to_string())?;
            Ok(crate::bip32::ExtendedPubKey::from_priv(&secp, &xpriv))
        }
    }

    #[tokio::test]
    async fn in_memory_signer_extended_public_key_matches_wallet_derivation() {
        use std::str::FromStr;
        let (wallet, _info) = test_wallet_and_info();
        let root = match &wallet.wallet_type {
            crate::wallet::WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.clone(),
            _ => unreachable!("test_wallet_and_info produces a mnemonic wallet"),
        };
        let signer = InMemorySigner {
            root,
            network: Network::Testnet,
        };
        // A hardened path — only derivable with the private key, which is the
        // whole point of exposing extended-pubkey export on the signer.
        let path = DerivationPath::from_str("m/9'/1'/15'/0'").expect("valid path");
        let from_signer =
            signer.extended_public_key(&path).await.expect("signer extended_public_key");
        let from_wallet = wallet.derive_extended_public_key(&path).expect("wallet extended pubkey");
        assert_eq!(
            from_signer, from_wallet,
            "signer xpub at a hardened path must equal the wallet's own derivation"
        );
    }

    #[tokio::test]
    async fn test_signer_empty_credit_outputs_rejected() {
        let (wallet, mut info) = test_wallet_and_info();
        let root = match &wallet.wallet_type {
            crate::wallet::WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.clone(),
            _ => unreachable!("test_wallet_and_info produces a mnemonic wallet"),
        };
        let signer = InMemorySigner {
            root,
            network: Network::Testnet,
        };
        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                vec![],
                1000,
                false,
                &signer,
            )
            .await;
        assert!(matches!(result, Err(AssetLockError::Builder(BuilderError::NoOutputs))));
    }

    #[tokio::test]
    async fn test_signer_invalid_account_index() {
        let (wallet, mut info) = test_wallet_and_info();
        let root = match &wallet.wallet_type {
            crate::wallet::WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.clone(),
            _ => unreachable!(),
        };
        let signer = InMemorySigner {
            root,
            network: Network::Testnet,
        };
        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                &[AccountTypePreference::BIP44],
                99,
                test_credit_outputs(&[100_000]),
                1000,
                false,
                &signer,
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::Builder(BuilderError::AccountNotFound(_)))),
            "a single named source is strict: the absent account must be an error"
        );
    }

    #[tokio::test]
    async fn test_signer_without_digest_support_rejected() {
        // A signer that advertises no methods (or only transaction-level
        // signing) must be rejected by the digest-driven build path before
        // any UTXO state is touched.
        struct NoDigestSigner;
        #[async_trait::async_trait]
        impl Signer for NoDigestSigner {
            type Error = String;
            fn supported_methods(&self) -> &[SignerMethod] {
                &[SignerMethod::Transaction(crate::signer::TransactionCategory::PlatformCredits)]
            }
            async fn sign_ecdsa(
                &self,
                _: &DerivationPath,
                _: [u8; 32],
            ) -> Result<(secp256k1::ecdsa::Signature, PublicKey), Self::Error> {
                unreachable!("should be rejected before any signing is attempted")
            }
            async fn public_key(&self, _: &DerivationPath) -> Result<PublicKey, Self::Error> {
                unreachable!()
            }
        }

        let (wallet, mut info) = test_wallet_and_info();
        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                test_credit_outputs(&[100_000]),
                1000,
                false,
                &NoDigestSigner,
            )
            .await;
        // The unfunded wallet may also surface a CoinSelection error before
        // the signer is reached; either way the build cannot succeed.
        assert!(matches!(result, Err(AssetLockError::Builder(_))));
    }

    #[tokio::test]
    async fn test_signer_happy_path_end_to_end() {
        let (wallet, mut info) = test_wallet_and_info();
        let root = match &wallet.wallet_type {
            crate::wallet::WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.clone(),
            _ => unreachable!(),
        };

        // Coin selection needs a confirmed, spendable output the signer can
        // sign for.
        insert_funded_utxo(&mut info, &wallet, 0x11, 1_000_000, true);
        info.update_last_processed_height(1100);

        let signer = InMemorySigner {
            root,
            network: Network::Testnet,
        };

        let credit_amounts = [200_000u64, 300_000u64];
        let fundings = test_credit_outputs(&credit_amounts);
        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                fundings,
                1000,
                false,
                &signer,
            )
            .await
            .expect("build_asset_lock_with_signer should succeed with funded wallet");

        // Result shape: signer path returns public keys + paths, one per
        // credit output, in payload order.
        let pub_keys = match &result.keys {
            AssetLockCreditKeys::Public(v) => v,
            AssetLockCreditKeys::Private(_) => panic!("signer path must return Public keys"),
        };
        assert_eq!(pub_keys.len(), credit_amounts.len(), "one (pubkey, path) per credit output");

        // DIP-00X: tx.output[0] is the OP_RETURN burn carrying the total
        // locked amount. Credit outputs live only in the payload, not in
        // tx.output.
        let total_credit: u64 = credit_amounts.iter().sum();
        let burn = &result.transaction.output[0];
        assert_eq!(burn.value, total_credit, "burn output must carry total credit");
        assert!(
            burn.script_pubkey.is_op_return(),
            "tx.output[0] must be OP_RETURN, got {:?}",
            burn.script_pubkey
        );

        // Every input should have been signed — empty script_sig means
        // the signer was never called for that input.
        assert!(
            !result.transaction.input.is_empty(),
            "transaction should have at least one selected input"
        );
        for (i, txin) in result.transaction.input.iter().enumerate() {
            assert!(
                !txin.script_sig.is_empty(),
                "input {i} has empty script_sig — signer did not produce a signature"
            );
        }
    }

    #[tokio::test]
    async fn test_signer_insufficient_funds() {
        let (wallet, mut info) = test_wallet_and_info();
        let root = match &wallet.wallet_type {
            crate::wallet::WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.clone(),
            _ => unreachable!(),
        };
        let signer = InMemorySigner {
            root,
            network: Network::Testnet,
        };
        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                test_credit_outputs(&[500_000]),
                1000,
                false,
                &signer,
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::Builder(_))),
            "Expected Builder error for insufficient funds, got: {:?}",
            result.err()
        );
    }

    // -- Pooled funding --------------------------------------------------
    //
    // Asset locks fund from a LIST of sources. These pin the three things the
    // pooling has to get right: it really spans accounts, it tolerates the
    // sources a wallet does not have, and every failure path after the build
    // gives back the reservations it took — in *each* contributing account,
    // since a pooled build reserves per account under one owner token.

    /// The default pooled set, mirroring platform's `ASSET_LOCK_FUNDING_SOURCES`.
    const POOLED: [AccountTypePreference; 3] = [
        AccountTypePreference::BIP44,
        AccountTypePreference::BIP32,
        AccountTypePreference::AllDashpayReceivingFunds,
    ];

    /// Fund the BIP32 account at index 0 with a confirmed UTXO.
    fn insert_funded_bip32_utxo(
        info: &mut ManagedWalletInfo,
        wallet: &Wallet,
        txid_byte: u8,
        value: u64,
    ) -> OutPoint {
        let account_xpub = wallet
            .accounts
            .standard_bip32_accounts
            .get(&0)
            .expect("default wallet has BIP32 account 0")
            .account_xpub;
        let account = info.accounts.standard_bip32_accounts.get_mut(&0).unwrap();
        let funding_address = account.next_receive_address(Some(&account_xpub), true).unwrap();
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([txid_byte; 32]),
            vout: 0,
        };
        account.utxos.insert(
            outpoint,
            Utxo {
                outpoint,
                txout: TxOut {
                    value,
                    script_pubkey: funding_address.script_pubkey(),
                },
                address: funding_address,
                height: 1000,
                is_coinbase: false,
                is_confirmed: true,
                is_instantlocked: false,
                is_locked: false,
                is_trusted: false,
            },
        );
        outpoint
    }

    fn bip44_0() -> AccountType {
        AccountType::Standard {
            index: 0,
            standard_account_type: crate::account::StandardAccountType::BIP44Account,
        }
    }

    fn bip32_0() -> AccountType {
        AccountType::Standard {
            index: 0,
            standard_account_type: crate::account::StandardAccountType::BIP32Account,
        }
    }

    /// A credit output whose one-time key comes from an identity top-up
    /// account that does not exist, so credit-key derivation fails *after* the
    /// transaction is built and signed — the window in which a pooled build
    /// holds reservations it must give back.
    fn credit_output_with_missing_key_account() -> Vec<CreditOutputFunding> {
        let mut fundings = test_credit_outputs(&[400_000]);
        fundings[0].funding_type = AssetLockFundingType::IdentityTopUp;
        fundings[0].identity_index = 7;
        fundings
    }

    /// Reserved outpoints across the two standard accounts at height 1100.
    fn reserved_outpoints(info: &ManagedWalletInfo) -> HashSet<OutPoint> {
        [bip44_0(), bip32_0()]
            .iter()
            .filter_map(|at| info.accounts.funds_account(at))
            .flat_map(|account| account.reservations().reserved(1100))
            .collect()
    }

    /// Neither standard account covers the lock on its own, so the build only
    /// succeeds by pooling both — which also proves the derivation paths were
    /// collected across accounts, since every input had to be signed. Change
    /// goes back to BIP44 (the first source), each account reserves what it
    /// contributed in its own set, and both are reported as funding accounts.
    #[tokio::test]
    async fn pooled_asset_lock_spans_the_standard_accounts() {
        let (wallet, mut info) = test_wallet_and_info();
        let bip44 = insert_funded_utxo(&mut info, &wallet, 0x11, 300_000, true);
        let bip32 = insert_funded_bip32_utxo(&mut info, &wallet, 0x22, 300_000);
        info.update_last_processed_height(1100);

        let result = info
            .build_asset_lock(&wallet, &POOLED, 0, test_credit_outputs(&[500_000]), 1000, false)
            .await
            .expect("a 500k lock funded by two 300k accounts");

        let spent: HashSet<OutPoint> =
            result.transaction.input.iter().map(|txin| txin.previous_output).collect();
        assert_eq!(spent, HashSet::from([bip44, bip32]), "the lock must pool both accounts");
        for (i, txin) in result.transaction.input.iter().enumerate() {
            assert!(!txin.script_sig.is_empty(), "input {i} not signed");
        }

        // Change returns to the FIRST source, not to whichever account happened
        // to be selected from last.
        let change = result
            .transaction
            .output
            .iter()
            .find(|out| !out.script_pubkey.is_op_return())
            .expect("600k in against a 500k lock leaves change");
        let bip44_account = info.accounts.standard_bip44_accounts.get(&0).unwrap();
        assert!(
            bip44_account
                .managed_account_type()
                .all_script_pubkeys()
                .contains(&change.script_pubkey),
            "change must return to the BIP44 account"
        );

        // One token, but the reservation lives in each contributing account's
        // own set — that set is the one its next coin selection consults.
        assert!(result.reservation_token.is_some());
        assert_eq!(bip44_account.reservations().reserved(1100), HashSet::from([bip44]));
        assert_eq!(
            info.accounts.standard_bip32_accounts.get(&0).unwrap().reservations().reserved(1100),
            HashSet::from([bip32])
        );
        assert_eq!(
            result.funding_accounts.iter().copied().collect::<HashSet<_>>(),
            HashSet::from([bip44_0(), bip32_0()])
        );
    }

    /// A pooled list names sources this wallet may have nothing for. Skipping
    /// them is the point: a wallet with no DashPay contacts still funds an
    /// asset lock, and only the accounts that contributed are reported.
    #[tokio::test]
    async fn pooled_sources_skip_what_the_wallet_does_not_have() {
        let (wallet, mut info) = test_wallet_and_info();
        let bip44 = insert_funded_utxo(&mut info, &wallet, 0x11, 900_000, true);
        info.update_last_processed_height(1100);

        let result = info
            .build_asset_lock(&wallet, &POOLED, 0, test_credit_outputs(&[500_000]), 1000, false)
            .await
            .expect("no contacts and an empty BIP32 account must not block the build");

        let spent: Vec<OutPoint> =
            result.transaction.input.iter().map(|txin| txin.previous_output).collect();
        assert_eq!(spent, vec![bip44]);
        assert_eq!(
            result.funding_accounts,
            vec![bip44_0()],
            "an account that contributed nothing is not a funding account"
        );
    }

    /// A pooled list that funds nothing at all is still an error — leniency
    /// skips absent sources, it does not invent funds.
    #[tokio::test]
    async fn pooled_sources_that_resolve_to_nothing_are_an_error() {
        let (wallet, mut info) = test_wallet_and_info();
        info.update_last_processed_height(1100);

        let result = info
            .build_asset_lock(&wallet, &POOLED, 99, test_credit_outputs(&[500_000]), 1000, false)
            .await;

        assert!(
            matches!(result, Err(AssetLockError::Builder(BuilderError::AccountNotFound(_)))),
            "no account of any named source at index 99"
        );
    }

    /// Mixed coins must never ride alongside transparent ones: pooling would
    /// link them in a single transaction and undo the mixing. Rejected before
    /// any wallet state is touched, drain or not.
    #[test_case(true ; "drain")]
    #[test_case(false ; "exact amount")]
    #[tokio::test]
    async fn coinjoin_cannot_be_pooled_with_transparent_sources(drain: bool) {
        let (wallet, mut info) = test_wallet_and_info();
        insert_funded_coinjoin_utxo(&mut info, &wallet, 0x41, 900_000, true);
        insert_funded_utxo(&mut info, &wallet, 0x11, 900_000, true);
        info.update_last_processed_height(1100);

        let result = info
            .build_asset_lock(
                &wallet,
                &[AccountTypePreference::CoinJoin, AccountTypePreference::BIP44],
                0,
                test_credit_outputs(&[500_000]),
                1000,
                drain,
            )
            .await;

        assert!(matches!(result, Err(AssetLockError::Builder(BuilderError::InvalidData(_)))));
        assert!(
            reserved_outpoints(&info).is_empty()
                && info
                    .accounts
                    .coinjoin_accounts
                    .get(&0)
                    .unwrap()
                    .reservations()
                    .reserved(1100)
                    .is_empty(),
            "a rejected source list must not have reserved anything"
        );
    }

    /// The failure window a pooled build opens: the transaction is already
    /// built, signed and reserved when credit-key derivation fails. The caller
    /// never receives the token, so nothing else can release those inputs —
    /// they must be freed here, in EVERY contributing account, or the funds
    /// stay stranded until the 24-block TTL sweep.
    #[tokio::test]
    async fn credit_key_failure_releases_the_reservation_in_every_pooled_account() {
        let (wallet, mut info) = test_wallet_and_info();
        insert_funded_utxo(&mut info, &wallet, 0x11, 300_000, true);
        insert_funded_bip32_utxo(&mut info, &wallet, 0x22, 300_000);
        info.update_last_processed_height(1100);

        let result = info
            .build_asset_lock(
                &wallet,
                &POOLED,
                0,
                credit_output_with_missing_key_account(),
                1000,
                false,
            )
            .await;

        assert!(
            matches!(result, Err(AssetLockError::FundingAccountNotFound(_))),
            "the absent identity top-up account must fail credit-key derivation"
        );
        assert!(
            reserved_outpoints(&info).is_empty(),
            "both pooled accounts must have released this build's reservation"
        );
    }

    /// [`credit_key_failure_releases_the_reservation_in_every_pooled_account`]
    /// for the signer-driven builder, whose bookkeeping loop runs after an
    /// `.await` and so had the same stranding window.
    #[tokio::test]
    async fn signer_credit_key_failure_releases_the_reservation_in_every_pooled_account() {
        let (wallet, mut info) = test_wallet_and_info();
        insert_funded_utxo(&mut info, &wallet, 0x11, 300_000, true);
        insert_funded_bip32_utxo(&mut info, &wallet, 0x22, 300_000);
        info.update_last_processed_height(1100);
        let root = match &wallet.wallet_type {
            crate::wallet::WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.clone(),
            _ => unreachable!("test_wallet_and_info produces a mnemonic wallet"),
        };
        let signer = InMemorySigner {
            root,
            network: Network::Testnet,
        };

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                &POOLED,
                0,
                credit_output_with_missing_key_account(),
                1000,
                false,
                &signer,
            )
            .await;

        assert!(
            matches!(result, Err(AssetLockError::FundingAccountNotFound(_))),
            "the absent identity top-up account must fail credit-key bookkeeping"
        );
        assert!(
            reserved_outpoints(&info).is_empty(),
            "both pooled accounts must have released this build's reservation"
        );
    }

    /// A signing failure is handled one layer down, by the builder itself —
    /// which must also reach every funding account, not just the first.
    #[tokio::test]
    async fn signing_failure_releases_the_reservation_in_every_pooled_account() {
        struct FailingSigner;

        #[async_trait::async_trait]
        impl Signer for FailingSigner {
            type Error = String;

            fn supported_methods(&self) -> &[SignerMethod] {
                IN_MEMORY_METHODS
            }

            async fn sign_ecdsa(
                &self,
                _path: &DerivationPath,
                _sighash: [u8; 32],
            ) -> Result<(secp256k1::ecdsa::Signature, PublicKey), Self::Error> {
                Err("signing device unavailable".to_string())
            }

            async fn public_key(&self, _path: &DerivationPath) -> Result<PublicKey, Self::Error> {
                Err("signing device unavailable".to_string())
            }
        }

        let (wallet, mut info) = test_wallet_and_info();
        insert_funded_utxo(&mut info, &wallet, 0x11, 300_000, true);
        insert_funded_bip32_utxo(&mut info, &wallet, 0x22, 300_000);
        info.update_last_processed_height(1100);

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                &POOLED,
                0,
                test_credit_outputs(&[500_000]),
                1000,
                false,
                &FailingSigner,
            )
            .await;

        assert!(result.is_err(), "a failing signer must not produce a transaction");
        assert!(
            reserved_outpoints(&info).is_empty(),
            "both pooled accounts must have released this build's reservation"
        );
    }
}
