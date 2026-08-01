//! Asset lock transaction builder.
//!
//! Builds a Core special transaction (type 8) with `AssetLockPayload` that
//! locks Dash for Platform credits.

use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::{OutPoint, Transaction, TxOut};
use secp256k1::PublicKey;
use std::fmt;

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::{ManagedCoreKeysAccount, ReservationToken};
use crate::signer::Signer;
use crate::wallet::managed_wallet_info::coin_selection::SelectionStrategy;
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::wallet::managed_wallet_info::transaction_builder::{BuilderError, TransactionBuilder};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::wallet::Wallet;
use crate::DerivationPath;

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

/// Which wallet account supplies the funding UTXOs (and signs the inputs)
/// of an asset lock transaction.
///
/// `Bip44` is the standard spendable balance — the historical behavior of
/// the builders below. `CoinJoin` lets mixed coins fund an asset lock
/// directly, without first sweeping them through a transparent BIP44
/// address (which would link the mixed UTXOs to a reusable transparent
/// address for an extra hop).
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
    /// or `None` if the funding account carried no reservation set.
    ///
    /// The caller broadcasts `transaction` and, on a rejected broadcast, must
    /// release the reserved inputs with
    /// [`ManagedCoreFundsAccount::release_reservation_if_owner`] passing this
    /// token — never the unconditional `release_reservation` — so a reservation
    /// the TTL sweep reclaimed and another build re-took mid-broadcast is not
    /// freed out from under that other build. See `dashpay/platform#4185`.
    ///
    /// [`ManagedCoreFundsAccount::release_reservation_if_owner`]: crate::managed_account::ManagedCoreFundsAccount::release_reservation_if_owner
    pub reservation_token: Option<ReservationToken>,
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
    /// The specified funding account (BIP44 or CoinJoin, by index) was not found.
    AccountNotFound(u32),
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
            Self::AccountNotFound(idx) => write!(f, "funding account {} not found", idx),
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

/// Shared guard for both asset-lock builders: a drain rewrites exactly one
/// credit output, and CoinJoin accounts have no change-address pool semantics
/// for asset locks (change would need re-denomination), so they only support
/// the whole-balance drain.
fn validate_drain_funding(
    funding_account: AssetLockFundingAccount,
    credit_output_count: usize,
    drain: bool,
) -> Result<(), AssetLockError> {
    if drain && credit_output_count != 1 {
        return Err(AssetLockError::Builder(BuilderError::InvalidData(
            "drain asset lock requires exactly one credit output".into(),
        )));
    }
    if matches!(funding_account, AssetLockFundingAccount::CoinJoin { .. }) && !drain {
        return Err(AssetLockError::Builder(BuilderError::InvalidData(
            "CoinJoin-funded asset locks support drain mode only".into(),
        )));
    }
    Ok(())
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
    /// `funding_account` picks which account family supplies (and signs) the
    /// funding UTXOs — see [`AssetLockFundingAccount`]. `drain` locks the
    /// account's whole spendable balance: every final UTXO is consumed and
    /// the single credit output's value is rewritten to `Σ inputs − fee`
    /// (the caller's credit-output value is ignored; exactly one credit
    /// output is required).
    pub async fn build_asset_lock(
        &mut self,
        wallet: &Wallet,
        funding_account: AssetLockFundingAccount,
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

        let account_index = funding_account.account_index();
        let acc = match funding_account {
            AssetLockFundingAccount::Bip44 {
                ..
            } => wallet
                .get_bip44_account(account_index)
                .ok_or(AssetLockError::AccountNotFound(account_index))?,
            AssetLockFundingAccount::CoinJoin {
                ..
            } => wallet
                .get_coinjoin_account(account_index)
                .ok_or(AssetLockError::AccountNotFound(account_index))?,
        };

        let funds_acc = match funding_account {
            AssetLockFundingAccount::Bip44 {
                ..
            } => self
                .accounts
                .standard_bip44_accounts
                .get_mut(&account_index)
                .ok_or(AssetLockError::AccountNotFound(account_index))?,
            AssetLockFundingAccount::CoinJoin {
                ..
            } => self
                .accounts
                .coinjoin_accounts
                .get_mut(&account_index)
                .ok_or(AssetLockError::AccountNotFound(account_index))?,
        };

        validate_drain_funding(funding_account, credit_output_fundings.len(), drain)?;

        let credit_outputs: Vec<TxOut> =
            credit_output_fundings.iter().map(|f| f.output.clone()).collect();

        // Build first, derive credit keys after — a build failure must not
        // consume any funding-key indices.
        let mut builder = TransactionBuilder::new()
            .set_fee_rate(FeeRate::new(fee_per_kb))
            .set_current_height(height)
            .set_special_payload(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(
                credit_outputs,
            )));
        if drain {
            builder = builder.set_selection_strategy(SelectionStrategy::All);
        }
        let (transaction, fee, reservation_token) = builder
            .set_funding(funds_acc, acc)
            .require_final_inputs()
            .build_signed_reserved(wallet, |addr| funds_acc.address_derivation_path(&addr))
            .await?;

        // The build above reserved the funding inputs. Clone the reservation
        // handle (a shared `Arc` view of the same set) now, before the loop
        // below re-borrows `self.accounts` — a mid-loop failure can no longer
        // reach `funds_acc` to release, and the caller never received the token
        // to release it either, so a leaked reservation would strand the
        // already-signed inputs until the 24-block TTL sweep. Owner-guarded
        // release only: an unconditional release could free a concurrent
        // build's inputs that the TTL sweep + re-reserve handed over during
        // this build (the TOCTOU of `dashpay/platform#4185`).
        let reservations = funds_acc.reservations().clone();
        let reserved: Vec<OutPoint> =
            transaction.input.iter().map(|input| input.previous_output).collect();

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
                if let Some(token) = reservation_token {
                    reservations.release_if_owner(&reserved, token);
                }
                return Err(e);
            }
        };

        Ok(AssetLockResult {
            transaction,
            fee,
            keys: AssetLockCreditKeys::Private(keys),
            reservation_token,
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
    /// `funding_account` / `drain` — see [`Self::build_asset_lock`].
    pub async fn build_asset_lock_with_signer<S: Signer>(
        &mut self,
        wallet: &Wallet,
        funding_account: AssetLockFundingAccount,
        credit_output_fundings: Vec<CreditOutputFunding>,
        fee_per_kb: u64,
        drain: bool,
        signer: &S,
    ) -> Result<AssetLockResult, AssetLockError> {
        let height = self.last_processed_height();

        let account_index = funding_account.account_index();
        let acc = match funding_account {
            AssetLockFundingAccount::Bip44 {
                ..
            } => wallet
                .get_bip44_account(account_index)
                .ok_or(AssetLockError::AccountNotFound(account_index))?
                .clone(),
            AssetLockFundingAccount::CoinJoin {
                ..
            } => wallet
                .get_coinjoin_account(account_index)
                .ok_or(AssetLockError::AccountNotFound(account_index))?
                .clone(),
        };

        let funds_acc = match funding_account {
            AssetLockFundingAccount::Bip44 {
                ..
            } => self
                .accounts
                .standard_bip44_accounts
                .get_mut(&account_index)
                .ok_or(AssetLockError::AccountNotFound(account_index))?,
            AssetLockFundingAccount::CoinJoin {
                ..
            } => self
                .accounts
                .coinjoin_accounts
                .get_mut(&account_index)
                .ok_or(AssetLockError::AccountNotFound(account_index))?,
        };

        validate_drain_funding(funding_account, credit_output_fundings.len(), drain)?;

        let credit_outputs: Vec<TxOut> =
            credit_output_fundings.iter().map(|f| f.output.clone()).collect();

        let mut builder = TransactionBuilder::new()
            .set_fee_rate(FeeRate::new(fee_per_kb))
            .set_current_height(height)
            .set_special_payload(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(
                credit_outputs,
            )));
        if drain {
            builder = builder.set_selection_strategy(SelectionStrategy::All);
        }
        let (transaction, fee, reservation_token) = builder
            .set_funding(funds_acc, &acc)
            .require_final_inputs()
            .build_signed_reserved(signer, |addr| funds_acc.address_derivation_path(&addr))
            .await?;

        // The build above reserved the funding inputs. Clone the reservation
        // handle (a shared `Arc` view of the same set) before the bookkeeping
        // loop below re-borrows `self.accounts`, so a failure during Phase 1–3
        // — which runs after the transaction is already signed — can still
        // release THIS build's reservation instead of stranding the signed
        // inputs until the 24-block TTL sweep. Owner-guarded release only: an
        // unconditional release could free a concurrent build's inputs that the
        // TTL sweep + re-reserve handed over during this build (the TOCTOU of
        // `dashpay/platform#4185`).
        let reservations = funds_acc.reservations().clone();
        let reserved: Vec<OutPoint> =
            transaction.input.iter().map(|input| input.previous_output).collect();

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
                if let Some(token) = reservation_token {
                    reservations.release_if_owner(&reserved, token);
                }
                return Err(e);
            }
        };

        Ok(AssetLockResult {
            transaction,
            fee,
            keys: AssetLockCreditKeys::Public(credit_output_keys),
            reservation_token,
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
                AssetLockFundingAccount::CoinJoin {
                    account_index: 0,
                },
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
                AssetLockFundingAccount::CoinJoin {
                    account_index: 0,
                },
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
                AssetLockFundingAccount::CoinJoin {
                    account_index: 0,
                },
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
        assert_eq!(AssetLockError::AccountNotFound(5).to_string(), "funding account 5 not found");
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
            .build_asset_lock(
                &wallet,
                AssetLockFundingAccount::Bip44 {
                    account_index: 0,
                },
                vec![],
                1000,
                false,
            )
            .await;
        assert!(matches!(result, Err(AssetLockError::Builder(BuilderError::NoOutputs))));
    }

    #[tokio::test]
    async fn test_invalid_account_index() {
        let (wallet, mut info) = test_wallet_and_info();
        let result = info
            .build_asset_lock(
                &wallet,
                AssetLockFundingAccount::Bip44 {
                    account_index: 99,
                },
                test_credit_outputs(&[100_000]),
                1000,
                false,
            )
            .await;
        assert!(matches!(result, Err(AssetLockError::AccountNotFound(99))));
    }

    #[tokio::test]
    async fn test_insufficient_funds() {
        // Wallet has no UTXOs, so coin selection should fail
        let (wallet, mut info) = test_wallet_and_info();
        let result = info
            .build_asset_lock(
                &wallet,
                AssetLockFundingAccount::Bip44 {
                    account_index: 0,
                },
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
                AssetLockFundingAccount::Bip44 {
                    account_index: 0,
                },
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
                AssetLockFundingAccount::Bip44 {
                    account_index: 0,
                },
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
                AssetLockFundingAccount::Bip44 {
                    account_index: 0,
                },
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
                AssetLockFundingAccount::Bip44 {
                    account_index: 99,
                },
                test_credit_outputs(&[100_000]),
                1000,
                false,
                &signer,
            )
            .await;
        assert!(matches!(result, Err(AssetLockError::AccountNotFound(99))));
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
                AssetLockFundingAccount::Bip44 {
                    account_index: 0,
                },
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
                AssetLockFundingAccount::Bip44 {
                    account_index: 0,
                },
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
                AssetLockFundingAccount::Bip44 {
                    account_index: 0,
                },
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
}
