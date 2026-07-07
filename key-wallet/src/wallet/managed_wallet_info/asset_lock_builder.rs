//! Asset lock transaction builder.
//!
//! Builds a Core special transaction (type 8) with `AssetLockPayload` that
//! locks Dash for Platform credits.

use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::{Transaction, TxOut};
use secp256k1::PublicKey;
use std::fmt;

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::ManagedCoreKeysAccount;
use crate::signer::Signer;
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
    /// The specified BIP44 account was not found.
    AccountNotFound(u32),
    /// No change address available.
    NoChangeAddress,
    /// An explicit override funding UTXO was supplied but is not final
    /// (neither confirmed nor InstantSend-locked). Asset locks must be funded
    /// by a final input per DIP-0010, so this is surfaced as a distinct caller
    /// error rather than silently filtered out of coin selection.
    OverrideInputNotFinal,
    /// An explicit override funding UTXO's `address` and `txout.script_pubkey`
    /// disagree. Signing derives the key from `address` but signs over
    /// `script_pubkey`, so a mismatched pair is rejected up front rather than
    /// producing an account-key signature over an unrelated script.
    OverrideInputScriptMismatch,
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
            Self::AccountNotFound(idx) => write!(f, "BIP44 account {} not found", idx),
            Self::NoChangeAddress => write!(f, "No change address available"),
            Self::OverrideInputNotFinal => {
                write!(
                    f,
                    "Override funding UTXO is not final (not confirmed or InstantSend-locked)"
                )
            }
            Self::OverrideInputScriptMismatch => {
                write!(f, "Override funding UTXO's address does not match its script_pubkey")
            }
            Self::Builder(e) => write!(f, "Transaction builder error: {e}"),
        }
    }
}

impl std::error::Error for AssetLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Builder(e) => Some(e),
            _ => None,
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

impl ManagedWalletInfo {
    /// Build and sign an asset lock transaction.
    ///
    /// Creates a special transaction (type 8) with `AssetLockPayload` that locks
    /// Dash for Platform credits. Derives one unique private key per credit output.
    ///
    /// The transaction is built first, and keys are only derived after a successful
    /// build — so no addresses are consumed if the build fails.
    pub async fn build_asset_lock(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        credit_output_fundings: Vec<CreditOutputFunding>,
        fee_per_kb: u64,
    ) -> Result<AssetLockResult, AssetLockError> {
        // Surface watch-only / no-private-key wallets here so we don't reserve
        // a change index before the build can possibly succeed.
        let root_xpriv =
            wallet.root_extended_priv_key().map_err(|_| AssetLockError::WatchOnlyWallet)?.clone();

        let network = self.network;
        let height = self.last_processed_height();

        let acc = &wallet
            .get_bip44_account(account_index)
            .ok_or(AssetLockError::AccountNotFound(account_index))?;

        let funds_acc = self
            .accounts
            .standard_bip44_accounts
            .get_mut(&account_index)
            .ok_or(AssetLockError::AccountNotFound(account_index))?;

        let credit_outputs: Vec<TxOut> =
            credit_output_fundings.iter().map(|f| f.output.clone()).collect();

        // Build first, derive credit keys after — a build failure must not
        // consume any funding-key indices.
        let (transaction, fee) = TransactionBuilder::new()
            .set_fee_rate(FeeRate::new(fee_per_kb))
            .set_current_height(height)
            .set_special_payload(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(
                credit_outputs,
            )))
            .set_funding(funds_acc, acc)
            .require_final_inputs()
            .build_signed(wallet, |addr| funds_acc.address_derivation_path(&addr))
            .await?;

        // Derive one private key per credit output.
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

        Ok(AssetLockResult {
            transaction,
            fee,
            keys: AssetLockCreditKeys::Private(keys),
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
    /// # Funding source
    ///
    /// - `override_utxo: None` funds the lock via the account's own UTXO set
    ///   and the automatic coin selector, exactly as the default path always
    ///   has.
    /// - `override_utxo: Some(utxo)` makes `utxo` the *only* candidate,
    ///   bypassing the account UTXO set entirely. The flags on `utxo` are
    ///   trusted verbatim: this method performs no on-chain verification that
    ///   the coin is genuinely unspent — that is the caller's responsibility.
    ///   Change and reservation handling are identical to the default path.
    ///
    /// # Errors
    ///
    /// With an `override_utxo`, returns [`AssetLockError::OverrideInputNotFinal`]
    /// if it is neither confirmed nor InstantSend-locked (asset locks require a
    /// final funding input per DIP-0010), or
    /// [`AssetLockError::OverrideInputScriptMismatch`] if its `address` and
    /// `txout.script_pubkey` disagree.
    pub async fn build_asset_lock_with_signer<S: Signer>(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        credit_output_fundings: Vec<CreditOutputFunding>,
        fee_per_kb: u64,
        signer: &S,
        override_utxo: Option<crate::Utxo>,
    ) -> Result<AssetLockResult, AssetLockError> {
        let height = self.last_processed_height();

        let acc = wallet
            .get_bip44_account(account_index)
            .ok_or(AssetLockError::AccountNotFound(account_index))?
            .clone();

        let funds_acc = self
            .accounts
            .standard_bip44_accounts
            .get_mut(&account_index)
            .ok_or(AssetLockError::AccountNotFound(account_index))?;

        let credit_outputs: Vec<TxOut> =
            credit_output_fundings.iter().map(|f| f.output.clone()).collect();

        let builder = TransactionBuilder::new()
            .set_fee_rate(FeeRate::new(fee_per_kb))
            .set_current_height(height)
            .set_special_payload(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(
                credit_outputs,
            )));

        let builder = match override_utxo {
            Some(utxo) => {
                // Signing derives the key from `utxo.address` but signs over
                // `utxo.txout.script_pubkey`; reject a mismatched pair so an
                // account-derivable address can never sign an unrelated script.
                if utxo.address.script_pubkey() != utxo.txout.script_pubkey {
                    return Err(AssetLockError::OverrideInputScriptMismatch);
                }
                // Reject a non-final override eagerly and distinctly instead of
                // letting `require_final_inputs` silently filter it into a
                // generic insufficient-funds failure.
                if !(utxo.is_confirmed || utxo.is_instantlocked) {
                    return Err(AssetLockError::OverrideInputNotFinal);
                }
                builder.set_funding_with_inputs(funds_acc, &acc, [utxo])
            }
            None => builder.set_funding(funds_acc, &acc),
        };

        let (transaction, fee) = builder
            .require_final_inputs()
            .build_signed(signer, |addr| funds_acc.address_derivation_path(&addr))
            .await?;

        // Credit-output bookkeeping: for each funding, peek the next unused
        // path on its account, ask the signer for the matching pubkey, and
        // only mark the index used once the signer has succeeded.
        //
        // This protects against a signer failure mid-loop leaving earlier
        // fundings' pool indices irreversibly consumed: if `public_key`
        // errors, the current funding's index is still free, and no
        // subsequent fundings have touched their pools yet.
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

        Ok(AssetLockResult {
            transaction,
            fee,
            keys: AssetLockCreditKeys::Public(credit_output_keys),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{ExtendedPubKeySigner, SignerMethod};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::{Network, Utxo};
    use dashcore::{Address, OutPoint, ScriptBuf, Txid};
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

    /// Build an override `Utxo` at a fresh account-0 receive address but
    /// deliberately do **not** insert it into `funds_acc.utxos`: the override
    /// path must accept a coin the local index has never seen. The address is a
    /// real, derivable account address so the signer can sign for it
    /// end-to-end.
    fn make_override_utxo(
        info: &mut ManagedWalletInfo,
        wallet: &Wallet,
        txid_byte: u8,
        value: u64,
        is_confirmed: bool,
        is_instantlocked: bool,
    ) -> Utxo {
        let account_xpub = wallet.get_bip44_account(0).unwrap().account_xpub;
        let account = info.accounts.standard_bip44_accounts.get_mut(&0).unwrap();
        let funding_address = account.next_receive_address(Some(&account_xpub), true).unwrap();
        Utxo {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([txid_byte; 32]),
                vout: 0,
            },
            txout: TxOut {
                value,
                script_pubkey: funding_address.script_pubkey(),
            },
            address: funding_address,
            height: 1000,
            is_coinbase: false,
            is_confirmed,
            is_instantlocked,
            is_locked: false,
            is_trusted: false,
        }
    }

    /// A signer backed by the test wallet's own root key — signs for any address
    /// the funding account can derive a path for.
    fn in_memory_signer(wallet: &Wallet) -> InMemorySigner {
        let root = match &wallet.wallet_type {
            crate::wallet::WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.clone(),
            _ => unreachable!("test_wallet_and_info produces a mnemonic wallet"),
        };
        InMemorySigner {
            root,
            network: Network::Testnet,
        }
    }

    /// Reserved outpoints held by account 0 at `height`.
    fn reserved_outpoints(
        info: &ManagedWalletInfo,
        height: u32,
    ) -> std::collections::HashSet<OutPoint> {
        info.accounts.standard_bip44_accounts.get(&0).unwrap().reservations().reserved(height)
    }

    // -- Error type tests --

    #[test]
    fn test_error_display() {
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

    #[tokio::test]
    async fn test_empty_credit_outputs_rejected() {
        let (wallet, mut info) = test_wallet_and_info();
        let result = info.build_asset_lock(&wallet, 0, vec![], 1000).await;
        assert!(matches!(result, Err(AssetLockError::Builder(BuilderError::NoOutputs))));
    }

    #[tokio::test]
    async fn test_invalid_account_index() {
        let (wallet, mut info) = test_wallet_and_info();
        let result =
            info.build_asset_lock(&wallet, 99, test_credit_outputs(&[100_000]), 1000).await;
        assert!(matches!(result, Err(AssetLockError::AccountNotFound(99))));
    }

    #[tokio::test]
    async fn test_insufficient_funds() {
        // Wallet has no UTXOs, so coin selection should fail
        let (wallet, mut info) = test_wallet_and_info();
        let result = info.build_asset_lock(&wallet, 0, test_credit_outputs(&[500_000]), 1000).await;
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

        let result = info.build_asset_lock(&wallet, 0, test_credit_outputs(&[200_000]), 1000).await;
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
            .build_asset_lock(&wallet, 0, test_credit_outputs(&[200_000]), 1000)
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
        let result =
            info.build_asset_lock_with_signer(&wallet, 0, vec![], 1000, &signer, None).await;
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
                99,
                test_credit_outputs(&[100_000]),
                1000,
                &signer,
                None,
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
                0,
                test_credit_outputs(&[100_000]),
                1000,
                &NoDigestSigner,
                None,
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
            .build_asset_lock_with_signer(&wallet, 0, fundings, 1000, &signer, None)
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
                0,
                test_credit_outputs(&[500_000]),
                1000,
                &signer,
                None,
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::Builder(_))),
            "Expected Builder error for insufficient funds, got: {:?}",
            result.err()
        );
    }

    // -- Explicit UTXO override tests --

    /// The override UTXO is the sole input; the auto-selector's candidate pool
    /// (the account's own UTXOs) is never consulted.
    #[tokio::test]
    async fn test_override_utxo_is_sole_input_ignoring_auto_selector_pool() {
        let (wallet, mut info) = test_wallet_and_info();
        // Three confirmed decoys, each alone sufficient for amount + fee.
        let decoy_a = insert_funded_utxo(&mut info, &wallet, 0x22, 1_000_000, true);
        let decoy_b = insert_funded_utxo(&mut info, &wallet, 0x23, 1_000_000, true);
        let decoy_c = insert_funded_utxo(&mut info, &wallet, 0x24, 1_000_000, true);
        let override_utxo = make_override_utxo(&mut info, &wallet, 0x77, 1_000_000, true, false);
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                0,
                test_credit_outputs(&[200_000]),
                1000,
                &signer,
                Some(override_utxo.clone()),
            )
            .await
            .expect("override funds the asset lock");

        assert_eq!(result.transaction.input.len(), 1, "override must be the sole input");
        assert_eq!(
            result.transaction.input[0].previous_output, override_utxo.outpoint,
            "the one input must be the override outpoint"
        );
        for decoy in [decoy_a, decoy_b, decoy_c] {
            assert!(
                result.transaction.input.iter().all(|i| i.previous_output != decoy),
                "a decoy from funds_acc.utxos leaked into the override build"
            );
        }
    }

    /// An override worth less than amount + fee fails with a typed builder error
    /// and does NOT silently fall back to the sufficient decoy; no reservation
    /// is left behind.
    #[tokio::test]
    async fn test_override_utxo_insufficient_value_returns_typed_error_not_auto_fallback() {
        let (wallet, mut info) = test_wallet_and_info();
        // A decoy that WOULD cover the lock if auto-selection ran.
        insert_funded_utxo(&mut info, &wallet, 0x22, 5_000_000, true);
        let override_utxo = make_override_utxo(&mut info, &wallet, 0x77, 1, true, false);
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                0,
                test_credit_outputs(&[200_000]),
                1000,
                &signer,
                Some(override_utxo),
            )
            .await;

        assert!(
            matches!(
                result,
                Err(AssetLockError::Builder(
                    BuilderError::InsufficientFunds { .. } | BuilderError::CoinSelection(_)
                ))
            ),
            "insufficient override must surface a typed builder error, not fall back to the decoy; got {:?}",
            result.err()
        );
        assert!(
            reserved_outpoints(&info, 1100).is_empty(),
            "a failed build must not leave any UTXO reserved"
        );
    }

    /// With `override_utxo: None`, behaviour is byte-for-byte the legacy
    /// auto-selection path: only the confirmed UTXO is spent (mirror of
    /// `test_selects_only_final_funding`).
    #[tokio::test]
    async fn test_no_override_auto_selection_behavior_unchanged() {
        let (wallet, mut info) = test_wallet_and_info();
        let confirmed = insert_funded_utxo(&mut info, &wallet, 0x22, 1_000_000, true);
        insert_funded_utxo(&mut info, &wallet, 0x33, 5_000_000, false);
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                0,
                test_credit_outputs(&[200_000]),
                1000,
                &signer,
                None,
            )
            .await
            .expect("confirmed funds should cover the asset lock");

        assert!(!result.transaction.input.is_empty());
        for txin in &result.transaction.input {
            assert_eq!(txin.previous_output, confirmed, "auto-selection spent a non-final input");
        }
    }

    /// `override_utxo: None` still derives a change address and reserves the
    /// spent input, exactly as `set_funding` does today.
    #[tokio::test]
    async fn test_no_override_still_derives_change_address_and_reserves_inputs() {
        let (wallet, mut info) = test_wallet_and_info();
        let funded = insert_funded_utxo(&mut info, &wallet, 0x22, 1_000_000, true);
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                0,
                test_credit_outputs(&[200_000]),
                1000,
                &signer,
                None,
            )
            .await
            .expect("build should succeed and produce change");

        // OP_RETURN burn + change output.
        assert_eq!(result.transaction.output.len(), 2, "expected burn + change output");
        let change = &result.transaction.output[1];
        assert!(change.value > 546, "change must exceed the dust threshold");
        assert!(
            reserved_outpoints(&info, 1100).contains(&funded),
            "the spent input must be reserved after a successful build"
        );
    }

    /// Regression guard: an override worth more than amount + fee + dust
    /// produces a real, account-controlled change output — not
    /// `NoChangeAddress`, not a burned excess.
    #[tokio::test]
    async fn test_override_utxo_still_produces_change_output() {
        let (wallet, mut info) = test_wallet_and_info();
        let override_value = 1_000_000u64;
        let override_utxo =
            make_override_utxo(&mut info, &wallet, 0x77, override_value, true, false);
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        let total_credit = 200_000u64;
        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                0,
                test_credit_outputs(&[total_credit]),
                1000,
                &signer,
                Some(override_utxo.clone()),
            )
            .await
            .expect("override with excess must produce change, not NoChangeAddress");

        assert_eq!(result.transaction.output.len(), 2, "expected burn + change output");
        let burn = &result.transaction.output[0];
        assert_eq!(burn.value, total_credit, "burn output must carry the total credit");
        let change = &result.transaction.output[1];
        assert!(change.value > 546, "change must exceed the dust threshold");

        // The on-chain fee is what's left after burn + change; it must be a
        // sane positive amount (excess was NOT burned as fee).
        let on_chain_fee = override_value - burn.value - change.value;
        assert!(
            (100..10_000).contains(&on_chain_fee),
            "unexpected fee {on_chain_fee}: excess may have been burned instead of returned as change"
        );

        // Change pays an account-derivable address, distinct from the override's
        // own script.
        let change_addr = Address::from_script(&change.script_pubkey, Network::Testnet)
            .expect("change output is a standard address");
        let funds_acc = info.accounts.standard_bip44_accounts.get(&0).unwrap();
        assert!(
            funds_acc.address_derivation_path(&change_addr).is_some(),
            "change must pay an address the funding account controls"
        );
        assert_ne!(
            change.script_pubkey, override_utxo.txout.script_pubkey,
            "change must not reuse the override UTXO's own script"
        );
    }

    /// The override outpoint is reserved after a successful build, and a second
    /// build reusing it fails at selection (the reserved filter removes it),
    /// leaving the first build's reservation intact.
    #[tokio::test]
    async fn test_override_utxo_still_reserved_after_successful_build() {
        let (wallet, mut info) = test_wallet_and_info();
        let override_utxo = make_override_utxo(&mut info, &wallet, 0x77, 1_000_000, true, false);
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        info.build_asset_lock_with_signer(
            &wallet,
            0,
            test_credit_outputs(&[200_000]),
            1000,
            &signer,
            Some(override_utxo.clone()),
        )
        .await
        .expect("first build succeeds");

        assert!(
            reserved_outpoints(&info, 1100).contains(&override_utxo.outpoint),
            "override outpoint must be reserved after the first build"
        );

        // Reusing the same override outpoint: the reserved filter empties the
        // candidate pool, so selection fails.
        let second = info
            .build_asset_lock_with_signer(
                &wallet,
                0,
                test_credit_outputs(&[200_000]),
                1000,
                &signer,
                Some(override_utxo.clone()),
            )
            .await;
        assert!(
            matches!(second, Err(AssetLockError::Builder(_))),
            "a second build reusing a reserved override must not double-spend it; got {:?}",
            second.err()
        );
        assert!(
            reserved_outpoints(&info, 1100).contains(&override_utxo.outpoint),
            "the first build's reservation must survive the failed second build"
        );
    }

    /// A non-final override (`is_confirmed == false && is_instantlocked ==
    /// false`) is rejected eagerly with the distinct `OverrideInputNotFinal`
    /// error, NOT silently filtered into a generic insufficient-funds failure.
    ///
    /// Contract: the override mechanism trusts the caller-supplied finality
    /// flags at face value — it performs no independent on-chain verification;
    /// that is the caller's (DET's oracle) responsibility. A non-final flag is a
    /// distinct, deliberate caller error.
    #[tokio::test]
    async fn test_override_utxo_not_final_rejected_with_typed_error() {
        let (wallet, mut info) = test_wallet_and_info();
        let override_utxo = make_override_utxo(&mut info, &wallet, 0x77, 1_000_000, false, false);
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                0,
                test_credit_outputs(&[200_000]),
                1000,
                &signer,
                Some(override_utxo),
            )
            .await;

        assert!(
            matches!(result, Err(AssetLockError::OverrideInputNotFinal)),
            "a non-final override must be rejected with OverrideInputNotFinal; got {:?}",
            result.err()
        );
    }

    /// An override whose outpoint is absent from `funds_acc.utxos` is accepted
    /// at face value: the override path must not require local-index presence
    /// (the very divergence the mitigation exists for).
    #[tokio::test]
    async fn test_override_utxo_absent_from_local_index_still_accepted() {
        let (wallet, mut info) = test_wallet_and_info();
        let override_utxo = make_override_utxo(&mut info, &wallet, 0x77, 1_000_000, true, false);
        // Confirm it is genuinely absent from the local UTXO index.
        assert!(
            !info
                .accounts
                .standard_bip44_accounts
                .get(&0)
                .unwrap()
                .utxos
                .contains_key(&override_utxo.outpoint),
            "override outpoint must not be present in the local index for this test"
        );
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                0,
                test_credit_outputs(&[200_000]),
                1000,
                &signer,
                Some(override_utxo.clone()),
            )
            .await
            .expect("override absent from the local index must still be accepted");

        assert_eq!(result.transaction.input.len(), 1);
        assert_eq!(result.transaction.input[0].previous_output, override_utxo.outpoint);
    }

    /// Empty credit outputs are still rejected with `NoOutputs`, even when an
    /// override is supplied: override plumbing must not short-circuit earlier
    /// output validation.
    #[tokio::test]
    async fn test_override_empty_credit_outputs_still_rejected() {
        let (wallet, mut info) = test_wallet_and_info();
        let override_utxo = make_override_utxo(&mut info, &wallet, 0x77, 1_000_000, true, false);
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        let result = info
            .build_asset_lock_with_signer(&wallet, 0, vec![], 1000, &signer, Some(override_utxo))
            .await;
        assert!(matches!(result, Err(AssetLockError::Builder(BuilderError::NoOutputs))));
    }

    /// A nonexistent account index is still rejected with `AccountNotFound`
    /// before the override is ever consulted.
    #[tokio::test]
    async fn test_override_invalid_account_index_still_rejected() {
        let (wallet, mut info) = test_wallet_and_info();
        let override_utxo = make_override_utxo(&mut info, &wallet, 0x77, 1_000_000, true, false);
        let signer = in_memory_signer(&wallet);

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                99,
                test_credit_outputs(&[100_000]),
                1000,
                &signer,
                Some(override_utxo),
            )
            .await;
        assert!(matches!(result, Err(AssetLockError::AccountNotFound(99))));
    }

    /// An override whose `address` and `txout.script_pubkey` disagree is
    /// rejected up front with `OverrideInputScriptMismatch` — an
    /// account-derivable address must never sign over an unrelated script.
    #[tokio::test]
    async fn test_override_utxo_script_mismatch_rejected() {
        let (wallet, mut info) = test_wallet_and_info();
        let mut override_utxo =
            make_override_utxo(&mut info, &wallet, 0x77, 1_000_000, true, false);
        // Corrupt the script so it no longer matches the (account-derivable)
        // address the key would be derived from.
        override_utxo.txout.script_pubkey = Address::dummy(Network::Testnet, 5).script_pubkey();
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                0,
                test_credit_outputs(&[200_000]),
                1000,
                &signer,
                Some(override_utxo),
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::OverrideInputScriptMismatch)),
            "address/script mismatch must be rejected with OverrideInputScriptMismatch; got {:?}",
            result.err()
        );
    }

    /// An override whose address is not derivable by the funding account (a coin
    /// from a different wallet) fails closed at signing with a typed error and
    /// strands no reservation — the finality/script guards trust caller flags,
    /// so ownership is enforced downstream by the signer's path resolver.
    #[tokio::test]
    async fn test_override_utxo_foreign_address_fails_at_signing_without_reservation() {
        let (wallet, mut info) = test_wallet_and_info();

        // A confirmed override at an address derived from an unrelated wallet:
        // internally consistent (its own address matches its own script) so it
        // clears the eager guards, but unknown to `funds_acc`, so no derivation
        // path resolves for it during signing.
        let (foreign_wallet, mut foreign_info) = test_wallet_and_info();
        let foreign_xpub = foreign_wallet.get_bip44_account(0).unwrap().account_xpub;
        let foreign_address = foreign_info
            .accounts
            .standard_bip44_accounts
            .get_mut(&0)
            .unwrap()
            .next_receive_address(Some(&foreign_xpub), true)
            .unwrap();
        let override_utxo = Utxo {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([0x99; 32]),
                vout: 0,
            },
            txout: TxOut {
                value: 1_000_000,
                script_pubkey: foreign_address.script_pubkey(),
            },
            address: foreign_address,
            height: 1000,
            is_coinbase: false,
            is_confirmed: true,
            is_instantlocked: false,
            is_locked: false,
            is_trusted: false,
        };
        info.update_last_processed_height(1100);
        let signer = in_memory_signer(&wallet);

        let result = info
            .build_asset_lock_with_signer(
                &wallet,
                0,
                test_credit_outputs(&[200_000]),
                1000,
                &signer,
                Some(override_utxo),
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::Builder(BuilderError::SigningFailed(_)))),
            "a foreign-account override must fail closed at signing; got {:?}",
            result.err()
        );
        assert!(
            reserved_outpoints(&info, 1100).is_empty(),
            "a signing failure must strand no reservation"
        );
    }
}
