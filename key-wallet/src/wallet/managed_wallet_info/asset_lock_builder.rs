//! Asset lock transaction builder.
//!
//! Builds a Core special transaction (type 8) with `AssetLockPayload` that
//! locks Dash for Platform credits.

use dashcore::blockdata::script::{Builder, PushBytes};
use dashcore::sighash::{EcdsaSighashType, SighashCache};
use dashcore::{Address, ScriptBuf, Transaction, TxOut};
use dashcore_hashes::Hash;
use secp256k1::PublicKey;
use std::collections::HashMap;
use std::fmt;

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::ManagedCoreFundsAccount;
use crate::signer::{Signer, SignerMethod};
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
    /// The external signer reported an error.
    Signer(String),
    /// Signing produced an unexpected state (e.g. input without a known path).
    SigningFailed(String),
    /// The signer does not advertise a method required by this build path.
    UnsupportedSignerMethod(SignerMethod),
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
            Self::Signer(msg) => write!(f, "Signer error: {msg}"),
            Self::SigningFailed(msg) => write!(f, "Signing failed: {msg}"),
            Self::UnsupportedSignerMethod(m) => {
                write!(f, "Signer does not support required method {m:?}")
            }
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
) -> Result<&mut ManagedCoreFundsAccount, AssetLockError> {
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
        for pool in funding_account.managed_account_type().address_pools() {
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

        let last_processed_height = self.last_processed_height();

        // Separate credit outputs from funding specs
        let credit_outputs: Vec<TxOut> =
            credit_output_fundings.iter().map(|f| f.output.clone()).collect();

        // Build the transaction FIRST — before deriving keys.
        // This ensures no addresses are consumed if the build fails.
        //
        // Per DIP-00X (AssetLockTx), `tx.output[0]` must be an OP_RETURN
        // burn carrying the total amount being locked — this is what
        // "destroys" the Dash coins on the L1 chain. The credit outputs
        // themselves live only in the special transaction payload; they
        // describe where the resulting Platform credits are delivered.
        //
        // The previous implementation added the credit outputs as raw
        // `tx.output` entries (and duplicated them in the payload),
        // producing a structurally-invalid asset lock transaction that
        // masternodes refused to IS-lock.
        let total_credit: u64 = credit_outputs.iter().map(|o| o.value).sum();
        let burn_output = TxOut {
            value: total_credit,
            script_pubkey: ScriptBuf::new_op_return(&[]),
        };

        let tx_builder = TransactionBuilder::new()
            .set_change_address(change_address)
            .set_fee_rate(FeeRate::new(fee_per_kb))
            .add_raw_output(burn_output);

        let tx_builder_with_inputs = tx_builder.select_inputs(
            &utxos,
            SelectionStrategy::BranchAndBound,
            last_processed_height,
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
    pub async fn build_asset_lock_with_signer<S: Signer>(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        credit_output_fundings: Vec<CreditOutputFunding>,
        fee_per_kb: u64,
        signer: &S,
    ) -> Result<AssetLockResult, AssetLockError> {
        if credit_output_fundings.is_empty() {
            return Err(AssetLockError::NoCreditOutputs);
        }

        // This build path drives signing via pre-computed P2PKH sighashes,
        // so the signer must support blind digest signing. Signers that
        // only advertise transaction-level signing (typical of hardware
        // wallets) need a future build path that hands them the full tx.
        if !signer.supports(SignerMethod::Digest) {
            return Err(AssetLockError::UnsupportedSignerMethod(SignerMethod::Digest));
        }

        // UTXOs and address→path map from the funding account.
        let funding_account = self
            .accounts
            .standard_bip44_accounts
            .get(&account_index)
            .ok_or(AssetLockError::AccountNotFound(account_index))?;

        let utxos: Vec<Utxo> = funding_account.utxos.values().cloned().collect();
        let mut address_to_path: HashMap<Address, DerivationPath> = HashMap::new();
        for pool in funding_account.managed_account_type().address_pools() {
            for addr_info in pool.addresses.values() {
                address_to_path.insert(addr_info.address.clone(), addr_info.path.clone());
            }
        }

        // Next change address — derivable from the account xpub, no signing key needed.
        let xpub = wallet.get_bip44_account(account_index).map(|a| a.account_xpub);
        let change_address = self
            .accounts
            .standard_bip44_accounts
            .get_mut(&account_index)
            .and_then(|account| account.next_change_address(xpub.as_ref(), true).ok())
            .ok_or(AssetLockError::NoChangeAddress)?;

        let last_processed_height = self.last_processed_height();

        let credit_outputs: Vec<TxOut> =
            credit_output_fundings.iter().map(|f| f.output.clone()).collect();

        // Same burn-output shape as the soft-wallet path: tx.output[0] is an
        // OP_RETURN burn carrying the total locked amount, credit outputs
        // live only in the payload. See build_asset_lock for details.
        let total_credit: u64 = credit_outputs.iter().map(|o| o.value).sum();
        let burn_output = TxOut {
            value: total_credit,
            script_pubkey: ScriptBuf::new_op_return(&[]),
        };

        // Build the transaction WITHOUT keys — TransactionBuilder's internal
        // signer is skipped when every input's key is None, producing an
        // unsigned tx we then sign ourselves via the Signer.
        let tx_builder = TransactionBuilder::new()
            .set_change_address(change_address)
            .set_fee_rate(FeeRate::new(fee_per_kb))
            .add_raw_output(burn_output);

        let tx_builder_with_inputs = tx_builder.select_inputs(
            &utxos,
            SelectionStrategy::BranchAndBound,
            last_processed_height,
            |_utxo| None,
        )?;

        let outputs_count_before = tx_builder_with_inputs.outputs().len();
        let fee = tx_builder_with_inputs.calculate_fee();
        let fee_with_extra = tx_builder_with_inputs.calculate_fee_with_extra_output();

        let mut transaction = tx_builder_with_inputs.build_asset_lock(credit_outputs)?;

        let actual_fee = if transaction.output.len() > outputs_count_before {
            fee_with_extra
        } else {
            fee
        };

        // Map each input back to its prev-txout via UTXO outpoint so we can
        // compute the legacy P2PKH sighash and look up its derivation path.
        let utxo_by_outpoint: HashMap<_, _> =
            utxos.iter().map(|u| (u.outpoint, u.clone())).collect();

        let mut scripts: Vec<ScriptBuf> = Vec::with_capacity(transaction.input.len());
        {
            let cache = SighashCache::new(&transaction);
            for (index, txin) in transaction.input.iter().enumerate() {
                let utxo = utxo_by_outpoint.get(&txin.previous_output).ok_or_else(|| {
                    AssetLockError::SigningFailed(format!(
                        "selected UTXO {:?} not found in funding account",
                        txin.previous_output
                    ))
                })?;
                let path = address_to_path.get(&utxo.address).ok_or_else(|| {
                    AssetLockError::SigningFailed(format!(
                        "no derivation path for input address {}",
                        utxo.address
                    ))
                })?;

                let sighash = cache
                    .legacy_signature_hash(
                        index,
                        &utxo.txout.script_pubkey,
                        EcdsaSighashType::All.to_u32(),
                    )
                    .map_err(|e| {
                        AssetLockError::SigningFailed(format!(
                            "failed to compute sighash for input {index}: {e}"
                        ))
                    })?;

                let (sig, pubkey) = signer
                    .sign_ecdsa(path, *sighash.as_byte_array())
                    .await
                    .map_err(|e| AssetLockError::Signer(e.to_string()))?;

                let mut sig_bytes = sig.serialize_der().to_vec();
                sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);

                let script_sig = Builder::new()
                    .push_slice(<&PushBytes>::try_from(sig_bytes.as_slice()).map_err(|_| {
                        AssetLockError::SigningFailed("invalid signature length".into())
                    })?)
                    .push_slice(pubkey.serialize())
                    .into_script();

                scripts.push(script_sig);
            }
        }
        for (index, script_sig) in scripts.into_iter().enumerate() {
            transaction.input[index].script_sig = script_sig;
        }

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
            fee: actual_fee,
            keys: AssetLockCreditKeys::Public(credit_output_keys),
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
        let info = ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);
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
        let result = info.build_asset_lock_with_signer(&wallet, 0, vec![], 1000, &signer).await;
        assert!(matches!(result, Err(AssetLockError::NoCreditOutputs)));
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
            )
            .await;
        assert!(matches!(
            result,
            Err(AssetLockError::UnsupportedSignerMethod(SignerMethod::Digest))
        ));
    }

    #[tokio::test]
    async fn test_signer_happy_path_end_to_end() {
        use crate::Utxo;
        use dashcore::{OutPoint, TxOut, Txid};

        let (wallet, mut info) = test_wallet_and_info();
        let root = match &wallet.wallet_type {
            crate::wallet::WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.clone(),
            _ => unreachable!(),
        };

        // Generate a receive address on account 0 and fund it with a
        // real UTXO at that address — coin selection needs a confirmed,
        // spendable output the signer can sign for.
        let account_xpub = wallet.get_bip44_account(0).unwrap().account_xpub;
        let funding_address = info
            .accounts
            .standard_bip44_accounts
            .get_mut(&0)
            .unwrap()
            .next_receive_address(Some(&account_xpub), true)
            .unwrap();

        let utxo = Utxo {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            txout: TxOut {
                value: 1_000_000,
                script_pubkey: funding_address.script_pubkey(),
            },
            address: funding_address,
            height: 1000,
            is_coinbase: false,
            is_confirmed: true,
            is_instantlocked: false,
            is_locked: false,
            is_trusted: false,
        };
        info.accounts
            .standard_bip44_accounts
            .get_mut(&0)
            .unwrap()
            .utxos
            .insert(utxo.outpoint, utxo);
        info.update_last_processed_height(1100);

        let signer = InMemorySigner {
            root,
            network: Network::Testnet,
        };

        let credit_amounts = [200_000u64, 300_000u64];
        let fundings = test_credit_outputs(&credit_amounts);
        let result = info
            .build_asset_lock_with_signer(&wallet, 0, fundings, 1000, &signer)
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
            )
            .await;
        assert!(
            matches!(result, Err(AssetLockError::Builder(_))),
            "Expected Builder error for insufficient funds, got: {:?}",
            result.err()
        );
    }
}
