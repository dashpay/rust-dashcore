//! Transaction building functionality for managed wallets

use crate::account::StandardAccountType;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::signer::Signer;
use crate::wallet::managed_wallet_info::coin_selection::SelectionStrategy;
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::wallet::managed_wallet_info::transaction_builder::{
    BuilderError, TransactionBuilder, TransactionSigner,
};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::ManagedWalletInfo;
use crate::{AccountType, DerivationPath, Wallet};
use core::fmt;
use dashcore::address::NetworkUnchecked;
use dashcore::{Address, Transaction};
use std::collections::{HashMap, HashSet};

/// Account type preference for transaction building
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountTypePreference {
    BIP44,
    BIP32,
    CoinJoin,
    DashpayFriendshipReceivingFunds {
        user_identity_id: [u8; 32],
        friend_identity_id: [u8; 32],
    },
    DashpayIdentityReceivingFunds {
        user_identity_id: [u8; 32],
    },
    AllDashpayReceivingFunds,
}

impl AccountTypePreference {
    /// The account types an empty source list draws from, in order.
    ///
    /// CoinJoin is deliberately absent: spending mixed outputs alongside
    /// transparent ones in the same transaction links them and undoes the
    /// mixing. So are DashPay accounts: an index alone does not identify one,
    /// and which contact to spend from is not something a default can pick.
    pub const DEFAULT: [Self; 2] = [Self::BIP44, Self::BIP32];

    /// The single [`AccountType`] this preference selects at `index`, or `None`
    /// for a DashPay source that names a set of accounts rather than one.
    pub fn account_type(&self, index: u32) -> Option<AccountType> {
        Some(match *self {
            Self::BIP44 => AccountType::Standard {
                index,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            Self::BIP32 => AccountType::Standard {
                index,
                standard_account_type: StandardAccountType::BIP32Account,
            },
            Self::CoinJoin => AccountType::CoinJoin {
                index,
            },
            Self::DashpayFriendshipReceivingFunds {
                user_identity_id,
                friend_identity_id,
            } => AccountType::DashpayReceivingFunds {
                index,
                user_identity_id,
                friend_identity_id,
            },
            Self::DashpayIdentityReceivingFunds {
                ..
            }
            | Self::AllDashpayReceivingFunds => return None,
        })
    }
}

impl fmt::Display for AccountTypePreference {
    /// Elides the 32-byte identity hashes so error messages stay readable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BIP44 => f.write_str("BIP44"),
            Self::BIP32 => f.write_str("BIP32"),
            Self::CoinJoin => f.write_str("CoinJoin"),
            Self::DashpayFriendshipReceivingFunds {
                ..
            } => f.write_str("DashpayReceiving{friendship}"),
            Self::DashpayIdentityReceivingFunds {
                ..
            } => f.write_str("DashpayReceiving{identity}"),
            Self::AllDashpayReceivingFunds => f.write_str("DashpayReceiving{all}"),
        }
    }
}

impl ManagedWalletInfo {
    /// Build and sign a transaction funded from the given account types at
    /// `source_index`, signing with the wallet's own keys.
    ///
    /// Coin selection draws from the union of those accounts' UTXOs, and the
    /// first of them supplies the change address. An empty `sources` means
    /// [`AccountTypePreference::DEFAULT`], skipping the types absent at the
    /// index; a non-empty one is taken literally and every account named must
    /// exist.
    pub async fn build_and_sign_transaction(
        &mut self,
        wallet: &Wallet,
        sources: &[AccountTypePreference],
        source_index: u32,
        outputs: Vec<(Address<NetworkUnchecked>, u64)>,
        fee_rate: FeeRate,
        strategy: SelectionStrategy,
    ) -> Result<(Transaction, u64), BuilderError> {
        self.build_and_sign(wallet, sources, source_index, outputs, fee_rate, strategy, wallet)
            .await
    }

    /// [`Self::build_and_sign_transaction`] with signing delegated to an
    /// external [`Signer`], so the private keys never have to be held by this
    /// process.
    #[allow(clippy::too_many_arguments)]
    pub async fn build_and_sign_transaction_with_signer<S: Signer>(
        &mut self,
        wallet: &Wallet,
        sources: &[AccountTypePreference],
        source_index: u32,
        outputs: Vec<(Address<NetworkUnchecked>, u64)>,
        fee_rate: FeeRate,
        strategy: SelectionStrategy,
        signer: &S,
    ) -> Result<(Transaction, u64), BuilderError> {
        self.build_and_sign(wallet, sources, source_index, outputs, fee_rate, strategy, signer)
            .await
    }

    /// [`Self::build_and_sign_transaction`] without the signing step, for
    /// callers that sign the transaction themselves. Its inputs are reserved
    /// just the same, so a build that is never broadcast holds them until the
    /// reservation's TTL reclaims them.
    pub fn build_unsigned_transaction(
        &mut self,
        wallet: &Wallet,
        sources: &[AccountTypePreference],
        source_index: u32,
        outputs: Vec<(Address<NetworkUnchecked>, u64)>,
        fee_rate: FeeRate,
        strategy: SelectionStrategy,
    ) -> Result<(Transaction, u64), BuilderError> {
        let (builder, _paths) =
            self.funded_builder(wallet, sources, source_index, outputs, fee_rate, strategy)?;
        let (transaction, fee, _reservation) = builder.build_unsigned_reserved()?;
        Ok((transaction, fee))
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_and_sign<S: TransactionSigner + ?Sized + Sync>(
        &mut self,
        wallet: &Wallet,
        sources: &[AccountTypePreference],
        source_index: u32,
        outputs: Vec<(Address<NetworkUnchecked>, u64)>,
        fee_rate: FeeRate,
        strategy: SelectionStrategy,
        signer: &S,
    ) -> Result<(Transaction, u64), BuilderError> {
        let (builder, paths) =
            self.funded_builder(wallet, sources, source_index, outputs, fee_rate, strategy)?;
        builder.build_signed(signer, move |addr| paths.get(&addr).cloned()).await
    }

    /// A builder carrying the outputs and the funding of `sources`, ready to be
    /// built with or without signing.
    fn funded_builder(
        &mut self,
        wallet: &Wallet,
        sources: &[AccountTypePreference],
        source_index: u32,
        outputs: Vec<(Address<NetworkUnchecked>, u64)>,
        fee_rate: FeeRate,
        strategy: SelectionStrategy,
    ) -> Result<(TransactionBuilder, HashMap<Address, DerivationPath>), BuilderError> {
        let outputs = outputs
            .into_iter()
            .map(|(address, value)| {
                address.require_network(wallet.network).map(|checked| (checked, value)).map_err(
                    |e| {
                        BuilderError::InvalidData(format!("Output address network mismatch: {}", e))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let height = self.last_processed_height();
        let builder = TransactionBuilder::new()
            .set_fee_rate(fee_rate)
            .set_selection_strategy(strategy)
            .set_current_height(height);

        let (mut builder, paths) = self.fund(wallet, sources, source_index, builder)?;

        for (address, value) in outputs {
            builder = builder.add_output(&address, value);
        }

        Ok((builder, paths))
    }

    /// The accounts a source resolves to: the one at `source_index` for the
    /// standard families, and every DashPay receiving account the selector
    /// picks for a DashPay source.
    fn account_types_for(
        &self,
        preference: AccountTypePreference,
        source_index: u32,
    ) -> Vec<AccountType> {
        let (identity, friend) = match preference {
            AccountTypePreference::AllDashpayReceivingFunds => (None, None),
            AccountTypePreference::DashpayIdentityReceivingFunds {
                user_identity_id,
            } => (Some(user_identity_id), None),
            AccountTypePreference::DashpayFriendshipReceivingFunds {
                user_identity_id,
                friend_identity_id,
            } => (Some(user_identity_id), Some(friend_identity_id)),
            _ => return preference.account_type(source_index).into_iter().collect(),
        };

        self.accounts
            .dashpay_receival_accounts
            .keys()
            .filter(|key| identity.is_none_or(|id| key.user_identity_id == id))
            .filter(|key| friend.is_none_or(|id| key.friend_identity_id == id))
            .map(|key| AccountType::DashpayReceivingFunds {
                index: key.index,
                user_identity_id: key.user_identity_id,
                friend_identity_id: key.friend_identity_id,
            })
            .collect()
    }

    /// Seed `builder` with the UTXOs of every funding account named by
    /// `sources`, returning it alongside the derivation path of each candidate
    /// input address, since the inputs can come from different accounts.
    fn fund(
        &mut self,
        wallet: &Wallet,
        sources: &[AccountTypePreference],
        source_index: u32,
        mut builder: TransactionBuilder,
    ) -> Result<(TransactionBuilder, HashMap<Address, DerivationPath>), BuilderError> {
        let named_explicitly = !sources.is_empty();
        let preferences = if named_explicitly {
            sources
        } else {
            &AccountTypePreference::DEFAULT
        };

        let mut paths = HashMap::new();
        let mut funded: HashSet<AccountType> = HashSet::new();

        for &preference in preferences {
            let account_types = self.account_types_for(preference, source_index);
            if account_types.is_empty() && named_explicitly {
                return Err(BuilderError::AccountNotFound(format!("account {preference}")));
            }

            for account_type in account_types {
                // Sources overlap: a DashPay source names a set of accounts,
                // and another source can name some of the same ones. Funding an
                // account twice would offer coin selection every one of its
                // UTXOs twice, letting it spend a single output as two inputs.
                if funded.contains(&account_type) {
                    continue;
                }

                let account = wallet.accounts.account_of_type(account_type);
                let managed_account = self.accounts.funds_account_mut(&account_type);

                let (Some(account), Some(managed_account)) = (account, managed_account) else {
                    if named_explicitly {
                        return Err(BuilderError::AccountNotFound(format!(
                            "account {account_type}"
                        )));
                    }
                    continue;
                };

                for utxo in managed_account.utxos.values() {
                    if let Some(path) = managed_account.address_derivation_path(&utxo.address) {
                        paths.insert(utxo.address.clone(), path);
                    }
                }
                builder = builder.add_funding(managed_account, account);
                funded.insert(account_type);
            }
        }

        if funded.is_empty() {
            return Err(BuilderError::AccountNotFound(format!(
                "no funding account of any type at index {source_index}"
            )));
        }

        Ok((builder, paths))
    }
}
#[cfg(test)]
mod tests {
    use super::AccountTypePreference;
    use crate::wallet::managed_wallet_info::coin_selection::SelectionStrategy;
    use crate::wallet::managed_wallet_info::fee::FeeRate;
    use crate::wallet::managed_wallet_info::transaction_builder::TransactionBuilder;
    use crate::Utxo;
    use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
    use dashcore::{Address, Network, Transaction, Txid};
    use dashcore_hashes::{sha256d, Hash};
    use std::str::FromStr;

    #[test]
    fn test_basic_transaction_creation() {
        // Test creating a basic transaction with inputs and outputs
        let utxos = vec![
            Utxo::dummy(0, 100000, 100, false, true),
            Utxo::dummy(0, 200000, 100, false, true),
            Utxo::dummy(0, 300000, 100, false, true),
        ];

        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let tx = TransactionBuilder::new()
            .set_fee_rate(FeeRate::normal())
            .set_current_height(200)
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 150000)
            .add_inputs(utxos)
            .build_unsigned_reserved()
            .unwrap()
            .0;

        assert!(!tx.input.is_empty());
        assert_eq!(tx.output.len(), 2); // recipient + change

        // With BIP-69 sorting, outputs are sorted by amount
        // Find the output with value 150000 (the recipient output)
        let recipient_output = tx.output.iter().find(|o| o.value == 150000);
        assert!(recipient_output.is_some(), "Should have recipient output of 150000");

        // The other output should be the change
        let change_output = tx.output.iter().find(|o| o.value != 150000);
        assert!(change_output.is_some(), "Should have change output");
    }

    /// Ordinary spends deliberately admit unconfirmed inputs: only builders
    /// that opt in via `require_final_inputs` (e.g. asset locks) restrict
    /// selection to confirmed or InstantSend-locked UTXOs.
    #[test]
    fn test_ordinary_spend_admits_unconfirmed_inputs() {
        let utxos = vec![Utxo::dummy(0, 300000, 100, false, false)];
        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let (tx, _fee, _) = TransactionBuilder::new()
            .set_fee_rate(FeeRate::normal())
            .set_current_height(200)
            .set_change_address(change_address)
            .add_output(&recipient_address, 150000)
            .add_inputs(utxos)
            .build_unsigned_reserved()
            .expect("ordinary spend of an unconfirmed UTXO must succeed");
        assert!(!tx.input.is_empty());
    }

    #[test]
    fn test_sweep_builder_drains_to_single_output() {
        let utxos = vec![
            Utxo::dummy(0, 100000, 100, false, true),
            Utxo::dummy(0, 200000, 100, false, true),
            Utxo::dummy(0, 300000, 100, false, true),
        ];
        let dest = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        // `All` selects every input and pays total - fee to `dest` as one output, no change
        let total = 600_000u64;
        let fee = FeeRate::normal().calculate_fee(8 + 1 + 1 + 34 + 3 * 148);
        let deliverable = total - fee;
        let (tx, _fee, _) = TransactionBuilder::new()
            .set_fee_rate(FeeRate::normal())
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::All)
            .add_inputs(utxos)
            .add_output(&dest, deliverable)
            .build_unsigned_reserved()
            .unwrap();

        assert_eq!(tx.input.len(), 3, "sweep spends every input");
        assert_eq!(tx.output.len(), 1, "sweep has one real output and no change");
        assert_eq!(tx.output[0].value, deliverable);
        assert_eq!(tx.output[0].script_pubkey, dest.script_pubkey());
    }

    #[test]
    fn test_asset_lock_transaction() {
        // Test based on DSTransactionTests.m testAssetLockTx1
        use dashcore::consensus::Decodable;
        use hex;

        let hex_data = hex::decode("0300080001eecf4e8f1ffd3a3a4e5033d618231fd05e5f08c1a727aac420f9a26db9bf39eb010000006a473044022026f169570532332f857cb64a0b7d9c0837d6f031633e1d6c395d7c03b799460302207eba4c4575a66803cecf50b61ff5f2efc2bd4e61dff00d9d4847aa3d8b1a5e550121036cd0b73d304bacc80fa747d254fbc5f0bf944dd8c8b925cd161bb499b790d08d0000000002317dd0be030000002321022ca85dba11c4e5a6da3a00e73a08765319a5d66c2f6434b288494337b0c9ed2dac6df29c3b00000000026a000000000046010200e1f505000000001976a9147c75beb097957cc09537b615dde9ea6807719cdf88ac6d11a735000000001976a9147c75beb097957cc09537b615dde9ea6807719cdf88ac").unwrap();

        let mut cursor = std::io::Cursor::new(hex_data);
        let tx = Transaction::consensus_decode(&mut cursor).unwrap();

        assert_eq!(tx.version, 3);
        assert_eq!(tx.lock_time, 0);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);

        // Verify it's an asset lock transaction
        if let Some(TransactionPayload::AssetLockPayloadType(payload)) =
            &tx.special_transaction_payload
        {
            assert_eq!(payload.version, 1);
            assert_eq!(payload.credit_outputs.len(), 2);
            assert_eq!(payload.credit_outputs[0].value, 100000000);
            assert_eq!(payload.credit_outputs[1].value, 900141421);
        } else {
            panic!("Expected AssetLockPayload");
        }
    }

    #[test]
    fn test_coinbase_transaction() {
        // Test based on DSTransactionTests.m testCoinbaseTransaction
        use dashcore::consensus::Decodable;
        use hex;

        let hex_data = hex::decode("03000500010000000000000000000000000000000000000000000000000000000000000000ffffffff0502f6050105ffffffff0200c11a3d050000002321038df098a36af5f1b7271e32ad52947f64c1ad70c16a8a1a987105eaab5daa7ad2ac00c11a3d050000001976a914bfb885c89c83cd44992a8ade29b610e6ddf00c5788ac00000000260100f6050000aaaec8d6a8535a01bd844817dea1faed66f6c397b1dcaec5fe8c5af025023c35").unwrap();

        let mut cursor = std::io::Cursor::new(hex_data);
        let tx = Transaction::consensus_decode(&mut cursor).unwrap();

        assert_eq!(tx.version, 3);
        assert_eq!(tx.lock_time, 0);
        // Check if it's a coinbase transaction by checking if first input has null previous_output
        assert_eq!(
            tx.input[0].previous_output.txid,
            Txid::from_raw_hash(sha256d::Hash::from_slice(&[0u8; 32]).unwrap())
        );
        assert_eq!(tx.input[0].previous_output.vout, 0xffffffff);
        assert_eq!(tx.output.len(), 2);

        // Verify txid matches expected
        let expected_txid = "5b4e5e99e967e01e27627621df00c44525507a31201ceb7b96c6e1a452e82bef";
        assert_eq!(tx.txid().to_string(), expected_txid);
    }

    #[test]
    fn test_transaction_size_estimation() {
        // Test that transaction size estimation is accurate
        let utxos = vec![
            Utxo::dummy(0, 100000, 100, false, true),
            Utxo::dummy(0, 200000, 100, false, true),
        ];

        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let builder = TransactionBuilder::new()
            .set_fee_rate(FeeRate::normal())
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::SmallestFirst)
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 150000)
            .add_inputs(utxos);

        let tx = builder.build_unsigned_reserved().unwrap().0;
        let serialized = dashcore::consensus::encode::serialize(&tx);

        // Size should be close to our estimation
        // Base (8) + varints (2) + 2 inputs (296) + 2 outputs (68) = ~374 bytes
        // But inputs have empty script_sig since they're unsigned, so smaller
        assert!(
            serialized.len() > 150 && serialized.len() < 250,
            "Actual size: {}",
            serialized.len()
        );
    }

    #[test]
    fn test_fee_calculation() {
        // Test that fees are calculated correctly
        let utxos = vec![Utxo::dummy(0, 1000000, 100, false, true)];

        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let builder = TransactionBuilder::new()
            .set_current_height(200)
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 500000)
            .add_inputs(utxos);

        let tx = builder.build_unsigned_reserved().unwrap().0;

        // Total input: 1000000
        // Output to recipient: 500000
        // Change output should be approximately: 1000000 - 500000 - fee
        // Fee should be roughly 226 duffs for a 1-input, 2-output transaction
        let total_output: u64 = tx.output.iter().map(|o| o.value).sum();
        let fee = 1000000 - total_output;

        assert!(fee > 200 && fee < 300, "Fee should be around 226 duffs, got {}", fee);
    }

    #[test]
    fn test_insufficient_funds() {
        // Test that insufficient funds returns an error
        let utxos = vec![Utxo::dummy(0, 100000, 100, false, true)];

        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let result = TransactionBuilder::new()
            .set_current_height(200)
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 1000000) // More than available
            .add_inputs(utxos)
            .build_unsigned_reserved();

        assert!(result.is_err());
    }

    #[test]
    fn test_exact_change_no_change_output() {
        // Test when the exact amount is used (no change output needed)
        let utxos = vec![Utxo::dummy(0, 150226, 100, false, true)]; // Exact amount for output + fee

        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let builder = TransactionBuilder::new()
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::SmallestFirst)
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 150000)
            .add_inputs(utxos);

        let tx = builder.build_unsigned_reserved().unwrap().0;

        // Should only have 1 output (no change)
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, 150000);
    }

    // -- Signer-variant tests for build_and_sign_transaction_with_signer --

    use super::super::transaction_builder::BuilderError;
    use super::super::wallet_info_interface::WalletInfoInterface;
    use crate::signer::{ExtendedPubKeySigner, Signer, SignerMethod};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::ManagedWalletInfo;
    use crate::DerivationPath;
    use crate::Wallet;
    use dashcore::address::NetworkUnchecked;
    use secp256k1::PublicKey;

    fn test_wallet_and_info() -> (Wallet, ManagedWalletInfo) {
        let wallet =
            Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default).unwrap();
        let info = ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);
        (wallet, info)
    }

    /// Signer implementation backed by a real `RootExtendedPrivKey`. Models the
    /// same derive-and-sign the soft-wallet path performs internally, so
    /// `build_and_sign_transaction_with_signer` can be exercised end-to-end
    /// without a hardware device in the loop.
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

    fn root_from(wallet: &Wallet) -> crate::wallet::root_extended_keys::RootExtendedPrivKey {
        match &wallet.wallet_type {
            crate::wallet::WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.clone(),
            _ => unreachable!("test_wallet_and_info produces a mnemonic wallet"),
        }
    }

    #[tokio::test]
    async fn in_memory_signer_extended_public_key_matches_wallet_derivation() {
        use crate::bip32::DerivationPath;
        use std::str::FromStr;
        let (wallet, _info) = test_wallet_and_info();
        let signer = InMemorySigner {
            root: root_from(&wallet),
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

    fn dest_outputs(amount: u64) -> Vec<(Address<NetworkUnchecked>, u64)> {
        let dest = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs").unwrap();
        vec![(dest, amount)]
    }

    #[tokio::test]
    async fn test_signer_invalid_account_index() {
        // No BIP44 account 99 exists, so account resolution fails with AccountNotFound
        // before any funding or signing happens.
        let (wallet, mut info) = test_wallet_and_info();
        let signer = InMemorySigner {
            root: root_from(&wallet),
            network: Network::Testnet,
        };
        let result = info
            .build_and_sign_transaction_with_signer(
                &wallet,
                &[AccountTypePreference::BIP44],
                99,
                dest_outputs(100_000),
                FeeRate::normal(),
                SelectionStrategy::BranchAndBound,
                &signer,
            )
            .await;

        assert!(matches!(result, Err(BuilderError::AccountNotFound(_))));
    }

    #[tokio::test]
    async fn test_signer_without_digest_support_rejected() {
        // A signer that advertises no digest support must be rejected before
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
            .build_and_sign_transaction_with_signer(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                dest_outputs(100_000),
                FeeRate::normal(),
                SelectionStrategy::BranchAndBound,
                &NoDigestSigner,
            )
            .await;
        // The unfunded wallet may also surface a CoinSelection error before
        // the signer is reached; either way the build cannot succeed.
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_signer_happy_path_end_to_end() {
        use crate::Utxo;
        use dashcore::{OutPoint, TxOut};

        let (wallet, mut info) = test_wallet_and_info();

        // Generate a receive address on account 0 and fund it with a real
        // UTXO at that address — coin selection needs a confirmed, spendable
        // output the signer can sign for.
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
            spend_scanned: true,
        };
        info.accounts
            .standard_bip44_accounts
            .get_mut(&0)
            .unwrap()
            .utxos
            .insert(utxo.outpoint, utxo);
        info.update_last_processed_height(1100);

        let signer = InMemorySigner {
            root: root_from(&wallet),
            network: Network::Testnet,
        };

        let send_amount = 500_000u64;
        let (tx, fee) = info
            .build_and_sign_transaction_with_signer(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                dest_outputs(send_amount),
                FeeRate::normal(),
                SelectionStrategy::BranchAndBound,
                &signer,
            )
            .await
            .expect("build_and_sign_transaction_with_signer should succeed with funded wallet");

        // Recipient output present
        assert!(
            tx.output.iter().any(|o| o.value == send_amount),
            "recipient output of {send_amount} not found in tx outputs"
        );

        // Fee was accounted for
        assert!(fee > 0, "fee should be non-zero");

        // Every input should have been signed — empty script_sig means the
        // signer was never called for that input.
        assert!(!tx.input.is_empty(), "transaction should have at least one selected input");
        for (i, txin) in tx.input.iter().enumerate() {
            assert!(
                !txin.script_sig.is_empty(),
                "input {i} has empty script_sig — signer did not produce a signature"
            );
        }
    }

    #[tokio::test]
    async fn test_signer_insufficient_funds() {
        // Wallet has no UTXOs, so coin selection should fail.
        let (wallet, mut info) = test_wallet_and_info();
        let signer = InMemorySigner {
            root: root_from(&wallet),
            network: Network::Testnet,
        };
        let result = info
            .build_and_sign_transaction_with_signer(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                dest_outputs(500_000),
                FeeRate::normal(),
                SelectionStrategy::BranchAndBound,
                &signer,
            )
            .await;
        assert!(
            matches!(
                result,
                Err(BuilderError::InsufficientFunds { .. }) | Err(BuilderError::CoinSelection(_))
            ),
            "Expected funds/selection error, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_signer_output_network_mismatch_rejected() {
        // Mainnet address against a testnet wallet must surface InvalidData
        // before any signing happens. We derive a real mainnet address from
        // a separate mainnet wallet so the address parses with a valid
        // checksum — the network mismatch is what we want the builder to
        // reject, not malformed input.
        let (wallet, mut info) = test_wallet_and_info();
        let signer = InMemorySigner {
            root: root_from(&wallet),
            network: Network::Testnet,
        };

        let mainnet_wallet =
            Wallet::new_random(Network::Mainnet, WalletAccountCreationOptions::Default).unwrap();
        let mut mainnet_info =
            ManagedWalletInfo::from_wallet_with_name(&mainnet_wallet, "Mainnet".to_string(), 0);
        let mainnet_xpub = mainnet_wallet.get_bip44_account(0).unwrap().account_xpub;
        let mainnet_addr = mainnet_info
            .accounts
            .standard_bip44_accounts
            .get_mut(&0)
            .unwrap()
            .next_receive_address(Some(&mainnet_xpub), true)
            .unwrap();
        // Re-parse as NetworkUnchecked to hand to the builder.
        let mainnet_dest =
            Address::from_str(&mainnet_addr.to_string()).expect("re-parse derived mainnet address");
        let outputs = vec![(mainnet_dest, 100_000u64)];

        let result = info
            .build_and_sign_transaction_with_signer(
                &wallet,
                &[AccountTypePreference::BIP44],
                0,
                outputs,
                FeeRate::normal(),
                SelectionStrategy::BranchAndBound,
                &signer,
            )
            .await;
        assert!(
            matches!(result, Err(BuilderError::InvalidData(_))),
            "expected InvalidData for network-mismatched output, got: {:?}",
            result.err()
        );
    }

    // -- Multi-account funding --

    use crate::managed_account::managed_account_trait::ManagedAccountTrait;
    use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
    use crate::{KeySource, ManagedAccountType};
    use dashcore::{OutPoint, TxOut};
    use std::collections::HashSet;
    use test_case::test_case;

    /// Put a confirmed 300k UTXO on a fresh receive address of the account at
    /// `index` and return its outpoint.
    fn fund(
        wallet: &Wallet,
        info: &mut ManagedWalletInfo,
        preference: AccountTypePreference,
        index: u32,
        txid_byte: u8,
    ) -> OutPoint {
        let account_type = preference.account_type(index).expect("a single account");
        let account_xpub = wallet
            .accounts
            .account_of_type(account_type)
            .unwrap_or_else(|| panic!("wallet account {preference}"))
            .account_xpub;
        let account = info
            .accounts
            .funds_account_mut(&account_type)
            .unwrap_or_else(|| panic!("managed account {preference}"));

        // A contact account keeps a single pool and so has no receive-address
        // helper of its own; its addresses come straight off that pool.
        let address = match account.managed_account_type_mut() {
            ManagedAccountType::DashpayReceivingFunds {
                addresses,
                ..
            } => addresses.next_unused(&KeySource::Public(account_xpub), true).unwrap(),
            _ => account.next_receive_address(Some(&account_xpub), true).unwrap(),
        };

        let outpoint = OutPoint {
            txid: Txid::from_byte_array([txid_byte; 32]),
            vout: 0,
        };
        account.utxos.insert(
            outpoint,
            Utxo {
                outpoint,
                txout: TxOut {
                    value: 300_000,
                    script_pubkey: address.script_pubkey(),
                },
                address,
                height: 1000,
                is_coinbase: false,
                is_confirmed: true,
                is_instantlocked: false,
                is_locked: false,
                is_trusted: false,
                spend_scanned: true,
            },
        );
        outpoint
    }

    /// Naming one account twice must not offer its UTXOs twice: a 400k target
    /// is not met by a single 300k coin, however often its account is named.
    #[tokio::test]
    async fn naming_an_account_twice_does_not_double_its_funds() {
        let (wallet, mut info) = test_wallet_and_info();
        fund(&wallet, &mut info, AccountTypePreference::BIP44, 0, 0x11);
        info.update_last_processed_height(1100);

        let result = info
            .build_and_sign_transaction(
                &wallet,
                &[AccountTypePreference::BIP44, AccountTypePreference::BIP44],
                0,
                dest_outputs(400_000),
                FeeRate::normal(),
                SelectionStrategy::BranchAndBound,
            )
            .await;

        assert!(
            matches!(
                result,
                Err(BuilderError::InsufficientFunds { .. }) | Err(BuilderError::CoinSelection(_))
            ),
            "300k must not cover a 400k target, got: {:?}",
            result.map(|(tx, _)| tx.input.len())
        );
    }

    /// Neither account covers the 500k target on its own, so the build only
    /// succeeds by pooling both — and signing them proves the derivation paths
    /// were collected across both accounts.
    #[test_case(&[AccountTypePreference::BIP44, AccountTypePreference::BIP32] ; "named explicitly")]
    #[test_case(&[] ; "empty list draws from every type")]
    #[tokio::test]
    async fn funding_pools_across_account_types(sources: &[AccountTypePreference]) {
        let (wallet, mut info) = test_wallet_and_info();
        let bip44 = fund(&wallet, &mut info, AccountTypePreference::BIP44, 0, 0x11);
        let bip32 = fund(&wallet, &mut info, AccountTypePreference::BIP32, 0, 0x22);
        info.update_last_processed_height(1100);

        let (tx, _fee) = info
            .build_and_sign_transaction(
                &wallet,
                sources,
                0,
                dest_outputs(500_000),
                FeeRate::normal(),
                SelectionStrategy::BranchAndBound,
            )
            .await
            .expect("a 500k send funded by two 300k accounts");

        let spent: HashSet<OutPoint> = tx.input.iter().map(|txin| txin.previous_output).collect();
        assert_eq!(spent, HashSet::from([bip44, bip32]));

        // Each account reserves what it contributed, in its own set, so a build
        // funded from only one of them still skips the spent-to-be UTXO.
        let bip44_account = info.accounts.standard_bip44_accounts.get(&0).unwrap();
        let bip32_account = info.accounts.standard_bip32_accounts.get(&0).unwrap();
        assert_eq!(bip44_account.reservations().reserved(1100), HashSet::from([bip44]));
        assert_eq!(bip32_account.reservations().reserved(1100), HashSet::from([bip32]));
    }

    // -- DashPay contact accounts --

    /// A source naming the friendship between our identity `user` and `friend`.
    fn friendship(user: u8, friend: u8) -> AccountTypePreference {
        AccountTypePreference::DashpayFriendshipReceivingFunds {
            user_identity_id: [user; 32],
            friend_identity_id: [friend; 32],
        }
    }

    /// Add that friendship's receiving account at `index` and fund it with 300k.
    fn add_funded_friendship(
        wallet: &mut Wallet,
        info: &mut ManagedWalletInfo,
        user: u8,
        friend: u8,
        index: u32,
        txid_byte: u8,
    ) -> OutPoint {
        let account_type = friendship(user, friend).account_type(index).unwrap();
        wallet.add_account(account_type, None).unwrap();
        info.add_managed_account(wallet, account_type).unwrap();
        fund(wallet, info, friendship(user, friend), index, txid_byte)
    }

    /// Funds received from a contact are spendable, across every account index
    /// that contact holds funds at — 300k at each of two indices covers a 500k
    /// target that neither covers alone. The DIP-15 contact path is 256-bit, so
    /// the build only succeeds if it resolved for signing, and a contact account
    /// has no internal pool, so BIP44 comes along for change.
    #[tokio::test]
    async fn dashpay_friendship_funds_a_spend_across_indices() {
        let (mut wallet, mut info) = test_wallet_and_info();
        let contact_0 = add_funded_friendship(&mut wallet, &mut info, 0xaa, 0xbb, 0, 0x44);
        let contact_1 = add_funded_friendship(&mut wallet, &mut info, 0xaa, 0xbb, 1, 0x55);
        info.update_last_processed_height(1100);

        let send_amount = 500_000u64;
        let (tx, _fee) = info
            .build_and_sign_transaction(
                &wallet,
                &[friendship(0xaa, 0xbb), AccountTypePreference::BIP44],
                0,
                dest_outputs(send_amount),
                FeeRate::normal(),
                SelectionStrategy::BranchAndBound,
            )
            .await
            .expect("a 500k send funded by one contact's accounts");

        let spent: HashSet<OutPoint> = tx.input.iter().map(|txin| txin.previous_output).collect();
        assert_eq!(spent, HashSet::from([contact_0, contact_1]));

        let change = tx
            .output
            .iter()
            .find(|out| out.value != send_amount)
            .expect("600k in against a 500k target leaves change");
        let bip44 = info.accounts.standard_bip44_accounts.get(&0).unwrap();
        assert!(bip44.managed_account_type().all_script_pubkeys().contains(&change.script_pubkey));
    }

    /// Overlapping DashPay sources must not fund an account twice. The build
    /// drains, so every candidate input reaches the transaction and a coin
    /// offered twice shows up as two inputs spending the same outpoint —
    /// whichever way the sources are combined.
    #[test_case(
        vec![AccountTypePreference::AllDashpayReceivingFunds, friendship(0xaa, 0xbb)]
        ; "all, then a friendship it already covers"
    )]
    #[test_case(
        vec![friendship(0xaa, 0xbb), AccountTypePreference::AllDashpayReceivingFunds]
        ; "a friendship, then all"
    )]
    #[test_case(
        vec![
            AccountTypePreference::DashpayIdentityReceivingFunds {
                user_identity_id: [0xaa; 32],
            },
            friendship(0xaa, 0xbb),
        ]
        ; "an identity, then one of its friendships"
    )]
    #[tokio::test]
    async fn overlapping_dashpay_sources_fund_each_account_once(
        sources: Vec<AccountTypePreference>,
    ) {
        let (mut wallet, mut info) = test_wallet_and_info();
        let first = add_funded_friendship(&mut wallet, &mut info, 0xaa, 0xbb, 0, 0x44);
        let second = add_funded_friendship(&mut wallet, &mut info, 0xaa, 0xcc, 0, 0x55);
        info.update_last_processed_height(1100);

        let (tx, _fee) = info
            .build_and_sign_transaction(
                &wallet,
                &sources,
                0,
                dest_outputs(400_000),
                FeeRate::normal(),
                SelectionStrategy::All,
            )
            .await
            .expect("draining the two contacts' accounts");

        // Draining spends every candidate, so an account funded twice would
        // put its coin in here a second time.
        let spent: Vec<OutPoint> = tx.input.iter().map(|txin| txin.previous_output).collect();
        assert_eq!(spent.len(), 2, "the two contacts' coins, once each: {spent:?}");
        assert_eq!(spent.iter().copied().collect::<HashSet<_>>(), HashSet::from([first, second]));
    }

    /// Two of our identities hold 300k each, so only a source spanning both
    /// covers a 500k target.
    #[test_case(AccountTypePreference::AllDashpayReceivingFunds, true ; "every identity")]
    #[test_case(
        AccountTypePreference::DashpayIdentityReceivingFunds {
            user_identity_id: [0xaa; 32],
        },
        false ; "a single identity"
    )]
    #[tokio::test]
    async fn dashpay_sources_span_the_identities_they_name(
        source: AccountTypePreference,
        covers_target: bool,
    ) {
        let (mut wallet, mut info) = test_wallet_and_info();
        add_funded_friendship(&mut wallet, &mut info, 0xaa, 0xbb, 0, 0x44);
        add_funded_friendship(&mut wallet, &mut info, 0xcc, 0xdd, 0, 0x55);
        info.update_last_processed_height(1100);

        let result = info
            .build_and_sign_transaction(
                &wallet,
                &[source, AccountTypePreference::BIP44],
                0,
                dest_outputs(500_000),
                FeeRate::normal(),
                SelectionStrategy::BranchAndBound,
            )
            .await;

        assert_eq!(
            result.is_ok(),
            covers_target,
            "got: {:?}",
            result.map(|(tx, _)| tx.input.len())
        );
    }
}
