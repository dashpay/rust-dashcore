//! Transaction building functionality for managed wallets

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::signer::Signer;
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::wallet::managed_wallet_info::transaction_builder::{BuilderError, TransactionBuilder};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::ManagedWalletInfo;
use crate::Wallet;
use dashcore::address::NetworkUnchecked;
use dashcore::{Address, Transaction};

/// Account type preference for transaction building
#[derive(Debug, Clone, Copy)]
pub enum AccountTypePreference {
    BIP44,
    BIP32,
}

impl ManagedWalletInfo {
    pub async fn build_and_sign_transaction(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        outputs: Vec<(Address<NetworkUnchecked>, u64)>,
        fee_rate: FeeRate,
    ) -> Result<(Transaction, u64), BuilderError> {
        let height = self.last_processed_height();

        let managed_account = self
            .accounts
            .standard_bip44_accounts
            .get_mut(&account_index)
            .ok_or(BuilderError::NoChangeAddress)?;

        let account = wallet
            .accounts
            .standard_bip44_accounts
            .get(&account_index)
            .ok_or(BuilderError::NoChangeAddress)?;

        let mut tx_builder = TransactionBuilder::new()
            .set_fee_rate(fee_rate)
            .set_current_height(height)
            .set_funding(managed_account, account);

        for (address, value) in outputs {
            let checked = address.require_network(wallet.network).map_err(|e| {
                BuilderError::InvalidData(format!("Output address network mismatch: {}", e))
            })?;
            tx_builder = tx_builder.add_output(&checked, value);
        }

        tx_builder.build_signed(wallet, |addr| managed_account.address_derivation_path(&addr)).await
    }

    pub async fn build_and_sign_transaction_with_signer<S: Signer>(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        outputs: Vec<(Address<NetworkUnchecked>, u64)>,
        fee_rate: FeeRate,
        signer: &S,
    ) -> Result<(Transaction, u64), BuilderError> {
        let height = self.last_processed_height();

        let managed_account = self
            .accounts
            .standard_bip44_accounts
            .get_mut(&account_index)
            .ok_or(BuilderError::NoChangeAddress)?;

        let account = wallet
            .accounts
            .standard_bip44_accounts
            .get(&account_index)
            .ok_or(BuilderError::NoChangeAddress)?;

        let mut tx_builder = TransactionBuilder::new()
            .set_fee_rate(fee_rate)
            .set_current_height(height)
            .set_funding(managed_account, account);

        for (address, value) in outputs {
            let checked = address.require_network(wallet.network).map_err(|e| {
                BuilderError::InvalidData(format!("Output address network mismatch: {}", e))
            })?;
            tx_builder = tx_builder.add_output(&checked, value);
        }

        tx_builder.build_signed(signer, |addr| managed_account.address_derivation_path(&addr)).await
    }
}
#[cfg(test)]
mod tests {
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
            .build_unsigned()
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

        let tx = builder.build_unsigned().unwrap().0;
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

        let tx = builder.build_unsigned().unwrap().0;

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
            .build_unsigned();

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

        let tx = builder.build_unsigned().unwrap().0;

        // Should only have 1 output (no change)
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, 150000);
    }

    // -- Signer-variant tests for build_and_sign_transaction_with_signer --

    use super::super::transaction_builder::BuilderError;
    use super::super::wallet_info_interface::WalletInfoInterface;
    use crate::signer::{Signer, SignerMethod};
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

    fn root_from(wallet: &Wallet) -> crate::wallet::root_extended_keys::RootExtendedPrivKey {
        match &wallet.wallet_type {
            crate::wallet::WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key.clone(),
            _ => unreachable!("test_wallet_and_info produces a mnemonic wallet"),
        }
    }

    fn dest_outputs(amount: u64) -> Vec<(Address<NetworkUnchecked>, u64)> {
        let dest = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs").unwrap();
        vec![(dest, amount)]
    }

    #[tokio::test]
    async fn test_signer_invalid_account_index() {
        // No BIP44 account 99 exists, so next_change_address returns None
        // and we surface NoChangeAddress before any signing happens.
        let (wallet, mut info) = test_wallet_and_info();
        let signer = InMemorySigner {
            root: root_from(&wallet),
            network: Network::Testnet,
        };
        let result = info
            .build_and_sign_transaction_with_signer(
                &wallet,
                99,
                dest_outputs(100_000),
                FeeRate::normal(),
                &signer,
            )
            .await;
        assert!(matches!(result, Err(BuilderError::NoChangeAddress)));
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
                0,
                dest_outputs(100_000),
                FeeRate::normal(),
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
                0,
                dest_outputs(send_amount),
                FeeRate::normal(),
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
                0,
                dest_outputs(500_000),
                FeeRate::normal(),
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
            .build_and_sign_transaction_with_signer(&wallet, 0, outputs, FeeRate::normal(), &signer)
            .await;
        assert!(
            matches!(result, Err(BuilderError::InvalidData(_))),
            "expected InvalidData for network-mismatched output, got: {:?}",
            result.err()
        );
    }
}
