//! Transaction building functionality for managed wallets

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::wallet::managed_wallet_info::coin_selection::SelectionStrategy;
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::wallet::managed_wallet_info::transaction_builder::{BuilderError, TransactionBuilder};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::{ManagedWalletInfo, WalletType};
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
    pub fn build_and_sign_transaction(
        &mut self,
        wallet: &Wallet,
        account_index: u32,
        outputs: Vec<(Address<NetworkUnchecked>, u64)>,
        fee_rate: FeeRate,
    ) -> Result<(Transaction, u64), BuilderError> {
        // Get change address through the manager
        let change_address = self
            .next_change_address(wallet, account_index, AccountTypePreference::BIP44, true)
            .ok_or(BuilderError::NoChangeAddress)?;

        let managed_account = self
            .accounts
            .standard_bip44_accounts
            .get_mut(&account_index)
            .expect("Impossible state, if change address is Some, account must be Some");

        // Convert FFI outputs to Rust outputs
        let mut tx_builder = TransactionBuilder::new();

        for output in outputs {
            let checked_address = output.0.require_network(wallet.network).map_err(|e| {
                BuilderError::InvalidData(format!("Output address network mismatch: {}", e))
            })?;
            tx_builder = tx_builder.add_output(&checked_address, output.1)?;
        }

        tx_builder = tx_builder.set_change_address(change_address).set_fee_rate(fee_rate);

        // Get available UTXOs (collect owned UTXOs, not references)
        let utxos: Vec<crate::Utxo> = managed_account.utxos.values().cloned().collect();

        // Get the wallet's root extended private key for signing
        let root_xpriv = match &wallet.wallet_type {
            WalletType::Mnemonic {
                root_extended_private_key,
                ..
            } => root_extended_private_key,
            WalletType::Seed {
                root_extended_private_key,
                ..
            } => root_extended_private_key,
            WalletType::ExtendedPrivKey(root_extended_private_key) => root_extended_private_key,
            _ => {
                return Err(BuilderError::InvalidData(
                    "Cannot sign with watch-only wallet".to_string(),
                ));
            }
        };

        // Build a map of address -> derivation path for all addresses in the account
        use std::collections::HashMap;
        let mut address_to_path: HashMap<dashcore::Address, crate::DerivationPath> = HashMap::new();

        // Collect from all address pools (receive, change, etc.)
        for pool in managed_account.managed_account_type().address_pools() {
            for addr_info in pool.addresses.values() {
                address_to_path.insert(addr_info.address.clone(), addr_info.path.clone());
            }
        }

        // Select inputs and build transaction
        let mut tx_builder = tx_builder.select_inputs(
            &utxos,
            SelectionStrategy::BranchAndBound,
            self.last_processed_height(),
            |utxo| {
                // Look up the derivation path for this UTXO's address
                let path = address_to_path.get(&utxo.address)?;

                // Convert root key to ExtendedPrivKey and derive the child key
                let root_ext_priv = root_xpriv.to_extended_priv_key(wallet.network);
                let secp = secp256k1::Secp256k1::new();
                let derived_xpriv = root_ext_priv.derive_priv(&secp, path).ok()?;

                Some(derived_xpriv.private_key)
            },
        )?;

        let transaction = tx_builder.build()?;

        // This is tricky, the transaction creation + fee calculation need a little
        // bit of love to avoid this kind of logic.
        //
        // First, we need to know that TransactionBuilder may add an extra output for change
        // to the final transaction but not to itself, with that knowledge, we can compare the
        // number of outputs in the transaction with the number of outputs in the TransactionBuilder
        // to then call the appropriate fee calculation method
        let fee = if transaction.output.len() > tx_builder.outputs().len() {
            tx_builder.calculate_fee_with_extra_output()
        } else {
            tx_builder.calculate_fee()
        };

        Ok((transaction, fee))
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

        let mut builder = TransactionBuilder::new()
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change_address.clone());

        // Add output
        builder = builder.add_output(&recipient_address, 150000).unwrap();

        // Select inputs
        builder = builder
            .select_inputs(
                &utxos,
                SelectionStrategy::SmallestFirst,
                200,
                |_| None, // No private keys for unsigned
            )
            .unwrap();

        let tx = builder.build().unwrap();

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

        let mut builder = TransactionBuilder::new()
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 150000)
            .unwrap()
            .select_inputs(&utxos, SelectionStrategy::SmallestFirst, 200, |_| None)
            .unwrap();

        let tx = builder.build().unwrap();
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

        let mut builder = TransactionBuilder::new()
            .set_fee_rate(FeeRate::normal()) // 1 duff per byte
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 500000)
            .unwrap()
            .select_inputs(&utxos, SelectionStrategy::SmallestFirst, 200, |_| None)
            .unwrap();

        let tx = builder.build().unwrap();

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
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 1000000) // More than available
            .unwrap()
            .select_inputs(&utxos, SelectionStrategy::SmallestFirst, 200, |_| None);

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

        let mut builder = TransactionBuilder::new()
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 150000)
            .unwrap()
            .select_inputs(&utxos, SelectionStrategy::SmallestFirst, 200, |_| None)
            .unwrap();

        let tx = builder.build().unwrap();

        // Should only have 1 output (no change)
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, 150000);
    }
}
