//! Transaction building functionality for managed wallets

use super::coin_selection::{SelectionError, SelectionStrategy};
use super::fee::FeeLevel;
use super::transaction_builder::{BuilderError, TransactionBuilder};
use super::ManagedWalletInfo;
use crate::{Address, Network, Wallet};
use alloc::vec::Vec;
use dashcore::Transaction;

/// Account type preference for transaction building
#[derive(Debug, Clone, Copy)]
pub enum AccountTypePreference {
    /// Use BIP44 account only
    BIP44,
    /// Use BIP32 account only  
    BIP32,
    /// Prefer BIP44, fallback to BIP32
    PreferBIP44,
    /// Prefer BIP32, fallback to BIP44
    PreferBIP32,
}

/// Transaction creation error
#[derive(Debug)]
pub enum TransactionError {
    /// No account found for the specified type
    NoAccount,
    /// Insufficient funds
    InsufficientFunds,
    /// Failed to generate change address
    ChangeAddressGeneration(String),
    /// Transaction building failed
    BuildFailed(String),
    /// Coin selection failed
    CoinSelection(SelectionError),
}

impl ManagedWalletInfo {
    /// Create an unsigned payment transaction
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_unsigned_payment_transaction_internal(
        &mut self,
        wallet: &Wallet,
        network: Network,
        account_index: u32,
        account_type_pref: Option<AccountTypePreference>,
        recipients: Vec<(Address, u64)>,
        fee_level: FeeLevel,
        current_block_height: u32,
    ) -> Result<Transaction, TransactionError> {
        // Get the wallet's account collection for this network
        let wallet_collection = wallet.accounts.get(&network).ok_or(TransactionError::NoAccount)?;

        // Get the mutable account collection from managed info
        let managed_collection =
            self.accounts.get_mut(&network).ok_or(TransactionError::NoAccount)?;

        // Use BIP44 as default if no preference specified
        let pref = account_type_pref.unwrap_or(AccountTypePreference::BIP44);

        // Get the immutable account from wallet for address generation
        let wallet_account = match pref {
            AccountTypePreference::BIP44 => wallet_collection
                .standard_bip44_accounts
                .get(&account_index)
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::BIP32 => wallet_collection
                .standard_bip32_accounts
                .get(&account_index)
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::PreferBIP44 => wallet_collection
                .standard_bip44_accounts
                .get(&account_index)
                .or_else(|| wallet_collection.standard_bip32_accounts.get(&account_index))
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::PreferBIP32 => wallet_collection
                .standard_bip32_accounts
                .get(&account_index)
                .or_else(|| wallet_collection.standard_bip44_accounts.get(&account_index))
                .ok_or(TransactionError::NoAccount)?,
        };

        // Get the mutable managed account for UTXO access
        let managed_account = match pref {
            AccountTypePreference::BIP44 => managed_collection
                .standard_bip44_accounts
                .get_mut(&account_index)
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::BIP32 => managed_collection
                .standard_bip32_accounts
                .get_mut(&account_index)
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::PreferBIP44 => managed_collection
                .standard_bip44_accounts
                .get_mut(&account_index)
                .or_else(|| managed_collection.standard_bip32_accounts.get_mut(&account_index))
                .ok_or(TransactionError::NoAccount)?,
            AccountTypePreference::PreferBIP32 => managed_collection
                .standard_bip32_accounts
                .get_mut(&account_index)
                .or_else(|| managed_collection.standard_bip44_accounts.get_mut(&account_index))
                .ok_or(TransactionError::NoAccount)?,
        };

        // Generate change address using the wallet account
        let change_address = managed_account
            .get_next_change_address(&wallet_account.account_xpub, network)
            .map_err(|e| {
                TransactionError::ChangeAddressGeneration(format!(
                    "Failed to generate change address: {}",
                    e
                ))
            })?;

        if managed_account.utxos.is_empty() {
            return Err(TransactionError::InsufficientFunds);
        }

        // Get all UTXOs from the managed account as a vector
        let all_utxos: Vec<_> = managed_account.utxos.values().cloned().collect();

        // Use TransactionBuilder to create the transaction
        let mut builder = TransactionBuilder::new()
            .set_fee_level(fee_level)
            .set_change_address(change_address.clone());

        // Add outputs for recipients first
        for (address, amount) in recipients {
            builder = builder
                .add_output(&address, amount)
                .map_err(|e| TransactionError::BuildFailed(e.to_string()))?;
        }

        // Select inputs using OptimalConsolidation strategy
        // The target amount is calculated from the outputs already added
        // Note: We don't have private keys here since this is for unsigned transactions
        builder = builder
            .select_inputs(
                &all_utxos,
                SelectionStrategy::OptimalConsolidation,
                current_block_height,
                |_| None, // No private keys for unsigned transaction
            )
            .map_err(|e| match e {
                BuilderError::CoinSelection(err) => TransactionError::CoinSelection(err),
                _ => TransactionError::BuildFailed(e.to_string()),
            })?;

        // Build the unsigned transaction
        let transaction =
            builder.build().map_err(|e| TransactionError::BuildFailed(e.to_string()))?;

        // Mark the change address as used in the managed account
        managed_account.mark_address_used(&change_address);

        // Lock the UTXOs that were selected for this transaction
        for input in &transaction.input {
            if let Some(stored_utxo) = managed_account.utxos.get_mut(&input.previous_output) {
                stored_utxo.is_locked = true; // Lock the UTXO while transaction is pending
            }
        }

        Ok(transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::managed_wallet_info::transaction_builder::TransactionBuilder;
    use crate::Utxo;
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
    use dashcore::{Address, Network, OutPoint, Transaction, TxOut, Txid};
    use dashcore_hashes::{sha256d, Hash};
    use std::str::FromStr;

    fn test_utxo(value: u64, confirmed: bool) -> Utxo {
        let outpoint = OutPoint {
            txid: Txid::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap()),
            vout: 0,
        };

        let txout = TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        };

        let address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[
                0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
                0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
                0x88, 0x7e, 0x5b, 0x23, 0x52,
            ])
            .unwrap(),
            Network::Testnet,
        );

        let mut utxo = Utxo::new(outpoint, txout, address, 100, false);
        utxo.is_confirmed = confirmed;
        utxo
    }

    #[test]
    fn test_basic_transaction_creation() {
        // Test creating a basic transaction with inputs and outputs
        let utxos = vec![test_utxo(100000, true), test_utxo(200000, true), test_utxo(300000, true)];

        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let mut builder = TransactionBuilder::new()
            .set_fee_level(FeeLevel::Normal)
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

        assert!(tx.input.len() > 0);
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
        let utxos = vec![test_utxo(100000, true), test_utxo(200000, true)];

        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let builder = TransactionBuilder::new()
            .set_fee_level(FeeLevel::Normal)
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
        let utxos = vec![test_utxo(1000000, true)];

        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let builder = TransactionBuilder::new()
            .set_fee_level(FeeLevel::Normal) // 1 duff per byte
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
        let utxos = vec![test_utxo(10000, true)];

        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let result = TransactionBuilder::new()
            .set_fee_level(FeeLevel::Normal)
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 1000000) // More than available
            .unwrap()
            .select_inputs(&utxos, SelectionStrategy::SmallestFirst, 200, |_| None);

        assert!(result.is_err());
    }

    #[test]
    fn test_exact_change_no_change_output() {
        // Test when the exact amount is used (no change output needed)
        let utxos = vec![test_utxo(150226, true)]; // Exact amount for output + fee

        let recipient_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();
        let change_address = Address::from_str("yXfXh3jFYHHxnJZVsXnPcktCENqPaAhcX1")
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap();

        let builder = TransactionBuilder::new()
            .set_fee_level(FeeLevel::Normal)
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
