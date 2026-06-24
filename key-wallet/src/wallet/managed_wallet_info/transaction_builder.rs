//! Transaction building with dashcore types
//!
//! This module provides high-level transaction building functionality
//! using types from the dashcore crate.

use crate::managed_account::ManagedCoreFundsAccount;
use crate::wallet::managed_wallet_info::coin_selection::{CoinSelector, SelectionStrategy};
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::{Account, DerivationPath, Signer, Utxo, Wallet};
use core::fmt;
use dashcore::blockdata::script::{Builder, PushBytes, ScriptBuf};
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::Transaction;
use dashcore::consensus::Encodable;
use dashcore::sighash::{EcdsaSighashType, LegacySighash, SighashCache};
use dashcore::Address;
use dashcore::{TxIn, TxOut};
use dashcore_hashes::Hash;
use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, Secp256k1};
use std::cmp::Ordering;

/// A transaction with more inputs would exceed the relay standard-size cap (~100 KB at ~148
/// bytes/signed input) and be rejected by the network
const MAX_STANDARD_TX_INPUTS: usize = 500;

/// Calculate varint size for a given number
fn varint_size(n: usize) -> usize {
    match n {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x10000..=0xFFFFFFFF => 5,
        _ => 9,
    }
}

/// Transaction builder for creating Dash transactions
///
/// This builder implements BIP-69 (Lexicographical Indexing of Transaction Inputs and Outputs)
/// to ensure deterministic ordering and improve privacy by preventing information leakage
/// through predictable input/output ordering patterns.
pub struct TransactionBuilder {
    inputs: Vec<Utxo>,
    change_addr: Option<Address>,
    outputs: Vec<TxOut>,
    fee_rate: FeeRate,
    current_height: u32,
    selection_strategy: SelectionStrategy,
    /// Special transaction payload for Dash-specific transactions
    special_payload: Option<TransactionPayload>,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            change_addr: None,
            outputs: Vec::new(),
            fee_rate: FeeRate::normal(),
            current_height: 0,
            selection_strategy: SelectionStrategy::BranchAndBound,
            special_payload: None,
        }
    }

    pub fn set_current_height(mut self, current_height: u32) -> Self {
        self.current_height = current_height;
        self
    }

    pub fn set_selection_strategy(mut self, strategy: SelectionStrategy) -> Self {
        self.selection_strategy = strategy;
        self
    }

    pub fn set_funding(mut self, funds_acc: &mut ManagedCoreFundsAccount, acc: &Account) -> Self {
        self.inputs = funds_acc.utxos.values().cloned().collect();
        self.change_addr = funds_acc.next_change_address(Some(&acc.account_xpub), true).ok();
        self
    }

    pub fn set_change_address(mut self, change_addr: Address) -> Self {
        self.change_addr = Some(change_addr);
        self
    }

    pub fn add_inputs(mut self, inputs: impl IntoIterator<Item = Utxo>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    /// Add an output to a specific address
    ///
    /// Note: Outputs will be sorted according to BIP-69 when the transaction is built:
    /// - First by amount (ascending)
    /// - Then by scriptPubKey (lexicographically)
    pub fn add_output(mut self, address: &Address, amount: u64) -> Self {
        let script_pubkey = address.script_pubkey();
        self.outputs.push(TxOut {
            value: amount,
            script_pubkey,
        });
        self
    }

    pub fn set_fee_rate(mut self, fee_rate: FeeRate) -> Self {
        self.fee_rate = fee_rate;
        self
    }

    pub fn set_special_payload(mut self, payload: TransactionPayload) -> Self {
        self.special_payload = Some(payload);
        self
    }

    /// Effective `tx.output` count: for AssetLock the only on-chain output is
    /// the OP_RETURN burn (credit outputs live in the payload), otherwise it's
    /// the user-provided outputs.
    fn effective_outputs_count(&self) -> usize {
        match &self.special_payload {
            Some(TransactionPayload::AssetLockPayloadType(_)) => 1,
            _ => self.outputs.len(),
        }
    }

    /// Calculate the base transaction size excluding inputs
    /// Based on dashsync/DashSync/shared/Models/Transactions/Base/DSTransaction.m
    fn calculate_base_size(&self) -> usize {
        // Base: version (2) + type (2) + locktime (4) = 8 bytes
        let mut size = 8;

        // Add varint for input count (will be added later, typically 1 byte)
        size += 1;

        let outputs_count = self.effective_outputs_count();

        // Add varint for output count
        size += varint_size(
            outputs_count
                + if self.change_addr.is_some() {
                    1
                } else {
                    0
                },
        );

        // Add outputs size (TX_OUTPUT_SIZE = 34 bytes per P2PKH output)
        size += outputs_count * 34;

        // Add change output if we have a change address
        if self.change_addr.is_some() {
            size += 34; // TX_OUTPUT_SIZE
        }

        // Add special payload size if present
        // Based on dashsync payload size calculations
        if let Some(ref payload) = self.special_payload {
            let payload_size = match payload {
                TransactionPayload::CoinbasePayloadType(p) => {
                    // version (2) + height (4) + merkleRootMasternodeList (32) + merkleRootQuorums (32)
                    let mut size = 2 + 4 + 32 + 32;
                    // Optional fields for newer versions
                    if p.best_cl_height.is_some() {
                        size += 4; // best_cl_height
                        size += 96; // best_cl_signature (BLS)
                    }
                    if p.asset_locked_amount.is_some() {
                        size += 8; // asset_locked_amount
                    }
                    size
                }
                TransactionPayload::ProviderRegistrationPayloadType(p) => {
                    // Base payload + signature
                    // version (2) + type (2) + mode (2) + collateralHash (32) + collateralIndex (4)
                    // + ipAddress (16) + port (2) + KeyIDOwner (20) + KeyIDOperator (20) + KeyIDVoting (20)
                    // + operatorReward (2) + scriptPayoutSize + scriptPayout + inputsHash (32)
                    // + payloadSigSize (1-9) + payloadSig (up to 75)
                    let script_size = p.script_payout.len();
                    let base = 2
                        + 2
                        + 2
                        + 32
                        + 4
                        + 16
                        + 2
                        + 20
                        + 20
                        + 20
                        + 2
                        + varint_size(script_size)
                        + script_size
                        + 32;
                    base + varint_size(75) + 75 // MAX_ECDSA_SIGNATURE_SIZE = 75
                }
                TransactionPayload::ProviderUpdateServicePayloadType(p) => {
                    // version (2) + optionally mn_type (2) + proTxHash (32) + ipAddress (16) + port (2)
                    // + scriptPayoutSize + scriptPayout + inputsHash (32) + payloadSig (96 for BLS)
                    let script_size = p.script_payout.len();
                    let mut size =
                        2 + 32 + 16 + 2 + varint_size(script_size) + script_size + 32 + 96;
                    if p.mn_type.is_some() {
                        size += 2; // mn_type for BasicBLS version
                    }
                    // Platform fields for Evo masternodes
                    if p.platform_node_id.is_some() {
                        size += 20; // platform_node_id
                        size += 2; // platform_p2p_port
                        size += 2; // platform_http_port
                    }
                    size
                }
                TransactionPayload::ProviderUpdateRegistrarPayloadType(p) => {
                    // version (2) + proTxHash (32) + mode (2) + PubKeyOperator (48) + KeyIDVoting (20)
                    // + scriptPayoutSize + scriptPayout + inputsHash (32) + payloadSig (up to 75)
                    let script_size = p.script_payout.len();
                    2 + 32 + 2 + 48 + 20 + varint_size(script_size) + script_size + 32 + 75
                }
                TransactionPayload::ProviderUpdateRevocationPayloadType(_) => {
                    // version (2) + proTxHash (32) + reason (2) + inputsHash (32) + payloadSig (96 for BLS)
                    2 + 32 + 2 + 32 + 96
                }
                TransactionPayload::AssetLockPayloadType(p) => {
                    // version (1) + creditOutputsCount + creditOutputs
                    1 + varint_size(p.credit_outputs.len()) + p.credit_outputs.len() * 34
                }
                TransactionPayload::AssetUnlockPayloadType(_p) => {
                    // version (1) + index (8) + fee (4) + requestHeight (4) + quorumHash (32) + quorumSig (96)
                    1 + 8 + 4 + 4 + 32 + 96
                }
                _ => 100, // Default estimate for unknown types
            };

            // Add varint for payload length
            size += varint_size(payload_size) + payload_size;
        }

        size
    }

    fn assemble_unsigned(mut self) -> Result<(Transaction, Vec<Utxo>), BuilderError> {
        if let Some(TransactionPayload::AssetLockPayloadType(p)) = &self.special_payload {
            if p.credit_outputs.is_empty() {
                return Err(BuilderError::NoOutputs);
            }
        } else if self.outputs.is_empty() && self.special_payload.is_none() {
            return Err(BuilderError::NoOutputs);
        }

        // A drain (`All`) never emits change; drop the change address before sizing so the fee
        // estimate doesn't include a phantom (~34-byte) change output.
        if self.selection_strategy == SelectionStrategy::All {
            self.change_addr = None;
        }

        // For AssetLock the on-chain spend equals the OP_RETURN burn, which
        // mirrors the sum of the credit_outputs carried in the payload. For
        // every other tx type, it's just the sum of user-provided outputs.
        let total_output: u64 = match &self.special_payload {
            Some(TransactionPayload::AssetLockPayloadType(p)) => {
                p.credit_outputs.iter().map(|o| o.value).sum()
            }
            _ => self.outputs.iter().map(|o| o.value).sum(),
        };

        let selection = CoinSelector::new(self.selection_strategy)
            .select_coins_with_size(
                self.inputs.iter(),
                total_output,
                self.fee_rate,
                self.current_height,
                self.calculate_base_size(),
                148, // Size per P2PKH input
            )
            .map_err(BuilderError::CoinSelection)?;

        let mut selected_inputs = selection.selected;

        if selected_inputs.len() > MAX_STANDARD_TX_INPUTS {
            return Err(BuilderError::TooManyInputs {
                count: selected_inputs.len(),
                max: MAX_STANDARD_TX_INPUTS,
            });
        }

        let total_input: u64 = selected_inputs.iter().map(|u| u.value()).sum();

        if total_input < total_output + selection.estimated_fee {
            return Err(BuilderError::InsufficientFunds {
                available: total_input,
                required: total_output + selection.estimated_fee,
            });
        }

        let change_amount =
            total_input.saturating_sub(total_output).saturating_sub(selection.estimated_fee);
        let mut tx_outputs = match &self.special_payload {
            Some(TransactionPayload::AssetLockPayloadType(_)) => vec![TxOut {
                value: total_output,
                script_pubkey: ScriptBuf::new_op_return(&[]),
            }],
            _ => self.outputs,
        };

        if self.selection_strategy == SelectionStrategy::All {
            // Drain: the single output takes the whole balance minus fee (the caller's amount is
            // ignored); no change.
            let [out] = tx_outputs.as_mut_slice() else {
                return Err(BuilderError::InvalidData(
                    "SelectionStrategy::All requires exactly one output (the destination)".into(),
                ));
            };
            out.value = total_input.saturating_sub(selection.estimated_fee);
        } else if change_amount > 546 {
            // Add change output if above dust threshold
            let Some(change_addr) = self.change_addr else {
                return Err(BuilderError::NoChangeAddress);
            };
            tx_outputs.push(TxOut {
                value: change_amount,
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        if !matches!(self.special_payload, Some(TransactionPayload::AssetLockPayloadType(_))) {
            tx_outputs.sort_by(bip69_output_sorter);
        }

        selected_inputs.sort_by(bip69_input_sorter);
        let tx_inputs: Vec<TxIn> = selected_inputs
            .iter()
            .map(|utxo| TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff, // Dash doesn't use RBF, so we use the standard sequence number
                witness: dashcore::blockdata::witness::Witness::new(),
            })
            .collect();

        let transaction = Transaction {
            version: 3,
            lock_time: 0,
            input: tx_inputs,
            output: tx_outputs,
            special_transaction_payload: self.special_payload,
        };

        return Ok((transaction, selected_inputs));

        // BIP-69: Sort outputs by amount first, then by scriptPubKey
        // lexicographically.
        fn bip69_output_sorter(a: &TxOut, b: &TxOut) -> Ordering {
            match a.value.cmp(&b.value) {
                Ordering::Equal => a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()),
                other => other,
            }
        }

        // BIP-69: Sort inputs by transaction hash and then by output index.
        fn bip69_input_sorter(a: &Utxo, b: &Utxo) -> Ordering {
            let tx_hash_a = a.outpoint.txid.to_byte_array();
            let tx_hash_b = b.outpoint.txid.to_byte_array();

            match tx_hash_a.cmp(&tx_hash_b) {
                Ordering::Equal => a.outpoint.vout.cmp(&b.outpoint.vout),
                other => other,
            }
        }
    }

    pub fn build_unsigned(self) -> Result<(Transaction, u64), BuilderError> {
        let fee_rate = self.fee_rate;

        let (tx, _) = self.assemble_unsigned()?;

        let mut tx_bytes = Vec::new();
        tx.consensus_encode(&mut tx_bytes).unwrap();

        let fee = fee_rate.calculate_fee(tx_bytes.len());

        Ok((tx, fee))
    }

    /// Build and sign the transaction. The `path_resolver` maps each input
    /// address to the derivation path the signer should use for that input.
    /// The returned fee is computed from the encoded size of the signed tx.
    pub async fn build_signed<S, P>(
        self,
        signer: &S,
        path_resolver: P,
    ) -> Result<(Transaction, u64), BuilderError>
    where
        S: TransactionSigner + ?Sized + Sync,
        P: Fn(Address) -> Option<DerivationPath> + Send,
    {
        let fee_rate = self.fee_rate;

        let (tx, inputs) = self.assemble_unsigned()?;
        let tx = signer.sign_tx(tx, inputs, path_resolver).await?;

        let mut tx_bytes = Vec::new();
        tx.consensus_encode(&mut tx_bytes).unwrap();

        let fee = fee_rate.calculate_fee(tx_bytes.len());

        Ok((tx, fee))
    }
}

#[async_trait::async_trait]
pub trait TransactionSigner {
    async fn sign_tx(
        &self,
        mut tx: Transaction,
        inputs: Vec<Utxo>,
        path_resolver: impl Fn(Address) -> Option<DerivationPath> + Send,
    ) -> Result<Transaction, BuilderError> {
        let tasks: Vec<(LegacySighash, DerivationPath)> = {
            let cache = SighashCache::new(&tx);
            let mut tasks = Vec::with_capacity(inputs.len());
            for (index, utxo) in inputs.iter().enumerate() {
                let path = path_resolver(utxo.address.clone()).ok_or_else(|| {
                    BuilderError::SigningFailed(format!(
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
                        BuilderError::SigningFailed(format!("Failed to compute sighash: {}", e))
                    })?;

                tasks.push((sighash, path));
            }
            tasks
        };

        let mut signatures = Vec::with_capacity(tasks.len());
        for (sighash, path) in tasks {
            let (sig, pubkey) = self.sig_and_pubkey(sighash, path).await?;

            let mut sig_bytes = sig.serialize_der().to_vec();
            sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);

            let script_sig =
                Builder::new()
                    .push_slice(<&PushBytes>::try_from(sig_bytes.as_slice()).map_err(|_| {
                        BuilderError::SigningFailed("invalid signature length".into())
                    })?)
                    .push_slice(pubkey.serialize())
                    .into_script();

            signatures.push(script_sig);
        }

        for (index, script_sig) in signatures.into_iter().enumerate() {
            tx.input[index].script_sig = script_sig;
        }

        Ok(tx)
    }

    async fn sig_and_pubkey(
        &self,
        sighash: LegacySighash,
        path: DerivationPath,
    ) -> Result<(Signature, PublicKey), BuilderError>;
}

#[async_trait::async_trait]
impl TransactionSigner for Wallet {
    async fn sig_and_pubkey(
        &self,
        sighash: LegacySighash,
        path: DerivationPath,
    ) -> Result<(Signature, PublicKey), BuilderError> {
        let secp = Secp256k1::new();

        let root_xpriv =
            self.root_extended_priv_key().map_err(|_| BuilderError::WatchOnlyWallet)?;

        let root_ext_priv = root_xpriv.to_extended_priv_key(self.network);
        let derived_xpriv = root_ext_priv.derive_priv(&secp, &path).map_err(|e| {
            BuilderError::SigningFailed(format!("couldn't derive extended priv key: {}", e))
        })?;
        let key = derived_xpriv.private_key;

        let message = Message::from_digest(*sighash.as_byte_array());
        let signature = secp.sign_ecdsa(&message, &key);
        let pubkey = PublicKey::from_secret_key(&secp, &key);

        Ok((signature, pubkey))
    }
}

#[async_trait::async_trait]
impl<S: Signer> TransactionSigner for S {
    async fn sig_and_pubkey(
        &self,
        sighash: LegacySighash,
        path: DerivationPath,
    ) -> Result<(Signature, PublicKey), BuilderError> {
        if !self.supports(crate::signer::SignerMethod::Digest) {
            return Err(BuilderError::SigningFailed(format!(
                "signer does not support required method {:?}",
                crate::signer::SignerMethod::Digest
            )));
        }
        self.sign_ecdsa(&path, *sighash.as_byte_array())
            .await
            .map_err(|e| BuilderError::SigningFailed(e.to_string()))
    }
}

/// Errors that can occur during transaction building
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    /// No inputs provided
    NoInputs,
    /// No outputs provided
    NoOutputs,
    /// No change address provided
    NoChangeAddress,
    /// The requested funding account does not exist
    AccountNotFound(String),
    /// Insufficient funds
    InsufficientFunds {
        available: u64,
        required: u64,
    },
    /// Invalid amount
    InvalidAmount(String),
    /// Invalid data
    InvalidData(String),
    /// Signing failed
    SigningFailed(String),
    /// Coin selection error
    CoinSelection(crate::wallet::managed_wallet_info::coin_selection::SelectionError),
    /// Signing was attempted with a watch-only wallet
    WatchOnlyWallet,
    /// More inputs than fit in a single standard transaction
    TooManyInputs {
        count: usize,
        max: usize,
    },
}

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInputs => write!(f, "No inputs provided"),
            Self::NoOutputs => write!(f, "No outputs provided"),
            Self::NoChangeAddress => write!(f, "No change address provided"),
            Self::AccountNotFound(msg) => write!(f, "Account not found: {msg}"),
            Self::InsufficientFunds {
                available,
                required,
            } => {
                write!(f, "Insufficient funds: available {}, required {}", available, required)
            }
            Self::InvalidAmount(msg) => write!(f, "Invalid amount: {}", msg),
            Self::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            Self::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            Self::CoinSelection(err) => write!(f, "Coin selection error: {}", err),
            Self::WatchOnlyWallet => write!(f, "Cannot sign with a watch-only wallet"),
            Self::TooManyInputs {
                count,
                max,
            } => {
                write!(f, "Too many inputs for a standard transaction: {count} (max {max})")
            }
        }
    }
}

impl std::error::Error for BuilderError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;
    use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
    use dashcore::{OutPoint, Txid};
    use dashcore_hashes::{sha256d, Hash};
    use hex;

    #[test]
    fn test_transaction_builder_basic() {
        let utxo = Utxo::dummy(0, 100000, 100, false, true);
        let destination = Address::dummy(Network::Testnet, 0);
        let change = Address::dummy(Network::Testnet, 0);

        let tx = TransactionBuilder::new()
            .set_current_height(200)
            .add_inputs([utxo])
            .add_output(&destination, 50000)
            .set_change_address(change)
            .build_unsigned()
            .map(|(tx, _)| tx);

        assert!(tx.is_ok());
        let transaction = tx.unwrap();
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.output.len(), 2); // Output + change
    }

    #[test]
    fn test_insufficient_funds() {
        let utxo = Utxo::dummy(0, 10000, 100, false, true);
        let destination = Address::dummy(Network::Testnet, 0);

        let result = TransactionBuilder::new()
            .set_current_height(200)
            .add_inputs([utxo])
            .add_output(&destination, 50000)
            .build_unsigned();

        // Insufficient funds now surface via the coin selector wrapper too.
        assert!(matches!(
            result,
            Err(BuilderError::InsufficientFunds { .. }) | Err(BuilderError::CoinSelection(_))
        ));
    }

    #[test]
    fn test_asset_lock_transaction() {
        // Test based on DSTransactionTests.m testAssetLockTx1
        use dashcore::consensus::Decodable;
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

        let recipient_address = Address::dummy(Network::Testnet, 0);
        let change_address = Address::dummy(Network::Testnet, 0);

        let builder = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 150000)
            .add_inputs(utxos);

        // Test calculate_base_size
        let base_size = builder.calculate_base_size();
        // Base (8) + input varint (1) + output varint (1) + 1 output (34) + 1 change (34) = 78 bytes
        assert!(
            base_size > 70 && base_size < 85,
            "Base size should be around 78 bytes, got {}",
            base_size
        );

        // estimate_transaction_size was removed in the new builder API; if a
        // future test needs full-size estimation, derive it from a real build.
    }

    #[test]
    fn test_fee_calculation() {
        // Test that fees are calculated correctly
        let utxos = vec![Utxo::dummy(0, 1000000, 100, false, true)];

        let recipient_address = Address::dummy(Network::Testnet, 0);
        let change_address = Address::dummy(Network::Testnet, 0);

        let tx = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal()) // 1 duff per byte
            .set_change_address(change_address.clone())
            .add_inputs(utxos)
            .add_output(&recipient_address, 500000)
            .build_unsigned()
            .unwrap()
            .0;

        // Total input: 1000000
        // Output to recipient: 500000
        // Change output should be approximately: 1000000 - 500000 - fee
        // Fee should be roughly 226 duffs for a 1-input, 2-output transaction
        let total_output: u64 = tx.output.iter().map(|o| o.value).sum();
        let fee = 1000000 - total_output;

        assert!(fee > 200 && fee < 300, "Fee should be around 226 duffs, got {}", fee);
    }

    #[test]
    fn test_exact_change_no_change_output() {
        // Test when the exact amount is used (no change output needed)
        let utxos = vec![Utxo::dummy(0, 150226, 100, false, true)]; // Exact amount for output + fee

        let recipient_address = Address::dummy(Network::Testnet, 0);
        let change_address = Address::dummy(Network::Testnet, 0);

        let tx = TransactionBuilder::new()
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::SmallestFirst)
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change_address.clone())
            .add_inputs(utxos)
            .add_output(&recipient_address, 150000)
            .build_unsigned()
            .unwrap()
            .0;

        // Should only have 1 output (no change) because change is below dust threshold
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, 150000);
    }

    #[test]
    fn test_special_payload_size_calculations() {
        // Test that special payload sizes are calculated correctly
        let utxo = Utxo::dummy(0, 100000, 100, false, true);
        let destination = Address::dummy(Network::Testnet, 0);
        let change = Address::dummy(Network::Testnet, 0);

        // Test with AssetLock payload
        let credit_outputs = vec![
            TxOut {
                value: 100000000,
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: 895000941,
                script_pubkey: ScriptBuf::new(),
            },
        ];

        let asset_lock_payload = AssetLockPayload {
            version: 1,
            credit_outputs: credit_outputs.clone(),
        };

        let builder = TransactionBuilder::new()
            .set_current_height(200)
            .add_inputs([utxo.clone()])
            .add_output(&destination, 50000)
            .set_change_address(change.clone())
            .set_special_payload(TransactionPayload::AssetLockPayloadType(asset_lock_payload));

        let base_size = builder.calculate_base_size();
        // Should include special payload size
        assert!(base_size > 100, "Base size with AssetLock payload should be larger");

        // Test with CoinbasePayload
        use dashcore::blockdata::transaction::special_transaction::coinbase::CoinbasePayload;
        use dashcore::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};

        let coinbase_payload = CoinbasePayload {
            version: 3,
            height: 1526,
            merkle_root_masternode_list: MerkleRootMasternodeList::from_raw_hash(
                sha256d::Hash::from_slice(&[0xaa; 32]).unwrap(),
            ),
            merkle_root_quorums: MerkleRootQuorums::from_raw_hash(
                sha256d::Hash::from_slice(&[0xbb; 32]).unwrap(),
            ),
            best_cl_height: Some(1500),
            best_cl_signature: Some(dashcore::bls_sig_utils::BLSSignature::from([0; 96])),
            asset_locked_amount: Some(1000000),
        };

        let builder2 = TransactionBuilder::new()
            .set_current_height(200)
            .add_inputs([utxo])
            .add_output(&destination, 50000)
            .set_change_address(change)
            .set_special_payload(TransactionPayload::CoinbasePayloadType(coinbase_payload));

        let base_size2 = builder2.calculate_base_size();
        // Coinbase payload: 2 + 4 + 32 + 32 + 4 + 96 + 8 = 178 bytes + varint
        assert!(base_size2 > 180, "Base size with Coinbase payload should be larger");
    }

    #[test]
    fn test_bip69_output_ordering() {
        // Test that outputs are sorted according to BIP-69
        let utxo = Utxo::dummy(0, 1000000, 100, false, true);
        let address1 = Address::dummy(Network::Testnet, 0);
        let address2 = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[
                0x02, 0x60, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
                0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
                0x88, 0x7e, 0x5b, 0x23, 0x52,
            ])
            .unwrap(),
            Network::Testnet,
        );
        let change_address = Address::dummy(Network::Testnet, 0);

        let tx = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change_address)
            .add_inputs([utxo])
            // Add outputs in non-sorted order
            .add_output(&address1, 300000) // Higher amount
            .add_output(&address2, 100000) // Lower amount
            .add_output(&address1, 200000) // Middle amount
            .build_unsigned()
            .unwrap()
            .0;

        // Verify outputs are sorted by amount (ascending)
        assert!(tx.output[0].value <= tx.output[1].value);
        assert!(tx.output[1].value <= tx.output[2].value);

        // The lowest value should be 100000
        assert_eq!(tx.output[0].value, 100000);
    }

    #[test]
    fn test_bip69_input_ordering() {
        // Test that inputs are sorted according to BIP-69
        let mut utxo1 = Utxo::new(
            OutPoint {
                txid: Txid::from_raw_hash(sha256d::Hash::from_slice(&[2u8; 32]).unwrap()),
                vout: 1,
            },
            TxOut {
                value: 100000,
                script_pubkey: ScriptBuf::new(),
            },
            Address::dummy(Network::Testnet, 0),
            100,
            false,
        );
        utxo1.is_confirmed = true;

        let mut utxo2 = Utxo::new(
            OutPoint {
                txid: Txid::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap()),
                vout: 2,
            },
            TxOut {
                value: 200000,
                script_pubkey: ScriptBuf::new(),
            },
            Address::dummy(Network::Testnet, 0),
            100,
            false,
        );
        utxo2.is_confirmed = true;

        let mut utxo3 = Utxo::new(
            OutPoint {
                txid: Txid::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap()),
                vout: 0,
            },
            TxOut {
                value: 300000,
                script_pubkey: ScriptBuf::new(),
            },
            Address::dummy(Network::Testnet, 0),
            100,
            false,
        );
        utxo3.is_confirmed = true;

        let destination = Address::dummy(Network::Testnet, 0);
        let change = Address::dummy(Network::Testnet, 0);

        let tx = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change)
            // Add inputs in non-sorted order
            .add_inputs([utxo1.clone()])
            .add_inputs([utxo2.clone()])
            .add_inputs([utxo3.clone()])
            .add_output(&destination, 500000)
            .build_unsigned()
            .unwrap()
            .0;

        // Verify inputs are sorted by txid first, then by vout
        // Expected order: [1u8; 32]:0, [1u8; 32]:2, [2u8; 32]:1
        assert_eq!(
            tx.input[0].previous_output.txid,
            Txid::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap())
        );
        assert_eq!(tx.input[0].previous_output.vout, 0);

        assert_eq!(
            tx.input[1].previous_output.txid,
            Txid::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap())
        );
        assert_eq!(tx.input[1].previous_output.vout, 2);

        assert_eq!(
            tx.input[2].previous_output.txid,
            Txid::from_raw_hash(sha256d::Hash::from_slice(&[2u8; 32]).unwrap())
        );
        assert_eq!(tx.input[2].previous_output.vout, 1);
    }

    #[test]
    fn test_coin_selection_with_special_payload() {
        // Test that coin selection considers special payload size
        let utxos = vec![
            Utxo::dummy(0, 50000, 100, false, true),
            Utxo::dummy(0, 60000, 100, false, true),
            Utxo::dummy(0, 70000, 100, false, true),
        ];

        let recipient_address = Address::dummy(Network::Testnet, 0);
        let change_address = Address::dummy(Network::Testnet, 0);

        // Create a large special payload that affects fee calculation
        let credit_outputs = vec![
            TxOut {
                value: 10000,
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: 20000,
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: 30000,
                script_pubkey: ScriptBuf::new(),
            },
        ];

        let asset_lock_payload = AssetLockPayload {
            version: 1,
            credit_outputs,
        };

        let tx = TransactionBuilder::new()
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::SmallestFirst)
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change_address)
            .set_special_payload(TransactionPayload::AssetLockPayloadType(asset_lock_payload))
            .add_output(&recipient_address, 50000)
            .add_inputs(utxos)
            .build_unsigned()
            .unwrap()
            .0;

        // Should have selected enough inputs to cover output + fees for larger transaction
        assert!(
            tx.input.len() >= 2,
            "Should select multiple inputs to cover fees for special payload"
        );
    }
}
