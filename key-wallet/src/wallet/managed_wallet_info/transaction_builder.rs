//! Transaction building with dashcore types
//!
//! This module provides high-level transaction building functionality
//! using types from the dashcore crate.

use alloc::vec::Vec;
use core::fmt;

use dashcore::blockdata::script::{Builder, PushBytes, ScriptBuf};
use dashcore::blockdata::transaction::special_transaction::{
    asset_lock::AssetLockPayload,
    coinbase::CoinbasePayload,
    provider_registration::{ProviderMasternodeType, ProviderRegistrationPayload},
    provider_update_registrar::ProviderUpdateRegistrarPayload,
    provider_update_revocation::ProviderUpdateRevocationPayload,
    provider_update_service::ProviderUpdateServicePayload,
    TransactionPayload,
};
use dashcore::blockdata::transaction::Transaction;
use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
use dashcore::hash_types::{InputsHash, MerkleRootMasternodeList, MerkleRootQuorums, PubkeyHash};
use dashcore::sighash::{EcdsaSighashType, SighashCache};
use dashcore::Address;
use dashcore::{OutPoint, TxIn, TxOut, Txid};
use dashcore_hashes::Hash;
use secp256k1::{Message, Secp256k1, SecretKey};
use std::net::SocketAddr;

use crate::wallet::managed_wallet_info::coin_selection::{CoinSelector, SelectionStrategy};
use crate::wallet::managed_wallet_info::fee::FeeLevel;
use crate::Utxo;

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
    /// Selected UTXOs with their private keys
    inputs: Vec<(Utxo, Option<SecretKey>)>,
    /// Outputs to create
    outputs: Vec<TxOut>,
    /// Change address
    change_address: Option<Address>,
    /// Fee rate or level
    fee_level: FeeLevel,
    /// Lock time
    lock_time: u32,
    /// Transaction version
    version: u16,
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
            outputs: Vec::new(),
            change_address: None,
            fee_level: FeeLevel::Normal,
            lock_time: 0,
            version: 2, // Default to version 2 for Dash
            special_payload: None,
        }
    }

    /// Add a UTXO input with optional private key for signing
    pub fn add_input(mut self, utxo: Utxo, key: Option<SecretKey>) -> Self {
        self.inputs.push((utxo, key));
        self
    }

    /// Add multiple inputs
    pub fn add_inputs(mut self, inputs: Vec<(Utxo, Option<SecretKey>)>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    /// Select inputs automatically using coin selection
    ///
    /// This method requires outputs to be added first so it knows how much to select.
    /// For special transactions without regular outputs, add the required inputs manually.
    pub fn select_inputs(
        mut self,
        available_utxos: &[Utxo],
        strategy: SelectionStrategy,
        current_height: u32,
        keys: impl Fn(&Utxo) -> Option<SecretKey>,
    ) -> Result<Self, BuilderError> {
        // Calculate target amount from outputs
        let target_amount = self.total_output_value();

        if target_amount == 0 && self.special_payload.is_none() {
            return Err(BuilderError::NoOutputs);
        }

        // Calculate the base transaction size including existing outputs and special payload
        let base_size = self.calculate_base_size();
        let input_size = 148; // Size per P2PKH input

        let fee_rate = self.fee_level.fee_rate();

        // Use the CoinSelector with the proper size context
        let selector = CoinSelector::new(strategy);
        let selection = selector
            .select_coins_with_size(
                available_utxos,
                target_amount,
                fee_rate,
                current_height,
                base_size,
                input_size,
            )
            .map_err(BuilderError::CoinSelection)?;

        // Add selected UTXOs with their keys
        for utxo in selection.selected {
            let key = keys(&utxo);
            self.inputs.push((utxo, key));
        }

        Ok(self)
    }

    /// Add an output to a specific address
    ///
    /// Note: Outputs will be sorted according to BIP-69 when the transaction is built:
    /// - First by amount (ascending)
    /// - Then by scriptPubKey (lexicographically)
    pub fn add_output(mut self, address: &Address, amount: u64) -> Result<Self, BuilderError> {
        if amount == 0 {
            return Err(BuilderError::InvalidAmount("Output amount cannot be zero".into()));
        }

        let script_pubkey = address.script_pubkey();
        self.outputs.push(TxOut {
            value: amount,
            script_pubkey,
        });
        Ok(self)
    }

    /// Add a data output (OP_RETURN)
    ///
    /// Note: Outputs will be sorted according to BIP-69 when the transaction is built:
    /// - First by amount (ascending) - data outputs have 0 value
    /// - Then by scriptPubKey (lexicographically)
    pub fn add_data_output(mut self, data: Vec<u8>) -> Result<Self, BuilderError> {
        if data.len() > 80 {
            return Err(BuilderError::InvalidData("Data output too large (max 80 bytes)".into()));
        }

        let script = Builder::new()
            .push_opcode(dashcore::blockdata::opcodes::all::OP_RETURN)
            .push_slice(
                <&PushBytes>::try_from(data.as_slice())
                    .map_err(|_| BuilderError::InvalidData("Invalid data length".into()))?,
            )
            .into_script();

        self.outputs.push(TxOut {
            value: 0,
            script_pubkey: script,
        });
        Ok(self)
    }

    /// Set the change address
    pub fn set_change_address(mut self, address: Address) -> Self {
        self.change_address = Some(address);
        self
    }

    /// Set the fee level
    pub fn set_fee_level(mut self, level: FeeLevel) -> Self {
        self.fee_level = level;
        self
    }

    /// Set the lock time
    pub fn set_lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = lock_time;
        self
    }

    /// Set the transaction version
    pub fn set_version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    /// Set the special transaction payload
    pub fn set_special_payload(mut self, payload: TransactionPayload) -> Self {
        self.special_payload = Some(payload);
        self
    }

    /// Get the total value of all outputs added so far
    pub fn total_output_value(&self) -> u64 {
        self.outputs.iter().map(|out| out.value).sum()
    }

    /// Calculate the base transaction size excluding inputs
    /// Based on dashsync/DashSync/shared/Models/Transactions/Base/DSTransaction.m
    fn calculate_base_size(&self) -> usize {
        // Base: version (2) + type (2) + locktime (4) = 8 bytes
        let mut size = 8;

        // Add varint for input count (will be added later, typically 1 byte)
        size += 1;

        // Add varint for output count
        size += varint_size(
            self.outputs.len()
                + if self.change_address.is_some() {
                    1
                } else {
                    0
                },
        );

        // Add outputs size (TX_OUTPUT_SIZE = 34 bytes per P2PKH output)
        size += self.outputs.len() * 34;

        // Add change output if we have a change address
        if self.change_address.is_some() {
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

    /// Build the transaction
    ///
    /// Uses the special payload if one was set via `set_special_payload`
    pub fn build(self) -> Result<Transaction, BuilderError> {
        self.build_internal()
    }

    /// Build the transaction with an explicit special transaction payload
    ///
    /// This overrides any payload set via `set_special_payload`.
    /// Supports Dash-specific transaction types like:
    /// - ProRegTx (Provider Registration)
    /// - ProUpServTx (Provider Update Service)
    /// - ProUpRegTx (Provider Update Registrar)
    /// - ProUpRevTx (Provider Update Revocation)
    /// - CoinJoin transactions
    /// - InstantSend transactions
    /// - And other special transaction types
    pub fn build_with_payload(
        mut self,
        payload: Option<TransactionPayload>,
    ) -> Result<Transaction, BuilderError> {
        self.special_payload = payload;
        self.build_internal()
    }

    /// Internal build method that uses the stored special_payload
    fn build_internal(mut self) -> Result<Transaction, BuilderError> {
        if self.inputs.is_empty() {
            return Err(BuilderError::NoInputs);
        }

        if self.outputs.is_empty() {
            return Err(BuilderError::NoOutputs);
        }

        // Calculate total input value
        let total_input: u64 = self.inputs.iter().map(|(utxo, _)| utxo.value()).sum();

        // Calculate total output value
        let total_output: u64 = self.outputs.iter().map(|out| out.value).sum();

        if total_input < total_output {
            return Err(BuilderError::InsufficientFunds {
                available: total_input,
                required: total_output,
            });
        }

        // BIP-69: Sort inputs by transaction hash (reversed) and then by output index
        // We need to maintain the association between UTXOs and their keys
        let mut sorted_inputs = self.inputs.clone();
        sorted_inputs.sort_by(|a, b| {
            // First compare by transaction hash (reversed byte order)
            let tx_hash_a = a.0.outpoint.txid.to_byte_array();
            let tx_hash_b = b.0.outpoint.txid.to_byte_array();

            match tx_hash_a.cmp(&tx_hash_b) {
                std::cmp::Ordering::Equal => {
                    // If transaction hashes match, compare by output index
                    a.0.outpoint.vout.cmp(&b.0.outpoint.vout)
                }
                other => other,
            }
        });

        // Create transaction inputs from sorted inputs
        // Dash doesn't use RBF, so we use the standard sequence number
        let sequence = 0xffffffff;

        let tx_inputs: Vec<TxIn> = sorted_inputs
            .iter()
            .map(|(utxo, _)| TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
            })
            .collect();

        let mut tx_outputs = self.outputs.clone();

        // Calculate fee
        let fee_rate = self.fee_level.fee_rate();
        let estimated_size = self.estimate_transaction_size(tx_inputs.len(), tx_outputs.len() + 1);
        let fee = fee_rate.calculate_fee(estimated_size);

        let change_amount = total_input.saturating_sub(total_output).saturating_sub(fee);

        // Add change output if needed
        if change_amount > 546 {
            // Above dust threshold
            if let Some(change_addr) = &self.change_address {
                let change_script = change_addr.script_pubkey();
                tx_outputs.push(TxOut {
                    value: change_amount,
                    script_pubkey: change_script,
                });
            } else {
                return Err(BuilderError::NoChangeAddress);
            }
        }

        // BIP-69: Sort outputs by amount first, then by scriptPubKey lexicographically
        tx_outputs.sort_by(|a, b| {
            match a.value.cmp(&b.value) {
                std::cmp::Ordering::Equal => {
                    // If amounts match, compare scriptPubKeys lexicographically
                    a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes())
                }
                other => other,
            }
        });

        // Create unsigned transaction with optional special payload
        // Update sorted_inputs to maintain the key association after sorting
        let mut transaction = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: tx_inputs,
            output: tx_outputs,
            special_transaction_payload: self.special_payload.take(),
        };

        // Sign inputs if keys are provided
        if sorted_inputs.iter().any(|(_, key)| key.is_some()) {
            transaction = self.sign_transaction_with_sorted_inputs(transaction, sorted_inputs)?;
        }

        Ok(transaction)
    }

    /// Build a Provider Registration Transaction (ProRegTx)
    ///
    /// Used to register a new masternode on the network
    ///
    /// Note: This method intentionally takes many parameters rather than a single
    /// payload object to make the API more explicit and allow callers to construct
    /// transactions without needing to build intermediate payload types.
    #[allow(clippy::too_many_arguments)]
    pub fn build_provider_registration(
        self,
        masternode_type: ProviderMasternodeType,
        masternode_mode: u16,
        collateral_outpoint: OutPoint,
        service_address: SocketAddr,
        owner_key_hash: PubkeyHash,
        operator_public_key: BLSPublicKey,
        voting_key_hash: PubkeyHash,
        operator_reward: u16,
        script_payout: ScriptBuf,
        inputs_hash: InputsHash,
        signature: Vec<u8>,
        platform_node_id: Option<PubkeyHash>,
        platform_p2p_port: Option<u16>,
        platform_http_port: Option<u16>,
    ) -> Result<Transaction, BuilderError> {
        let payload = ProviderRegistrationPayload {
            version: 2,
            masternode_type,
            masternode_mode,
            collateral_outpoint,
            service_address,
            owner_key_hash,
            operator_public_key,
            voting_key_hash,
            operator_reward,
            script_payout,
            inputs_hash,
            signature,
            platform_node_id,
            platform_p2p_port,
            platform_http_port,
        };
        self.build_with_payload(Some(TransactionPayload::ProviderRegistrationPayloadType(payload)))
    }

    /// Build a Provider Update Service Transaction (ProUpServTx)
    ///
    /// Used to update the service details of an existing masternode
    ///
    /// Note: This method intentionally takes many parameters rather than a single
    /// payload object to make the API more explicit and allow callers to construct
    /// transactions without needing to build intermediate payload types.
    #[allow(clippy::too_many_arguments)]
    pub fn build_provider_update_service(
        self,
        mn_type: Option<u16>,
        pro_tx_hash: Txid,
        ip_address: u128,
        port: u16,
        script_payout: ScriptBuf,
        inputs_hash: InputsHash,
        platform_node_id: Option<[u8; 20]>,
        platform_p2p_port: Option<u16>,
        platform_http_port: Option<u16>,
        payload_sig: BLSSignature,
    ) -> Result<Transaction, BuilderError> {
        let payload = ProviderUpdateServicePayload {
            version: 2,
            mn_type,
            pro_tx_hash,
            ip_address,
            port,
            script_payout,
            inputs_hash,
            platform_node_id,
            platform_p2p_port,
            platform_http_port,
            payload_sig,
        };
        self.build_with_payload(Some(TransactionPayload::ProviderUpdateServicePayloadType(payload)))
    }

    /// Build a Provider Update Registrar Transaction (ProUpRegTx)
    ///
    /// Used to update the registrar details of an existing masternode
    ///
    /// Note: This method intentionally takes many parameters rather than a single
    /// payload object to make the API more explicit and allow callers to construct
    /// transactions without needing to build intermediate payload types.
    #[allow(clippy::too_many_arguments)]
    pub fn build_provider_update_registrar(
        self,
        pro_tx_hash: Txid,
        provider_mode: u16,
        operator_public_key: BLSPublicKey,
        voting_key_hash: PubkeyHash,
        script_payout: ScriptBuf,
        inputs_hash: InputsHash,
        payload_sig: Vec<u8>,
    ) -> Result<Transaction, BuilderError> {
        let payload = ProviderUpdateRegistrarPayload {
            version: 2,
            pro_tx_hash,
            provider_mode,
            operator_public_key,
            voting_key_hash,
            script_payout,
            inputs_hash,
            payload_sig,
        };
        self.build_with_payload(Some(TransactionPayload::ProviderUpdateRegistrarPayloadType(
            payload,
        )))
    }

    /// Build a Provider Update Revocation Transaction (ProUpRevTx)
    ///
    /// Used to revoke an existing masternode
    pub fn build_provider_update_revocation(
        self,
        pro_tx_hash: Txid,
        reason: u16,
        inputs_hash: InputsHash,
        payload_sig: BLSSignature,
    ) -> Result<Transaction, BuilderError> {
        let payload = ProviderUpdateRevocationPayload {
            version: 2,
            pro_tx_hash,
            reason,
            inputs_hash,
            payload_sig,
        };
        self.build_with_payload(Some(TransactionPayload::ProviderUpdateRevocationPayloadType(
            payload,
        )))
    }

    /// Build a Coinbase Transaction
    ///
    /// Used for block rewards and includes additional coinbase-specific data
    pub fn build_coinbase(
        self,
        height: u32,
        merkle_root_masternode_list: MerkleRootMasternodeList,
        merkle_root_quorums: MerkleRootQuorums,
        best_cl_height: Option<u32>,
        best_cl_signature: Option<BLSSignature>,
        asset_locked_amount: Option<u64>,
    ) -> Result<Transaction, BuilderError> {
        let payload = CoinbasePayload {
            version: 3, // Current coinbase version
            height,
            merkle_root_masternode_list,
            merkle_root_quorums,
            best_cl_height,
            best_cl_signature,
            asset_locked_amount,
        };
        self.build_with_payload(Some(TransactionPayload::CoinbasePayloadType(payload)))
    }

    /// Build an Asset Lock Transaction
    ///
    /// Used to lock Dash for use in Platform (creates Platform credits)
    pub fn build_asset_lock(self, credit_outputs: Vec<TxOut>) -> Result<Transaction, BuilderError> {
        let payload = AssetLockPayload {
            version: 0,
            credit_outputs,
        };
        self.build_with_payload(Some(TransactionPayload::AssetLockPayloadType(payload)))
    }

    /// Estimate transaction size in bytes
    fn estimate_transaction_size(&self, input_count: usize, output_count: usize) -> usize {
        // Base: version (2) + type (2) + locktime (4) = 8 bytes
        let mut size = 8;

        // Add varints for input/output counts
        size += varint_size(input_count);
        size += varint_size(output_count);

        // Add inputs (TX_INPUT_SIZE = 148 bytes per P2PKH input)
        size += input_count * 148;

        // Add outputs (TX_OUTPUT_SIZE = 34 bytes per P2PKH output)
        size += output_count * 34;

        // Add special payload size if present (same logic as calculate_base_size)
        if let Some(ref payload) = self.special_payload {
            let payload_size = match payload {
                TransactionPayload::CoinbasePayloadType(p) => {
                    let mut size = 2 + 4 + 32 + 32;
                    if p.best_cl_height.is_some() {
                        size += 4 + 96;
                    }
                    if p.asset_locked_amount.is_some() {
                        size += 8;
                    }
                    size
                }
                TransactionPayload::ProviderRegistrationPayloadType(p) => {
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
                    base + varint_size(75) + 75
                }
                TransactionPayload::ProviderUpdateServicePayloadType(p) => {
                    let script_size = p.script_payout.len();
                    let mut size =
                        2 + 32 + 16 + 2 + varint_size(script_size) + script_size + 32 + 96;
                    if p.mn_type.is_some() {
                        size += 2;
                    }
                    if p.platform_node_id.is_some() {
                        size += 20 + 2 + 2;
                    }
                    size
                }
                TransactionPayload::ProviderUpdateRegistrarPayloadType(p) => {
                    let script_size = p.script_payout.len();
                    2 + 32 + 2 + 48 + 20 + varint_size(script_size) + script_size + 32 + 75
                }
                TransactionPayload::ProviderUpdateRevocationPayloadType(_) => 2 + 32 + 2 + 32 + 96,
                TransactionPayload::AssetLockPayloadType(p) => {
                    1 + varint_size(p.credit_outputs.len()) + p.credit_outputs.len() * 34
                }
                TransactionPayload::AssetUnlockPayloadType(_) => 1 + 8 + 4 + 4 + 32 + 96,
                _ => 100,
            };

            size += varint_size(payload_size) + payload_size;
        }

        size
    }

    /// Sign the transaction with sorted inputs (for BIP-69 compliance)
    fn sign_transaction_with_sorted_inputs(
        &self,
        mut tx: Transaction,
        sorted_inputs: Vec<(Utxo, Option<SecretKey>)>,
    ) -> Result<Transaction, BuilderError> {
        let secp = Secp256k1::new();

        // Collect all signatures first, then apply them
        let mut signatures = Vec::new();
        {
            let cache = SighashCache::new(&tx);

            for (index, (utxo, key_opt)) in sorted_inputs.iter().enumerate() {
                if let Some(key) = key_opt {
                    // Get the script pubkey from the UTXO
                    let script_pubkey = &utxo.txout.script_pubkey;

                    // Create signature hash for P2PKH
                    let sighash = cache
                        .legacy_signature_hash(index, script_pubkey, EcdsaSighashType::All.to_u32())
                        .map_err(|e| {
                            BuilderError::SigningFailed(format!("Failed to compute sighash: {}", e))
                        })?;

                    // Sign the hash
                    let message = Message::from_digest(*sighash.as_byte_array());
                    let signature = secp.sign_ecdsa(&message, key);

                    // Create script signature (P2PKH)
                    let mut sig_bytes = signature.serialize_der().to_vec();
                    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);

                    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, key);

                    let script_sig = Builder::new()
                        .push_slice(<&PushBytes>::try_from(sig_bytes.as_slice()).map_err(|_| {
                            BuilderError::SigningFailed("Invalid signature length".into())
                        })?)
                        .push_slice(pubkey.serialize())
                        .into_script();

                    signatures.push((index, script_sig));
                } else {
                    signatures.push((index, ScriptBuf::new()));
                }
            }
        } // cache goes out of scope here

        // Apply signatures
        for (index, script_sig) in signatures {
            tx.input[index].script_sig = script_sig;
        }

        Ok(tx)
    }

    /// Sign the transaction (legacy method for backward compatibility)
    pub fn sign_transaction(&self, tx: Transaction) -> Result<Transaction, BuilderError> {
        // For backward compatibility, we sort the inputs according to BIP-69 before signing
        let mut sorted_inputs = self.inputs.clone();
        sorted_inputs.sort_by(|a, b| {
            let tx_hash_a = a.0.outpoint.txid.to_byte_array();
            let tx_hash_b = b.0.outpoint.txid.to_byte_array();

            match tx_hash_a.cmp(&tx_hash_b) {
                std::cmp::Ordering::Equal => a.0.outpoint.vout.cmp(&b.0.outpoint.vout),
                other => other,
            }
        });

        self.sign_transaction_with_sorted_inputs(tx, sorted_inputs)
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
}

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInputs => write!(f, "No inputs provided"),
            Self::NoOutputs => write!(f, "No outputs provided"),
            Self::NoChangeAddress => write!(f, "No change address provided"),
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
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuilderError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;
    use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
    use dashcore_hashes::{sha256d, Hash};
    use hex;

    #[test]
    fn test_transaction_builder_basic() {
        let utxo = Utxo::dummy(0, 100000, 100, false, true);
        let destination = Address::dummy(Network::Testnet, 0);
        let change = Address::dummy(Network::Testnet, 0);

        let tx = TransactionBuilder::new()
            .add_input(utxo, None)
            .add_output(&destination, 50000)
            .unwrap()
            .set_change_address(change)
            .build();

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
            .add_input(utxo, None)
            .add_output(&destination, 50000)
            .unwrap()
            .build();

        assert!(matches!(result, Err(BuilderError::InsufficientFunds { .. })));
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
            .set_fee_level(FeeLevel::Normal)
            .set_change_address(change_address.clone())
            .add_output(&recipient_address, 150000)
            .unwrap()
            .add_inputs(utxos.into_iter().map(|u| (u, None)).collect());

        // Test calculate_base_size
        let base_size = builder.calculate_base_size();
        // Base (8) + input varint (1) + output varint (1) + 1 output (34) + 1 change (34) = 78 bytes
        assert!(
            base_size > 70 && base_size < 85,
            "Base size should be around 78 bytes, got {}",
            base_size
        );

        // Test estimate_transaction_size
        let estimated_size = builder.estimate_transaction_size(2, 2);
        // Base (8) + varints (2) + 2 inputs (296) + 2 outputs (68) = ~374 bytes
        assert!(
            estimated_size > 370 && estimated_size < 380,
            "Estimated size should be around 374 bytes, got {}",
            estimated_size
        );
    }

    #[test]
    fn test_fee_calculation() {
        // Test that fees are calculated correctly
        let utxos = vec![Utxo::dummy(0, 1000000, 100, false, true)];

        let recipient_address = Address::dummy(Network::Testnet, 0);
        let change_address = Address::dummy(Network::Testnet, 0);

        let tx = TransactionBuilder::new()
            .set_fee_level(FeeLevel::Normal) // 1 duff per byte
            .set_change_address(change_address.clone())
            .add_inputs(utxos.into_iter().map(|u| (u, None)).collect())
            .add_output(&recipient_address, 500000)
            .unwrap()
            .build()
            .unwrap();

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
            .set_fee_level(FeeLevel::Normal)
            .set_change_address(change_address.clone())
            .add_inputs(utxos.into_iter().map(|u| (u, None)).collect())
            .add_output(&recipient_address, 150000)
            .unwrap()
            .build()
            .unwrap();

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
            .add_input(utxo.clone(), None)
            .add_output(&destination, 50000)
            .unwrap()
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
            .add_input(utxo, None)
            .add_output(&destination, 50000)
            .unwrap()
            .set_change_address(change)
            .set_special_payload(TransactionPayload::CoinbasePayloadType(coinbase_payload));

        let base_size2 = builder2.calculate_base_size();
        // Coinbase payload: 2 + 4 + 32 + 32 + 4 + 96 + 8 = 178 bytes + varint
        assert!(base_size2 > 180, "Base size with Coinbase payload should be larger");
    }

    #[test]
    fn test_build_with_payload_override() {
        // Test that build_with_payload overrides set_special_payload
        let utxo = Utxo::dummy(0, 100000, 100, false, true);
        let destination = Address::dummy(Network::Testnet, 0);
        let change = Address::dummy(Network::Testnet, 0);

        let credit_outputs = vec![TxOut {
            value: 50000,
            script_pubkey: ScriptBuf::new(),
        }];

        let original_payload = AssetLockPayload {
            version: 1,
            credit_outputs: credit_outputs.clone(),
        };

        let override_payload = AssetLockPayload {
            version: 2,
            credit_outputs: vec![TxOut {
                value: 75000,
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let tx = TransactionBuilder::new()
            .add_input(utxo, None)
            .add_output(&destination, 30000)
            .unwrap()
            .set_change_address(change)
            .set_special_payload(TransactionPayload::AssetLockPayloadType(original_payload))
            .build_with_payload(Some(TransactionPayload::AssetLockPayloadType(override_payload)))
            .unwrap();

        // Should use the override payload
        if let Some(TransactionPayload::AssetLockPayloadType(payload)) =
            &tx.special_transaction_payload
        {
            assert_eq!(payload.version, 2);
            assert_eq!(payload.credit_outputs.len(), 1);
            assert_eq!(payload.credit_outputs[0].value, 75000);
        } else {
            panic!("Expected AssetLockPayload");
        }
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
            .set_fee_level(FeeLevel::Normal)
            .set_change_address(change_address)
            .add_input(utxo, None)
            // Add outputs in non-sorted order
            .add_output(&address1, 300000)
            .unwrap() // Higher amount
            .add_output(&address2, 100000)
            .unwrap() // Lower amount
            .add_output(&address1, 200000)
            .unwrap() // Middle amount
            .build()
            .unwrap();

        // Verify outputs are sorted by amount (ascending)
        assert!(tx.output[0].value <= tx.output[1].value);
        assert!(tx.output[1].value <= tx.output[2].value);

        // The lowest value should be 100000
        assert_eq!(tx.output[0].value, 100000);
    }

    #[test]
    fn test_bip69_input_ordering() {
        // Test that inputs are sorted according to BIP-69
        let utxo1 = Utxo::new(
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

        let utxo2 = Utxo::new(
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

        let utxo3 = Utxo::new(
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

        let destination = Address::dummy(Network::Testnet, 0);
        let change = Address::dummy(Network::Testnet, 0);

        let tx = TransactionBuilder::new()
            .set_fee_level(FeeLevel::Normal)
            .set_change_address(change)
            // Add inputs in non-sorted order
            .add_input(utxo1.clone(), None)
            .add_input(utxo2.clone(), None)
            .add_input(utxo3.clone(), None)
            .add_output(&destination, 500000)
            .unwrap()
            .build()
            .unwrap();

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

        let result = TransactionBuilder::new()
            .set_fee_level(FeeLevel::Normal)
            .set_change_address(change_address)
            .set_special_payload(TransactionPayload::AssetLockPayloadType(asset_lock_payload))
            .add_output(&recipient_address, 50000)
            .unwrap()
            .select_inputs(&utxos, SelectionStrategy::SmallestFirst, 200, |_| None);

        assert!(result.is_ok());
        let builder = result.unwrap();
        let tx = builder.build().unwrap();

        // Should have selected enough inputs to cover output + fees for larger transaction
        assert!(
            tx.input.len() >= 2,
            "Should select multiple inputs to cover fees for special payload"
        );
    }
}
