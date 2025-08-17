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
use dashcore::hash_types::{
    InputsHash, MerkleRootMasternodeList, MerkleRootQuorums, ProTxHash, PubkeyHash,
};
use dashcore::sighash::{EcdsaSighashType, SighashCache};
use dashcore::Address;
use dashcore::{OutPoint, TxIn, TxOut, Txid};
use dashcore_hashes::Hash;
use secp256k1::{Message, Secp256k1, SecretKey};
use std::net::SocketAddr;

use crate::wallet::managed_wallet_info::coin_selection::{CoinSelector, SelectionStrategy};
use crate::wallet::managed_wallet_info::fee::FeeLevel;
use crate::Utxo;

/// Transaction builder for creating Dash transactions
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

        let fee_rate = self.fee_level.fee_rate();
        let selector = CoinSelector::new(strategy);

        let selection = selector
            .select_coins(available_utxos, target_amount, fee_rate, current_height)
            .map_err(BuilderError::CoinSelection)?;

        // Add selected UTXOs with their keys
        for utxo in selection.selected {
            let key = keys(&utxo);
            self.inputs.push((utxo, key));
        }

        Ok(self)
    }

    /// Add an output to a specific address
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

        // Create transaction inputs
        // Dash doesn't use RBF, so we use the standard sequence number
        let sequence = 0xffffffff;

        let tx_inputs: Vec<TxIn> = self
            .inputs
            .iter()
            .map(|(utxo, _)| TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: dashcore::blockdata::witness::Witness::new(),
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

        // Create unsigned transaction with optional special payload
        // Clone the special_payload to avoid move issues with sign_transaction
        let mut transaction = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: tx_inputs,
            output: tx_outputs,
            special_transaction_payload: self.special_payload.take(),
        };

        // Sign inputs if keys are provided
        if self.inputs.iter().any(|(_, key)| key.is_some()) {
            transaction = self.sign_transaction(transaction)?;
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
        crate::wallet::managed_wallet_info::fee::estimate_tx_size(
            input_count,
            output_count,
            self.change_address.is_some(),
        )
    }

    /// Sign the transaction
    fn sign_transaction(&self, mut tx: Transaction) -> Result<Transaction, BuilderError> {
        let secp = Secp256k1::new();

        // Collect all signatures first, then apply them
        let mut signatures = Vec::new();
        {
            let cache = SighashCache::new(&tx);

            for (index, (utxo, key_opt)) in self.inputs.iter().enumerate() {
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
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::{OutPoint, TxOut, Txid};
    use dashcore_hashes::{sha256d, Hash};

    fn test_utxo(value: u64) -> Utxo {
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
        utxo.is_confirmed = true;
        utxo
    }

    fn test_address() -> Address {
        Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[
                0x03, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
                0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
                0x88, 0x7e, 0x5b, 0x23, 0x52,
            ])
            .unwrap(),
            Network::Testnet,
        )
    }

    #[test]
    fn test_transaction_builder_basic() {
        let utxo = test_utxo(100000);
        let destination = test_address();
        let change = test_address();

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
        let utxo = test_utxo(10000);
        let destination = test_address();

        let result = TransactionBuilder::new()
            .add_input(utxo, None)
            .add_output(&destination, 50000)
            .unwrap()
            .build();

        assert!(matches!(result, Err(BuilderError::InsufficientFunds { .. })));
    }
}
