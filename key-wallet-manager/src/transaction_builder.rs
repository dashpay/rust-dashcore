//! Transaction building with dashcore types
//!
//! This module provides high-level transaction building functionality
//! using types from the dashcore crate.

use alloc::vec::Vec;
use core::fmt;

use dashcore::blockdata::transaction::Transaction;
use dashcore::blockdata::transaction::txin::TxIn;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::blockdata::script::{ScriptBuf, Builder, PushBytes};
use dashcore::sighash::{EcdsaSighashType, SighashCache};
use dashcore_hashes::Hash;
use key_wallet::{Address, Network};
use secp256k1::{Message, Secp256k1, SecretKey};

use crate::utxo::Utxo;
use crate::fee::FeeLevel;
use crate::coin_selection::{CoinSelector, SelectionStrategy};

/// Transaction builder for creating Dash transactions
pub struct TransactionBuilder {
    /// Network
    network: Network,
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
    version: i32,
    /// Whether to enable RBF (Replace-By-Fee)
    enable_rbf: bool,
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new(network: Network) -> Self {
        Self {
            network,
            inputs: Vec::new(),
            outputs: Vec::new(),
            change_address: None,
            fee_level: FeeLevel::Normal,
            lock_time: 0,
            version: 2, // Default to version 2 for Dash
            enable_rbf: true,
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
    pub fn select_inputs(
        mut self,
        available_utxos: &[Utxo],
        target_amount: u64,
        strategy: SelectionStrategy,
        current_height: u32,
        keys: impl Fn(&Utxo) -> Option<SecretKey>,
    ) -> Result<Self, BuilderError> {
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
        
        let script_pubkey = ScriptBuf::from(address.script_pubkey());
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
            .push_slice(<&PushBytes>::try_from(data.as_slice()).map_err(|_| BuilderError::InvalidData("Invalid data length".into()))?)
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
    pub fn set_version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }

    /// Enable or disable RBF
    pub fn enable_rbf(mut self, enable: bool) -> Self {
        self.enable_rbf = enable;
        self
    }

    /// Build the transaction
    pub fn build(self) -> Result<Transaction, BuilderError> {
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
        let sequence = if self.enable_rbf {
            0xfffffffd // RBF enabled
        } else {
            0xffffffff // RBF disabled
        };
        
        let tx_inputs: Vec<TxIn> = self.inputs
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
                let change_script = ScriptBuf::from(change_addr.script_pubkey());
                tx_outputs.push(TxOut {
                    value: change_amount,
                    script_pubkey: change_script,
                });
            } else {
                return Err(BuilderError::NoChangeAddress);
            }
        }
        
        // Create unsigned transaction
        let mut transaction = Transaction {
            version: self.version as u16,
            lock_time: self.lock_time,
            input: tx_inputs,
            output: tx_outputs,
            special_transaction_payload: None,
        };
        
        // Sign inputs if keys are provided
        if self.inputs.iter().any(|(_, key)| key.is_some()) {
            transaction = self.sign_transaction(transaction)?;
        }
        
        Ok(transaction)
    }

    /// Estimate transaction size in bytes
    fn estimate_transaction_size(&self, input_count: usize, output_count: usize) -> usize {
        crate::fee::estimate_tx_size(input_count, output_count, self.change_address.is_some())
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
                    let sighash = cache.legacy_signature_hash(
                        index,
                        &script_pubkey,
                        EcdsaSighashType::All.to_u32()
                    ).map_err(|e| BuilderError::SigningFailed(format!("Failed to compute sighash: {}", e)))?;
                    
                    // Sign the hash  
                    let message = Message::from_digest(*sighash.as_byte_array());
                    let signature = secp.sign_ecdsa(&message, key);
                    
                    // Create script signature (P2PKH)
                    let mut sig_bytes = signature.serialize_der().to_vec();
                    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);
                    
                    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, key);
                    
                    let script_sig = Builder::new()
                        .push_slice(<&PushBytes>::try_from(sig_bytes.as_slice()).map_err(|_| BuilderError::SigningFailed("Invalid signature length".into()))?)
                        .push_slice(&pubkey.serialize())
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
    CoinSelection(crate::coin_selection::SelectionError),
}

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInputs => write!(f, "No inputs provided"),
            Self::NoOutputs => write!(f, "No outputs provided"),
            Self::NoChangeAddress => write!(f, "No change address provided"),
            Self::InsufficientFunds { available, required } => {
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
    use dashcore::hash_types::Txid;
    use dashcore_hashes::Hash;

    fn test_utxo(value: u64) -> Utxo {
        let outpoint = OutPoint {
            txid: Txid::from_slice(&[1u8; 32]).unwrap(),
            vout: 0,
        };
        
        let txout = TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        };
        
        let address = Address::p2pkh(
            &secp256k1::PublicKey::from_slice(&[
                0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a,
                0x2f, 0xe8, 0x3c, 0x1a, 0xf1, 0xa8, 0x40, 0x3c, 0xb5,
                0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a,
                0x04, 0x88, 0x7e, 0x5b, 0x23, 0x52,
            ]).unwrap(),
            Network::Testnet,
        );
        
        let mut utxo = Utxo::new(outpoint, txout, address, 100, false);
        utxo.is_confirmed = true;
        utxo
    }

    fn test_address() -> Address {
        Address::p2pkh(
            &secp256k1::PublicKey::from_slice(&[
                0x03, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a,
                0x2f, 0xe8, 0x3c, 0x1a, 0xf1, 0xa8, 0x40, 0x3c, 0xb5,
                0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a,
                0x04, 0x88, 0x7e, 0x5b, 0x23, 0x52,
            ]).unwrap(),
            Network::Testnet,
        )
    }

    #[test]
    fn test_transaction_builder_basic() {
        let utxo = test_utxo(100000);
        let destination = test_address();
        let change = test_address();
        
        let tx = TransactionBuilder::new(Network::Testnet)
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
        
        let result = TransactionBuilder::new(Network::Testnet)
            .add_input(utxo, None)
            .add_output(&destination, 50000)
            .unwrap()
            .build();
        
        assert!(matches!(result, Err(BuilderError::InsufficientFunds { .. })));
    }
}