//! Transaction building with dashcore types
//!
//! This module provides high-level transaction building functionality
//! using types from the dashcore crate.

use alloc::vec::Vec;
use core::fmt;
use dashcore::consensus::Encodable;
use std::collections::HashMap;

use dashcore::blockdata::script::{Builder, PushBytes};
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::Transaction;
use dashcore::sighash::{EcdsaSighashType, SighashCache};
use dashcore::Address;
use dashcore::{TxIn, TxOut};
use dashcore_hashes::Hash;
use secp256k1::{Message, Secp256k1};

use crate::account::{ManagedAccountTrait, ManagedCoreAccount};
use crate::transaction::coin_selection::{SelectionError, UtxoSelector, UtxoSelectorStrategy};
use crate::transaction::fee::FeeRate;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::{ManagedWalletInfo, WalletType};
use crate::{Account, DerivationPath, Utxo, Wallet};

/// Errors that can occur during transaction building
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionBuildingError {
    NoOutputs,
    ZeroValueOutputs,
    AccountError(String),
    InvalidAmount(String),
    SigningFailed(String),
    CoinSelection(SelectionError),
}

impl fmt::Display for TransactionBuildingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoOutputs => write!(f, "No outputs provided"),
            Self::ZeroValueOutputs => write!(f, "Sero value outputs"),
            Self::AccountError(msg) => write!(f, "Account error: {}", msg),
            Self::InvalidAmount(msg) => write!(f, "Invalid amount: {}", msg),
            Self::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            Self::CoinSelection(err) => write!(f, "Coin selection error: {}", err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TransactionBuildingError {}

/// Transaction builder for creating Dash transactions
///
/// This builder implements BIP-69 (Lexicographical Indexing of Transaction Inputs and Outputs)
/// to ensure deterministic ordering and improve privacy by preventing information leakage
/// through predictable input/output ordering patterns.
pub struct TransactionBuilder<'a> {
    /// Sender account
    managed_wallet: &'a ManagedWalletInfo,
    wallet: &'a Wallet,
    managed_account: &'a mut ManagedCoreAccount,
    account: &'a Account,

    /// Fee rate (satoshis per kilobyte)
    fee_rate: FeeRate,
    selection_strategy: UtxoSelectorStrategy,

    /// Transaction fields
    version: u16,
    lock_time: u32,
    outputs: Vec<TxOut>,
    special_transaction_payload: Option<TransactionPayload>,
}

impl<'a> TransactionBuilder<'a> {
    /// Create a new transaction builder
    pub fn new(
        managed_wallet: &'a ManagedWalletInfo,
        wallet: &'a Wallet,
        managed_account: &'a mut ManagedCoreAccount,
        account: &'a Account,
    ) -> Self {
        Self {
            managed_wallet,
            wallet,
            managed_account,
            account,

            fee_rate: FeeRate::normal(),
            selection_strategy: UtxoSelectorStrategy::OptimalConsolidation,

            version: 2,
            lock_time: 0,
            outputs: Vec::new(),
            special_transaction_payload: None,
        }
    }

    /// Add an output to a specific address
    ///
    /// Note: Outputs will be sorted according to BIP-69 when the transaction is built:
    /// - First by amount (ascending)
    /// - Then by scriptPubKey (lexicographically)
    pub fn add_output(
        mut self,
        address: &Address,
        amount: u64,
    ) -> Result<Self, TransactionBuildingError> {
        if amount == 0 {
            return Err(TransactionBuildingError::InvalidAmount(
                "Output amount cannot be zero".into(),
            ));
        }

        let script_pubkey = address.script_pubkey();
        self.outputs.push(TxOut {
            value: amount,
            script_pubkey,
        });
        Ok(self)
    }

    /// Set the fee rate
    pub fn set_fee_rate(mut self, fee_rate: FeeRate) -> Self {
        self.fee_rate = fee_rate;
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
        self.special_transaction_payload = Some(payload);
        self
    }

    /// Build the transaction
    pub fn build(self) -> Result<Transaction, TransactionBuildingError> {
        if self.outputs.is_empty() {
            return Err(TransactionBuildingError::NoOutputs);
        }

        let total_output: u64 = self.outputs.iter().map(|out| out.value).sum();

        if total_output == 0 && self.special_transaction_payload.is_none() {
            return Err(TransactionBuildingError::ZeroValueOutputs);
        }

        let mut tx = Transaction {
            version: self.version.clone(),
            lock_time: self.lock_time.clone(),
            input: Vec::new(),
            output: self.outputs.clone(),
            special_transaction_payload: self.special_transaction_payload.clone(),
        };

        // the coin selection logic is hard to follow so read carefully
        // First we add a dummy output for the change,
        // we are about to build the transaction by approximation

        {
            let account_xpub = &self.account.account_xpub;
            let change_addr = self
                .managed_account
                .next_change_address(Some(account_xpub), true)
                .map_err(|e| TransactionBuildingError::AccountError(e.to_string()))?;
            let change_script = change_addr.script_pubkey();
            tx.output.push(TxOut {
                value: 0,
                script_pubkey: change_script,
            });
        }

        // we calculate the current fee for the current state of the transaction (no inputs yet)
        let mut current_fee = {
            let mut buff = Vec::new();
            tx.consensus_encode(&mut buff).expect("The writer cannot fail");
            self.fee_rate.calculate_fee(buff.len())
        };

        // Lets iterate until we build a transaction that has enough inputs to pay the outputs + fee
        loop {
            // Represents the min required value of the change output to be added to the transaction
            const DUST: u64 = 1000;

            // Select utxo that can afford the output sum + fee + DUST
            // By adding DUST we ensure the change always reaches the min required amount
            let selection = UtxoSelector::new(self.selection_strategy)
                .select(
                    total_output + current_fee + DUST,
                    self.managed_account.utxos().values(),
                    self.managed_wallet.synced_height(),
                )
                .map_err(TransactionBuildingError::CoinSelection)?;

            let total_input: u64 = selection.iter().map(|utxo| utxo.value()).sum();

            self.add_signed_inputs(&mut tx, &selection)?;

            // Here we recalculate the fee with the new inputs inside the transaction
            current_fee = {
                let mut buff = Vec::new();
                tx.consensus_encode(&mut buff).expect("The writer cannot fail");
                self.fee_rate.calculate_fee(buff.len())
            };

            // Check the inputs obtained are enough, if not, execute the loop again, but this time
            // with the current_fee updated with the new min number of inputs. This ensures next
            // iteration selects the same inputs + new ones to pay for the new fee
            if total_input >= total_output + current_fee + DUST {
                // We added the change output as the last one, just update it with the correct amount
                let change_amount = total_input - total_output - current_fee;
                let change_output = tx
                    .output
                    .last_mut()
                    .expect("Transaction is expect to have more than one output");
                change_output.value = change_amount;
                break;
            }
        }

        let tx_outputs = &mut tx.output;
        let tx_inputs = &mut tx.input;

        // BIP-69: Sort outputs by amount first, then by scriptPubKey lexicographically
        tx_outputs.sort_by(|a, b| match a.value.cmp(&b.value) {
            std::cmp::Ordering::Equal => a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()),
            other => other,
        });

        // BIP-69: Sort inputs by transaction hash (reversed) and then by output index
        tx_inputs.sort_by(|a, b| {
            let tx_hash_a = a.previous_output.txid.to_byte_array();
            let tx_hash_b = b.previous_output.txid.to_byte_array();

            match tx_hash_a.cmp(&tx_hash_b) {
                std::cmp::Ordering::Equal => a.previous_output.vout.cmp(&b.previous_output.vout),
                other => other,
            }
        });

        Ok(tx)
    }

    fn add_signed_inputs(
        &self,
        tx: &mut Transaction,
        utxos: &Vec<&Utxo>,
    ) -> Result<(), TransactionBuildingError> {
        let root_xpriv = match &self.wallet.wallet_type {
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
                return Err(TransactionBuildingError::SigningFailed(
                    "Cannot sign with watch-only wallet".to_string(),
                ));
            }
        };

        // Build a map of address -> derivation path for all addresses in the account
        let mut address_to_path: HashMap<Address, DerivationPath> = HashMap::new();

        // Collect from all address pools (receive, change, etc.)
        for pool in self.managed_account.account_type.address_pools() {
            for addr_info in pool.addresses.values() {
                address_to_path.insert(addr_info.address.clone(), addr_info.path.clone());
            }
        }

        let secp = Secp256k1::new();

        // Collect all signatures first, then apply them
        let mut inputs = Vec::new();

        let cache = SighashCache::new(&*tx);

        for (index, &utxo) in utxos.iter().enumerate() {
            let key = {
                // Look up the derivation path for this UTXO's address
                let path = address_to_path.get(&utxo.address).ok_or(
                    TransactionBuildingError::SigningFailed(format!(
                        "Derivation path not found for address {}",
                        utxo.address,
                    )),
                )?;

                // Convert root key to ExtendedPrivKey and derive the child key
                let root_ext_priv = root_xpriv.to_extended_priv_key(self.account.network);
                let secp = secp256k1::Secp256k1::new();
                let derived_xpriv = root_ext_priv
                    .derive_priv(&secp, path)
                    .map_err(|e| TransactionBuildingError::SigningFailed(e.to_string()))?;

                derived_xpriv.private_key
            };

            // Get the script pubkey from the UTXO
            let script_pubkey = &utxo.txout.script_pubkey;

            // Create signature hash for P2PKH
            let sighash = cache
                .legacy_signature_hash(index, script_pubkey, EcdsaSighashType::All.to_u32())
                .map_err(|e| {
                    TransactionBuildingError::SigningFailed(format!(
                        "Failed to compute sighash: {}",
                        e
                    ))
                })?;

            // Sign the hash
            let message = Message::from_digest(*sighash.as_byte_array());
            let signature = secp.sign_ecdsa(&message, &key);

            // Create script signature (P2PKH)
            let mut sig_bytes = signature.serialize_der().to_vec();
            sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);

            let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &key);

            let script_sig = Builder::new()
                .push_slice(<&PushBytes>::try_from(sig_bytes.as_slice()).map_err(|_| {
                    TransactionBuildingError::SigningFailed("Invalid signature length".into())
                })?)
                .push_slice(pubkey.serialize())
                .into_script();

            // Map the UTXO to TxIn with the new scrip_sig
            // Dash doesn't use RBF, so we use the standard sequence number
            let sequence = 0xffffffff;

            let txin = TxIn {
                previous_output: utxo.outpoint,
                script_sig,
                sequence,
                witness: dashcore::blockdata::witness::Witness::new(),
            };

            inputs.push(txin);
        }

        tx.input = inputs;

        Ok(())
    }
}
