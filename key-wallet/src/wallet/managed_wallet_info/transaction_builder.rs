//! Transaction building with dashcore types
//!
//! This module provides high-level transaction building functionality
//! using types from the dashcore crate.

use crate::managed_account::reservation::{ReservationSet, ReservationToken};
use crate::managed_account::ManagedCoreFundsAccount;
use crate::wallet::managed_wallet_info::coin_selection::{
    CoinSelector, SelectionStrategy, CHANGE_OUTPUT_SIZE, TX_OUTPUT_SIZE,
};
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::{Account, DerivationPath, Signer, Utxo, Wallet};
use core::fmt;
use dashcore::blockdata::opcodes;
use dashcore::blockdata::script::{Builder, PushBytes, ScriptBuf};
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::sighash::{EcdsaSighashType, LegacySighash, SighashCache};
use dashcore::Address;
use dashcore::{Network, TxIn, TxOut};
use dashcore_hashes::Hash;
use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, Secp256k1};
use std::cmp::Ordering;
use std::collections::HashSet;

/// A transaction with more inputs would exceed the relay standard-size cap (~100 KB at ~148
/// bytes/signed input) and be rejected by the network
const MAX_STANDARD_TX_INPUTS: usize = 500;
/// Relay-policy limit for OP_RETURN payloads, matching Dash Core's `-datacarriersize` default.
/// Public so callers can reject an over-long payload before handing over a builder
/// `add_op_return` would consume.
pub const MAX_STANDARD_OP_RETURN_BYTES: usize = 80;

/// Calculate varint size for a given number
fn varint_size(n: usize) -> usize {
    match n {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x10000..=0xFFFFFFFF => 5,
        _ => 9,
    }
}

fn serialized_output_size(output: &TxOut) -> usize {
    serialized_script_output_size(&output.script_pubkey)
}

fn serialized_script_output_size(script_pubkey: &ScriptBuf) -> usize {
    let script_len = script_pubkey.as_bytes().len();
    8 + varint_size(script_len) + script_len
}

fn addresses_share_network(left: &Address, right: &Address) -> bool {
    // Checked addresses retain their encoded network prefix, not a unique Network value:
    // legacy testnet/devnet/regtest addresses intentionally share one prefix. Treat two
    // addresses as compatible when at least one supported network accepts both encodings.
    [Network::Mainnet, Network::Testnet, Network::Devnet, Network::Regtest].into_iter().any(
        |network| {
            left.as_unchecked().is_valid_for_network(network)
                && right.as_unchecked().is_valid_for_network(network)
        },
    )
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
    require_final_inputs: bool,
    preserve_output_order: bool,
    change_to_first_input: bool,
    /// Special transaction payload for Dash-specific transactions
    special_payload: Option<TransactionPayload>,
    /// Reservation set of each funding account paired with the outpoints that
    /// account contributed, captured by `add_funding`. Reservations live on the
    /// account that holds the UTXO, so each account reserves its own share of
    /// the chosen inputs — all under the one token this build is stamped with.
    funding: Vec<(ReservationSet, HashSet<OutPoint>)>,
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
            require_final_inputs: false,
            preserve_output_order: false,
            change_to_first_input: false,
            special_payload: None,
            funding: Vec::new(),
        }
    }

    /// Restrict coin selection to final inputs: confirmed or
    /// InstantSend-locked UTXOs. Per DIP-0010 only such inputs are
    /// InstantSend-eligible, so transactions that must receive an
    /// InstantSend lock themselves (e.g. asset locks funding Platform
    /// credits) must never spend other mempool outputs, including our
    /// own trusted change.
    pub fn require_final_inputs(mut self) -> Self {
        self.require_final_inputs = true;
        self
    }

    pub fn set_current_height(mut self, current_height: u32) -> Self {
        self.current_height = current_height;
        self
    }

    pub fn set_selection_strategy(mut self, strategy: SelectionStrategy) -> Self {
        self.selection_strategy = strategy;
        self
    }

    /// Add a funding account's spendable UTXOs to the candidate input set,
    /// skipping any already reserved by another in-flight build.
    ///
    /// Call it once per funding account: coin selection then draws from the
    /// union of their UTXOs, and the first account supplies the change
    /// address.
    ///
    /// This call and the later `assemble_unsigned` that reserves the chosen
    /// inputs must run under one uninterrupted hold of the wallet lock. If two
    /// builds interleave between here and their reservation, both can observe the
    /// same UTXO as free and select it, defeating the reservation. The builder
    /// must therefore not be held across an `await` between `add_funding` and
    /// `build_signed` or `assemble_unsigned`, since suspending there reopens the
    /// read-then-reserve window for a concurrent build.
    pub fn add_funding(mut self, funds_acc: &mut ManagedCoreFundsAccount, acc: &Account) -> Self {
        let reserved = funds_acc.reservations().reserved(self.current_height);
        // An outpoint the builder already holds — seeded by `add_inputs`, or
        // offered by an earlier `add_funding` of an overlapping account — must
        // not become a second candidate for the SAME outpoint. Coin selection
        // does not deduplicate (and `SelectionStrategy::All` takes every
        // candidate), so a duplicate would be spent twice in one transaction and
        // Core rejects duplicate prevouts. This is additive funding's hazard
        // specifically: the `set_funding` it replaced overwrote `inputs`, so a
        // pre-seeded outpoint was silently dropped instead of duplicated.
        let present: HashSet<OutPoint> = self.inputs.iter().map(|utxo| utxo.outpoint).collect();
        let mut candidates: Vec<Utxo> = Vec::new();
        // Every unreserved UTXO this account owns that ends up in the candidate
        // pool — including one pre-seeded by `add_inputs` — so that if selection
        // picks it, THIS account reserves it. Recording only the UTXOs added
        // here would leave a pre-seeded input unreserved and free for a
        // concurrent build to select.
        let mut owned: HashSet<OutPoint> = HashSet::new();
        for utxo in funds_acc.utxos.values() {
            if reserved.contains(&utxo.outpoint) {
                continue;
            }
            owned.insert(utxo.outpoint);
            if present.contains(&utxo.outpoint) {
                continue;
            }
            candidates.push(utxo.clone());
        }
        self.funding.push((funds_acc.reservations().clone(), owned));
        self.inputs.extend(candidates);
        if self.change_addr.is_none() {
            self.change_addr = funds_acc.next_change_address(Some(&acc.account_xpub), true).ok();
        }
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
    /// Note: by default outputs are sorted according to BIP-69 when the transaction is built:
    /// - First by amount (ascending)
    /// - Then by scriptPubKey (lexicographically)
    ///
    /// Call [`Self::preserve_output_order`] to keep insertion order instead.
    pub fn add_output(mut self, address: &Address, amount: u64) -> Self {
        let script_pubkey = address.script_pubkey();
        self.outputs.push(TxOut {
            value: amount,
            script_pubkey,
        });
        self
    }

    /// Add an OP_RETURN output carrying `data` (value 0).
    ///
    /// Errors if `data` exceeds [`MAX_STANDARD_OP_RETURN_BYTES`].
    pub fn add_op_return(mut self, data: &[u8]) -> Result<Self, BuilderError> {
        if data.len() > MAX_STANDARD_OP_RETURN_BYTES {
            return Err(BuilderError::OpReturnDataTooLarge {
                len: data.len(),
                max: MAX_STANDARD_OP_RETURN_BYTES,
            });
        }

        let push_bytes =
            <&PushBytes>::try_from(data).map_err(|_| BuilderError::OpReturnDataTooLarge {
                len: data.len(),
                max: MAX_STANDARD_OP_RETURN_BYTES,
            })?;
        self.outputs.push(TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::all::OP_RETURN)
                .push_slice(push_bytes)
                .into_script(),
        });
        Ok(self)
    }

    /// Preserve outputs in insertion order instead of applying BIP-69 sorting.
    pub fn preserve_output_order(mut self) -> Self {
        self.preserve_output_order = true;
        self
    }

    /// Route change to the address of the first selected input (post-sort).
    pub fn change_to_first_input(mut self) -> Self {
        self.change_to_first_input = true;
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

    fn should_estimate_change_output(&self) -> bool {
        self.change_addr.is_some() || self.change_to_first_input
    }

    /// Dust threshold for an output of `output_size` serialized bytes, mirroring Dash Core's
    /// `GetDustThreshold`: the output is dust when spending it would cost more than a third of
    /// its value at the dust relay fee, i.e. `3 * (output_size + 148)` duffs for the 148-byte
    /// P2PKH input that would spend it.
    ///
    /// The flat 546 this replaces is exactly this formula for a 34-byte P2PKH output, so nothing
    /// moves for the ordinary path. It matters for `change_to_first_input`, where change is
    /// routed to whatever script VIN0 uses: a 43-byte output has a 573-duff threshold, so a
    /// 550-duff change output would have passed a flat 546 check and then been rejected as dust
    /// by the network.
    fn dust_threshold(output_size: usize) -> u64 {
        3 * (output_size as u64 + 148)
    }

    fn estimated_change_output_size(&self) -> usize {
        if self.change_to_first_input {
            // Coin selection may choose any spendable input, then BIP-69 determines VIN0.
            // Reserve the largest eligible routing script so every possible winner is covered.
            self.inputs
                .iter()
                .filter(|utxo| utxo.is_spendable(self.current_height))
                .map(|utxo| serialized_script_output_size(&utxo.address.script_pubkey()))
                .max()
                .unwrap_or(CHANGE_OUTPUT_SIZE)
        } else {
            self.change_addr
                .as_ref()
                .map(|address| serialized_script_output_size(&address.script_pubkey()))
                .unwrap_or(0)
        }
    }

    fn effective_outputs_size(&self) -> usize {
        match &self.special_payload {
            // The asset-lock burn output is sized at the flat TX_OUTPUT_SIZE rather than its
            // real ~11 serialized bytes. The real size is smaller, so this over-estimates and
            // over-pays slightly — deliberately kept identical to the pre-OP_RETURN behaviour
            // so identity funding fees do not move as a side effect of Maya support.
            Some(TransactionPayload::AssetLockPayloadType(_)) => TX_OUTPUT_SIZE,
            _ => self.outputs.iter().map(serialized_output_size).sum(),
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
                + if self.should_estimate_change_output() {
                    1
                } else {
                    0
                },
        );

        // Add serialized output sizes. A P2PKH output still measures TX_OUTPUT_SIZE;
        // non-standard outputs such as OP_RETURN are sized from their real script.
        size += self.effective_outputs_size();

        // Add change using the actual configured script size, or the largest eligible input
        // script when change will be routed to VIN0.
        if self.should_estimate_change_output() {
            size += self.estimated_change_output_size();
        }

        // Add special payload size if present
        // Based on dashsync payload size calculations
        if let Some(ref payload) = self.special_payload {
            let payload_size = Self::estimated_payload_size(payload);

            // Add varint for payload length
            size += varint_size(payload_size) + payload_size;
        }

        size
    }

    /// Estimated serialized size of a special payload, as priced into the fee by
    /// [`Self::calculate_base_size`]. Also the yardstick
    /// [`Self::build_signed_reserved_with_payload_finalizer`] holds a finalized
    /// payload against: the fee is fixed at selection time from the placeholder's
    /// estimate, so a finalized payload may not estimate larger.
    fn estimated_payload_size(payload: &TransactionPayload) -> usize {
        match payload {
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
                let mut size = 2 + 32 + 16 + 2 + varint_size(script_size) + script_size + 32 + 96;
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
                1 + varint_size(p.credit_outputs.len()) + p.credit_outputs.len() * TX_OUTPUT_SIZE
            }
            TransactionPayload::AssetUnlockPayloadType(_p) => {
                // version (1) + index (8) + fee (4) + requestHeight (4) + quorumHash (32) + quorumSig (96)
                1 + 8 + 4 + 4 + 32 + 96
            }
            _ => 100, // Default estimate for unknown types
        }
    }

    /// Select inputs, build the unsigned transaction, and reserve the chosen
    /// inputs. The optional [`ReservationToken`] is `Some` exactly when a
    /// reservation set was attached (via [`add_funding`]) and identifies the
    /// reservation this build just took, so a caller that later abandons the
    /// build can release *only* its own inputs via
    /// [`ReservationSet::release_if_owner`]. It is `None` for builds with no
    /// reservation set (nothing was reserved, nothing to release).
    ///
    /// [`add_funding`]: Self::add_funding
    fn assemble_unsigned(
        mut self,
    ) -> Result<(Transaction, Vec<Utxo>, Option<ReservationToken>), BuilderError> {
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
            self.change_to_first_input = false;
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

        if self.require_final_inputs {
            self.inputs.retain(|utxo| utxo.is_confirmed || utxo.is_instantlocked);
        }

        // Must match `calculate_base_size`, including the conservative VIN0 routing-script size.
        let change_output_size = self.estimated_change_output_size();

        let selection = CoinSelector::new(self.selection_strategy)
            .select_coins_with_size(
                self.inputs.iter(),
                total_output,
                self.fee_rate,
                self.current_height,
                self.calculate_base_size(),
                change_output_size,
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

        selected_inputs.sort_by(bip69_input_sorter);

        let change_amount =
            total_input.saturating_sub(total_output).saturating_sub(selection.estimated_fee);
        // Computed before `self.outputs` is moved out below.
        let change_dust_threshold = Self::dust_threshold(self.estimated_change_output_size());
        let mut tx_outputs = match &self.special_payload {
            Some(TransactionPayload::AssetLockPayloadType(_)) => vec![TxOut {
                value: total_output,
                script_pubkey: ScriptBuf::new_op_return(&[]),
            }],
            _ => self.outputs,
        };

        if self.selection_strategy == SelectionStrategy::All {
            // Drain: the single VALUE-CARRYING output takes the whole balance minus fee (the
            // caller's amount is ignored); no change.
            let drained = total_input.saturating_sub(selection.estimated_fee);
            if drained == 0 {
                return Err(BuilderError::InsufficientFunds {
                    available: total_input,
                    required: selection.estimated_fee,
                });
            }
            // Zero-value data carriers ride along with a drain. A MAYAChain deposit is the
            // motivating case: the memo MUST be on-chain as an OP_RETURN beside the vault
            // output, so refusing every second output made "swap my whole balance" impossible
            // to express — callers had to guess the fee, subtract it themselves and send an
            // explicit amount, which under-pays the destination whenever the guess is low.
            // Data outputs claim none of the drained balance, and `effective_outputs_size`
            // already prices their bytes into the fee, so the drain arithmetic is unchanged.
            //
            // An asset lock is the exception: ITS single output IS an OP_RETURN (the burn
            // mirroring the payload credits), so it stays the value carrier.
            let is_asset_lock =
                matches!(self.special_payload, Some(TransactionPayload::AssetLockPayloadType(_)));
            if !is_asset_lock
                && tx_outputs.iter().any(|out| out.script_pubkey.is_op_return() && out.value != 0)
            {
                return Err(BuilderError::InvalidData(
                    "SelectionStrategy::All requires OP_RETURN outputs to be zero-value: a data \
                     carrier with a value would claim part of the drained balance"
                        .into(),
                ));
            }
            let value_carriers = if is_asset_lock {
                tx_outputs.len()
            } else {
                tx_outputs.iter().filter(|out| !out.script_pubkey.is_op_return()).count()
            };
            if value_carriers != 1 {
                return Err(BuilderError::InvalidData(
                    "SelectionStrategy::All requires exactly one spendable output (the \
                     destination); only zero-value OP_RETURN data outputs may accompany it"
                        .into(),
                ));
            }
            // The count above already proves a carrier exists, so neither arm can
            // come back empty today. Resolve it fallibly anyway: this is library
            // code, and a later change to that invariant should surface as a typed
            // error rather than a panic in a caller's process.
            let carrier = if is_asset_lock {
                tx_outputs.first_mut()
            } else {
                tx_outputs.iter_mut().find(|out| !out.script_pubkey.is_op_return())
            };
            let Some(out) = carrier else {
                return Err(BuilderError::InvalidData(
                    "SelectionStrategy::All found no spendable output to receive the drained \
                     balance"
                        .into(),
                ));
            };
            out.value = drained;
            // An asset-lock drain must also rewrite the payload's credit
            // output: the on-chain OP_RETURN burn (`out` above) mirrors the
            // payload credit sum, and a mismatch is consensus-invalid.
            if let Some(TransactionPayload::AssetLockPayloadType(payload)) =
                &mut self.special_payload
            {
                let [credit] = payload.credit_outputs.as_mut_slice() else {
                    return Err(BuilderError::InvalidData(
                        "SelectionStrategy::All with an asset-lock payload requires exactly one \
                         credit output"
                            .into(),
                    ));
                };
                credit.value = drained;
            }
        } else if change_amount > change_dust_threshold {
            // Add change output if above dust threshold
            let change_script_pubkey = if self.change_to_first_input {
                let Some(first_input) = selected_inputs.first() else {
                    return Err(BuilderError::NoInputs);
                };
                if self.change_addr.as_ref().is_some_and(|change_addr| {
                    !addresses_share_network(&first_input.address, change_addr)
                }) {
                    return Err(BuilderError::InvalidData(
                        "Input-derived change address network does not match configured change address"
                            .into(),
                    ));
                }
                first_input.address.script_pubkey()
            } else {
                let Some(change_addr) = self.change_addr else {
                    return Err(BuilderError::NoChangeAddress);
                };
                change_addr.script_pubkey()
            };

            tx_outputs.push(TxOut {
                value: change_amount,
                script_pubkey: change_script_pubkey,
            });
        }

        if !self.preserve_output_order
            && !matches!(self.special_payload, Some(TransactionPayload::AssetLockPayloadType(_)))
        {
            tx_outputs.sort_by(bip69_output_sorter);
        }
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

        // Reserve the chosen inputs so a concurrent build skips them until the
        // broadcast transaction is processed back into the wallet (which
        // releases the reservation) or the TTL backstop reclaims it. Each
        // account reserves the inputs it contributed, since its own set is the
        // one its coin selection consults. Keep the stamped owner token so the
        // caller can release only this reservation if the build is later
        // abandoned (see `release_if_owner`).
        let reservation_token = (!self.funding.is_empty()).then(|| {
            let owner = ReservationToken::next();
            for (reservations, candidates) in &self.funding {
                let outpoints: Vec<OutPoint> = selected_inputs
                    .iter()
                    .map(|utxo| utxo.outpoint)
                    .filter(|outpoint| candidates.contains(outpoint))
                    .collect();
                reservations.reserve(&outpoints, self.current_height, owner);
            }
            owner
        });

        return Ok((transaction, selected_inputs, reservation_token));

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

    /// Build the unsigned transaction, returning it alongside the fee it pays
    /// and the [`ReservationToken`] stamped onto the inputs this build reserved
    /// (`None` when no reservation set is attached).
    ///
    /// The returned fee is the fee the transaction actually pays:
    /// Σ(selected input values) − Σ(output values). This can exceed the
    /// size-based fee target when a dust change remainder (≤ 546 duffs) is
    /// dropped and left to miners.
    ///
    /// Hold the returned token when the transaction may be abandoned after an
    /// `.await` that releases the wallet lock — most importantly the platform
    /// broadcast path, which reserves inputs, awaits the broadcast, and on
    /// rejection must release them — and release with
    /// [`ManagedCoreFundsAccount::release_reservation_if_owner`] on *every*
    /// funding account passed to [`Self::add_funding`]: each account reserves
    /// only the inputs it contributed, in its own set. See
    /// `ReservationSet::release_if_owner` for why owner-guarded release is
    /// required (`dashpay/platform#4185`).
    pub fn build_unsigned_reserved(
        self,
    ) -> Result<(Transaction, u64, Option<ReservationToken>), BuilderError> {
        let (tx, inputs, reservation) = self.assemble_unsigned()?;

        let total_input: u64 = inputs.iter().map(|utxo| utxo.value()).sum();
        let total_output: u64 = tx.output.iter().map(|out| out.value).sum();

        Ok((tx, total_input.saturating_sub(total_output), reservation))
    }

    /// Build and sign the transaction. The `path_resolver` maps each input
    /// address to the derivation path the signer should use for that input.
    /// The returned fee is the fee the transaction actually pays:
    /// Σ(selected input values) − Σ(output values). This can exceed the
    /// size-based fee target when a dust change remainder (≤ 546 duffs) is
    /// dropped and left to miners.
    pub async fn build_signed<S, P>(
        self,
        signer: &S,
        path_resolver: P,
    ) -> Result<(Transaction, u64), BuilderError>
    where
        S: TransactionSigner + ?Sized + Sync,
        P: Fn(Address) -> Option<DerivationPath> + Send,
    {
        let (tx, fee, _reservation) = self.build_signed_reserved(signer, path_resolver).await?;
        Ok((tx, fee))
    }

    /// Like [`Self::build_signed`], but also returns the [`ReservationToken`]
    /// stamped onto the inputs this build reserved (`None` when no reservation
    /// set is attached), for callers that may later abandon the transaction
    /// after awaiting a broadcast. See [`Self::build_unsigned_reserved`] for why
    /// the token is needed and how to release with it.
    pub async fn build_signed_reserved<S, P>(
        self,
        signer: &S,
        path_resolver: P,
    ) -> Result<(Transaction, u64, Option<ReservationToken>), BuilderError>
    where
        S: TransactionSigner + ?Sized + Sync,
        P: Fn(Address) -> Option<DerivationPath> + Send,
    {
        let funding = self.funding.clone();

        let (tx, inputs, reservation) = self.assemble_unsigned()?;
        let total_input: u64 = inputs.iter().map(|utxo| utxo.value()).sum();
        // Signing never reaches the network for a local key, but an external
        // signer can fail. A failed sign means the reserved inputs are still
        // spendable, so release them now instead of stranding the funds until
        // the TTL backstop reclaims them.
        //
        // Release owner-guarded: `sign_tx` is an `.await`, and while it runs the
        // TTL sweep could reclaim this build's reservation and a concurrent
        // build could re-reserve the same outpoint under a new token. An
        // unconditional release-by-outpoint would then free that other build's
        // inputs (the double-spend window of `dashpay/platform#4185`), so we
        // release only outpoints still owned by the token this build stamped.
        let reserved: Vec<OutPoint> = inputs.iter().map(|utxo| utxo.outpoint).collect();
        let tx = match signer.sign_tx(tx, inputs, path_resolver).await {
            Ok(tx) => tx,
            Err(err) => {
                if let Some(token) = reservation {
                    for (reservations, _) in &funding {
                        reservations.release_if_owner(&reserved, token);
                    }
                }
                return Err(err);
            }
        };

        let total_output: u64 = tx.output.iter().map(|out| out.value).sum();

        Ok((tx, total_input.saturating_sub(total_output), reservation))
    }

    /// Like [`Self::build_signed_reserved`], but with a payload-finalization
    /// seam between input selection and input signing, for special
    /// transactions whose payload commits to the chosen inputs and is itself
    /// signed — a ProUpServTx's `inputs_hash` + operator-BLS `payload_sig`
    /// being the motivating case.
    ///
    /// The builder must be given a placeholder payload via
    /// [`Self::set_special_payload`]: the same variant with every
    /// selection-dependent field (inputs hash, payload signature) zeroed, so
    /// coin selection prices the payload bytes into the fee. After selection
    /// reserves the chosen inputs, `finalize_payload` receives the unsigned
    /// transaction — inputs chosen and BIP-69 sorted, placeholder payload
    /// still attached — and returns the finalized payload; the builder
    /// installs it and only then computes each input's sighash, which covers
    /// the finalized payload. Because that payload signature commits to the
    /// input set, the input set is frozen from the finalizer on: there is no
    /// fee-bump or input-substitution path for such a transaction.
    ///
    /// Fails without running the finalizer when no placeholder payload was
    /// set, and fails after it when the finalized payload is a different
    /// variant or estimates larger than the placeholder (the fee was fixed at
    /// selection time, so growth would underpay the configured fee rate). On
    /// any failure — finalizer error, guard, or signing — the reservation is
    /// released owner-guarded, exactly as in [`Self::build_signed_reserved`].
    pub async fn build_signed_reserved_with_payload_finalizer<S, P, F>(
        self,
        signer: &S,
        path_resolver: P,
        finalize_payload: F,
    ) -> Result<(Transaction, u64, Option<ReservationToken>), BuilderError>
    where
        S: TransactionSigner + ?Sized + Sync,
        P: Fn(Address) -> Option<DerivationPath> + Send,
        F: FnOnce(&Transaction) -> Result<TransactionPayload, BuilderError> + Send,
    {
        if self.special_payload.is_none() {
            return Err(BuilderError::InvalidData(
                "payload finalizer requires a placeholder payload: call set_special_payload with \
                 the same variant (selection-dependent fields zeroed) so selection prices its \
                 bytes into the fee"
                    .into(),
            ));
        }

        let funding = self.funding.clone();
        let (mut tx, inputs, reservation) = self.assemble_unsigned()?;
        let total_input: u64 = inputs.iter().map(|utxo| utxo.value()).sum();
        // Same owner-guarded release discipline as `build_signed_reserved`:
        // a failure past this point leaves the inputs spendable, so free them
        // for the next build instead of stranding them until the TTL backstop.
        let reserved: Vec<OutPoint> = inputs.iter().map(|utxo| utxo.outpoint).collect();
        fn release(
            funding: &[(ReservationSet, HashSet<OutPoint>)],
            reserved: &[OutPoint],
            reservation: Option<ReservationToken>,
        ) {
            if let Some(token) = reservation {
                for (reservations, _) in funding {
                    reservations.release_if_owner(reserved, token);
                }
            }
        }

        let finalized = match finalize_payload(&tx) {
            Ok(payload) => payload,
            Err(err) => {
                release(&funding, &reserved, reservation);
                return Err(err);
            }
        };

        // `assemble_unsigned` carries the placeholder into the transaction
        // unchanged for every payload type (only an asset-lock drain rewrites
        // one, and that variant has no selection-dependent fields to
        // finalize). Guard rather than unwrap: this is library code.
        let Some(placeholder) = tx.special_transaction_payload.as_ref() else {
            release(&funding, &reserved, reservation);
            return Err(BuilderError::InvalidData(
                "placeholder payload missing from the assembled transaction".into(),
            ));
        };
        if core::mem::discriminant(&finalized) != core::mem::discriminant(placeholder) {
            release(&funding, &reserved, reservation);
            return Err(BuilderError::InvalidData(
                "finalized payload is a different variant than the placeholder the fee was \
                 selected for"
                    .into(),
            ));
        }
        let placeholder_size = Self::estimated_payload_size(placeholder);
        let finalized_size = Self::estimated_payload_size(&finalized);
        if finalized_size > placeholder_size {
            release(&funding, &reserved, reservation);
            return Err(BuilderError::InvalidData(format!(
                "finalized payload estimates {finalized_size} bytes, larger than the \
                 {placeholder_size}-byte placeholder the fee was selected for"
            )));
        }
        tx.special_transaction_payload = Some(finalized);

        // Input sighashes cover the finalized payload (the legacy sighash
        // consensus-encodes the whole transaction, payload included), so
        // signing must come after the payload is installed.
        let tx = match signer.sign_tx(tx, inputs, path_resolver).await {
            Ok(tx) => tx,
            Err(err) => {
                release(&funding, &reserved, reservation);
                return Err(err);
            }
        };

        let total_output: u64 = tx.output.iter().map(|out| out.value).sum();

        Ok((tx, total_input.saturating_sub(total_output), reservation))
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
    /// OP_RETURN payload exceeds the standard relay-policy size.
    OpReturnDataTooLarge {
        len: usize,
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
            Self::OpReturnDataTooLarge {
                len,
                max,
            } => {
                write!(f, "OP_RETURN payload too large: {len} bytes (max {max})")
            }
        }
    }
}

impl std::error::Error for BuilderError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestWalletContext;
    use crate::Network;
    use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
    use dashcore::consensus::serialize;
    use dashcore::{OutPoint, Txid};
    use dashcore_hashes::{sha256d, Hash};
    use hex;

    fn op_return_script(data: &[u8]) -> ScriptBuf {
        let push_bytes = <&PushBytes>::try_from(data).expect("test OP_RETURN bytes");
        Builder::new().push_opcode(opcodes::all::OP_RETURN).push_slice(push_bytes).into_script()
    }

    fn build_unsigned_legacy(mut builder: TransactionBuilder) -> (Transaction, u64) {
        if let Some(TransactionPayload::AssetLockPayloadType(p)) = &builder.special_payload {
            assert!(!p.credit_outputs.is_empty(), "legacy helper expects outputs");
        } else if builder.outputs.is_empty() && builder.special_payload.is_none() {
            panic!("legacy helper expects outputs");
        }

        if builder.selection_strategy == SelectionStrategy::All {
            builder.change_addr = None;
        }

        let total_output: u64 = match &builder.special_payload {
            Some(TransactionPayload::AssetLockPayloadType(p)) => {
                p.credit_outputs.iter().map(|o| o.value).sum()
            }
            _ => builder.outputs.iter().map(|o| o.value).sum(),
        };

        if builder.require_final_inputs {
            builder.inputs.retain(|utxo| utxo.is_confirmed || utxo.is_instantlocked);
        }

        let selection = CoinSelector::new(builder.selection_strategy)
            .select_coins_with_size(
                builder.inputs.iter(),
                total_output,
                builder.fee_rate,
                builder.current_height,
                builder.calculate_base_size(),
                // The selector's last argument is the change-output size. The legacy path
                // budgeted one only when a change address was set — reproduce exactly that,
                // so the comparison isolates the output-sizing change.
                if builder.change_addr.is_some() {
                    CHANGE_OUTPUT_SIZE
                } else {
                    0
                },
            )
            .expect("legacy selection");

        let mut selected_inputs = selection.selected;
        let total_input: u64 = selected_inputs.iter().map(|u| u.value()).sum();
        let change_amount =
            total_input.saturating_sub(total_output).saturating_sub(selection.estimated_fee);

        let mut tx_outputs = match &builder.special_payload {
            Some(TransactionPayload::AssetLockPayloadType(_)) => vec![TxOut {
                value: total_output,
                script_pubkey: ScriptBuf::new_op_return(&[]),
            }],
            _ => builder.outputs,
        };

        if builder.selection_strategy == SelectionStrategy::All {
            let [out] = tx_outputs.as_mut_slice() else {
                panic!("legacy helper expects a single drain output");
            };
            out.value = total_input.saturating_sub(selection.estimated_fee);
        } else if change_amount > 546 {
            let change_addr = builder.change_addr.expect("legacy change address");
            tx_outputs.push(TxOut {
                value: change_amount,
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        if !matches!(builder.special_payload, Some(TransactionPayload::AssetLockPayloadType(_))) {
            tx_outputs.sort_by(|a, b| match a.value.cmp(&b.value) {
                Ordering::Equal => a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()),
                other => other,
            });
        }

        selected_inputs.sort_by(|a, b| {
            let tx_hash_a = a.outpoint.txid.to_byte_array();
            let tx_hash_b = b.outpoint.txid.to_byte_array();

            match tx_hash_a.cmp(&tx_hash_b) {
                Ordering::Equal => a.outpoint.vout.cmp(&b.outpoint.vout),
                other => other,
            }
        });

        let tx = Transaction {
            version: 3,
            lock_time: 0,
            input: selected_inputs
                .iter()
                .map(|utxo| TxIn {
                    previous_output: utxo.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: 0xffffffff,
                    witness: dashcore::blockdata::witness::Witness::new(),
                })
                .collect(),
            output: tx_outputs,
            special_transaction_payload: builder.special_payload,
        };

        let total_output: u64 = tx.output.iter().map(|out| out.value).sum();
        (tx, total_input.saturating_sub(total_output))
    }

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
            .build_unsigned_reserved()
            .map(|(tx, _, _)| tx);

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
            .build_unsigned_reserved();

        // Insufficient funds now surface via the coin selector wrapper too.
        assert!(matches!(
            result,
            Err(BuilderError::InsufficientFunds { .. }) | Err(BuilderError::CoinSelection(_))
        ));
    }

    #[test]
    fn test_no_change_address_large_surplus_errors_not_burned() {
        // Review finding: a send that leaves a large remainder but has no change address must
        // error (NoChangeAddress), not silently pay the entire surplus to miners.
        let utxo = Utxo::dummy(0, 10_000_000, 100, false, true);
        let destination = Address::dummy(Network::Testnet, 0);

        let result = TransactionBuilder::new()
            .set_current_height(200)
            .add_inputs([utxo]) // no set_change_address
            .add_output(&destination, 100_000)
            .build_unsigned_reserved();

        assert!(
            matches!(result, Err(BuilderError::NoChangeAddress)),
            "surplus with no change address must error, got {result:?}"
        );
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
            .build_unsigned_reserved()
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
            .build_unsigned_reserved()
            .unwrap()
            .0;

        // Should only have 1 output (no change) because change is below dust threshold
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, 150000);
    }

    /// When the change remainder is dust (≤ 546 duffs) the builder drops it and
    /// those duffs go to miners. The returned fee must be what the transaction
    /// actually pays (Σ inputs − Σ outputs), not the smaller size-based target.
    #[test]
    fn test_dropped_dust_change_counts_toward_returned_fee() {
        // 150000 to recipient + 226 size fee + 300 dust remainder
        let utxos = vec![Utxo::dummy(0, 150526, 100, false, true)];

        let recipient_address = Address::dummy(Network::Testnet, 0);
        let change_address = Address::dummy(Network::Testnet, 0);

        let (tx, fee, _) = TransactionBuilder::new()
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::SmallestFirst)
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change_address)
            .add_inputs(utxos)
            .add_output(&recipient_address, 150000)
            .build_unsigned_reserved()
            .unwrap();

        assert_eq!(tx.output.len(), 1, "dust change must be dropped");
        let total_output: u64 = tx.output.iter().map(|o| o.value).sum();
        assert_eq!(fee, 150526 - total_output, "fee must equal inputs minus outputs");
        assert_eq!(fee, 526, "fee must include the 300-duff dropped dust remainder");
    }

    /// An asset lock burns the locked amount into an on-chain OP_RETURN output
    /// mirroring the payload's credit outputs. That output is part of
    /// Σ(outputs), so the returned fee must be the miner fee only — the locked
    /// credits must never be counted as fee.
    #[test]
    fn test_asset_lock_fee_excludes_locked_credits() {
        let utxos = vec![Utxo::dummy(0, 1_000_000, 100, false, true)];
        let change_address = Address::dummy(Network::Testnet, 0);

        let asset_lock_payload = AssetLockPayload {
            version: 1,
            credit_outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let (tx, fee, _) = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change_address)
            .set_special_payload(TransactionPayload::AssetLockPayloadType(asset_lock_payload))
            .add_inputs(utxos)
            .build_unsigned_reserved()
            .unwrap();

        assert_eq!(tx.output.len(), 2, "OP_RETURN burn output + change");
        let total_output: u64 = tx.output.iter().map(|o| o.value).sum();
        assert_eq!(fee, 1_000_000 - total_output, "fee must equal inputs minus outputs");
        assert!(
            fee < 1_000,
            "fee must be the miner fee only, not include the 100k locked credits, got {}",
            fee
        );
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
            .build_unsigned_reserved()
            .unwrap()
            .0;

        // Verify outputs are sorted by amount (ascending)
        assert!(tx.output[0].value <= tx.output[1].value);
        assert!(tx.output[1].value <= tx.output[2].value);

        // The lowest value should be 100000
        assert_eq!(tx.output[0].value, 100000);
    }

    #[test]
    fn test_maya_deposit_shape_preserves_output_order_and_routes_change_to_first_input() {
        let vault = Address::dummy(Network::Testnet, 42);
        let memo = vec![0x4d; MAX_STANDARD_OP_RETURN_BYTES];
        let utxos = vec![
            Utxo::dummy(0x02, 80_000, 100, false, true),
            Utxo::dummy(0x01, 80_000, 100, false, true),
        ];

        let (tx, fee, _reservation) = TransactionBuilder::new()
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::SmallestFirst)
            .set_fee_rate(FeeRate::normal())
            .add_inputs(utxos)
            .add_output(&vault, 120_000)
            .add_op_return(&memo)
            .expect("valid OP_RETURN")
            .preserve_output_order()
            .change_to_first_input()
            .build_unsigned_reserved()
            .expect("maya-shaped transaction");

        assert_eq!(tx.output.len(), 3, "vault + memo + change");
        assert_eq!(tx.output[0].script_pubkey, vault.script_pubkey());
        assert_eq!(tx.output[1].value, 0);
        assert!(tx.output[1].script_pubkey.is_op_return());
        assert_eq!(tx.output[1].script_pubkey, op_return_script(&memo));
        assert_eq!(
            &tx.output[1].script_pubkey.as_bytes()
                [tx.output[1].script_pubkey.as_bytes().len() - memo.len()..],
            memo.as_slice()
        );
        assert_eq!(tx.output[2].script_pubkey, Address::dummy(Network::Testnet, 1).script_pubkey());

        // `build_unsigned` leaves every script_sig empty, so the serialized bytes are ~107
        // short per input (41 unsigned vs the 148 a signed P2PKH input costs). Comparing the
        // fee against that would pass no matter how badly the estimate under-counted — the
        // very regression the precise output sizing exists to prevent. Measure against the
        // signed size the builder itself assumes.
        const SIGNED_INPUT_SIZE: usize = 148;
        const UNSIGNED_INPUT_SIZE: usize = 41;
        let signed_size = (serialize(&tx).len()
            + tx.input.len() * (SIGNED_INPUT_SIZE - UNSIGNED_INPUT_SIZE))
            as u64;
        assert!(
            fee >= signed_size,
            "fee {fee} must cover the signed size {signed_size} at the 1 duff/byte relay minimum"
        );
    }

    #[test]
    fn test_change_to_first_input_sizes_larger_routing_script() {
        let routed_address =
            Address::p2wsh(&Builder::new().push_int(1).into_script(), Network::Testnet);
        let mut routed_input = Utxo::dummy(0x01, 100_000, 100, false, true);
        routed_input.address = routed_address.clone();
        routed_input.txout.script_pubkey = routed_address.script_pubkey();

        let builder = TransactionBuilder::new()
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::SmallestFirst)
            .set_fee_rate(FeeRate::normal())
            .set_change_address(Address::dummy(Network::Testnet, 13))
            .add_inputs([routed_input])
            .add_output(&Address::dummy(Network::Testnet, 42), 50_000)
            .change_to_first_input();

        let routed_output_size = serialized_script_output_size(&routed_address.script_pubkey());
        assert!(routed_output_size > CHANGE_OUTPUT_SIZE);
        assert_eq!(builder.estimated_change_output_size(), routed_output_size);

        let (tx, fee, _reservation) =
            builder.build_unsigned_reserved().expect("witness-routed change transaction");
        assert_eq!(tx.output.len(), 2);
        assert!(tx
            .output
            .iter()
            .any(|output| output.script_pubkey == routed_address.script_pubkey()));

        const SIGNED_INPUT_SIZE: usize = 148;
        const UNSIGNED_INPUT_SIZE: usize = 41;
        let signed_size = (serialize(&tx).len()
            + tx.input.len() * (SIGNED_INPUT_SIZE - UNSIGNED_INPUT_SIZE))
            as u64;
        assert!(
            fee >= signed_size,
            "fee {fee} must cover the larger routed output at signed size {signed_size}"
        );
    }

    #[test]
    fn test_change_to_first_input_rejects_configured_network_mismatch() {
        let mainnet_address = Address::dummy(Network::Mainnet, 1);
        let mut input = Utxo::dummy(0x01, 100_000, 100, false, true);
        input.address = mainnet_address.clone();
        input.txout.script_pubkey = mainnet_address.script_pubkey();

        let result = TransactionBuilder::new()
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::SmallestFirst)
            .set_change_address(Address::dummy(Network::Testnet, 13))
            .add_inputs([input])
            .add_output(&Address::dummy(Network::Testnet, 42), 50_000)
            .change_to_first_input()
            .build_unsigned_reserved();

        assert!(matches!(
            result,
            Err(BuilderError::InvalidData(message))
                if message.contains("network does not match")
        ));
    }

    /// The precise per-output sizing added for OP_RETURN support must not move the fee
    /// estimate for any transaction shape that existed before it: P2PKH outputs really are
    /// 34 serialized bytes, and the asset-lock burn is deliberately still charged at 34.
    #[test]
    fn test_base_size_unchanged_for_pre_op_return_shapes() {
        fn legacy_base_size(outputs_count: usize, has_change: bool, payload_size: usize) -> usize {
            let mut size = 8 + 1;
            size += varint_size(outputs_count + usize::from(has_change));
            size += outputs_count * 34;
            if has_change {
                size += 34;
            }
            if payload_size > 0 {
                size += varint_size(payload_size) + payload_size;
            }
            size
        }

        let plain = TransactionBuilder::new()
            .set_change_address(Address::dummy(Network::Testnet, 13))
            .add_output(&Address::dummy(Network::Testnet, 11), 80_000)
            .add_output(&Address::dummy(Network::Testnet, 12), 60_000);
        assert_eq!(plain.calculate_base_size(), legacy_base_size(2, true, 0));

        let no_change =
            TransactionBuilder::new().add_output(&Address::dummy(Network::Testnet, 11), 80_000);
        assert_eq!(no_change.calculate_base_size(), legacy_base_size(1, false, 0));

        let asset_lock = TransactionBuilder::new()
            .set_change_address(Address::dummy(Network::Testnet, 13))
            .set_special_payload(TransactionPayload::AssetLockPayloadType(AssetLockPayload {
                version: 1,
                credit_outputs: vec![TxOut {
                    value: 50_000,
                    script_pubkey: Address::dummy(Network::Testnet, 14).script_pubkey(),
                }],
            }));
        let payload_size = 1 + varint_size(1) + 34;
        assert_eq!(
            asset_lock.calculate_base_size(),
            legacy_base_size(1, true, payload_size),
            "asset-lock sizing must stay byte-identical to the pre-OP_RETURN estimate"
        );
    }

    /// The dust threshold has to follow the change script, not assume P2PKH. Pins both ends:
    /// the P2PKH case must still be exactly the 546 the flat literal used to hard-code, and a
    /// larger routed script must demand proportionally more before change is worth creating.
    #[test]
    fn test_dust_threshold_follows_the_change_output_size() {
        assert_eq!(
            TransactionBuilder::dust_threshold(CHANGE_OUTPUT_SIZE),
            546,
            "P2PKH change must keep the historical 546-duff threshold"
        );
        // A 43-byte output (e.g. P2WSH) costs the same 148-byte input to spend, so its threshold
        // is 3 * (43 + 148). A 550-duff change output clears 546 but is dust at this size.
        assert_eq!(TransactionBuilder::dust_threshold(43), 573);
        assert!(550 > TransactionBuilder::dust_threshold(CHANGE_OUTPUT_SIZE));
        assert!(550 < TransactionBuilder::dust_threshold(43));
    }

    /// Pins the boundary itself, not just an under-sized fixture: exactly
    /// [`MAX_STANDARD_OP_RETURN_BYTES`] must be accepted and one byte more refused, with the
    /// error reporting both sides so a caller can render something useful.
    #[test]
    fn test_add_op_return_enforces_the_standard_ceiling() {
        TransactionBuilder::new()
            .add_op_return(&[0x4d; MAX_STANDARD_OP_RETURN_BYTES])
            .expect("a payload at exactly the ceiling is standard and must be accepted");

        match TransactionBuilder::new().add_op_return(&[0u8; MAX_STANDARD_OP_RETURN_BYTES + 1]) {
            Err(BuilderError::OpReturnDataTooLarge {
                len,
                max,
            }) => {
                assert_eq!(len, MAX_STANDARD_OP_RETURN_BYTES + 1);
                assert_eq!(max, MAX_STANDARD_OP_RETURN_BYTES);
            }
            _ => panic!("expected oversized OP_RETURN error"),
        }
    }

    #[test]
    fn test_default_ordinary_send_matches_legacy_bytes() {
        let inputs = vec![
            Utxo::dummy(0x03, 120_000, 100, false, true),
            Utxo::dummy(0x01, 130_000, 100, false, true),
        ];
        let destination_a = Address::dummy(Network::Testnet, 11);
        let destination_b = Address::dummy(Network::Testnet, 12);
        let change = Address::dummy(Network::Testnet, 13);

        let builder = TransactionBuilder::new()
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::SmallestFirst)
            .set_fee_rate(FeeRate::normal())
            .set_change_address(change)
            .add_inputs(inputs)
            .add_output(&destination_a, 80_000)
            .add_output(&destination_b, 60_000);

        let (legacy_tx, legacy_fee) = build_unsigned_legacy(builder);

        let (tx, fee, _reservation) = TransactionBuilder::new()
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::SmallestFirst)
            .set_fee_rate(FeeRate::normal())
            .set_change_address(Address::dummy(Network::Testnet, 13))
            .add_inputs([
                Utxo::dummy(0x03, 120_000, 100, false, true),
                Utxo::dummy(0x01, 130_000, 100, false, true),
            ])
            .add_output(&destination_a, 80_000)
            .add_output(&destination_b, 60_000)
            .build_unsigned_reserved()
            .expect("ordinary send");

        assert_eq!(serialize(&tx), serialize(&legacy_tx));
        assert_eq!(fee, legacy_fee);
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
            .build_unsigned_reserved()
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
            .build_unsigned_reserved()
            .unwrap()
            .0;

        // Should have selected enough inputs to cover output + fees for larger transaction
        assert!(
            tx.input.len() >= 2,
            "Should select multiple inputs to cover fees for special payload"
        );
    }

    #[test]
    fn set_funding_skips_reserved_utxos() {
        let ctx = TestWalletContext::new_random();
        let account =
            ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").clone();

        let mut funds = ManagedCoreFundsAccount::dummy_bip44();
        let reserved = Utxo::dummy(0x01, 100_000, 100, false, true);
        let free = Utxo::dummy(0x02, 200_000, 100, false, true);
        funds.utxos.insert(reserved.outpoint, reserved.clone());
        funds.utxos.insert(free.outpoint, free.clone());

        funds.reservations().reserve(&[reserved.outpoint], 200, ReservationToken::next());

        let builder =
            TransactionBuilder::new().set_current_height(200).add_funding(&mut funds, &account);

        let candidates: Vec<OutPoint> = builder.inputs.iter().map(|utxo| utxo.outpoint).collect();
        assert!(!candidates.contains(&reserved.outpoint));
        assert!(candidates.contains(&free.outpoint));
    }

    /// A UTXO seeded with `add_inputs` and then offered again by `add_funding`
    /// must appear ONCE. Additive funding otherwise pushes a second candidate
    /// for the same outpoint, and since coin selection does not deduplicate,
    /// `SelectionStrategy::All` spends it twice — a transaction Core rejects
    /// for duplicate prevouts.
    #[test]
    fn add_funding_does_not_duplicate_a_pre_seeded_input() {
        let ctx = TestWalletContext::new_random();
        let account =
            ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").clone();

        let mut funds = ManagedCoreFundsAccount::dummy_bip44();
        let seeded = Utxo::dummy(0x01, 500_000, 100, false, true);
        let other = Utxo::dummy(0x02, 500_000, 100, false, true);
        funds.utxos.insert(seeded.outpoint, seeded.clone());
        funds.utxos.insert(other.outpoint, other.clone());

        let builder = TransactionBuilder::new()
            .set_current_height(200)
            .set_selection_strategy(SelectionStrategy::All)
            .add_inputs(vec![seeded.clone()])
            .add_funding(&mut funds, &account)
            .add_output(&ctx.receive_address, 100_000);

        let candidates: Vec<OutPoint> = builder.inputs.iter().map(|utxo| utxo.outpoint).collect();
        assert_eq!(
            candidates.iter().filter(|op| **op == seeded.outpoint).count(),
            1,
            "the pre-seeded outpoint must be offered exactly once, got {candidates:?}"
        );

        let (tx, _fee, token) = builder.build_unsigned_reserved().expect("build");
        let mut prevouts: Vec<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
        prevouts.sort_by_key(|op| (op.txid.to_byte_array(), op.vout));
        let deduped = {
            let mut d = prevouts.clone();
            d.dedup();
            d
        };
        assert_eq!(prevouts, deduped, "transaction must not contain duplicate prevouts");

        // The pre-seeded input still belongs to this account, so a drain that
        // spends it must RESERVE it — otherwise a concurrent build would see it
        // as free and double-spend it.
        assert!(token.is_some(), "a funded build stamps a reservation token");
        let reserved = funds.reservations().reserved(200);
        assert!(
            reserved.contains(&seeded.outpoint),
            "the pre-seeded input must be reserved by the account that owns it"
        );
    }

    #[tokio::test]
    async fn build_signed_releases_reservation_on_signing_failure() {
        let ctx = TestWalletContext::new_random();
        let account =
            ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").clone();

        let mut funds = ManagedCoreFundsAccount::dummy_bip44();
        let utxo = Utxo::dummy(0x01, 1_000_000, 100, false, true);
        funds.utxos.insert(utxo.outpoint, utxo.clone());

        let destination = Address::dummy(Network::Testnet, 0);
        let builder = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .add_funding(&mut funds, &account)
            .set_change_address(Address::dummy(Network::Testnet, 1))
            .add_output(&destination, 500_000);

        // A resolver that never finds a derivation path forces signing to fail
        // after the inputs have already been reserved by `assemble_unsigned`.
        let result = builder.build_signed(&ctx.wallet, |_addr| None).await;
        assert!(result.is_err());

        // The failed sign must leave no reservation behind, so the UTXO stays
        // selectable instead of being stranded until the TTL backstop.
        assert!(funds.reservations().reserved(200).is_empty());
    }

    #[test]
    fn build_unsigned_reserves_selected_inputs() {
        let ctx = TestWalletContext::new_random();
        let account =
            ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").clone();

        let mut funds = ManagedCoreFundsAccount::dummy_bip44();
        let utxo = Utxo::dummy(0x01, 1_000_000, 100, false, true);
        funds.utxos.insert(utxo.outpoint, utxo.clone());

        let destination = Address::dummy(Network::Testnet, 0);
        let (tx, _, _) = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .add_funding(&mut funds, &account)
            .set_change_address(Address::dummy(Network::Testnet, 1))
            .add_output(&destination, 500_000)
            .build_unsigned_reserved()
            .expect("build unsigned");

        // Every input the build selected is reserved, so a later build observes
        // them as taken and skips them.
        let reserved = funds.reservations().reserved(200);
        assert!(!reserved.is_empty());
        for input in &tx.input {
            assert!(reserved.contains(&input.previous_output));
        }

        // Abandoning the build releases its inputs immediately rather than
        // stranding them until the TTL backstop reclaims them.
        funds.release_reservation(&tx);
        assert!(funds.reservations().reserved(200).is_empty());
    }

    /// A MAYACHAIN-style drain: sweep the wallet to the vault while the swap memo rides along
    /// as a zero-value OP_RETURN. Before this was allowed, "swap my whole balance" could not be
    /// expressed at all — the caller had to guess the fee and send an explicit amount.
    #[test]
    fn test_drain_allows_a_zero_value_op_return_beside_the_destination() {
        let utxo = Utxo::dummy(0, 100_000, 100, false, true);
        let vault = Address::dummy(Network::Testnet, 0);
        let memo = b"=:ETH.ETH:0x1c7b17362c84287bd1184447e6dfeaf920c31bbe";

        let (tx, fee, _reservation) = TransactionBuilder::new()
            .set_current_height(200)
            .add_inputs([utxo])
            .add_output(&vault, 1) // ignored by a drain
            .add_op_return(memo)
            .expect("memo within the OP_RETURN ceiling")
            .preserve_output_order()
            .set_selection_strategy(SelectionStrategy::All)
            .build_unsigned_reserved()
            .expect("a drain with a data carrier builds");

        assert_eq!(tx.output.len(), 2, "vault + memo, no change");
        // The vault takes everything the fee does not.
        assert_eq!(tx.output[0].value, 100_000 - fee);
        assert_eq!(tx.output[0].script_pubkey, vault.script_pubkey());
        // The memo is on-chain, zero-value, and still at VOUT1.
        assert_eq!(tx.output[1].value, 0);
        assert_eq!(tx.output[1].script_pubkey, op_return_script(memo));
        // Nothing is left behind: inputs are fully accounted for by outputs + fee.
        assert_eq!(tx.output.iter().map(|o| o.value).sum::<u64>() + fee, 100_000);
    }

    /// The data carrier's bytes must be paid for. A drain whose fee ignored the OP_RETURN would
    /// under-pay the miner and risk a stuck deposit.
    #[test]
    fn test_drain_fee_covers_the_data_carrier_bytes() {
        let memo = vec![0x4d; 60];
        let build = |with_memo: bool| {
            let mut b = TransactionBuilder::new()
                .set_current_height(200)
                .add_inputs([Utxo::dummy(0, 100_000, 100, false, true)])
                .add_output(&Address::dummy(Network::Testnet, 0), 1)
                .set_selection_strategy(SelectionStrategy::All);
            if with_memo {
                b = b
                    .add_op_return(&memo)
                    .expect("memo within the ceiling")
                    .preserve_output_order();
            }
            let (tx, fee, _reservation) = b.build_unsigned_reserved().expect("drain builds");
            (tx, fee)
        };

        let (plain_tx, plain_fee) = build(false);
        let (memo_tx, memo_fee) = build(true);

        // "Costs more" is too weak on its own: it passes even when the extra fee
        // falls short of the bytes the carrier actually adds. Price the fee
        // against the SERIALIZED transactions instead, so an under-priced data
        // carrier — the case that lets a drain broadcast below the relay rate —
        // fails here.
        let plain_size = dashcore::consensus::serialize(&plain_tx).len() as u64;
        let memo_size = dashcore::consensus::serialize(&memo_tx).len() as u64;

        // These are unsigned transactions, so the fee must exceed the bytes on
        // hand by the signature allowance the estimator adds per input. Both
        // builds spend the same single input, so that allowance is identical:
        // whatever the carrier costs shows up entirely as extra size.
        assert!(
            memo_fee > memo_size,
            "the fee ({memo_fee}) must cover the {memo_size} serialized bytes plus signatures"
        );
        assert_eq!(
            memo_fee - memo_size,
            plain_fee - plain_size,
            "the carrier must not disturb the per-input signature allowance"
        );

        // The heart of it: every byte the carrier adds is paid for, at the same
        // rate as the rest of the transaction. Equality (not >=) is deliberate —
        // it catches under-pricing AND a fee that silently drifts upward.
        let size_delta = memo_size - plain_size;
        let fee_delta = memo_fee - plain_fee;
        assert!(
            size_delta >= memo.len() as u64,
            "a {}-byte memo must add at least its payload to the serialized size (added {size_delta})",
            memo.len()
        );
        assert_eq!(
            fee_delta, size_delta,
            "the {size_delta} bytes the carrier adds must be priced at the transaction's own rate"
        );

        // And the deliverable output shrank by exactly that extra fee: the
        // zero-value carrier takes nothing from the destination beyond its bytes.
        let deliverable = |tx: &Transaction| {
            tx.output
                .iter()
                .find(|o| !o.script_pubkey.is_op_return())
                .expect("one value carrier")
                .value
        };
        assert_eq!(
            deliverable(&plain_tx) - deliverable(&memo_tx),
            fee_delta,
            "the zero-value carrier must cost the destination exactly the extra fee"
        );
    }

    /// Two spendable outputs remain ambiguous: a drain has one balance to give away.
    #[test]
    fn test_drain_still_rejects_two_spendable_outputs() {
        let result = TransactionBuilder::new()
            .set_current_height(200)
            .add_inputs([Utxo::dummy(0, 100_000, 100, false, true)])
            .add_output(&Address::dummy(Network::Testnet, 0), 1)
            .add_output(&Address::dummy(Network::Testnet, 1), 1)
            .set_selection_strategy(SelectionStrategy::All)
            .build_unsigned_reserved();

        match result {
            Err(BuilderError::InvalidData(message)) => {
                assert!(message.contains("exactly one spendable output"), "got: {message}");
            }
            other => panic!("expected the two-destination drain to be rejected, got {other:?}"),
        }
    }

    /// A value-bearing OP_RETURN would claim part of the drained balance and overspend.
    #[test]
    fn test_drain_rejects_a_value_bearing_data_carrier() {
        let mut builder = TransactionBuilder::new()
            .set_current_height(200)
            .add_inputs([Utxo::dummy(0, 100_000, 100, false, true)])
            .add_output(&Address::dummy(Network::Testnet, 0), 1)
            .add_op_return(b"memo")
            .expect("memo within the ceiling")
            .set_selection_strategy(SelectionStrategy::All);
        // Reach past the builder API, which cannot express this, to prove the guard holds.
        builder.outputs.last_mut().expect("the data output").value = 5_000;

        match builder.build_unsigned_reserved() {
            Err(BuilderError::InvalidData(message)) => {
                assert!(message.contains("zero-value"), "got: {message}");
            }
            other => panic!("expected a value-bearing data carrier to be rejected, got {other:?}"),
        }
    }

    /// An asset-lock drain is the one case whose value carrier IS an OP_RETURN (the burn
    /// mirroring the payload credits) — it must keep working unchanged.
    #[test]
    fn test_asset_lock_drain_still_uses_its_burn_output_as_the_carrier() {
        let credit_script = Address::dummy(Network::Testnet, 14).script_pubkey();
        let (tx, fee, _reservation) = TransactionBuilder::new()
            .set_current_height(200)
            .add_inputs([Utxo::dummy(0, 100_000, 100, false, true)])
            .set_special_payload(TransactionPayload::AssetLockPayloadType(AssetLockPayload {
                version: 1,
                credit_outputs: vec![TxOut {
                    value: 1,
                    script_pubkey: credit_script,
                }],
            }))
            .set_selection_strategy(SelectionStrategy::All)
            .build_unsigned_reserved()
            .expect("asset-lock drain builds");

        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, 100_000 - fee);
        assert!(tx.output[0].script_pubkey.is_op_return());
        match tx.special_transaction_payload {
            Some(TransactionPayload::AssetLockPayloadType(p)) => {
                assert_eq!(p.credit_outputs[0].value, 100_000 - fee, "credits mirror the burn");
            }
            other => panic!("expected the asset-lock payload, got {other:?}"),
        }
    }

    /// Placeholder ProUpServTx payload with every selection-dependent field
    /// zeroed, as a finalizer-seam caller would construct it before selection.
    fn pro_up_serv_placeholder(script_payout: ScriptBuf) -> TransactionPayload {
        use dashcore::blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
        use dashcore::bls_sig_utils::BLSSignature;
        use dashcore::hash_types::InputsHash;

        TransactionPayload::ProviderUpdateServicePayloadType(ProviderUpdateServicePayload::new(
            Some(0),
            Txid::all_zeros(),
            0x00000000000000000000ffff7f000001, // 127.0.0.1 mapped
            19999,
            script_payout,
            InputsHash::all_zeros(),
            None,
            None,
            None,
            BLSSignature::from([0; 96]),
        ))
    }

    #[tokio::test]
    async fn payload_finalizer_installs_payload_before_input_signing() {
        use dashcore::bls_sig_utils::BLSSignature;

        let ctx = TestWalletContext::new_random();
        let account =
            ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").clone();

        let mut funds = ManagedCoreFundsAccount::dummy_bip44();
        let a = Utxo::dummy(0x01, 600_000, 100, false, true);
        let b = Utxo::dummy(0x02, 600_000, 100, false, true);
        funds.utxos.insert(a.outpoint, a.clone());
        funds.utxos.insert(b.outpoint, b.clone());

        let (tx, fee, token) = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .add_funding(&mut funds, &account)
            .set_change_address(Address::dummy(Network::Testnet, 1))
            .set_special_payload(pro_up_serv_placeholder(ScriptBuf::new()))
            .build_signed_reserved_with_payload_finalizer(
                &ctx.wallet,
                |_addr| Some(DerivationPath::master()),
                |unsigned| {
                    // The finalizer sees the selected inputs (unsigned) and the
                    // placeholder payload, exactly what inputs_hash + a payload
                    // signature need.
                    assert!(!unsigned.input.is_empty(), "inputs are selected before finalizing");
                    assert!(
                        unsigned.input.iter().all(|input| input.script_sig.is_empty()),
                        "inputs must not be signed before the payload is finalized"
                    );
                    let Some(TransactionPayload::ProviderUpdateServicePayloadType(placeholder)) =
                        &unsigned.special_transaction_payload
                    else {
                        panic!("placeholder payload must still be attached");
                    };
                    let mut finalized = placeholder.clone();
                    finalized.inputs_hash = unsigned.hash_inputs();
                    finalized.payload_sig = BLSSignature::from([0xAB; 96]);
                    Ok(TransactionPayload::ProviderUpdateServicePayloadType(finalized))
                },
            )
            .await
            .expect("finalized build signs");

        assert!(fee > 0);
        assert!(token.is_some(), "a funded build stamps a reservation token");
        let Some(TransactionPayload::ProviderUpdateServicePayloadType(payload)) =
            &tx.special_transaction_payload
        else {
            panic!("finalized payload must ride the signed transaction");
        };
        assert_eq!(payload.inputs_hash, tx.hash_inputs(), "inputs_hash commits to the input set");
        assert_eq!(payload.payload_sig, BLSSignature::from([0xAB; 96]));
        assert!(
            tx.input.iter().all(|input| !input.script_sig.is_empty()),
            "every input is ECDSA-signed after the payload landed"
        );
        // The selected inputs stay reserved for the caller to broadcast.
        let reserved = funds.reservations().reserved(200);
        for input in &tx.input {
            assert!(reserved.contains(&input.previous_output));
        }
    }

    #[tokio::test]
    async fn payload_finalizer_error_releases_reservation() {
        let ctx = TestWalletContext::new_random();
        let account =
            ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").clone();

        let mut funds = ManagedCoreFundsAccount::dummy_bip44();
        let utxo = Utxo::dummy(0x01, 1_000_000, 100, false, true);
        funds.utxos.insert(utxo.outpoint, utxo.clone());

        let result = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .add_funding(&mut funds, &account)
            .set_change_address(Address::dummy(Network::Testnet, 1))
            .set_special_payload(pro_up_serv_placeholder(ScriptBuf::new()))
            .build_signed_reserved_with_payload_finalizer(
                &ctx.wallet,
                |_addr| Some(DerivationPath::master()),
                |_unsigned| Err(BuilderError::SigningFailed("operator key rejected".into())),
            )
            .await;

        assert!(matches!(result, Err(BuilderError::SigningFailed(_))));
        assert!(
            funds.reservations().reserved(200).is_empty(),
            "a failed finalize must release the reserved inputs"
        );
    }

    #[tokio::test]
    async fn payload_finalizer_rejects_a_variant_change() {
        use dashcore::blockdata::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
        use dashcore::bls_sig_utils::BLSSignature;

        let ctx = TestWalletContext::new_random();
        let account =
            ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").clone();

        let mut funds = ManagedCoreFundsAccount::dummy_bip44();
        let utxo = Utxo::dummy(0x01, 1_000_000, 100, false, true);
        funds.utxos.insert(utxo.outpoint, utxo.clone());

        let result = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .add_funding(&mut funds, &account)
            .set_change_address(Address::dummy(Network::Testnet, 1))
            .set_special_payload(pro_up_serv_placeholder(ScriptBuf::new()))
            .build_signed_reserved_with_payload_finalizer(
                &ctx.wallet,
                |_addr| Some(DerivationPath::master()),
                |unsigned| {
                    Ok(TransactionPayload::ProviderUpdateRevocationPayloadType(
                        ProviderUpdateRevocationPayload {
                            version: ProviderUpdateRevocationPayload::CURRENT_VERSION,
                            pro_tx_hash: Txid::all_zeros(),
                            reason: 0,
                            inputs_hash: unsigned.hash_inputs(),
                            payload_sig: BLSSignature::from([0; 96]),
                        },
                    ))
                },
            )
            .await;

        assert!(matches!(result, Err(BuilderError::InvalidData(_))));
        assert!(funds.reservations().reserved(200).is_empty());
    }

    #[tokio::test]
    async fn payload_finalizer_rejects_a_payload_that_outgrew_its_placeholder() {
        let ctx = TestWalletContext::new_random();
        let account =
            ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").clone();

        let mut funds = ManagedCoreFundsAccount::dummy_bip44();
        let utxo = Utxo::dummy(0x01, 1_000_000, 100, false, true);
        funds.utxos.insert(utxo.outpoint, utxo.clone());

        let result = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .add_funding(&mut funds, &account)
            .set_change_address(Address::dummy(Network::Testnet, 1))
            // Placeholder priced with an empty payout script...
            .set_special_payload(pro_up_serv_placeholder(ScriptBuf::new()))
            .build_signed_reserved_with_payload_finalizer(
                &ctx.wallet,
                |_addr| Some(DerivationPath::master()),
                // ...but finalized with a 25-byte P2PKH script the fee never
                // paid for.
                |_unsigned| {
                    Ok(pro_up_serv_placeholder(Address::dummy(Network::Testnet, 2).script_pubkey()))
                },
            )
            .await;

        assert!(matches!(result, Err(BuilderError::InvalidData(_))));
        assert!(funds.reservations().reserved(200).is_empty());
    }

    #[tokio::test]
    async fn payload_finalizer_requires_a_placeholder_payload() {
        let ctx = TestWalletContext::new_random();
        let account =
            ctx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").clone();

        let mut funds = ManagedCoreFundsAccount::dummy_bip44();
        let utxo = Utxo::dummy(0x01, 1_000_000, 100, false, true);
        funds.utxos.insert(utxo.outpoint, utxo.clone());

        let result = TransactionBuilder::new()
            .set_current_height(200)
            .set_fee_rate(FeeRate::normal())
            .add_funding(&mut funds, &account)
            .set_change_address(Address::dummy(Network::Testnet, 1))
            .add_output(&Address::dummy(Network::Testnet, 0), 500_000)
            .build_signed_reserved_with_payload_finalizer(
                &ctx.wallet,
                |_addr| Some(DerivationPath::master()),
                |_unsigned| panic!("finalizer must not run without a placeholder"),
            )
            .await;

        assert!(matches!(result, Err(BuilderError::InvalidData(_))));
        assert!(
            funds.reservations().reserved(200).is_empty(),
            "the refusal happens before anything is reserved"
        );
    }

    /// The fee a finalizer-seam build pays must equal what the ordinary path
    /// charges for the same placeholder: the finalized payload swaps in at
    /// identical estimated size, so nothing about selection or change moves.
    #[test]
    fn payload_finalizer_size_guard_uses_the_fee_sizing_estimate() {
        let placeholder = pro_up_serv_placeholder(ScriptBuf::new());
        let finalized = pro_up_serv_placeholder(ScriptBuf::new());
        assert_eq!(
            TransactionBuilder::estimated_payload_size(&placeholder),
            TransactionBuilder::estimated_payload_size(&finalized),
        );
        let grown = pro_up_serv_placeholder(Address::dummy(Network::Testnet, 2).script_pubkey());
        assert!(
            TransactionBuilder::estimated_payload_size(&grown)
                > TransactionBuilder::estimated_payload_size(&placeholder)
        );
    }
}
