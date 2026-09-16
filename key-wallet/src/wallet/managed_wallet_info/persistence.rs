//! Atomic installation of a persistence adapter's materialized wallet state.

use super::wallet_info_interface::WalletInfoInterface;
use super::ManagedWalletInfo;
use crate::account::{AccountType, TransactionRecord};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::transaction_record::OutputRole;
use crate::managed_account::ManagedAccountRefMut;
use crate::utxo::Utxo;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{OutPoint, Txid};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

/// Complete transaction and coin state supplied by an external persistence adapter.
///
/// Store full records before key-wallet compacts finalized history. Records and UTXOs
/// must describe the same committed snapshot, with abandoned/conflicted records removed.
/// Account definitions, address pools and sync metadata belong to the receiving skeleton.
#[derive(Debug, Clone, Default)]
pub struct PersistedWalletState {
    /// All surviving records, including full records of finalized transactions.
    pub transactions: Vec<TransactionRecord>,
    /// The materialized unspent coins with their exact owning accounts.
    pub utxos: Vec<(AccountType, Utxo)>,
    /// Durable spend evidence, including outpoints whose spending record is unavailable.
    /// `Some(height)` proves a block-observed spend. `None` only blocks the output;
    /// claims covered by a record are derived from that record and remain releasable.
    pub additional_spent_outpoints: BTreeMap<OutPoint, Option<CoreBlockHeight>>,
}

/// A persisted snapshot could not be installed; the receiving wallet is unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError {
    /// Restore requires an account skeleton with no transaction or coin state.
    NonEmptyWallet,
    /// The combined coin values cannot be represented by the wallet balance.
    BalanceOverflow,
    /// A record or coin names an account absent from the skeleton.
    MissingAccount(AccountType),
    /// A coin names a keys-only account.
    NonFundingAccount(AccountType),
    /// A record's txid, input/output metadata or block height is inconsistent.
    InvalidRecord(Txid),
    /// More than one record names the same transaction and account.
    DuplicateRecord(Txid, AccountType),
    /// More than one unspent coin names the same outpoint.
    DuplicateUtxo(OutPoint),
    /// A coin's ownership, script or funding transaction metadata is inconsistent.
    InvalidUtxo(OutPoint),
    /// A coin is simultaneously unspent and claimed spent.
    SpentUtxo(OutPoint),
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonEmptyWallet => {
                f.write_str("persisted state requires an empty wallet skeleton")
            }
            Self::BalanceOverflow => {
                f.write_str("persisted coin values overflow the wallet balance")
            }
            Self::MissingAccount(account) => write!(f, "missing persisted account {account}"),
            Self::NonFundingAccount(account) => write!(f, "account {account} cannot hold coins"),
            Self::InvalidRecord(txid) => write!(f, "inconsistent persisted transaction {txid}"),
            Self::DuplicateRecord(txid, account) => {
                write!(f, "duplicate transaction {txid} in {account}")
            }
            Self::DuplicateUtxo(outpoint) => write!(f, "duplicate persisted coin {outpoint}"),
            Self::InvalidUtxo(outpoint) => write!(f, "inconsistent persisted coin {outpoint}"),
            Self::SpentUtxo(outpoint) => write!(f, "persisted coin {outpoint} is also spent"),
        }
    }
}

impl std::error::Error for RestoreError {}

impl ManagedWalletInfo {
    /// Install a complete persistence snapshot without replaying live transaction processing.
    ///
    /// Validates the entire snapshot before changing any state. The receiver must be a
    /// fresh account skeleton; account definitions, pools and sync metadata are preserved.
    /// Spend claims are derived before finalized records are compacted. Supplemental
    /// evidence without a record or block height conservatively blocks funding redelivery
    /// until a complete replacement snapshot can be built; it cannot be abandoned by txid.
    /// Returns [`RestoreError`] for an inconsistent snapshot or nonempty receiver.
    pub fn restore_persisted_state(
        &mut self,
        state: PersistedWalletState,
    ) -> Result<(), RestoreError> {
        self.validate_persisted_state(&state)?;
        let record_inputs: HashSet<_> = state
            .transactions
            .iter()
            .filter(|record| !record.transaction.is_coin_base())
            .flat_map(|record| record.transaction.input.iter().map(|input| input.previous_output))
            .collect();
        for (outpoint, height) in state.additional_spent_outpoints {
            if let Some(height) = height {
                self.observed_spent_outpoints.insert(outpoint, height);
            } else if !record_inputs.contains(&outpoint) {
                self.unattributed_spent_outpoints.insert(outpoint);
            }
        }
        let account_claims: HashSet<_> = state
            .transactions
            .iter()
            .filter(|record| !record.transaction.is_coin_base())
            .flat_map(|record| {
                record
                    .transaction
                    .input
                    .iter()
                    .map(|input| (record.account_type, input.previous_output))
            })
            .collect();
        for record in &state.transactions {
            if let Some(block) = record.context.block_info() {
                for input in &record.transaction.input {
                    if !input.previous_output.is_null() {
                        self.observed_spent_outpoints
                            .entry(input.previous_output)
                            .and_modify(|height| *height = (*height).max(block.height()))
                            .or_insert(block.height());
                    }
                }
            }
        }
        for record in state.transactions {
            if record.context.is_instant_send() {
                self.instant_send_locks.insert(record.txid);
            }
            for account in self.accounts.all_accounts_mut() {
                if account.managed_account_type().to_account_type() != record.account_type {
                    continue;
                }
                match account {
                    ManagedAccountRefMut::Funds(account) => {
                        for detail in &record.output_details {
                            let outpoint = OutPoint {
                                txid: record.txid,
                                vout: detail.index,
                            };
                            if matches!(detail.role, OutputRole::Received | OutputRole::Change)
                                && (record_inputs.contains(&outpoint)
                                    || self.observed_spent_outpoints.contains_key(&outpoint)
                                    || self.unattributed_spent_outpoints.contains(&outpoint))
                                && !account_claims.contains(&(record.account_type, outpoint))
                            {
                                if let Some(address) = &detail.address {
                                    account.spent_before_funded.insert(
                                        outpoint,
                                        Utxo::new(
                                            outpoint,
                                            record.transaction.output[detail.index as usize]
                                                .clone(),
                                            address.clone(),
                                            record
                                                .context
                                                .block_info()
                                                .map_or(0, |block| block.height()),
                                            record.transaction.is_coin_base(),
                                        ),
                                    );
                                }
                            }
                        }
                        account.restore_transaction_record(record);
                    }
                    ManagedAccountRefMut::Keys(account) => {
                        account.restore_transaction_record(record)
                    }
                }
                break;
            }
        }
        for (account_type, utxo) in state.utxos {
            for account in self.accounts.all_accounts_mut() {
                if let ManagedAccountRefMut::Funds(account) = account {
                    if account.managed_account_type().to_account_type() == account_type {
                        account.utxos.insert(utxo.outpoint, utxo);
                        break;
                    }
                }
            }
        }
        for account in self.accounts.dashpay_external_accounts.values_mut() {
            account.update_balance(self.metadata.last_processed_height);
        }
        self.update_balance();
        Ok(())
    }

    fn validate_persisted_state(&self, state: &PersistedWalletState) -> Result<(), RestoreError> {
        let accounts: BTreeMap<_, _> = self
            .accounts
            .all_accounts()
            .into_iter()
            .map(|account| (account.managed_account_type().to_account_type(), account))
            .collect();
        if !self.observed_spent_outpoints.is_empty()
            || !self.unattributed_spent_outpoints.is_empty()
            || !self.instant_send_locks.is_empty()
            || accounts.values().any(|account| {
                account.tx_count() != 0
                    || account.as_funds().is_some_and(|funds| funds.has_persisted_funds_state())
            })
        {
            return Err(RestoreError::NonEmptyWallet);
        }
        let mut records = HashSet::new();
        let mut spent: HashSet<_> = state.additional_spent_outpoints.keys().copied().collect();
        let mut transactions = BTreeMap::new();
        let mut funding_heights = BTreeMap::new();
        for record in &state.transactions {
            if !accounts.contains_key(&record.account_type) {
                return Err(RestoreError::MissingAccount(record.account_type));
            }
            let mut input_indices = HashSet::new();
            let mut output_indices = HashSet::new();
            if record.txid != record.transaction.txid()
                || record.input_details.iter().any(|detail| {
                    detail.index as usize >= record.transaction.input.len()
                        || !input_indices.insert(detail.index)
                        || !detail.address.as_unchecked().is_valid_for_network(self.network)
                })
                || record.output_details.iter().any(|detail| {
                    !output_indices.insert(detail.index)
                        || record.transaction.output.get(detail.index as usize).is_none_or(
                            |output| {
                                output.value != detail.value
                                    || detail.address.as_ref().is_some_and(|address| {
                                        address.script_pubkey() != output.script_pubkey
                                            || !address
                                                .as_unchecked()
                                                .is_valid_for_network(self.network)
                                    })
                            },
                        )
                })
            {
                return Err(RestoreError::InvalidRecord(record.txid));
            }
            if !records.insert((record.account_type, record.txid)) {
                return Err(RestoreError::DuplicateRecord(record.txid, record.account_type));
            }
            transactions.insert(record.txid, &record.transaction);
            if let Some(block) = record.context.block_info() {
                if funding_heights
                    .insert(record.txid, block.height())
                    .is_some_and(|height| height != block.height())
                {
                    return Err(RestoreError::InvalidRecord(record.txid));
                }
            }
            if !record.transaction.is_coin_base() {
                spent.extend(record.transaction.input.iter().map(|input| input.previous_output));
            }
        }
        let mut coins = HashSet::new();
        let mut total = 0u64;
        for (account_type, utxo) in &state.utxos {
            total = total.checked_add(utxo.txout.value).ok_or(RestoreError::BalanceOverflow)?;
            let account =
                accounts.get(account_type).ok_or(RestoreError::MissingAccount(*account_type))?;
            if account.as_funds().is_none() {
                return Err(RestoreError::NonFundingAccount(*account_type));
            }
            if !coins.insert(utxo.outpoint) {
                return Err(RestoreError::DuplicateUtxo(utxo.outpoint));
            }
            if spent.contains(&utxo.outpoint) {
                return Err(RestoreError::SpentUtxo(utxo.outpoint));
            }
            if (utxo.is_coinbase && utxo.height.checked_add(100).is_none())
                || funding_heights
                    .get(&utxo.outpoint.txid)
                    .is_some_and(|height| *height != utxo.height)
                || !account.contains_address(&utxo.address)
                || utxo.address.script_pubkey() != utxo.txout.script_pubkey
                || !utxo.address.as_unchecked().is_valid_for_network(self.network)
                || transactions.get(&utxo.outpoint.txid).is_some_and(|transaction| {
                    transaction.output.get(utxo.outpoint.vout as usize) != Some(&utxo.txout)
                        || transaction.is_coin_base() != utxo.is_coinbase
                })
            {
                return Err(RestoreError::InvalidUtxo(utxo.outpoint));
            }
        }
        Ok(())
    }
}

/// Output suppression and settled-input checks use distinct evidence.
pub(crate) trait SpendEvidence {
    fn blocks_output(&self, outpoint: &OutPoint) -> bool;
    fn is_settled(&self, outpoint: &OutPoint) -> bool;
}

impl SpendEvidence for BTreeMap<OutPoint, CoreBlockHeight> {
    fn blocks_output(&self, outpoint: &OutPoint) -> bool {
        self.contains_key(outpoint)
    }
    fn is_settled(&self, outpoint: &OutPoint) -> bool {
        self.contains_key(outpoint)
    }
}

pub(crate) struct WalletSpendEvidence<'a> {
    pub observed: &'a BTreeMap<OutPoint, CoreBlockHeight>,
    pub unattributed: &'a HashSet<OutPoint>,
    pub claimed: &'a HashSet<OutPoint>,
}

impl SpendEvidence for WalletSpendEvidence<'_> {
    fn blocks_output(&self, outpoint: &OutPoint) -> bool {
        self.observed.contains_key(outpoint)
            || self.unattributed.contains(outpoint)
            || self.claimed.contains(outpoint)
    }
    fn is_settled(&self, outpoint: &OutPoint) -> bool {
        self.observed.contains_key(outpoint)
    }
}
