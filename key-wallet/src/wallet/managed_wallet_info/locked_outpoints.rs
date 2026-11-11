//! Outpoints the wallet will not spend, like Dash Core's `setLockedCoins`.
//! See [`ManagedWalletInfo::locked_outpoints`] for the rules.

use super::ManagedWalletInfo;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::{OutPoint, Transaction, Txid};
use std::collections::BTreeSet;

/// The collateral `tx` registers when it is a ProRegTx, `None` otherwise.
///
/// A null collateral txid means the ProRegTx creates its collateral itself, as
/// its own output at `collateralIndex`. An index past its outputs names no coin
/// (Core rejects such a registration), so it yields `None`.
pub(crate) fn masternode_collateral(tx: &Transaction) -> Option<OutPoint> {
    let Some(TransactionPayload::ProviderRegistrationPayloadType(registration)) =
        &tx.special_transaction_payload
    else {
        return None;
    };
    let named = registration.collateral_outpoint;
    if named.txid != Txid::all_zeros() {
        return Some(named);
    }
    ((named.vout as usize) < tx.output.len()).then(|| OutPoint::new(tx.txid(), named.vout))
}

impl ManagedWalletInfo {
    /// The outpoints this wallet will not spend.
    ///
    /// Coin selection skips a coin in this set whatever the strategy, and its
    /// value counts as [`WalletCoreBalance::locked`](crate::WalletCoreBalance::locked).
    /// Only [`Self::unlock_outpoint`] removes an outpoint.
    ///
    /// # What locks an outpoint
    ///
    /// [`Self::lock_outpoint`], and a ProRegTx whose collateral is this
    /// wallet's, since spending the collateral ends the registration:
    ///
    /// - A collateral the ProRegTx creates (a null collateral txid names its
    ///   own output) is locked when that output pays the wallet, from the
    ///   first sighting, mempool included. An unconfirmed sighting does not
    ///   lock it again once the wallet holds it; a block does.
    /// - A collateral the ProRegTx names is locked only once the ProRegTx is
    ///   in a block, when the wallet holds the coin or the ProRegTx is
    ///   relevant to the wallet. An InstantSend context counts as
    ///   unconfirmed: the wallet does not verify InstantSend locks.
    ///
    /// Processing the block of a ProRegTx again locks its collateral again,
    /// also after an unlock. A ProRegTx that involves nothing of the wallet's
    /// locks nothing, so a named collateral that arrives after such a
    /// ProRegTx is not locked.
    ///
    /// The wallet locks from the registrations it is handed. A wallet without
    /// provider accounts does not watch its outpoints
    /// ([`WalletInfoInterface::monitored_filter_elements`]), so a
    /// compact-filter client never hands it a ProRegTx that only names one of
    /// its coins.
    ///
    /// # Lock flags
    ///
    /// An entry needs no coin behind it: a coin locked before it arrives,
    /// arrives locked. The wallet sets [`Utxo::is_locked`](crate::Utxo::is_locked)
    /// of every coin it holds from this set, so a flag written directly is
    /// overwritten.
    ///
    /// # Persistence
    ///
    /// The set is serialized with the wallet. A store that keeps wallet state
    /// another way saves the outpoints reported by
    /// [`TransactionCheckResult::locked_outpoints`](crate::transaction_checking::TransactionCheckResult::locked_outpoints),
    /// [`Self::lock_outpoint`] and [`Self::unlock_outpoint`], and calls
    /// [`Self::lock_outpoint`] for each on load, before or after
    /// [`Self::restore_utxos`].
    pub fn locked_outpoints(&self) -> &BTreeSet<OutPoint> {
        &self.locked_outpoints
    }

    /// Whether `outpoint` is locked. See [`Self::locked_outpoints`].
    pub fn is_outpoint_locked(&self, outpoint: &OutPoint) -> bool {
        self.locked_outpoints.contains(outpoint)
    }

    /// Lock `outpoint` and return whether it was not locked before. The
    /// wallet need not hold the coin yet. See [`Self::locked_outpoints`].
    pub fn lock_outpoint(&mut self, outpoint: OutPoint) -> bool {
        if !self.locked_outpoints.insert(outpoint) {
            return false;
        }
        if self.refresh_lock_flags([outpoint]) {
            self.update_balance();
        }
        true
    }

    /// Unlock `outpoint` and return whether it was locked. See
    /// [`Self::locked_outpoints`].
    pub fn unlock_outpoint(&mut self, outpoint: &OutPoint) -> bool {
        if !self.locked_outpoints.remove(outpoint) {
            return false;
        }
        if self.refresh_lock_flags([*outpoint]) {
            self.update_balance();
        }
        true
    }

    /// Lock `collateral`, the collateral of the ProRegTx `tx`, when it is
    /// this wallet's to keep. See [`Self::locked_outpoints`] for the rule.
    ///
    /// Call it once the accounts recorded `tx`, with the sighting that was
    /// checked: whether it was in a block (`confirmed`), whether the wallet
    /// held `collateral` before the check (`held_before`) and whether the
    /// check found `tx` relevant.
    ///
    /// Returns whether the collateral was not locked before. Only updates the
    /// set: the caller refreshes the flags of the coins involved.
    pub(crate) fn lock_masternode_collateral(
        &mut self,
        tx: &Transaction,
        collateral: OutPoint,
        confirmed: bool,
        held_before: bool,
        is_relevant: bool,
    ) -> bool {
        let holds = self.holds_coin(&collateral);
        // Only a null collateral txid yields the ProRegTx's own txid: no
        // transaction can name itself.
        let creates_it = collateral.txid == tx.txid();
        let locks = if creates_it {
            holds && (confirmed || !held_before)
        } else {
            // A named coin can arrive after its registration, so a relevant
            // registration locks it ahead.
            confirmed && (holds || is_relevant)
        };
        locks && self.locked_outpoints.insert(collateral)
    }

    /// Whether a funds account of this wallet holds `outpoint` as a coin. A
    /// coin it keeps aside as spent counts: a fork that drops the spend gives
    /// it back.
    pub(crate) fn holds_coin(&self, outpoint: &OutPoint) -> bool {
        self.accounts
            .all_funding_accounts()
            .iter()
            .any(|account| account.holds_or_keeps_aside(outpoint))
    }

    /// Set the lock flag of each coin this wallet holds among `outpoints` to
    /// its membership in the lock set. Returns whether any flag changed, which
    /// means the balance buckets are stale.
    pub(crate) fn refresh_lock_flags(
        &mut self,
        outpoints: impl IntoIterator<Item = OutPoint>,
    ) -> bool {
        let locked = &self.locked_outpoints;
        let mut accounts = self.accounts.all_funding_accounts_mut();
        let mut changed = false;
        for outpoint in outpoints {
            let is_locked = locked.contains(&outpoint);
            for account in accounts.iter_mut() {
                if let Some(utxo) = account.utxos.get_mut(&outpoint) {
                    changed |= utxo.is_locked != is_locked;
                    utxo.is_locked = is_locked;
                }
            }
        }
        changed
    }

    /// Set the lock flag of every coin this wallet holds to its membership in
    /// the lock set.
    ///
    /// Run before every balance refresh and before funding a transaction, so
    /// a coin that entered an account some other way than transaction
    /// checking or [`Self::restore_utxos`] picks up its lock too.
    pub(crate) fn refresh_all_lock_flags(&mut self) {
        let locked = &self.locked_outpoints;
        for account in self.accounts.all_funding_accounts_mut() {
            for utxo in account.utxos.values_mut() {
                utxo.is_locked = locked.contains(&utxo.outpoint);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::masternode_collateral;
    use dashcore::{Address, Network, OutPoint, PubkeyHash, Transaction, TxOut, Txid};

    /// A ProRegTx naming `collateral`, with `outputs` outputs of its own.
    fn registration(collateral: OutPoint, outputs: usize) -> Transaction {
        let output = TxOut {
            value: 1_000,
            script_pubkey: Address::dummy(Network::Testnet, 1).script_pubkey(),
        };
        let owner_key_hash = PubkeyHash::from_byte_array([0x70; 20]);
        Transaction::dummy_provider_registration(
            collateral,
            owner_key_hash,
            vec![output; outputs],
            0,
        )
    }

    #[test]
    fn an_external_collateral_is_the_outpoint_the_registration_names() {
        let named = OutPoint::new(Txid::from_byte_array([0x19; 32]), 3);
        assert_eq!(masternode_collateral(&registration(named, 1)), Some(named));
    }

    #[test]
    fn a_null_collateral_txid_names_the_registrations_own_output() {
        let tx = registration(OutPoint::new(Txid::all_zeros(), 1), 2);
        assert_eq!(masternode_collateral(&tx), Some(OutPoint::new(tx.txid(), 1)));
    }

    #[test]
    fn an_own_output_index_past_the_outputs_names_no_coin() {
        let tx = registration(OutPoint::new(Txid::all_zeros(), 2), 2);
        assert_eq!(masternode_collateral(&tx), None);
    }

    #[test]
    fn only_a_registration_has_a_collateral() {
        let address = Address::dummy(Network::Testnet, 1);
        assert_eq!(masternode_collateral(&Transaction::dummy(&address, 0..1, &[1_000])), None);
    }
}
