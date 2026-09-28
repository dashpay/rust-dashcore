//! Outpoints the wallet will not spend.
//!
//! The wallet keeps one set of locked outpoints, like Dash Core's
//! `setLockedCoins`, and coin selection never spends a coin in it. A ProRegTx
//! locks the collateral it registers; [`ManagedWalletInfo::lock_outpoint`] and
//! [`ManagedWalletInfo::unlock_outpoint`] lock and unlock anything by hand. See
//! [`ManagedWalletInfo::locked_outpoints`] for the full rules.

use super::ManagedWalletInfo;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::hashes::Hash;
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
    /// Coin selection never picks a coin whose outpoint is in this set, for any
    /// [`SelectionStrategy`](crate::wallet::managed_wallet_info::coin_selection::SelectionStrategy),
    /// the `All` drain included, and such a coin counts toward
    /// [`WalletCoreBalance::locked`](crate::WalletCoreBalance::locked) rather
    /// than the spendable balance.
    ///
    /// # What locks an outpoint
    ///
    /// - A ProRegTx. The wallet locks the collateral of every masternode
    ///   registration it processes, so an ordinary send never spends it:
    ///   spending the collateral would end the registration. The collateral is
    ///   the ProRegTx's `collateralOutpoint`, or, when that names a null txid,
    ///   the ProRegTx's own output at `collateralIndex`.
    /// - [`Self::lock_outpoint`].
    ///
    /// Only [`Self::unlock_outpoint`] removes an outpoint. A coin's amount is
    /// never a reason to lock it.
    ///
    /// # Order does not matter
    ///
    /// An entry does not need a coin behind it. A collateral seen after its
    /// ProRegTx, or a coin locked before it arrives, arrives locked. A ProRegTx
    /// naming a coin that is not this wallet's leaves an entry that never
    /// matches anything.
    ///
    /// # How long a lock lasts
    ///
    /// Until [`Self::unlock_outpoint`]. Dash Core ties the collateral lock to
    /// its masternode list: a ProUpRevTx leaves the masternode registered, so
    /// the collateral stays locked; a later ProRegTx naming the same collateral
    /// replaces the registration and keeps it locked; only spending the
    /// collateral ends the registration. Core then drops the lock along with
    /// the coin, and re-derives it from its masternode list whenever the coin
    /// could come back (on load, and when the spend is abandoned). An SPV
    /// wallet has no masternode list, so it keeps the entry instead: once the
    /// coin is spent the entry has nothing to act on, and a coin whose spend is
    /// reorged out or swept comes back locked.
    ///
    /// Processing a ProRegTx again (the block that confirms it, a rescan) locks
    /// its collateral again, as Core does on load.
    ///
    /// # The set is the source of truth
    ///
    /// Coin selection works on [`Utxo`](crate::Utxo)s and skips a locked one
    /// through [`Utxo::is_spendable`](crate::Utxo::is_spendable). The wallet
    /// keeps the `is_locked` flag of every coin it holds equal to membership in
    /// this set: when the coin arrives, when its outpoint is locked or
    /// unlocked, and on every balance refresh. A flag written on a held coin
    /// directly is overwritten by the next refresh.
    ///
    /// # Persistence
    ///
    /// The set is serialized with the wallet. A store that keeps wallet state
    /// some other way persists this set instead: the outpoints a transaction
    /// check locks arrive on
    /// [`TransactionCheckResult::locked_outpoints`](crate::transaction_checking::TransactionCheckResult::locked_outpoints),
    /// [`Self::lock_outpoint`] and [`Self::unlock_outpoint`] report their own
    /// changes, and on load the store calls [`Self::lock_outpoint`] for each
    /// persisted outpoint, before or after restoring the coins.
    pub fn locked_outpoints(&self) -> &BTreeSet<OutPoint> {
        &self.locked_outpoints
    }

    /// Whether `outpoint` is locked. See [`Self::locked_outpoints`].
    pub fn is_outpoint_locked(&self, outpoint: &OutPoint) -> bool {
        self.locked_outpoints.contains(outpoint)
    }

    /// Lock `outpoint`, so coin selection does not spend it until
    /// [`Self::unlock_outpoint`]. See [`Self::locked_outpoints`].
    ///
    /// The wallet does not need to hold the coin yet: it arrives locked.
    /// Returns `true` when the outpoint was not locked before. When the wallet
    /// holds the coin, its value moves to the locked balance.
    pub fn lock_outpoint(&mut self, outpoint: OutPoint) -> bool {
        if !self.locked_outpoints.insert(outpoint) {
            return false;
        }
        if self.refresh_lock_flags([outpoint]) {
            self.update_balance();
        }
        true
    }

    /// Unlock `outpoint`, so coin selection may spend it again. See
    /// [`Self::locked_outpoints`].
    ///
    /// Unlocking is never automatic, and a masternode collateral is unlocked
    /// only here. Returns `true` when the outpoint was locked. When the wallet
    /// holds the coin, its value moves back to the spendable balance.
    pub fn unlock_outpoint(&mut self, outpoint: &OutPoint) -> bool {
        if !self.locked_outpoints.remove(outpoint) {
            return false;
        }
        if self.refresh_lock_flags([*outpoint]) {
            self.update_balance();
        }
        true
    }

    /// Lock the collateral `tx` registers when it is a ProRegTx.
    ///
    /// Returns the collateral when it was not locked before. Only updates the
    /// set: the caller refreshes the flags of the coins involved.
    pub(crate) fn lock_masternode_collateral(&mut self, tx: &Transaction) -> Option<OutPoint> {
        let collateral = masternode_collateral(tx)?;
        self.locked_outpoints.insert(collateral).then_some(collateral)
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
    /// Run before every balance refresh, so coins inserted without going
    /// through transaction checking (a store restoring its coins, say) pick up
    /// their locks too.
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
    use dashcore::blockdata::transaction::special_transaction::provider_registration::{
        ProviderMasternodeType, ProviderRegistrationPayload,
    };
    use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
    use dashcore::bls_sig_utils::BLSPublicKey;
    use dashcore::hash_types::InputsHash;
    use dashcore::hashes::Hash;
    use dashcore::{Address, Network, OutPoint, PubkeyHash, ScriptBuf, Transaction, TxOut, Txid};

    /// A ProRegTx naming `collateral`, with `outputs` outputs of its own.
    fn registration(collateral: OutPoint, outputs: usize) -> Transaction {
        let key_hash = PubkeyHash::from_byte_array([0x70; 20]);
        Transaction {
            version: 3,
            lock_time: 0,
            input: Vec::new(),
            output: vec![
                TxOut {
                    value: 1_000,
                    script_pubkey: Address::dummy(Network::Testnet, 1).script_pubkey(),
                };
                outputs
            ],
            special_transaction_payload: Some(TransactionPayload::ProviderRegistrationPayloadType(
                ProviderRegistrationPayload {
                    version: 1,
                    masternode_type: ProviderMasternodeType::Regular,
                    masternode_mode: 0,
                    collateral_outpoint: collateral,
                    service_address: "127.0.0.1:19999".parse().expect("socket address"),
                    owner_key_hash: key_hash,
                    operator_public_key: BLSPublicKey::from([0x11; 48]),
                    voting_key_hash: key_hash,
                    operator_reward: 0,
                    script_payout: ScriptBuf::new(),
                    inputs_hash: InputsHash::all_zeros(),
                    signature: vec![0x33; 65],
                    platform_node_id: None,
                    platform_p2p_port: None,
                    platform_http_port: None,
                },
            )),
        }
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
