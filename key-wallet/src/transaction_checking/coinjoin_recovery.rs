//! Opt-in recovery of CoinJoin coins that landed past the address pool's gap
//! limit.
//!
//! CoinJoin discovery walks each CoinJoin chain forward and stops after
//! `gap_limit` unused addresses. A wallet migrated from DashSync breaks that
//! assumption: DashSync marked a CoinJoin address used the moment it handed it
//! to a mixing session, so every failed session left an address that is used
//! locally and empty on chain. Enough failed sessions in a row leave a run of
//! empty addresses wider than any fixed gap, and every mixed coin past that run
//! stays invisible no matter how often the wallet rescans (ticket 32008).
//!
//! Rescanning the wallet as it stands cannot fix that either: every old mix is
//! chainlocked by now, and a finalized transaction is never revisited, so a
//! coin found later in it is never credited. Recovery therefore starts from
//! fresh wallet state. [`ManagedWalletInfo::begin_coinjoin_recovery`] forgets
//! everything the wallet learned from the chain, rewinds its sync checkpoint to
//! just below its birth height, and turns the probe on for the replay that
//! follows; the sync layer sees the wallet behind and replays it from birth.
//!
//! During the replay, every transaction the regular check finds relevant has
//! its unclaimed P2PKH outputs compared against each CoinJoin chain, derived up
//! to [`COINJOIN_RECOVERY_PROBE_WINDOW`] addresses past the pool's generated
//! end. Only a matched address is added to the pool; the regular check then
//! credits the coin, marks the address used and maintains the gap past it, so
//! the empty run below it is never watched. The window keeps covering that run
//! for later transactions, and it moves up with every address the pool gains.
//!
//! The probe switches itself off once the wallet's committed sync height
//! reaches the height it had when the recovery began.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use dashcore::blockdata::transaction::Transaction;
use dashcore::hashes::Hash;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{PubkeyHash, ScriptBuf};

use super::account_checker::DerivedAddressInfo;
use crate::account::AccountType;
use crate::bip32::{ChildNumber, ExtendedPubKey};
use crate::managed_account::address_pool::AddressPoolType;
use crate::managed_account::managed_account_collection::ManagedAccountCollection;
use crate::managed_account::managed_account_ref::ManagedAccountRefMut;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::KeySource;

/// How far past the generated end of each CoinJoin chain a coin is searched
/// for: the widest run of empty addresses one step of recovery can cross. Each
/// address found moves the pool end, so the window travels with the coins;
/// DashSync derived up to ~10,500 CoinJoin addresses on heavily mixed wallets.
/// Derivation only; nothing in the window is watched unless a coin is found in
/// it.
pub const COINJOIN_RECOVERY_PROBE_WINDOW: u32 = 10_000;

/// A CoinJoin recovery replay running on one wallet.
pub struct CoinJoinRecovery {
    /// The committed sync height the wallet had when the recovery began. The
    /// replay is complete once the wallet is synced to it again.
    until_height: CoreBlockHeight,
    /// CoinJoin addresses found past the gap limit so far.
    found: u32,
    /// Whether the probe still runs; a cancel stops it while the replay goes
    /// on, and builds stay refused until it is done.
    probing: bool,
    /// Probe scripts derived per CoinJoin chain (account index, pool type), so
    /// the window is derived once per replay rather than once per transaction.
    chains: HashMap<(u32, AddressPoolType), ProbeRange>,
}

/// The indices of one chain derived for probing: every index from the first
/// one the pool lacked when this replay first probed it, up to `until`. Indices the
/// pool has gained since stay here: an output paying one of them is claimed by
/// the pool and so is never looked up.
struct ProbeRange {
    /// The chain's branch key, derived once.
    branch: ExtendedPubKey,
    /// Every probed address is P2PKH, so its key hash identifies it.
    hashes: HashMap<PubkeyHash, u32>,
    until: u32,
}

impl CoinJoinRecovery {
    fn new(until_height: CoreBlockHeight) -> Self {
        Self {
            until_height,
            found: 0,
            probing: true,
            chains: HashMap::new(),
        }
    }

    /// Where the replay stands.
    pub fn progress(&self) -> CoinJoinRecoveryProgress {
        CoinJoinRecoveryProgress {
            until_height: self.until_height,
            found: self.found,
            probing: self.probing,
        }
    }
}

/// Where a running CoinJoin recovery stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinJoinRecoveryProgress {
    /// The committed sync height at which the replay is complete.
    pub until_height: CoreBlockHeight,
    /// CoinJoin addresses past the gap limit found so far.
    pub found: u32,
    /// Whether the probe still runs: `false` once the recovery was cancelled
    /// and only its replay goes on.
    pub probing: bool,
}

/// A clone keeps the recovery running but derives its window again: copying
/// tens of thousands of scripts with every wallet snapshot would cost more than
/// deriving them.
impl Clone for CoinJoinRecovery {
    fn clone(&self) -> Self {
        Self {
            until_height: self.until_height,
            found: self.found,
            probing: self.probing,
            chains: HashMap::new(),
        }
    }
}

impl std::fmt::Debug for CoinJoinRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoinJoinRecovery")
            .field("until_height", &self.until_height)
            .field("found", &self.found)
            .field("probing", &self.probing)
            .field("chains", &self.chains.len())
            .finish()
    }
}

/// The branch index of a CoinJoin chain; `None` for pools a CoinJoin account
/// does not have.
fn branch_index(pool_type: AddressPoolType) -> Option<u32> {
    match pool_type {
        AddressPoolType::External => Some(0),
        AddressPoolType::Internal => Some(1),
        AddressPoolType::Absent | AddressPoolType::AbsentHardened => None,
    }
}

/// The key hash of `branch`'s child `index`, which the pool pays as P2PKH.
fn probe_hash(branch: &ExtendedPubKey, index: u32) -> crate::Result<PubkeyHash> {
    let child = ChildNumber::from_normal_idx(index).map_err(crate::Error::Bip32)?;
    let key = branch.ckd_pub(child).map_err(crate::Error::Bip32)?;
    Ok(dashcore::PublicKey::new(key.public_key).pubkey_hash())
}

/// The key hash a P2PKH script pays; `None` for any other script.
fn p2pkh_hash(script: &ScriptBuf) -> Option<PubkeyHash> {
    script.p2pkh_public_key_hash_bytes().and_then(|bytes| PubkeyHash::from_slice(bytes).ok())
}

/// Fresh address pools for the CoinJoin account `account`, carrying over from
/// its `old` pools what the replay cannot rediscover:
/// - a gap limit widened at runtime, with which the wallet found coins the
///   default gap would not;
/// - every address seen in use or handed out, with that state: its coin may lie
///   farther from the others than the probe window reaches, and one handed out
///   but not yet paid must not go to a second payer;
/// - the runs between those addresses no wider than the gap, which a normal
///   walk watches, and the gap past each used one. Only wider runs, the
///   walls, stay out of the pool.
fn fresh_coinjoin_pools(
    old: &ManagedAccountType,
    account: &crate::Account,
) -> Option<ManagedAccountType> {
    let mut fresh = match ManagedAccountCollection::fresh_managed_account_type(account) {
        Ok(fresh) => fresh,
        Err(e) => {
            tracing::warn!(error = %e, "CoinJoin recovery: could not rebuild the CoinJoin pools, keeping the old ones");
            return None;
        }
    };
    let key_source = KeySource::Public(account.account_xpub);
    let old_pools = old.address_pools();
    for pool in fresh.address_pools_mut() {
        let Some(old) = old_pools.iter().find(|old| old.pool_type == pool.pool_type) else {
            continue;
        };
        if old.gap_limit > pool.gap_limit {
            if let Err(e) = pool.set_gap_limit(old.gap_limit, &key_source) {
                tracing::warn!(error = %e, gap = old.gap_limit, "CoinJoin recovery: could not keep a widened gap limit");
            }
        }
        for (&index, info) in &old.addresses {
            let used = old.used_indices.contains(&index);
            if !used && !info.is_reserved() {
                continue;
            }
            if let Err(e) = pool.generate_address_at_index(index, &key_source, true) {
                tracing::warn!(error = %e, index, "CoinJoin recovery: could not keep an address");
                continue;
            }
            if used {
                pool.mark_index_used(index);
            }
            if let Some(kept) = pool.addresses.get_mut(&index) {
                if !used {
                    kept.state = info.state;
                }
                kept.label = info.label.clone();
                kept.metadata = info.metadata.clone();
            }
        }
        let kept: Vec<u32> = pool.addresses.keys().copied().collect();
        for pair in kept.windows(2) {
            let (low, high) = (pair[0], pair[1]);
            if high - low - 1 > pool.gap_limit {
                continue;
            }
            for index in low + 1..high {
                if let Err(e) = pool.generate_address_at_index(index, &key_source, true) {
                    tracing::warn!(error = %e, index, "CoinJoin recovery: could not fill a narrow run");
                }
            }
        }
        // The usual lookahead past every kept used address, as the old pool
        // had it, not only past the highest one.
        let used: Vec<u32> = pool.used_indices.iter().copied().collect();
        for index in used {
            for next in index.saturating_add(1)..=index.saturating_add(pool.gap_limit) {
                if let Err(e) = pool.generate_address_at_index(next, &key_source, true) {
                    tracing::warn!(error = %e, index = next, "CoinJoin recovery: could not extend the gap past a kept address");
                    break;
                }
            }
        }
    }
    Some(fresh)
}

impl ManagedWalletInfo {
    /// Forget everything the wallet learned from the chain and rewind it to
    /// just below its birth height, with the CoinJoin probe on for the replay.
    ///
    /// `known_height` is the highest height other sources (other wallets) know
    /// the chain to have reached. The replay is complete once the wallet is
    /// synced to it, or to its own synced or processed height, highest
    /// chainlock seen or unfinished replay target when higher; that height is
    /// returned. Fails when a recovery is already running on this wallet,
    /// the wallet has no CoinJoin account, unconfirmed transactions or coins
    /// reserved by a transaction build, nothing is known of the chain past its
    /// birth, or `wallet` is not this wallet's.
    pub(crate) fn begin_coinjoin_recovery(
        &mut self,
        wallet: &Wallet,
        known_height: CoreBlockHeight,
    ) -> crate::Result<CoreBlockHeight> {
        if wallet.wallet_id != self.wallet_id {
            return Err(crate::Error::InvalidParameter(
                "CoinJoin recovery: the wallet does not match this wallet info".to_string(),
            ));
        }
        if self.coinjoin_recovery.as_ref().is_some_and(|recovery| recovery.probing) {
            return Err(crate::Error::InvalidState(
                "a CoinJoin recovery is already running on this wallet".to_string(),
            ));
        }
        if self.accounts.coinjoin_accounts.is_empty() {
            return Err(crate::Error::InvalidState(
                "CoinJoin recovery: the wallet has no CoinJoin account".to_string(),
            ));
        }
        // Records not yet in a block are never delivered again by the replay,
        // which only brings back blocks; dropping them would hide a pending
        // send and offer the coins it spends again. Coins a build has reserved
        // are about to be spent the same way.
        let current_height = self.metadata.last_processed_height;
        let pending = self.accounts.all_accounts().iter().any(|account| {
            account.transactions().values().any(|record| !record.is_confirmed())
                || account.as_funds().is_some_and(|funds| funds.has_reservations(current_height))
        });
        if pending {
            return Err(crate::Error::InvalidState(
                "CoinJoin recovery: the wallet has unconfirmed transactions or coins reserved \
                 for one; start it once they are in a block, or abandon the ones that never \
                 will be"
                    .to_string(),
            ));
        }
        // A wallet still in its first sync has a synced height far below the
        // chain; the chainlocks seen mark where the final history, the part a
        // normal sync never revisits, ends.
        let chain_locked = self
            .metadata
            .last_applied_chain_lock
            .as_ref()
            .map(|chain_lock| chain_lock.block_height);
        // A replay a cancelled recovery left behind still has to get back to
        // where it was going.
        let until_height = known_height
            .max(self.metadata.synced_height)
            .max(self.metadata.last_processed_height)
            .max(self.coinjoin_recovery.as_ref().map_or(0, |recovery| recovery.until_height))
            .max(chain_locked.unwrap_or(0))
            .max(self.noted_chain_lock_height.unwrap_or(0));
        let floor = self.metadata.birth_height.saturating_sub(1);
        if until_height <= floor {
            return Err(crate::Error::InvalidState(
                "CoinJoin recovery: nothing is known of the chain past the wallet's birth yet; \
                 start it once the wallet has synced"
                    .to_string(),
            ));
        }
        self.reset_chain_state(wallet);
        self.set_funds_replaying(true);
        self.finished_coinjoin_recovery = None;
        self.coinjoin_recovery = Some(CoinJoinRecovery::new(until_height));
        tracing::info!(
            from_height = self.metadata.synced_height,
            until_height,
            "CoinJoin recovery: wallet reset, replaying from birth"
        );
        Ok(until_height)
    }

    /// Stop the probe of the running recovery before its replay is complete,
    /// returning how many CoinJoin addresses it found past the gap limit;
    /// `None` when no probe runs. The replay itself goes on as a normal sync,
    /// and builds stay refused until it is back at the height the recovery was
    /// to run to: until then the coins are those of a past height.
    pub(crate) fn cancel_coinjoin_recovery(&mut self) -> Option<u32> {
        let synced = self.metadata.synced_height;
        let recovery = self.coinjoin_recovery.as_mut().filter(|recovery| recovery.probing)?;
        recovery.probing = false;
        recovery.chains.clear();
        tracing::info!(
            height = synced,
            until_height = recovery.until_height,
            found = recovery.found,
            "CoinJoin recovery: cancelled, the replay goes on without the probe"
        );
        Some(recovery.found)
    }

    /// Called whenever the committed sync height advances: once it reaches the
    /// height the recovery was to run to, the recovery ends, builds are
    /// allowed again, and its result waits for
    /// [`Self::take_finished_coinjoin_recovery`].
    pub(crate) fn on_synced_height_advanced(&mut self) {
        let synced = self.metadata.synced_height;
        if !self.coinjoin_recovery.as_ref().is_some_and(|recovery| synced >= recovery.until_height)
        {
            return;
        }
        let Some(recovery) = self.coinjoin_recovery.take() else {
            return;
        };
        self.set_funds_replaying(false);
        tracing::info!(
            height = synced,
            found = recovery.found,
            "CoinJoin recovery: replay complete"
        );
        self.finished_coinjoin_recovery = Some(recovery.progress());
    }

    /// Where a recovery whose replay completed since the last call ended up;
    /// `probing` is `false` when it had been cancelled.
    pub(crate) fn take_finished_coinjoin_recovery(&mut self) -> Option<CoinJoinRecoveryProgress> {
        self.finished_coinjoin_recovery.take()
    }

    /// Whether a CoinJoin recovery replay is still catching up, so the coins
    /// are those of a past height.
    pub(crate) fn is_replaying(&self) -> bool {
        self.coinjoin_recovery.is_some()
    }

    /// Mark every funds account as replayed, or no longer, so transaction
    /// builds refuse to fund from it meanwhile.
    pub(crate) fn set_funds_replaying(&mut self, replaying: bool) {
        for account in self.accounts.all_accounts_mut() {
            if let ManagedAccountRefMut::Funds(funds) = account {
                funds.replaying = replaying;
            }
        }
    }

    /// Drop all chain-derived state so the wallet can be replayed from birth.
    ///
    /// Each CoinJoin account the wallet holds the key of gets fresh address
    /// pools (see [`fresh_coinjoin_pools`]), so a recovered wallet does not go
    /// on watching empty runs. Every other pool may hold addresses a walk from
    /// index 0 would never reach again (a DIP-15 contact pool, a migrated
    /// wallet's history), so it keeps its addresses and their usage. Platform
    /// accounts are not Core chain state and are left alone, as are the applied
    /// ChainLock, which keeps the replayed history final as it arrives, and the
    /// wallet's identity and metadata.
    fn reset_chain_state(&mut self, wallet: &Wallet) {
        for account in self.accounts.all_accounts_mut() {
            match account {
                ManagedAccountRefMut::Funds(funds) => {
                    let account_type = funds.managed_account_type().to_account_type();
                    let fresh = match account_type {
                        AccountType::CoinJoin {
                            ..
                        } => wallet.accounts.account_of_type(account_type).and_then(|account| {
                            fresh_coinjoin_pools(funds.managed_account_type(), account)
                        }),
                        _ => None,
                    };
                    funds.reset_chain_state(fresh);
                }
                ManagedAccountRefMut::Keys(keys) => keys.reset_chain_state(None),
            }
        }
        self.instant_send_locks.clear();
        self.observed_spent_outpoints.clear();
        // Only coverage is rewound, as for a new account, with a new account
        // generation so in-flight filter scans, which snapshotted the old
        // state, cannot certify coverage for the reset wallet.
        // `last_processed_height` is a chain fact: keeping it keeps replayed
        // coins' maturity and confirmations measured against the real chain.
        self.rewind_sync_checkpoint_for_new_account();
        self.update_balance();
    }

    /// While a recovery is running, add to the CoinJoin pools every address of
    /// ours that `tx` pays past a pool's generated end. `tx` must be one the
    /// regular check found relevant.
    ///
    /// Must run before the transaction updates the wallet, so that the caller's
    /// check that follows credits the outputs found here. Returns the addresses
    /// added, for the caller to hand to SPV as newly derived scripts.
    pub(crate) fn recover_coinjoin_outputs(
        &mut self,
        tx: &Transaction,
        wallet: &Wallet,
    ) -> Vec<DerivedAddressInfo> {
        let mut derived = Vec::new();
        let Some(recovery) = self.coinjoin_recovery.as_mut().filter(|recovery| recovery.probing)
        else {
            return derived;
        };

        let accounts = self.accounts.all_accounts();
        let unclaimed: HashSet<PubkeyHash> = tx
            .output
            .iter()
            .filter(|output| {
                !accounts
                    .iter()
                    .any(|account| account.contains_script_pub_key(&output.script_pubkey))
            })
            .filter_map(|output| p2pkh_hash(&output.script_pubkey))
            .collect();
        drop(accounts);
        if unclaimed.is_empty() {
            return derived;
        }

        for (&index, account) in self.accounts.coinjoin_accounts.iter_mut() {
            let account_type = account.managed_account_type().to_account_type();
            let key_source = wallet.key_source_for_account(account_type);
            let KeySource::Public(account_xpub) = key_source else {
                continue;
            };

            let mut extended = false;
            for pool in account.managed_account_type_mut().address_pools_mut() {
                let Some(branch_index) = branch_index(pool.pool_type) else {
                    continue;
                };
                let pool_end = pool.highest_generated.map(|h| h + 1).unwrap_or(0);
                let range = match recovery.chains.entry((index, pool.pool_type)) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let branch = match ChildNumber::from_normal_idx(branch_index)
                            .and_then(|child| account_xpub.ckd_pub(child))
                        {
                            Ok(branch) => branch,
                            Err(e) => {
                                tracing::warn!(error = %e, "CoinJoin recovery: branch derivation failed");
                                continue;
                            }
                        };
                        // From the first index the pool lacks: the reset may
                        // have kept used addresses past an empty run.
                        let first_missing = (0..pool_end)
                            .find(|&i| pool.info_at_index(i).is_none())
                            .unwrap_or(pool_end);
                        entry.insert(ProbeRange {
                            branch,
                            hashes: HashMap::new(),
                            until: first_missing,
                        })
                    }
                };
                // Each address found moves the pool end and with it the window,
                // so a second coin of this transaction may only come into reach
                // once the first is added: search again until nothing new turns
                // up, since a finalized transaction is never looked at again.
                let pool_type = pool.pool_type;
                let mut new_infos = Vec::new();
                let mut failed = HashSet::new();
                loop {
                    let window_start = pool.highest_generated.map(|h| h + 1).unwrap_or(0);
                    let end = window_start.saturating_add(COINJOIN_RECOVERY_PROBE_WINDOW);
                    while range.until < end {
                        let probe = range.until;
                        match probe_hash(&range.branch, probe) {
                            Ok(hash) => {
                                range.hashes.insert(hash, probe);
                                range.until += 1;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    index = probe,
                                    "CoinJoin recovery: derivation failed, searching below it only"
                                );
                                break;
                            }
                        }
                    }
                    let mut hits: Vec<u32> = unclaimed
                        .iter()
                        .filter_map(|hash| range.hashes.get(hash).copied())
                        .filter(|&index| {
                            pool.info_at_index(index).is_none() && !failed.contains(&index)
                        })
                        .collect();
                    if hits.is_empty() {
                        break;
                    }
                    hits.sort_unstable();
                    for next in hits {
                        if let Err(e) = pool.generate_address_at_index(next, &key_source, true) {
                            tracing::error!(
                                error = %e,
                                index = next,
                                "CoinJoin recovery: failed to add an address to the pool, its coin stays missing"
                            );
                            failed.insert(next);
                            continue;
                        }
                        match pool.info_at_index(next) {
                            Some(info) => new_infos.push(info.clone()),
                            // Never selected again, or the search would not end.
                            None => {
                                failed.insert(next);
                            }
                        }
                    }
                }
                if new_infos.is_empty() {
                    continue;
                }
                // The check that follows marks the found addresses used and
                // extends the gap past them, as for any other output of ours.
                tracing::info!(
                    txid = %tx.txid(),
                    pool_type = ?pool_type,
                    previous_end = pool_end.saturating_sub(1),
                    found = ?new_infos.iter().map(|info| info.index).collect::<Vec<_>>(),
                    "CoinJoin recovery: found outputs past the gap limit"
                );
                recovery.found += new_infos.len() as u32;
                derived.extend(new_infos.into_iter().map(|info| DerivedAddressInfo {
                    account_type,
                    pool_type,
                    info,
                }));
                extended = true;
            }
            if extended {
                account.bump_monitor_revision();
            }
        }

        derived
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountType, StandardAccountType};
    use crate::managed_account::managed_account_type::ManagedAccountType;
    use crate::transaction_checking::{BlockInfo, TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
    use crate::Network;
    use dashcore::ephemerealdata::chain_lock::ChainLock;
    use dashcore::{Address, BlockHash, OutPoint, TxIn, TxOut, Txid};

    const NETWORK: Network = Network::Testnet;
    /// 0.001 DASH CoinJoin denomination, fee included.
    const DENOM: u64 = 100_001;
    /// An index past the generated end of a fresh CoinJoin pool.
    const PAST_GAP: u32 = crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT;
    const GAP: u32 = crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT;

    struct Fixture {
        wallet: Wallet,
        managed: ManagedWalletInfo,
        key_source: KeySource,
    }

    /// A wallet with one CoinJoin account and a recovery running.
    fn fixture() -> Fixture {
        let mut fx = fixture_without_recovery(NETWORK);
        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start recovery");
        fx
    }

    fn fixture_without_recovery(network: Network) -> Fixture {
        let mut wallet =
            Wallet::new_random(network, WalletAccountCreationOptions::None).expect("wallet");
        wallet
            .add_account(
                AccountType::CoinJoin {
                    index: 0,
                },
                None,
            )
            .expect("CoinJoin account");
        let managed = ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);
        let xpub = wallet.accounts.coinjoin_accounts.get(&0).expect("account").account_xpub;
        Fixture {
            wallet,
            managed,
            key_source: KeySource::Public(xpub),
        }
    }

    fn coinjoin_address(fx: &mut Fixture, internal: bool, index: u32) -> Address {
        let account = fx.managed.first_coinjoin_managed_account_mut().expect("account");
        let ManagedAccountType::CoinJoin {
            external_addresses,
            internal_addresses,
            ..
        } = account.managed_account_type_mut()
        else {
            panic!("expected a CoinJoin account");
        };
        let pool = if internal {
            internal_addresses
        } else {
            external_addresses
        };
        pool.generate_address_at_index(index, &fx.key_source, false).expect("derive")
    }

    fn pool(
        fx: &Fixture,
        pool_type: AddressPoolType,
    ) -> &crate::managed_account::address_pool::AddressPool {
        fx.managed
            .first_coinjoin_managed_account()
            .expect("account")
            .managed_account_type()
            .address_pools()
            .into_iter()
            .find(|pool| pool.pool_type == pool_type)
            .expect("pool")
    }

    fn pool_end(fx: &Fixture, pool_type: AddressPoolType) -> Option<u32> {
        pool(fx, pool_type).highest_generated
    }

    fn block(height: u32) -> TransactionContext {
        TransactionContext::InChainLockedBlock(BlockInfo::new(
            height,
            BlockHash::from_slice(&[height as u8; 32]).expect("hash"),
            1_650_000_000 + height,
        ))
    }

    fn input(txid: Txid) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid,
                vout: 0,
            },
            ..Default::default()
        }
    }

    fn output(value: u64, address: &Address) -> TxOut {
        TxOut {
            value,
            script_pubkey: address.script_pubkey(),
        }
    }

    fn tx(input: Vec<TxIn>, output: Vec<TxOut>) -> Transaction {
        Transaction {
            version: 2,
            lock_time: 0,
            input,
            output,
            special_transaction_payload: None,
        }
    }

    /// Funds our CoinJoin external index 0 with one denomination at block 1.
    async fn fund(fx: &mut Fixture) -> Transaction {
        let first = coinjoin_address(fx, false, 0);
        let funding = Transaction::dummy(&first, 0..1, &[DENOM]);
        let funded =
            fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;
        assert_eq!(funded.total_received, DENOM, "funding must be credited");
        funding
    }

    /// Our funded coin plus two foreign ones in, three denominations out, ours
    /// to `ours` as output 1.
    fn mix_of(funding: &Transaction, ours: &Address) -> Transaction {
        tx(
            vec![
                input(Txid::from_byte_array([0xa1; 32])),
                input(funding.txid()),
                input(Txid::from_byte_array([0xa2; 32])),
            ],
            vec![
                output(DENOM, &Address::dummy(NETWORK, 1)),
                output(DENOM, ours),
                output(DENOM, &Address::dummy(NETWORK, 2)),
            ],
        )
    }

    async fn fund_and_mix(
        fx: &mut Fixture,
        ours: &Address,
    ) -> crate::transaction_checking::TransactionCheckResult {
        let funding = fund(fx).await;
        let mix = mix_of(&funding, ours);
        fx.managed.check_core_transaction(&mix, block(2), &mut fx.wallet, true, true).await
    }

    /// 32008: the mixed coin comes back past the gap limit. Only its address
    /// and the gap after it join the pool, not the empty run below it.
    #[tokio::test]
    async fn mixed_coin_returned_past_the_gap_limit_is_recovered() {
        let mut fx = fixture();
        let far_index = PAST_GAP + 250;
        let far = coinjoin_address(&mut fx, false, far_index);
        let result = fund_and_mix(&mut fx, &far).await;

        assert_eq!(result.total_sent, DENOM, "our input is debited");
        assert_eq!(result.total_received, DENOM, "the far output must be credited");
        assert!(
            result.new_addresses.iter().any(|d| d.info.index == far_index),
            "the recovered address must be reported as newly derived"
        );
        assert_eq!(fx.managed.balance.total(), DENOM, "nothing lost: balance equals the coin");
        let external = pool(&fx, AddressPoolType::External);
        assert_eq!(external.highest_generated, Some(far_index + GAP), "the gap follows the coin");
        assert!(
            (PAST_GAP + 1..far_index).all(|index| external.info_at_index(index).is_none()),
            "the empty run below the recovered address is not watched"
        );
        assert_eq!(fx.managed.coinjoin_recovery.as_ref().map(|r| r.progress().found), Some(1));
    }

    /// DashSync also mixed onto its internal CoinJoin chain.
    #[tokio::test]
    async fn mixed_coin_returned_past_the_gap_limit_on_the_internal_chain_is_recovered() {
        let mut fx = fixture();
        let far = coinjoin_address(&mut fx, true, PAST_GAP + 150);
        let result = fund_and_mix(&mut fx, &far).await;

        assert_eq!(result.total_received, DENOM, "the far internal output must be credited");
        assert_eq!(pool_end(&fx, AddressPoolType::Internal), Some(PAST_GAP + 150 + GAP));
        assert_eq!(fx.managed.balance.total(), DENOM);
    }

    /// A wallet on mainnet recovers the same way (32008 is a mainnet wallet).
    #[tokio::test]
    async fn mixed_coin_returned_past_the_gap_limit_is_recovered_on_mainnet() {
        let mut fx = fixture_without_recovery(Network::Mainnet);
        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start recovery");
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 250);
        let result = fund_and_mix(&mut fx, &far).await;
        assert_eq!(result.total_received, DENOM, "the far output must be credited");
        assert_eq!(fx.managed.balance.total(), DENOM);
    }

    /// Without a recovery running, nothing is probed: a normal wallet pays
    /// nothing for this, and the far coin stays missing as before.
    #[tokio::test]
    async fn without_a_recovery_nothing_is_probed() {
        let mut fx = fixture_without_recovery(NETWORK);
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 250);
        let result = fund_and_mix(&mut fx, &far).await;
        assert_eq!(result.total_received, 0);
        assert_eq!(pool_end(&fx, AddressPoolType::External), Some(GAP));
    }

    /// A coin that really left (all outputs foreign) is not credited, and the
    /// pool is not extended by the probe.
    #[tokio::test]
    async fn coin_that_really_left_is_not_credited() {
        let mut fx = fixture();
        let result = fund_and_mix(&mut fx, &Address::dummy(NETWORK, 3)).await;

        assert_eq!(result.total_received, 0);
        assert_eq!(
            pool_end(&fx, AddressPoolType::External),
            Some(GAP),
            "the probe found nothing, so the pool stays at the funding's gap"
        );
        assert_eq!(fx.managed.balance.total(), 0);
    }

    /// Past the probe window the output stays unknown: the window is a bound,
    /// not a guarantee.
    #[tokio::test]
    async fn output_past_the_probe_window_is_not_found() {
        let mut fx = fixture();
        let beyond = coinjoin_address(&mut fx, false, GAP + COINJOIN_RECOVERY_PROBE_WINDOW + 10);
        let result = fund_and_mix(&mut fx, &beyond).await;
        assert_eq!(result.total_received, 0);
    }

    /// A transaction the wallet does not find relevant is never probed, even
    /// when it pays a CoinJoin address of ours past the gap: the recovery
    /// follows the wallet's own coins, not every block it downloads.
    #[tokio::test]
    async fn an_irrelevant_transaction_is_not_probed() {
        let mut fx = fixture();
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 250);
        let foreign = tx(
            vec![input(Txid::from_byte_array([0xe1; 32]))],
            vec![output(DENOM, &far), output(DENOM, &Address::dummy(NETWORK, 7))],
        );
        let result =
            fx.managed.check_core_transaction(&foreign, block(2), &mut fx.wallet, true, true).await;
        assert!(!result.is_relevant);
        assert_eq!(pool_end(&fx, AddressPoolType::External), Some(GAP - 1));
    }

    /// A mix can return more of our coins than the inputs the wallet knows
    /// about (one of ours came from an address it has not discovered yet).
    /// Every one of them in the window must be found.
    #[tokio::test]
    async fn every_returned_coin_is_found_not_just_the_known_inputs() {
        let mut fx = fixture();
        let far_a = coinjoin_address(&mut fx, false, PAST_GAP + 200);
        let far_b = coinjoin_address(&mut fx, false, PAST_GAP + 800);
        let funding = fund(&mut fx).await;
        let mix = tx(
            vec![
                input(funding.txid()),
                // Ours as well, but on an address the wallet has not discovered.
                input(Txid::from_byte_array([0xb1; 32])),
                input(Txid::from_byte_array([0xb2; 32])),
            ],
            vec![
                output(DENOM, &far_a),
                output(DENOM, &Address::dummy(NETWORK, 4)),
                output(DENOM, &far_b),
            ],
        );
        let result =
            fx.managed.check_core_transaction(&mix, block(2), &mut fx.wallet, true, true).await;

        assert_eq!(result.total_received, 2 * DENOM, "both returned coins must be credited");
        assert_eq!(fx.managed.balance.total(), 2 * DENOM);
    }

    /// A mix spends a known coin of ours and one the wallet has not found yet;
    /// one coin comes back inside the pool, the other past the wall.
    #[tokio::test]
    async fn a_return_for_an_undiscovered_input_does_not_hide_a_far_coin() {
        let mut fx = fixture();
        let near = coinjoin_address(&mut fx, false, 5);
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 300);
        let funding = fund(&mut fx).await;
        let mix = tx(
            vec![
                input(funding.txid()),
                input(Txid::from_byte_array([0xc1; 32])),
                input(Txid::from_byte_array([0xc2; 32])),
            ],
            vec![
                output(DENOM, &near),
                output(DENOM, &Address::dummy(NETWORK, 5)),
                output(DENOM, &far),
            ],
        );
        let result =
            fx.managed.check_core_transaction(&mix, block(2), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_received, 2 * DENOM, "both returned coins must be credited");
        assert_eq!(fx.managed.balance.total(), 2 * DENOM);
    }

    /// The mix arrives before the coin it spends (rescan delivery order): no
    /// input is known yet, but an output to our pool makes it relevant.
    #[tokio::test]
    async fn a_mix_seen_before_its_funding_still_recovers_the_far_coin() {
        let mut fx = fixture();
        let near = coinjoin_address(&mut fx, false, 5);
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 300);
        let mix = tx(
            (0xd1..=0xd3).map(|n| input(Txid::from_byte_array([n; 32]))).collect(),
            vec![
                output(DENOM, &near),
                output(DENOM, &Address::dummy(NETWORK, 6)),
                output(DENOM, &far),
            ],
        );
        let result =
            fx.managed.check_core_transaction(&mix, block(3), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_received, 2 * DENOM, "both of our outputs must be credited");
    }

    /// DashSync created denominations from the main account onto CoinJoin
    /// addresses past the wall; no CoinJoin coin is spent, yet they are ours.
    #[tokio::test]
    async fn denominations_created_past_the_gap_from_the_main_account_are_recovered() {
        let mut fx = fixture_without_recovery(NETWORK);
        fx.wallet
            .add_account(
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .expect("BIP44 account");
        fx.managed = ManagedWalletInfo::from_wallet_with_name(&fx.wallet, "Test".to_string(), 0);
        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start recovery");
        let main_xpub =
            fx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").account_xpub;
        let main = {
            let account = fx.managed.first_bip44_managed_account_mut().expect("account");
            let pool = account
                .managed_account_type_mut()
                .address_pools_mut()
                .into_iter()
                .find(|pool| pool.pool_type == AddressPoolType::External)
                .expect("external pool");
            pool.generate_address_at_index(0, &KeySource::Public(main_xpub), false).expect("derive")
        };
        let funding = Transaction::dummy(&main, 0..1, &[5 * DENOM]);
        let funded =
            fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;
        assert_eq!(funded.total_received, 5 * DENOM, "funding must be credited");

        let far_a = coinjoin_address(&mut fx, false, PAST_GAP + 400);
        let far_b = coinjoin_address(&mut fx, false, PAST_GAP + 401);
        let create =
            tx(vec![input(funding.txid())], vec![output(DENOM, &far_a), output(DENOM, &far_b)]);
        let result =
            fx.managed.check_core_transaction(&create, block(2), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_sent, 5 * DENOM);
        assert_eq!(result.total_received, 2 * DENOM, "both denominations must be credited");
        let coinjoin = fx.managed.first_coinjoin_managed_account().expect("account");
        assert_eq!(coinjoin.utxos.len(), 2);
    }

    /// Whatever the amount: DashSync's denomination-creating transaction sent
    /// its odd change to the CoinJoin internal chain past the wall.
    #[tokio::test]
    async fn odd_change_past_the_gap_beside_a_far_denomination_is_recovered() {
        const CHANGE: u64 = 1_234_567;
        let mut fx = fixture();
        let first = coinjoin_address(&mut fx, false, 0);
        let funding = Transaction::dummy(&first, 0..1, &[DENOM + CHANGE]);
        fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 300);
        let change = coinjoin_address(&mut fx, true, PAST_GAP + 600);
        let create =
            tx(vec![input(funding.txid())], vec![output(DENOM, &far), output(CHANGE, &change)]);
        let result =
            fx.managed.check_core_transaction(&create, block(2), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_received, DENOM + CHANGE, "the change must be credited too");
    }

    /// The recovered coin is mixed again and comes back past the new pool end:
    /// the window moves up with the pool.
    #[tokio::test]
    async fn a_recovered_coin_mixed_again_past_the_new_end_is_recovered() {
        let mut fx = fixture();
        let first_far = coinjoin_address(&mut fx, false, PAST_GAP + 200);
        let funding = fund(&mut fx).await;
        let mix = mix_of(&funding, &first_far);
        let result =
            fx.managed.check_core_transaction(&mix, block(2), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_received, DENOM, "the first far output must be credited");

        let new_end = pool_end(&fx, AddressPoolType::External).expect("pool end");
        let second_far = coinjoin_address(&mut fx, false, new_end + COINJOIN_RECOVERY_PROBE_WINDOW);
        let remix = mix_of(&mix, &second_far);
        let remix = tx(
            vec![
                input(Txid::from_byte_array([0xf1; 32])),
                TxIn {
                    previous_output: OutPoint {
                        txid: mix.txid(),
                        vout: 1,
                    },
                    ..Default::default()
                },
            ],
            remix.output,
        );
        let result =
            fx.managed.check_core_transaction(&remix, block(3), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_sent, DENOM, "the recovered coin is debited");
        assert_eq!(result.total_received, DENOM, "the second far output must be credited");
        assert_eq!(fx.managed.balance.total(), DENOM, "exactly one coin, at the second address");
    }

    /// A coin paid later into the empty run below an earlier recovered address
    /// is still found: the window keeps covering the run the pool skipped.
    #[tokio::test]
    async fn a_later_coin_in_the_skipped_run_is_found() {
        let mut fx = fixture();
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 900);
        let funding = fund(&mut fx).await;
        let mix = mix_of(&funding, &far);
        fx.managed.check_core_transaction(&mix, block(2), &mut fx.wallet, true, true).await;

        let skipped = coinjoin_address(&mut fx, false, PAST_GAP + 300);
        let remix = tx(
            vec![
                input(Txid::from_byte_array([0xf2; 32])),
                TxIn {
                    previous_output: OutPoint {
                        txid: mix.txid(),
                        vout: 1,
                    },
                    ..Default::default()
                },
            ],
            vec![output(DENOM, &skipped), output(DENOM, &Address::dummy(NETWORK, 8))],
        );
        let result =
            fx.managed.check_core_transaction(&remix, block(3), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_received, DENOM, "the coin in the skipped run must be credited");
        assert_eq!(fx.managed.balance.total(), DENOM);
    }

    /// The case behind the reset: the wallet synced past a mix whose coin it
    /// could not see, and the chainlocked mix is never revisited. After the
    /// reset, replaying the same blocks credits the coin.
    #[tokio::test]
    async fn the_replay_credits_a_coin_of_a_finalized_mix() {
        let mut fx = fixture_without_recovery(NETWORK);
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 250);
        let funding = fund(&mut fx).await;
        let mix = mix_of(&funding, &far);
        let first =
            fx.managed.check_core_transaction(&mix, block(2), &mut fx.wallet, true, true).await;
        assert_eq!(first.total_received, 0, "without a recovery the coin is missing");
        assert_eq!(fx.managed.balance.total(), 0);

        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start recovery");
        assert_eq!(fx.managed.balance.total(), 0);
        let funded =
            fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;
        assert_eq!(funded.total_received, DENOM, "the replay records the funding again");
        let replayed =
            fx.managed.check_core_transaction(&mix, block(2), &mut fx.wallet, true, true).await;
        assert_eq!(replayed.total_received, DENOM, "the replay credits the far coin");
        assert_eq!(fx.managed.balance.total(), DENOM);
    }

    /// Starting a recovery drops the chain state, rewinds the checkpoint to
    /// just below birth and bumps the account generation, but keeps the
    /// processed height and the applied ChainLock; it ends once the replay is
    /// back at its start height.
    #[tokio::test]
    async fn the_reset_rewinds_and_the_recovery_ends_at_its_start_height() {
        let mut fx = fixture_without_recovery(NETWORK);
        fx.managed = ManagedWalletInfo::from_wallet_with_name(&fx.wallet, "Test".to_string(), 1);
        fund(&mut fx).await;
        fx.managed.update_synced_height(500);
        fx.managed.update_last_processed_height(500);
        fx.managed.apply_chain_lock(ChainLock::dummy(400));
        let generation = fx.managed.account_generation();
        assert_eq!(fx.managed.balance.total(), DENOM);

        let until = fx.managed.begin_coinjoin_recovery(&fx.wallet, 0).expect("start recovery");
        assert_eq!(until, 500);
        assert_eq!(fx.managed.balance.total(), 0);
        assert!(fx.managed.transaction_history().is_empty());
        assert!(fx.managed.first_coinjoin_managed_account().expect("account").utxos.is_empty());
        assert_eq!(fx.managed.synced_height(), 0);
        assert_eq!(fx.managed.last_processed_height(), 500, "a chain fact, kept");
        assert_eq!(fx.managed.account_generation(), generation + 1);
        assert_eq!(fx.managed.last_applied_chain_lock().map(|cl| cl.block_height), Some(400));
        assert!(
            fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).is_err(),
            "one recovery at a time per wallet"
        );

        fx.managed.update_synced_height(499);
        assert_eq!(
            {
                fx.managed.on_synced_height_advanced();
                fx.managed.take_finished_coinjoin_recovery()
            },
            None
        );
        assert!(fx.managed.coinjoin_recovery.is_some());
        fx.managed.update_synced_height(500);
        assert_eq!(
            {
                fx.managed.on_synced_height_advanced();
                fx.managed.take_finished_coinjoin_recovery().map(|p| p.found)
            },
            Some(0)
        );
        assert!(fx.managed.coinjoin_recovery.is_none(), "the probe is off again");
    }

    /// An account added from an extended public key alone cannot derive its
    /// addresses again, so the reset keeps them, with their usage.
    #[tokio::test]
    async fn the_reset_keeps_an_account_the_wallet_cannot_derive() {
        let mut fx = fixture_without_recovery(NETWORK);
        let other =
            Wallet::new_random(NETWORK, WalletAccountCreationOptions::Default).expect("wallet");
        let xpub =
            other.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").account_xpub;
        let account_type = AccountType::Standard {
            index: 7,
            standard_account_type: StandardAccountType::BIP44Account,
        };
        fx.managed.add_managed_account_from_xpub(account_type, xpub).expect("watch-only account");
        let addresses = |managed: &ManagedWalletInfo| {
            managed
                .accounts
                .standard_bip44_accounts
                .get(&7)
                .expect("account")
                .managed_account_type()
                .all_addresses()
        };
        let before = addresses(&fx.managed);
        assert!(!before.is_empty());

        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start recovery");
        assert_eq!(addresses(&fx.managed), before);
    }

    /// A wallet still in its first sync replays up to the chainlock it has
    /// seen, not just to where its own sync had got: the final history is
    /// what a normal sync would never revisit.
    #[tokio::test]
    async fn a_recovery_started_mid_sync_runs_to_the_chainlock() {
        let mut fx = fixture_without_recovery(NETWORK);
        fx.managed.update_synced_height(300);
        fx.managed.apply_chain_lock(ChainLock::dummy(900));
        assert_eq!(fx.managed.begin_coinjoin_recovery(&fx.wallet, 0).expect("start"), 900);
        fx.managed.update_synced_height(300);
        assert_eq!(
            {
                fx.managed.on_synced_height_advanced();
                fx.managed.take_finished_coinjoin_recovery()
            },
            None
        );
    }

    /// The replay only brings back blocks, so a pending transaction would be
    /// lost: the recovery waits until the wallet has none.
    #[tokio::test]
    async fn a_wallet_with_an_unconfirmed_transaction_cannot_start_a_recovery() {
        let mut fx = fixture_without_recovery(NETWORK);
        let first = coinjoin_address(&mut fx, false, 0);
        let pending = Transaction::dummy(&first, 0..1, &[DENOM]);
        fx.managed
            .check_core_transaction(
                &pending,
                TransactionContext::Mempool,
                &mut fx.wallet,
                true,
                true,
            )
            .await;
        assert!(matches!(
            fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000),
            Err(crate::Error::InvalidState(_))
        ));
        assert!(fx.managed.coinjoin_recovery.is_none());
        assert_eq!(fx.managed.transaction_history().len(), 1, "nothing was reset");
    }

    /// Two coins of one transaction: the second lies past the window the pool
    /// end opens, but inside the window the first coin's address opens. The
    /// probe searches again after each find, since the transaction is final.
    #[tokio::test]
    async fn a_second_coin_reachable_only_from_the_first_is_found() {
        let mut fx = fixture();
        let start = GAP + 1;
        let near_far = coinjoin_address(&mut fx, false, start + 9_000);
        let farther = coinjoin_address(&mut fx, false, start + 9_000 + 5_000);
        assert!(start + 9_000 + 5_000 >= start + COINJOIN_RECOVERY_PROBE_WINDOW);
        let funding = fund(&mut fx).await;
        let create = tx(
            vec![input(funding.txid())],
            vec![output(DENOM, &near_far), output(DENOM, &farther)],
        );
        let result =
            fx.managed.check_core_transaction(&create, block(2), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_received, 2 * DENOM, "both coins must be credited");
    }

    /// A wallet nobody has synced past its birth has nothing to recover yet;
    /// starting would end the replay at once.
    #[tokio::test]
    async fn a_recovery_with_nothing_known_of_the_chain_is_refused() {
        let mut fx = fixture_without_recovery(NETWORK);
        fx.managed = ManagedWalletInfo::from_wallet_with_name(&fx.wallet, "Test".to_string(), 100);
        assert!(matches!(
            fx.managed.begin_coinjoin_recovery(&fx.wallet, 0),
            Err(crate::Error::InvalidState(_))
        ));
        assert_eq!(fx.managed.begin_coinjoin_recovery(&fx.wallet, 5_000).expect("start"), 5_000);
        assert_eq!(fx.managed.synced_height(), 99);
    }

    /// Coins a transaction build has reserved are about to be spent by a
    /// transaction the replay would never deliver.
    #[tokio::test]
    async fn coins_reserved_by_a_build_block_the_recovery() {
        let mut fx = fixture_without_recovery(NETWORK);
        let funding = fund(&mut fx).await;
        let account = fx.managed.first_coinjoin_managed_account_mut().expect("account");
        account.reservations().reserve(
            &[OutPoint {
                txid: funding.txid(),
                vout: 0,
            }],
            0,
            crate::managed_account::reservation::ReservationToken::next(),
        );
        assert!(matches!(
            fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000),
            Err(crate::Error::InvalidState(_))
        ));
        assert_eq!(fx.managed.balance.total(), DENOM, "nothing was reset");
    }

    /// A wallet whose checkpoint sits below its birth stays there: the reset
    /// only ever rewinds.
    #[tokio::test]
    async fn the_reset_never_moves_the_checkpoint_forward() {
        let mut fx = fixture_without_recovery(NETWORK);
        fx.managed = ManagedWalletInfo::from_wallet_with_name(&fx.wallet, "Test".to_string(), 100);
        fx.managed.metadata.synced_height = 0;
        fx.managed.begin_coinjoin_recovery(&fx.wallet, 5_000).expect("start");
        assert_eq!(fx.managed.synced_height(), 0);
    }

    /// A cancelled recovery leaves the probe off and lets a new one start.
    #[tokio::test]
    async fn a_cancelled_recovery_turns_the_probe_off() {
        let mut fx = fixture();
        assert_eq!(fx.managed.cancel_coinjoin_recovery(), Some(0));
        assert_eq!(fx.managed.cancel_coinjoin_recovery(), None);
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 250);
        assert_eq!(fund_and_mix(&mut fx, &far).await.total_received, 0);
        assert!(fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).is_ok());
    }

    /// A gap limit the wallet widened at runtime survives the reset, so the
    /// replay finds what the normal sync found with it.
    #[tokio::test]
    async fn the_reset_keeps_a_widened_gap_limit() {
        let mut fx = fixture_without_recovery(NETWORK);
        let wide = GAP + 50;
        {
            let account = fx.managed.first_coinjoin_managed_account_mut().expect("account");
            for pool in account.managed_account_type_mut().address_pools_mut() {
                pool.set_gap_limit(wide, &fx.key_source).expect("widen");
            }
        }
        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start");
        let external = pool(&fx, AddressPoolType::External);
        assert_eq!(external.gap_limit, wide);
        assert_eq!(external.highest_generated, Some(wide - 1));
    }

    /// A pool outside CoinJoin may hold addresses a walk from index 0 never
    /// reaches again; the reset keeps them and their usage.
    #[tokio::test]
    async fn the_reset_keeps_addresses_outside_coinjoin_past_their_gap() {
        let mut fx = fixture_without_recovery(NETWORK);
        fx.wallet
            .add_account(
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .expect("BIP44 account");
        fx.managed = ManagedWalletInfo::from_wallet_with_name(&fx.wallet, "Test".to_string(), 0);
        let main_xpub =
            fx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").account_xpub;
        let far = {
            let account = fx.managed.first_bip44_managed_account_mut().expect("account");
            let pool = account
                .managed_account_type_mut()
                .address_pools_mut()
                .into_iter()
                .find(|pool| pool.pool_type == AddressPoolType::External)
                .expect("external pool");
            let far = pool
                .generate_address_at_index(500, &KeySource::Public(main_xpub), true)
                .expect("derive");
            pool.mark_used(&far);
            far
        };

        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start");
        let account = fx.managed.first_bip44_managed_account_mut().expect("account");
        let pool = account
            .managed_account_type()
            .address_pools()
            .into_iter()
            .find(|pool| pool.pool_type == AddressPoolType::External)
            .expect("external pool");
        assert_eq!(pool.address_index(&far), Some(500), "the far address is still watched");
        assert!(
            pool.used_indices.contains(&500),
            "its usage stays, so it is not handed out as fresh meanwhile"
        );
    }

    /// While the replay runs the coins are those of a past height, so the
    /// wallet refuses to build from them.
    #[tokio::test]
    async fn a_build_is_refused_while_the_replay_runs() {
        use crate::wallet::managed_wallet_info::coin_selection::SelectionStrategy;
        use crate::wallet::managed_wallet_info::fee::FeeRate;
        use crate::wallet::managed_wallet_info::transaction_builder::BuilderError;

        let mut fx = fixture();
        let to = Address::dummy(NETWORK, 9).to_string().parse().expect("address");
        let result = fx.managed.build_unsigned_transaction(
            &fx.wallet,
            &[],
            0,
            vec![(to, 1_000)],
            FeeRate::new(1000),
            SelectionStrategy::LargestFirst,
        );
        assert!(matches!(result, Err(BuilderError::RecoveryInProgress)));
    }

    /// An address handed out but not yet paid stays handed out across the
    /// reset, so it is not given to a second payer.
    #[tokio::test]
    async fn the_reset_keeps_reserved_addresses_reserved() {
        let mut fx = fixture_without_recovery(NETWORK);
        fx.wallet
            .add_account(
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .expect("BIP44 account");
        fx.managed = ManagedWalletInfo::from_wallet_with_name(&fx.wallet, "Test".to_string(), 0);
        let key_source = KeySource::Public(
            fx.wallet.accounts.standard_bip44_accounts.get(&0).expect("account").account_xpub,
        );
        let external = |managed: &mut ManagedWalletInfo| {
            managed
                .first_bip44_managed_account_mut()
                .expect("account")
                .managed_account_type_mut()
                .address_pools_mut()
                .into_iter()
                .find(|pool| pool.pool_type == AddressPoolType::External)
                .expect("external pool")
                .clone()
        };
        let handed_out = {
            let account = fx.managed.first_bip44_managed_account_mut().expect("account");
            let pool = account
                .managed_account_type_mut()
                .address_pools_mut()
                .into_iter()
                .find(|pool| pool.pool_type == AddressPoolType::External)
                .expect("external pool");
            pool.next_unused_and_reserve(&key_source, 1).expect("reserve")
        };

        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start");
        let pool = external(&mut fx.managed);
        assert!(pool.address_info(&handed_out).expect("kept").is_reserved());
    }

    /// A CoinJoin address the wallet had seen in use is kept by the reset even
    /// past an empty run wider than the window, and a coin later found in that
    /// run below it is still found.
    #[tokio::test]
    async fn the_reset_keeps_used_coinjoin_addresses_and_probes_below_them() {
        let mut fx = fixture_without_recovery(NETWORK);
        let kept_index = GAP + COINJOIN_RECOVERY_PROBE_WINDOW + 500;
        {
            let account = fx.managed.first_coinjoin_managed_account_mut().expect("account");
            let pool = account
                .managed_account_type_mut()
                .address_pools_mut()
                .into_iter()
                .find(|pool| pool.pool_type == AddressPoolType::External)
                .expect("external pool");
            pool.generate_address_at_index(kept_index, &fx.key_source, true).expect("derive");
            pool.mark_index_used(kept_index);
        }
        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start");
        let external = pool(&fx, AddressPoolType::External);
        assert!(external.info_at_index(kept_index).is_some(), "the used address is still watched");
        assert!(external.used_indices.contains(&kept_index), "and stays marked used");
        assert!(external.info_at_index(GAP + 300).is_none(), "the empty run is not");

        let below = coinjoin_address(&mut fx, false, GAP + 300);
        let result = fund_and_mix(&mut fx, &below).await;
        assert_eq!(result.total_received, DENOM, "a coin in the run below it is found");
    }

    /// A wallet without a CoinJoin account has nothing for a recovery to find.
    #[tokio::test]
    async fn a_wallet_without_coinjoin_cannot_start_a_recovery() {
        let wallet =
            Wallet::new_random(NETWORK, WalletAccountCreationOptions::None).expect("wallet");
        let mut managed = ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);
        assert!(matches!(
            managed.begin_coinjoin_recovery(&wallet, 1_000),
            Err(crate::Error::InvalidState(_))
        ));
    }

    /// A CoinJoin address handed out but not yet paid stays handed out in the
    /// rebuilt pool.
    #[tokio::test]
    async fn the_reset_keeps_reserved_coinjoin_addresses_reserved() {
        let mut fx = fixture_without_recovery(NETWORK);
        let handed_out = {
            let account = fx.managed.first_coinjoin_managed_account_mut().expect("account");
            let pool = account
                .managed_account_type_mut()
                .address_pools_mut()
                .into_iter()
                .find(|pool| pool.pool_type == AddressPoolType::External)
                .expect("external pool");
            pool.next_unused_and_reserve(&fx.key_source, 1).expect("reserve")
        };
        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start");
        let external = pool(&fx, AddressPoolType::External);
        assert!(external.address_info(&handed_out).expect("kept").is_reserved());
    }

    /// A build assembled straight from the builder refuses too: the replayed
    /// accounts offer no coins.
    #[tokio::test]
    async fn a_direct_builder_refuses_to_fund_from_a_replayed_account() {
        use crate::wallet::managed_wallet_info::transaction_builder::{
            BuilderError, TransactionBuilder,
        };

        let mut fx = fixture();
        let account = fx.wallet.accounts.coinjoin_accounts.get(&0).expect("account").clone();
        let funds = fx.managed.first_coinjoin_managed_account_mut().expect("account");
        let result = TransactionBuilder::new()
            .add_output(&Address::dummy(NETWORK, 9), 1_000)
            .add_funding(funds, &account)
            .build_unsigned_reserved();
        assert!(matches!(result, Err(BuilderError::RecoveryInProgress)));
    }

    /// Kept addresses close to each other keep the run between them watched,
    /// and each used one the gap past it, as a normal gap walk would; the rest
    /// of a wider run stays out.
    #[tokio::test]
    async fn the_reset_fills_narrow_runs_between_kept_addresses_only() {
        let mut fx = fixture_without_recovery(NETWORK);
        let near = GAP + 5;
        let far = near + GAP + 500;
        {
            let account = fx.managed.first_coinjoin_managed_account_mut().expect("account");
            let pool = account
                .managed_account_type_mut()
                .address_pools_mut()
                .into_iter()
                .find(|pool| pool.pool_type == AddressPoolType::External)
                .expect("external pool");
            for index in [near, far] {
                pool.generate_address_at_index(index, &fx.key_source, true).expect("derive");
                pool.mark_index_used(index);
            }
        }
        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start");
        let external = pool(&fx, AddressPoolType::External);
        assert!((0..=near + GAP).all(|index| external.info_at_index(index).is_some()));
        assert!(external.info_at_index(near + GAP + 1).is_none(), "the wide run stays out");
        assert!(external.info_at_index(far).is_some());
    }

    /// A cancelled probe does not free the coins: until the replay is back at
    /// the height the recovery was to run to, they are those of a past height.
    #[tokio::test]
    async fn builds_stay_refused_after_a_cancel_until_the_replay_catches_up() {
        use crate::wallet::managed_wallet_info::coin_selection::SelectionStrategy;
        use crate::wallet::managed_wallet_info::fee::FeeRate;
        use crate::wallet::managed_wallet_info::transaction_builder::BuilderError;

        let mut fx = fixture();
        fx.managed.cancel_coinjoin_recovery();
        let build = |fx: &mut Fixture| {
            let to = Address::dummy(NETWORK, 9).to_string().parse().expect("address");
            fx.managed.build_unsigned_transaction(
                &fx.wallet,
                &[],
                0,
                vec![(to, 1_000)],
                FeeRate::new(1000),
                SelectionStrategy::LargestFirst,
            )
        };
        assert!(matches!(build(&mut fx), Err(BuilderError::RecoveryInProgress)));
        fx.managed.update_synced_height(1_000);
        assert!(!matches!(build(&mut fx), Err(BuilderError::RecoveryInProgress)));
        assert!(
            matches!(
                fx.managed.take_finished_coinjoin_recovery(),
                Some(CoinJoinRecoveryProgress {
                    probing: false,
                    ..
                })
            ),
            "the end of a cancelled replay is reported as such"
        );
    }

    /// An account added while the replay runs holds coins of a past height
    /// as much as the others, so it refuses to fund a build too.
    #[tokio::test]
    async fn an_account_added_during_the_replay_is_replaying_too() {
        let mut fx = fixture();
        fx.wallet
            .add_account(
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .expect("BIP44 account");
        fx.managed
            .add_managed_account(
                &fx.wallet,
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
            )
            .expect("managed BIP44 account");
        assert!(fx.managed.first_bip44_managed_account_mut().expect("account").replaying);
    }

    /// The rebuilt pool keeps the usual lookahead past the highest kept used
    /// address, so a coin just past it is watched, not left to the probe.
    #[tokio::test]
    async fn the_rebuilt_pool_watches_the_gap_past_kept_addresses() {
        let mut fx = fixture_without_recovery(NETWORK);
        let kept_index = GAP + COINJOIN_RECOVERY_PROBE_WINDOW + 500;
        {
            let account = fx.managed.first_coinjoin_managed_account_mut().expect("account");
            let pool = account
                .managed_account_type_mut()
                .address_pools_mut()
                .into_iter()
                .find(|pool| pool.pool_type == AddressPoolType::External)
                .expect("external pool");
            pool.generate_address_at_index(kept_index, &fx.key_source, true).expect("derive");
            pool.mark_index_used(kept_index);
        }
        fx.managed.begin_coinjoin_recovery(&fx.wallet, 1_000).expect("start");
        assert_eq!(pool_end(&fx, AddressPoolType::External), Some(kept_index + GAP));
    }
}
