//! Managed core funds account: keys-account state plus balance, UTXOs, and spent outpoints.
//!
//! Composed of an inner [`ManagedCoreKeysAccount`] (which carries the address
//! pools, transactions, network, and monitor revision) plus the funds-specific
//! bookkeeping needed for accounts that hold and spend Dash directly
//! (Standard, CoinJoin, DashPay).
//!
//! Shared address-pool / key-derivation behavior is provided by
//! [`ManagedAccountTrait`] default methods; only the funds-specific pieces
//! (balance, UTXO updates, transaction recording, the Standard-account
//! receive/change paths) live here as inherent methods.

#[cfg(feature = "bls")]
use crate::account::BLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::EdDSAAccount;
use crate::account::TransactionRecord;
use crate::managed_account::address_pool;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::managed_account::managed_core_keys_account::ManagedCoreKeysAccount;
use crate::managed_account::reservation::{ReservationSet, ReservationToken};
use crate::managed_account::transaction_record::{
    InputDetail, OutputDetail, OutputRole, TransactionDirection,
};
use crate::transaction_checking::transaction_router::TransactionType;
use crate::transaction_checking::{AccountMatch, TransactionContext};
use crate::utxo::Utxo;
use crate::wallet::balance::WalletCoreBalance;
use crate::{ExtendedPubKey, Network};
use dashcore::blockdata::transaction::OutPoint;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, ScriptBuf, Transaction, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::{BTreeSet, HashSet};

/// Managed core funds account with mutable state including balance and UTXOs.
///
/// Wraps a [`ManagedCoreKeysAccount`] (the shared address-pool / transaction
/// state) and adds the funds-specific bookkeeping used by accounts that hold
/// and spend Dash directly (Standard, CoinJoin, DashPay).
///
/// Most read/write surface comes from [`ManagedAccountTrait`] default methods
/// — which delegate to the inner keys account via the primitive accessors —
/// so this struct only carries the funds-specific inherent methods (transaction
/// recording, the Standard-account receive/change paths, etc.). The
/// funds-specific state (`balance`, `utxos`) is reachable as a public field
/// directly.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ManagedCoreFundsAccount {
    /// Shared keys-account state (address pools, transactions, network,
    /// monitor revision).
    keys: ManagedCoreKeysAccount,
    /// Account balance information
    pub balance: WalletCoreBalance,
    /// UTXO set for this account
    pub utxos: BTreeMap<OutPoint, Utxo>,
    /// Outpoints spent by recorded transactions.
    /// Rebuilt from `transactions` during deserialization.
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    spent_outpoints: HashSet<OutPoint>,
    /// Outpoints reserved by in-flight transaction builds so concurrent builds
    /// do not select the same UTXO before the first build's transaction is
    /// processed. Empty after a restart, where chain and mempool sync
    /// re-establish which coins are spent.
    #[cfg_attr(feature = "serde", serde(skip))]
    reservations: ReservationSet,
}

/// What [`ManagedCoreFundsAccount::apply_abandon`] removed from one account.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AbandonRemoval {
    /// UTXOs the abandoned transactions had contributed.
    pub utxos: usize,
    /// Transaction records actually dropped — a txid the account never held
    /// removes nothing.
    pub records: usize,
}

impl ManagedCoreFundsAccount {
    /// Create a new managed funds account
    pub fn new(managed_account_type: ManagedAccountType, network: Network) -> Self {
        Self {
            keys: ManagedCoreKeysAccount::new(managed_account_type, network),
            balance: WalletCoreBalance::default(),
            utxos: BTreeMap::new(),
            spent_outpoints: HashSet::new(),
            reservations: ReservationSet::default(),
        }
    }

    /// Create a `ManagedCoreFundsAccount` from an [`Account`](super::super::Account).
    pub fn from_account(account: &super::super::Account) -> Self {
        Self::wrap(ManagedCoreKeysAccount::from_account(account))
    }

    /// Create a `ManagedCoreFundsAccount` from a [`BLSAccount`].
    #[cfg(feature = "bls")]
    pub fn from_bls_account(account: &BLSAccount) -> Self {
        Self::wrap(ManagedCoreKeysAccount::from_bls_account(account))
    }

    /// Create a `ManagedCoreFundsAccount` from an [`EdDSAAccount`].
    #[cfg(feature = "eddsa")]
    pub fn from_eddsa_account(account: &EdDSAAccount) -> Self {
        Self::wrap(ManagedCoreKeysAccount::from_eddsa_account(account))
    }

    fn wrap(keys: ManagedCoreKeysAccount) -> Self {
        Self {
            keys,
            balance: WalletCoreBalance::default(),
            utxos: BTreeMap::new(),
            spent_outpoints: HashSet::new(),
            reservations: ReservationSet::default(),
        }
    }

    /// Reservation set tracking outpoints chosen by in-flight transaction
    /// builds, consulted by coin selection so concurrent builds do not pick the
    /// same UTXO.
    ///
    /// The reservation is only effective when each build runs `set_funding`
    /// through `assemble_unsigned` under a single uninterrupted hold of the
    /// wallet lock. If two builds interleave between observing the UTXO set and
    /// reserving their inputs, both can see the same UTXO as free and select it.
    pub(crate) fn reservations(&self) -> &ReservationSet {
        &self.reservations
    }

    /// Release the reservations held for `tx`'s inputs. Call this when a built
    /// transaction will not be broadcast, e.g. the user cancelled, so its inputs
    /// become selectable again immediately instead of waiting out the TTL
    /// backstop. Broadcast transactions release on their own once the spend is
    /// processed back into the wallet, so this is only for abandoned builds.
    pub fn release_reservation(&self, tx: &Transaction) {
        self.reservations.release(tx.input.iter().map(|input| &input.previous_output));
    }

    /// Owner-guarded release of `tx`'s input reservations: releases an input
    /// only if it is *still owned by* `token`, the [`ReservationToken`] returned
    /// when this build reserved its inputs (from
    /// [`build_unsigned_reserved`]/[`build_signed_reserved`]).
    ///
    /// This is the release a caller must use when it abandons a transaction
    /// *after having `.await`ed something* between reserving and releasing —
    /// above all the platform broadcast path — never the unconditional
    /// [`Self::release_reservation`]. See `ReservationSet::release_if_owner` for
    /// the release/re-reserve race this closes and why the owner check must live
    /// inside key-wallet (`dashpay/platform#4185`).
    ///
    /// [`build_unsigned_reserved`]: crate::wallet::managed_wallet_info::transaction_builder::TransactionBuilder::build_unsigned_reserved
    /// [`build_signed_reserved`]: crate::wallet::managed_wallet_info::transaction_builder::TransactionBuilder::build_signed_reserved
    pub fn release_reservation_if_owner(&self, tx: &Transaction, token: ReservationToken) {
        let outpoints: Vec<OutPoint> = tx.input.iter().map(|input| input.previous_output).collect();
        self.reservations.release_if_owner(&outpoints, token);
    }

    /// Get a reference to the inner keys-account state.
    pub fn keys(&self) -> &ManagedCoreKeysAccount {
        &self.keys
    }

    /// Get a mutable reference to the inner keys-account state.
    pub fn keys_mut(&mut self) -> &mut ManagedCoreKeysAccount {
        &mut self.keys
    }

    /// Check if an outpoint was spent by a previously recorded transaction.
    fn is_outpoint_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_outpoints.contains(outpoint)
    }

    /// Collect the outpoints among `tx`'s inputs that this account holds as a
    /// final UTXO — confirmed, InstantSend-locked, or trusted.
    ///
    /// Used at the wallet level to assemble the cross-account parent view that
    /// [`Self::record_transaction`] needs: one account cannot tell whether a
    /// pooled transaction's other inputs are ours, but the wallet can ask every
    /// account and union the answers.
    pub(crate) fn collect_final_parents(&self, tx: &Transaction, into: &mut BTreeSet<OutPoint>) {
        for input in &tx.input {
            if self.utxos.get(&input.previous_output).is_some_and(|parent| {
                parent.is_confirmed || parent.is_instantlocked || parent.is_trusted
            }) {
                into.insert(input.previous_output);
            }
        }
    }

    /// Cached scriptPubKeys for every address that could still receive or hold
    /// funds under a single-use address discipline: addresses not yet used
    /// (the gap-limit lookahead, including reserved ones) plus used addresses
    /// that still hold at least one unspent output.
    ///
    /// A used address whose outputs are all spent is omitted. That is only
    /// sound for account types whose addresses are single-use by protocol
    /// (CoinJoin — reuse would link mixing rounds), where nothing ever pays a
    /// spent-and-emptied address again; callers must not apply this to
    /// account types where address reuse is merely discouraged.
    pub fn unspent_or_unused_script_pubkeys(&self) -> Vec<ScriptBuf> {
        let funded: HashSet<&ScriptBuf> =
            self.utxos.values().map(|utxo| &utxo.txout.script_pubkey).collect();
        self.managed_account_type()
            .address_pools()
            .iter()
            .flat_map(|pool| pool.addresses.values())
            .filter(|info| !info.is_used() || funded.contains(&info.script_pubkey))
            .map(|info| info.script_pubkey.clone())
            .collect()
    }

    /// Add new UTXOs for received outputs, remove spent ones.
    ///
    /// Skips any output whose outpoint is already in `observed_spent` — it is
    /// spent on-chain (dashpay/rust-dashcore#649), so the record stays consistent.
    ///
    /// `external_final_parents` carries the wallet-level view of the inputs:
    /// outpoints that a *sibling* account of the same wallet holds as final.
    /// See [`Self::record_transaction`] for why a per-account view is not
    /// enough. An empty set degrades this to the account-local check.
    fn update_utxos(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        observed_spent: &BTreeMap<OutPoint, CoreBlockHeight>,
        external_final_parents: &BTreeSet<OutPoint>,
    ) {
        // Update UTXOs only for spendable account types
        match self.keys.managed_account_type() {
            ManagedAccountType::Standard {
                ..
            }
            | ManagedAccountType::CoinJoin {
                ..
            }
            | ManagedAccountType::DashpayReceivingFunds {
                ..
            }
            | ManagedAccountType::DashpayExternalAccount {
                ..
            } => {
                let involved_addrs: BTreeSet<_> = account_match
                    .account_type_match
                    .all_involved_addresses()
                    .iter()
                    .map(|info| info.address.clone())
                    .collect();
                let change_addrs: BTreeSet<_> = account_match
                    .account_type_match
                    .involved_change_addresses()
                    .iter()
                    .map(|info| info.address.clone())
                    .collect();

                // Detect a trusted self-send, mirroring Bitcoin Core's
                // `CWalletTx::IsTrusted`: every input must spend one of our own
                // UTXOs that is itself final (confirmed, InstantSend-locked, or
                // trusted). Parent trust already carries the recursion, so one
                // level of lookup is transitive over the whole ancestry. The
                // spent parents are still present in `self.utxos` here because
                // they are only removed after the insert loop below. An unknown
                // or non-final parent denies trust, so funds that the network
                // may still drop never surface as confirmed.
                //
                // "Ours" is a wallet-level question, not an account-level one:
                // pooled funding (asset locks draw from BIP44 + BIP32 + the
                // DashPay contact-receiving accounts) routinely puts inputs
                // from a sibling account into a transaction whose change lands
                // here. Consulting only `self.utxos` would deny trust to our
                // own transfer and file its change under `unconfirmed`, so the
                // caller's wallet-wide view fills in the parents this account
                // cannot see.
                let all_inputs_final_and_ours = tx.input.iter().all(|input| {
                    self.utxos.get(&input.previous_output).is_some_and(|parent| {
                        parent.is_confirmed || parent.is_instantlocked || parent.is_trusted
                    }) || external_final_parents.contains(&input.previous_output)
                });

                let txid = tx.txid();
                let mut utxos_changed = false;

                // A transaction whose input a *block* already spent can never
                // confirm — unless this arrival is that block delivery itself.
                // The conflict sweep below only fires when the arriving
                // transaction is final, so without this the reverse order
                // (winner confirms, loser arrives afterwards as mempool)
                // credits the loser's outputs with nothing left to remove
                // them, and `is_spendable` would hand them to coin selection.
                let doomed_by_a_settled_spend = !context.confirmed()
                    && !matches!(context, TransactionContext::InstantSend(_))
                    && tx
                        .input
                        .iter()
                        .any(|input| observed_spent.contains_key(&input.previous_output));
                if doomed_by_a_settled_spend {
                    // Deliberately before any mutation: the record built by
                    // the caller stands, so history still shows the attempt,
                    // but nothing it created enters the UTXO set.
                    tracing::info!(
                        %txid,
                        "Not crediting a transaction whose input a block already spent"
                    );
                    return;
                }

                let network = self.keys.network();

                // Insert UTXOs for outputs paying to our addresses
                for (vout, output) in tx.output.iter().enumerate() {
                    if let Ok(addr) = Address::from_script(&output.script_pubkey, network) {
                        if involved_addrs.contains(&addr) {
                            let outpoint = OutPoint {
                                txid,
                                vout: vout as u32,
                            };

                            // Check if this outpoint was already spent by a transaction we've seen.
                            // This handles out-of-order block processing during rescan where a
                            // spending transaction at a higher height may be processed before
                            // the transaction that created the UTXO.
                            // TODO: This is mostly needed for wallet rescan from storage with the
                            //       there is a timing issue with event processing which might lead to
                            //       invalid UTXO set / balances. There might be a way around it.
                            if self.is_outpoint_spent(&outpoint) {
                                tracing::debug!(
                                    outpoint = %outpoint,
                                    "Skipping UTXO already spent by previously processed transaction"
                                );
                                continue;
                            }

                            // #649 spend-first ordering: the spend was observed in an
                            // earlier-processed block, so this output is genuinely spent
                            // on-chain even though this account has never seen it before —
                            // never insert it, so the record built below is born correct.
                            if observed_spent.contains_key(&outpoint) {
                                tracing::debug!(
                                    outpoint = %outpoint,
                                    "Skipping UTXO already observed spent in an earlier-processed block (#649)"
                                );
                                continue;
                            }

                            // Flag outputs from a "trusted" mempool transaction we created —
                            // one whose inputs all spend our own final UTXOs and which pays
                            // this output back to one of our internal (change) addresses.
                            // Such an output is just our previously-tracked funds returning,
                            // so `update_balance` credits it to the confirmed bucket even
                            // before the parent transaction settles.
                            let is_trusted_output =
                                all_inputs_final_and_ours && change_addrs.contains(&addr);
                            let txout = dashcore::TxOut {
                                value: output.value,
                                script_pubkey: output.script_pubkey.clone(),
                            };
                            let block_height = context.block_info().map_or(0, |info| info.height);
                            let mut utxo =
                                Utxo::new(outpoint, txout, addr, block_height, tx.is_coin_base());
                            utxo.is_confirmed = context.confirmed();
                            utxo.is_instantlocked =
                                matches!(context, TransactionContext::InstantSend(_));
                            utxo.is_trusted = is_trusted_output;
                            // Reprocessing (e.g. mempool→block) rebuilds this UTXO from
                            // scratch, so carry forward flags that must not regress. An
                            // InstantSend lock is permanent for a txid (DIP-0010) and
                            // trust only ever settles, so both latch monotonically. A
                            // coin reservation is orthogonal to chain context and is kept
                            // as-is. `is_confirmed` stays freshly derived so a reorg can
                            // still downgrade it.
                            if let Some(prior) = self.utxos.get(&outpoint) {
                                utxo.is_instantlocked |= prior.is_instantlocked;
                                utxo.is_trusted |= prior.is_trusted;
                                utxo.is_locked = prior.is_locked;
                            }
                            self.utxos.insert(outpoint, utxo);
                            utxos_changed = true;
                        }
                    }
                }

                // Remove UTXOs spent by this transaction and track spent outpoints.
                // Processing the spend also hands the inputs off from the
                // ephemeral build reservation to the durable spent set, so the
                // reservation taken when this transaction was built is released.
                self.reservations.release(tx.input.iter().map(|input| &input.previous_output));
                for input in &tx.input {
                    self.spent_outpoints.insert(input.previous_output);

                    if self.utxos.remove(&input.previous_output).is_some() {
                        tracing::debug!(
                            outpoint = %input.previous_output,
                            txid = %tx.txid(),
                            "Removed spent UTXO"
                        );
                        utxos_changed = true;
                    }
                }

                utxos_changed |= self.drop_conflicted_transactions(tx, &context);

                if utxos_changed {
                    self.keys.bump_monitor_revision();
                }
            }
            _ => {}
        }
    }

    /// Drop the spent-marks that `freed` contributed, keeping every mark a
    /// surviving record still claims.
    ///
    /// Deliberately *not* a wholesale rebuild from the live records. Under the
    /// default `keep-finalized-transactions = off` a chainlocked spend's
    /// record is reduced to its txid, so its inputs survive only as marks
    /// already in this set — reassigning from the record map would silently
    /// drop them and let a later backfill re-credit coins that are spent on
    /// chain. Only outpoints the removed records actually contributed are
    /// considered, and a removed record's input stays marked when a survivor
    /// spends it too (a loser spending A+B against a winner spending only A
    /// must leave A marked and free B).
    fn release_spent_marks(&mut self, freed: &HashSet<OutPoint>) {
        if freed.is_empty() {
            return;
        }
        let still_spent = rebuild_spent_outpoints(&self.keys);
        self.spent_outpoints
            .retain(|outpoint| !freed.contains(outpoint) || still_spent.contains(outpoint));
    }

    /// Remove every trace of `abandoned` from this account.
    ///
    /// Drops the outputs those transactions contributed and their records, and
    /// releases the outpoints they spent from `spent_outpoints` so the coins
    /// become eligible for rediscovery.
    ///
    /// The released parents are deliberately **not** re-inserted into `utxos`.
    /// `update_utxos` discards the `Utxo` when it removes a spent parent, and
    /// `InputDetail` keeps only index/value/address, so the flags that decide
    /// which balance bucket a restored coin belongs in are not retained
    /// anywhere. Inventing them would be a guess. What these coins genuinely
    /// are is unspent on chain — the abandoned transaction never reached the
    /// network — so the correct source of truth is a rescan, which releasing
    /// them from `spent_outpoints` now permits.
    ///
    /// Reservations are deliberately left alone. A recorded transaction has
    /// already handed its inputs from the ephemeral set to `spent_outpoints`
    /// (see `update_utxos`), so there is nothing of this build's left to
    /// release — while an unconditional release here could free a reservation
    /// a *newer* build has since taken over the same outpoints, which
    /// `ReservationSet::release` documents as forbidden for exactly this
    /// caller shape.
    ///
    /// Returns what was actually removed.
    pub(crate) fn apply_abandon(&mut self, abandoned: &BTreeSet<Txid>) -> AbandonRemoval {
        let doomed: Vec<OutPoint> = self
            .utxos
            .keys()
            .filter(|outpoint| abandoned.contains(&outpoint.txid))
            .copied()
            .collect();
        let utxos = doomed.len();
        for outpoint in doomed {
            self.utxos.remove(&outpoint);
        }

        let mut records = 0;
        let mut freed: HashSet<OutPoint> = HashSet::new();
        for txid in abandoned {
            if let Some(record) = self.keys.transactions_mut().remove(txid) {
                records += 1;
                freed.extend(record.transaction.input.iter().map(|input| input.previous_output));
            }
        }
        if records > 0 {
            self.release_spent_marks(&freed);
        }

        if utxos > 0 {
            self.keys.bump_monitor_revision();
        }
        AbandonRemoval {
            utxos,
            records,
        }
    }

    /// Drop the outputs of any recorded unconfirmed transaction that `tx`
    /// provably beat to one of its inputs.
    ///
    /// When `tx` arrives with a final context — in a block, or InstantSend
    /// locked — every input it spends is settled under Dash consensus. Any
    /// *other* transaction we recorded that spends the same outpoint can
    /// therefore never confirm, and the UTXOs it contributed (its change) are
    /// money that does not exist. Nothing else removes them: the loser is not
    /// in a block, so no block processing revisits it, and mempool expiry in
    /// dash-spv only drops its own tracking without telling the wallet. Left
    /// alone they are counted permanently — and as *confirmed*, not merely
    /// unconfirmed, whenever the trusted-self-send rule applies to them,
    /// which also makes them selectable by coin selection.
    ///
    /// This is deliberately narrow. It fires only on proof — a conflicting
    /// spend that is itself final — never on a timeout: the p2p network has no
    /// negative signal (modern Dash Core removed BIP61 `reject`), so a
    /// transaction that merely went quiet may still be alive in a miner's
    /// mempool, and un-applying it would re-expose its inputs to coin
    /// selection and invite a double-spend.
    ///
    /// Only the loser's *outputs* are reverted. Where the winner spends every
    /// input the loser did — the ordinary resend — that is complete: those
    /// inputs are correctly accounted for by `tx`, the transaction that
    /// actually spent them.
    ///
    /// A loser may also spend inputs the winner does not. Those coins are
    /// freed from `spent_outpoints` below, but they cannot be re-credited
    /// here: `update_utxos` discarded their `Utxo` — and its flags — when the
    /// loser was recorded, and `InputDetail` keeps only index/value/address.
    /// The release is what makes them recoverable: a rescan re-delivering the
    /// funding transaction inserts them again. Until that rescan they are
    /// absent from the balance.
    ///
    /// That recovery has a boundary worth knowing. A funding transaction that
    /// was chainlock-finalized keeps only its txid, so `has_transaction` stays
    /// true and re-delivery is not a new sighting — `confirm_transaction`
    /// returns before `update_utxos`, the only production insert site, and the
    /// coin does not come back. Recovering it needs a rescan deep enough to
    /// re-fetch the block, which is above this layer. Since Dash chainlocks
    /// within a block or two, that is the normal posture for older coins.
    ///
    /// Scope: account-local. A loser recorded here has its outputs dropped
    /// here; a loser whose change landed in a *different* account is not
    /// reached, because both the transaction records and the UTXO set are
    /// per-account. That covers the ordinary shape — a resend keeps the same
    /// funding account and so the same change account — but not every one.
    ///
    /// Returns whether any UTXO was removed.
    pub(crate) fn drop_conflicted_transactions(
        &mut self,
        tx: &Transaction,
        context: &TransactionContext,
    ) -> bool {
        if !(context.confirmed() || matches!(context, TransactionContext::InstantSend(_))) {
            return false;
        }

        let winner = tx.txid();
        let spent: BTreeSet<OutPoint> =
            tx.input.iter().map(|input| input.previous_output).collect();

        // A finalized transaction keeps only its txid, so a chainlocked record
        // can never be a loser here — and must not be, since it is settled.
        let mut losers: BTreeSet<Txid> = self
            .keys
            .transactions()
            .iter()
            .filter(|(txid, record)| {
                // Precedence, per DIP-10: a chainlock is final over
                // everything, an InstantSend lock is final against a double
                // spend, and a plain block is provisional until its own
                // chainlock lands. So an IS-locked record may only be evicted
                // by a chainlocked arrival — a plain `InBlock` winner cannot
                // overrule a lock the network already signed, and the block
                // it arrived in can still reorg away.
                let loser_is_locked = record.context.is_instant_send();
                **txid != winner
                    && !record.is_confirmed()
                    && (!loser_is_locked || context.is_chain_locked())
                    && record
                        .transaction
                        .input
                        .iter()
                        .any(|input| spent.contains(&input.previous_output))
            })
            .map(|(txid, _)| *txid)
            .collect();

        if losers.is_empty() {
            return false;
        }

        // A loser's change may already have funded further unconfirmed
        // transactions. Those can never exist either — their parent cannot —
        // so leaving their outputs credited would preserve the very
        // phantom-balance class this sweep exists to remove. Walk the
        // unconfirmed descendant closure; confirmed records are never
        // followed, since a transaction in a block spent something real.
        loop {
            let mut found = BTreeSet::new();
            for (txid, record) in self.keys.transactions() {
                if record.is_confirmed()
                    || record.context.is_instant_send()
                    || losers.contains(txid)
                    || *txid == winner
                {
                    continue;
                }
                if record
                    .transaction
                    .input
                    .iter()
                    .any(|input| losers.contains(&input.previous_output.txid))
                {
                    found.insert(*txid);
                }
            }
            let before = losers.len();
            losers.extend(found);
            if losers.len() == before {
                break;
            }
        }

        let mut changed = false;
        let mut freed: HashSet<OutPoint> = HashSet::new();
        for loser in &losers {
            let removed: Vec<OutPoint> =
                self.utxos.keys().filter(|outpoint| outpoint.txid == *loser).copied().collect();
            for outpoint in removed {
                self.utxos.remove(&outpoint);
                changed = true;
            }
            if let Some(record) = self.keys.transactions_mut().remove(loser) {
                freed.extend(record.transaction.input.iter().map(|input| input.previous_output));
            }
            tracing::info!(
                conflicted_txid = %loser,
                winning_txid = %winner,
                "Dropped a conflicted transaction: its input was spent by a final transaction"
            );
        }
        self.release_spent_marks(&freed);

        changed
    }

    /// Re-process an existing transaction with updated context (e.g.,
    /// mempool→block confirmation) and potentially new address matches
    /// from gap limit rescans.
    ///
    /// Returns `Some(record)` when the call results in a state change the
    /// caller should surface (record newly inserted or context updated).
    /// The record is cloned BEFORE any chainlock-driven pruning, so the
    /// caller can always include it in an event even when the
    /// `keep-finalized-transactions` Cargo feature is off and the record
    /// is dropped from `transactions` immediately after.
    ///
    /// Returns `None` when:
    /// - the tx is already finalized in a chainlocked block (record is
    ///   immutable; further events are redundant), or
    /// - the existing record's context already matches and confirmation
    ///   status didn't change.
    pub(crate) fn confirm_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
        observed_spent: &BTreeMap<OutPoint, CoreBlockHeight>,
        external_final_parents: &BTreeSet<OutPoint>,
    ) -> Option<TransactionRecord> {
        let txid = tx.txid();

        // Already finalized via a chainlock: the tx is immutable —
        // no record update, no UTXO refresh, no event needed.
        if self.keys.transaction_is_finalized(&txid) {
            return None;
        }

        if !self.keys.has_transaction(&txid) {
            // Genuinely new sighting — delegate to record_transaction
            // (which handles finalize-on-record itself).
            let record = self.record_transaction(
                tx,
                account_match,
                context,
                transaction_type,
                observed_spent,
                external_final_parents,
            );
            return Some(record);
        }

        let mut changed = false;
        if let Some(tx_record) = self.keys.transactions_mut().get_mut(&txid) {
            debug_assert_eq!(
                tx_record.transaction_type,
                transaction_type,
                "transaction_type changed between recordings for {}",
                tx.txid()
            );
            if tx_record.context != context {
                let was_confirmed = tx_record.context.confirmed();
                tx_record.update_context(context.clone());
                // Confirm-time upgrades within the confirmed state (e.g.
                // InBlock → InChainLockedBlock) are not signaled here.
                // Chainlock-driven promotions go through the dedicated
                // `apply_chain_lock` path which emits a single batched
                // ChainLockProcessed event.
                changed = !was_confirmed;
            }
        }

        // Capture the (possibly updated) record before any pruning so the
        // caller can still emit it in an event.
        let record_after = if changed {
            self.keys.transactions().get(&txid).cloned()
        } else {
            None
        };

        // The chainlock is the trigger for dropping the full record under
        // the default feature configuration; an IS-lock alone is *not*
        // enough — we keep the record so the surrounding block
        // confirmation can still write its height / block hash before the
        // chainlock catches up.
        #[cfg(not(feature = "keep-finalized-transactions"))]
        let drop_now = context.is_chain_locked();
        self.update_utxos(tx, account_match, context, observed_spent, external_final_parents);
        #[cfg(not(feature = "keep-finalized-transactions"))]
        if drop_now {
            self.keys.drop_finalized_transaction(&txid);
        }
        record_after
    }

    /// Record a new transaction and update UTXOs for spendable account types.
    ///
    /// `observed_spent` is the wallet-level `observed_spent_outpoints` view
    /// (dashpay/rust-dashcore#649), read-only from `check_core_transaction`.
    /// It is threaded into [`Self::update_utxos`], which skips inserting a UTXO
    /// for any output whose outpoint is already observed spent on-chain, so a
    /// coin whose spend was seen in an earlier-processed block is never
    /// (re-)tracked as spendable.
    ///
    /// `external_final_parents` is the wallet-level answer to "are these
    /// inputs ours and final" for parents this account does not hold. A
    /// transaction funded from several accounts — the normal shape for asset
    /// locks — is still our own self-send, and its change must not be filed
    /// under `unconfirmed` merely because the sibling account's UTXOs are
    /// invisible from here. Callers driving a single account directly pass an
    /// empty set and get the account-local behavior.
    pub(crate) fn record_transaction(
        &mut self,
        tx: &Transaction,
        account_match: &AccountMatch,
        context: TransactionContext,
        transaction_type: TransactionType,
        observed_spent: &BTreeMap<OutPoint, CoreBlockHeight>,
        external_final_parents: &BTreeSet<OutPoint>,
    ) -> TransactionRecord {
        let net_amount = account_match.received as i64 - account_match.sent as i64;

        let receive_addrs: HashSet<_> = account_match
            .account_type_match
            .involved_receive_addresses()
            .iter()
            .map(|info| &info.address)
            .collect();
        let change_addrs: HashSet<_> = account_match
            .account_type_match
            .involved_change_addresses()
            .iter()
            .map(|info| &info.address)
            .collect();

        // Input details must be built before `update_utxos` removes spent UTXOs
        let mut input_details = Vec::new();
        if !tx.is_coin_base() {
            for (idx, input) in tx.input.iter().enumerate() {
                if let Some(utxo) = self.utxos.get(&input.previous_output) {
                    input_details.push(InputDetail {
                        index: idx as u32,
                        value: utxo.txout.value,
                        address: utxo.address.clone(),
                    });
                }
            }
        }

        // Marks a transaction that spends our coins. `input_details` (built
        // above) and `account_match.sent` (built in `check_transaction_with_index`)
        // both derive from `self.utxos.get(&input.previous_output)` on this
        // account, with no UTXO mutation between the two lookups, so they
        // populate together; keeping both keeps this robust should the two
        // call sites ever compute over different UTXO snapshots.
        let has_inputs = !input_details.is_empty() || account_match.sent > 0;

        let network = self.keys.network();
        let resolved_outputs: Vec<Option<Address>> = tx
            .output
            .iter()
            .map(|output| Address::from_script(&output.script_pubkey, network).ok())
            .collect();

        // Build output details — annotate every output with its role
        let mut output_details = Vec::new();
        for (idx, output) in tx.output.iter().enumerate() {
            let role = match &resolved_outputs[idx] {
                Some(addr) if receive_addrs.contains(addr) => OutputRole::Received,
                Some(addr) if change_addrs.contains(addr) => OutputRole::Change,
                Some(_) if has_inputs => OutputRole::Sent,
                Some(_) => continue,
                None => {
                    if output.script_pubkey.is_provably_unspendable() {
                        OutputRole::Unspendable
                    } else if has_inputs {
                        OutputRole::Sent
                    } else {
                        continue;
                    }
                }
            };
            output_details.push(OutputDetail {
                index: idx as u32,
                role,
                address: resolved_outputs[idx].clone(),
                value: output.value,
            });
        }

        // Determine direction
        let has_sent = output_details.iter().any(|d| d.role == OutputRole::Sent);
        let has_our_outputs = output_details
            .iter()
            .any(|d| d.role == OutputRole::Received || d.role == OutputRole::Change);
        let direction = if transaction_type == TransactionType::CoinJoin {
            TransactionDirection::CoinJoin
        } else if !has_sent && has_inputs && has_our_outputs {
            TransactionDirection::Internal
        } else if has_inputs {
            TransactionDirection::Outgoing
        } else {
            TransactionDirection::Incoming
        };

        let tx_record = TransactionRecord::new(
            tx.clone(),
            self.keys.managed_account_type().to_account_type(),
            context.clone(),
            transaction_type,
            direction,
            input_details,
            output_details,
            net_amount,
        );

        let record = tx_record.clone();
        let txid = tx.txid();
        self.keys.transactions_mut().insert(txid, tx_record);

        // If the very first sighting is already chainlocked (e.g.
        // a wallet rescan from storage), drop the full record now and
        // keep only the txid in `finalized_txids`. No-op when the
        // feature is on (we want to keep the full record).
        #[cfg(not(feature = "keep-finalized-transactions"))]
        let drop_now = context.is_chain_locked();
        self.update_utxos(tx, account_match, context, observed_spent, external_final_parents);
        #[cfg(not(feature = "keep-finalized-transactions"))]
        if drop_now {
            self.keys.drop_finalized_transaction(&txid);
        }

        record
    }

    /// Mark all UTXOs belonging to a transaction as InstantSend-locked.
    /// Returns `true` if any UTXO was newly marked.
    pub(crate) fn mark_utxos_instant_send(&mut self, txid: &Txid) -> bool {
        let mut any_changed = false;
        for utxo in self.utxos.values_mut() {
            if utxo.outpoint.txid == *txid && !utxo.is_instantlocked {
                utxo.is_instantlocked = true;
                any_changed = true;
            }
        }
        any_changed
    }

    /// Return the UTXOs of this account for which
    /// [`Utxo::is_spendable`] holds at `last_processed_height`. See that method
    /// for the exact policy. Call this per-account rather than
    /// aggregating across the wallet, since spendability is
    /// account-type specific.
    pub fn spendable_utxos(&self, last_processed_height: u32) -> BTreeSet<&Utxo> {
        self.utxos.values().filter(|utxo| utxo.is_spendable(last_processed_height)).collect()
    }

    /// Promote any `InBlock` records at height `<= cl_height` to
    /// [`TransactionContext::InChainLockedBlock`] and return the
    /// promoted txids.
    ///
    /// Delegates the per-record promotion to
    /// [`ManagedCoreKeysAccount::apply_chain_lock`] (which under the
    /// default `keep-finalized-transactions=OFF` feature drops the
    /// full records and retains only txids). UTXO state and account
    /// balance are unaffected: a chainlock does not change a UTXO's
    /// spentness or maturity, only the certainty of its parent
    /// transaction.
    pub(crate) fn apply_chain_lock(&mut self, cl_height: CoreBlockHeight) -> Vec<Txid> {
        self.keys.apply_chain_lock(cl_height)
    }

    /// Update the account balance.
    ///
    /// Mature, non-locked UTXOs land in either the `confirmed` bucket
    /// (in a block, InstantSend-locked, or trusted mempool change) or
    /// the `unconfirmed` bucket (untrusted mempool only). Trusted
    /// mempool change is surfaced as confirmed because it is just our
    /// previously-tracked funds returning, see [`Utxo::is_trusted`].
    /// Both buckets are spendable per [`Utxo::is_spendable`]. The split
    /// is only for display.
    pub fn update_balance(&mut self, last_processed_height: u32) {
        let mut confirmed = 0;
        let mut unconfirmed = 0;
        let mut immature = 0;
        let mut locked = 0;
        for utxo in self.utxos.values() {
            let value = utxo.txout.value;
            if utxo.is_locked {
                locked += value;
            } else if !utxo.is_mature(last_processed_height) {
                immature += value;
            } else if utxo.is_confirmed || utxo.is_instantlocked || utxo.is_trusted {
                confirmed += value;
            } else {
                unconfirmed += value;
            }
        }
        self.balance = WalletCoreBalance::new(confirmed, unconfirmed, immature, locked);
    }

    /// Generate the next receive address using the optionally provided extended public key
    /// If no key is provided, can only return pre-generated unused addresses.
    /// Only valid for Standard accounts.
    pub fn next_receive_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addr =
                external_addresses.next_unused(&key_source, add_to_state).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate receive address",
                })?;
            self.keys.bump_monitor_revision();
            Ok(addr)
        } else {
            Err("Cannot generate receive address for non-standard account type")
        }
    }

    /// Generate the next change address using the optionally provided extended public key.
    /// Only valid for Standard accounts.
    pub fn next_change_address(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        add_to_state: bool,
    ) -> Result<Address, &'static str> {
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addr =
                internal_addresses.next_unused(&key_source, add_to_state).map_err(|e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate change address",
                })?;
            self.keys.bump_monitor_revision();
            Ok(addr)
        } else {
            Err("Cannot generate change address for non-standard account type")
        }
    }

    /// Generate and reserve the next receive address.
    ///
    /// Like [`Self::next_receive_address`] but atomically reserves the returned
    /// address so a concurrent hand-out cannot return the same one. The
    /// reservation persists until funds arrive (promoting it to used),
    /// [`Self::release_receive_reservation`] is called, or it is reclaimed by a
    /// TTL sweep. `now` is a caller-supplied timestamp (seconds) stamping the
    /// reservation. Only valid for Standard accounts.
    ///
    /// Derivation of fresh addresses on this path is unbounded, so callers are
    /// assumed trusted. See [`address_pool::AddressPool::next_unused_and_reserve`].
    pub fn next_receive_address_and_reserve(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        now: u64,
    ) -> Result<Address, &'static str> {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addr = external_addresses.next_unused_and_reserve(&key_source, now).map_err(
                |e| match e {
                    crate::error::Error::NoKeySource => {
                        "No unused addresses available and no key source provided"
                    }
                    _ => "Failed to generate receive address",
                },
            )?;
            self.keys.bump_monitor_revision();
            Ok(addr)
        } else {
            Err("Cannot generate receive address for non-standard account type")
        }
    }

    /// Release a previously reserved receive address back to the available pool.
    ///
    /// Idempotent: returns `false` if the address is unknown to the external
    /// pool or is not currently reserved. Bumps the monitor revision only when
    /// a reservation is actually cleared.
    pub fn release_receive_reservation(&mut self, address: &Address) -> bool {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            if let Some(index) = external_addresses.address_index(address) {
                if external_addresses.release_reservation(index) {
                    self.keys.bump_monitor_revision();
                    return true;
                }
            }
        }
        false
    }

    /// Reclaim receive reservations older than `ttl`, returning their addresses
    /// to the available pool.
    ///
    /// Backstop for reservations handed out but never funded and never
    /// explicitly released, which would otherwise pin gap-limit headroom
    /// forever. `now` and `ttl` are caller-supplied (seconds); the wallet keeps
    /// no clock. Returns the number of reservations reclaimed and bumps the
    /// monitor revision when that is non-zero. See
    /// [`address_pool::AddressPool::sweep_expired_reservations`].
    pub fn sweep_expired_receive_reservations(&mut self, now: u64, ttl: u64) -> usize {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            let reclaimed = external_addresses.sweep_expired_reservations(now, ttl);
            if reclaimed > 0 {
                self.keys.bump_monitor_revision();
            }
            reclaimed
        } else {
            0
        }
    }

    /// Generate multiple receive addresses at once using the optionally provided extended public key.
    /// Only valid for Standard accounts.
    pub fn next_receive_addresses(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        count: usize,
        add_to_state: bool,
    ) -> Result<Vec<Address>, String> {
        if let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addresses =
                external_addresses.next_unused_multiple(count, &key_source, add_to_state);
            if addresses.is_empty() && count > 0 {
                Err("Failed to generate any receive addresses".to_string())
            } else if addresses.len() < count
                && matches!(key_source, address_pool::KeySource::NoKeySource)
            {
                Err(format!(
                    "Could only generate {} out of {} requested addresses (no key source)",
                    addresses.len(),
                    count
                ))
            } else {
                Ok(addresses)
            }
        } else {
            Err("Cannot generate receive addresses for non-standard account type".to_string())
        }
    }

    /// Generate multiple change addresses at once using the optionally provided extended public key.
    /// Only valid for Standard accounts.
    pub fn next_change_addresses(
        &mut self,
        account_xpub: Option<&ExtendedPubKey>,
        count: usize,
        add_to_state: bool,
    ) -> Result<Vec<Address>, String> {
        if let ManagedAccountType::Standard {
            internal_addresses,
            ..
        } = self.keys.managed_account_type_mut()
        {
            let key_source = match account_xpub {
                Some(xpub) => address_pool::KeySource::Public(*xpub),
                None => address_pool::KeySource::NoKeySource,
            };

            let addresses =
                internal_addresses.next_unused_multiple(count, &key_source, add_to_state);
            if addresses.is_empty() && count > 0 {
                Err("Failed to generate any change addresses".to_string())
            } else if addresses.len() < count
                && matches!(key_source, address_pool::KeySource::NoKeySource)
            {
                Err(format!(
                    "Could only generate {} out of {} requested addresses (no key source)",
                    addresses.len(),
                    count
                ))
            } else {
                Ok(addresses)
            }
        } else {
            Err("Cannot generate change addresses for non-standard account type".to_string())
        }
    }

    /// Get the external gap limit for standard accounts
    pub fn external_gap_limit(&self) -> Option<u32> {
        match self.keys.managed_account_type() {
            ManagedAccountType::Standard {
                external_addresses,
                ..
            } => Some(external_addresses.gap_limit),
            _ => None,
        }
    }

    /// Get the internal gap limit for standard accounts
    pub fn internal_gap_limit(&self) -> Option<u32> {
        match self.keys.managed_account_type() {
            ManagedAccountType::Standard {
                internal_addresses,
                ..
            } => Some(internal_addresses.gap_limit),
            _ => None,
        }
    }
}

impl ManagedAccountTrait for ManagedCoreFundsAccount {
    fn managed_account_type(&self) -> &ManagedAccountType {
        self.keys.managed_account_type()
    }

    fn managed_account_type_mut(&mut self) -> &mut ManagedAccountType {
        self.keys.managed_account_type_mut()
    }

    fn network(&self) -> Network {
        self.keys.network()
    }

    fn transactions(&self) -> &BTreeMap<Txid, TransactionRecord> {
        self.keys.transactions()
    }

    fn transactions_mut(&mut self) -> &mut BTreeMap<Txid, TransactionRecord> {
        self.keys.transactions_mut()
    }

    fn has_transaction(&self, txid: &Txid) -> bool {
        self.keys.has_transaction(txid)
    }

    fn transaction_is_finalized(&self, txid: &Txid) -> bool {
        self.keys.transaction_is_finalized(txid)
    }

    fn monitor_revision(&self) -> u64 {
        self.keys.monitor_revision()
    }

    fn bump_monitor_revision(&mut self) {
        self.keys.bump_monitor_revision()
    }
}

/// Rebuild the account-local `spent_outpoints` set from recorded transactions.
///
/// Every input of every recorded transaction is a spend this account has seen,
/// so its `previous_output` belongs in the derived set. The field is not
/// serialized (`#[serde(skip_serializing)]`), so [`Deserialize`] and the test
/// reload simulation reconstruct it through here to stay in lockstep.
///
/// **Derives only from live records.** Under the default
/// `keep-finalized-transactions = off`, a chainlocked record is dropped to
/// just its txid, so its inputs survive only as entries already in the set —
/// which a wholesale rebuild would discard. Callers pruning a subset of
/// records must retain the rest rather than reassigning from this.
fn rebuild_spent_outpoints(keys: &ManagedCoreKeysAccount) -> HashSet<OutPoint> {
    keys.transactions()
        .values()
        .flat_map(|record| &record.transaction.input)
        .map(|input| input.previous_output)
        .collect()
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ManagedCoreFundsAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            keys: ManagedCoreKeysAccount,
            balance: WalletCoreBalance,
            utxos: BTreeMap<OutPoint, Utxo>,
        }

        let helper = Helper::deserialize(deserializer)?;

        let spent_outpoints = rebuild_spent_outpoints(&helper.keys);

        Ok(ManagedCoreFundsAccount {
            keys: helper.keys,
            balance: helper.balance,
            utxos: helper.utxos,
            spent_outpoints,
            reservations: ReservationSet::default(),
        })
    }
}
