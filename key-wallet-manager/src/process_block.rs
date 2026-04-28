use crate::wallet_interface::{BlockProcessingResult, MempoolTransactionResult, WalletInterface};
use crate::{WalletEvent, WalletId, WalletManager};
use async_trait::async_trait;
use core::fmt::Write as _;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Block, Transaction};
use key_wallet::managed_account::transaction_record::TransactionRecord;
use key_wallet::transaction_checking::{BlockInfo, TransactionContext};
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::broadcast;

#[async_trait]
impl<T: WalletInfoInterface + Send + Sync + 'static> WalletInterface for WalletManager<T> {
    async fn process_block_for_wallets(
        &mut self,
        block: &Block,
        height: CoreBlockHeight,
        wallets: &BTreeSet<WalletId>,
    ) -> BlockProcessingResult {
        let mut result = BlockProcessingResult::default();
        if wallets.is_empty() {
            return result;
        }
        let info = BlockInfo::new(height, block.block_hash(), block.header.time);

        let mut per_wallet_inserted: BTreeMap<WalletId, Vec<TransactionRecord>> = BTreeMap::new();
        let mut per_wallet_updated: BTreeMap<WalletId, Vec<TransactionRecord>> = BTreeMap::new();

        for tx in &block.txdata {
            let context = TransactionContext::InBlock(info);
            let check_result =
                self.check_transaction_in_wallets(tx, context, wallets, true, false).await;

            if !check_result.affected_wallets.is_empty() {
                if check_result.is_new_transaction {
                    result.new_txids.push(tx.txid());
                } else {
                    result.existing_txids.push(tx.txid());
                }
            }

            for (wallet_id, addrs) in check_result.new_addresses {
                result.new_addresses.entry(wallet_id).or_default().extend(addrs);
            }
            for (wallet_id, records) in check_result.per_wallet_new_records {
                per_wallet_inserted.entry(wallet_id).or_default().extend(records);
            }
            for (wallet_id, records) in check_result.per_wallet_updated_records {
                per_wallet_updated.entry(wallet_id).or_default().extend(records);
            }
        }

        self.finalize_block_advance(height, wallets, per_wallet_inserted, per_wallet_updated);

        result
    }

    async fn process_mempool_transaction(
        &mut self,
        tx: &Transaction,
        instant_lock: Option<InstantLock>,
    ) -> MempoolTransactionResult {
        let context = match instant_lock.as_ref() {
            Some(lock) => {
                debug_assert_eq!(lock.txid, tx.txid(), "InstantLock txid must match transaction");
                TransactionContext::InstantSend(lock.clone())
            }
            None => TransactionContext::Mempool,
        };
        let mut check_result =
            self.check_transaction_in_all_wallets(tx, context, true, false).await;

        let is_relevant = !check_result.affected_wallets.is_empty();
        let net_amount = if is_relevant {
            check_result.total_received as i64 - check_result.total_sent as i64
        } else {
            0
        };

        // Refresh cached balances for affected wallets before emitting so
        // every event carries a post-change balance.
        for wallet_id in &check_result.affected_wallets {
            if let Some(info) = self.wallet_infos.get_mut(wallet_id) {
                info.update_balance();
            }
        }

        let per_wallet_new_records = std::mem::take(&mut check_result.per_wallet_new_records);
        let per_wallet_updated_records =
            std::mem::take(&mut check_result.per_wallet_updated_records);

        for (wallet_id, records) in per_wallet_new_records {
            let Some(info) = self.wallet_infos.get(&wallet_id) else {
                continue;
            };
            let balance = info.balance();
            for record in records {
                let event = WalletEvent::TransactionDetected {
                    wallet_id,
                    record: Box::new(record),
                    balance,
                };
                let _ = self.event_sender.send(event);
            }
        }

        if let Some(lock) = instant_lock {
            for (wallet_id, records) in per_wallet_updated_records {
                if records.is_empty() {
                    continue;
                }
                let Some(info) = self.wallet_infos.get(&wallet_id) else {
                    continue;
                };
                let balance = info.balance();
                for record in records {
                    let event = WalletEvent::TransactionInstantLocked {
                        wallet_id,
                        txid: record.txid,
                        instant_lock: lock.clone(),
                        balance,
                    };
                    let _ = self.event_sender.send(event);
                }
            }
        }

        let new_addresses: Vec<Address> = check_result.all_new_addresses().cloned().collect();
        MempoolTransactionResult {
            is_relevant,
            net_amount,
            is_outgoing: net_amount < 0,
            addresses: check_result.involved_addresses,
            new_addresses,
        }
    }

    fn monitored_addresses(&self) -> Vec<Address> {
        self.monitored_addresses()
    }

    fn monitored_addresses_for(&self, wallet_id: &WalletId) -> Vec<Address> {
        self.wallet_infos.get(wallet_id).map(|info| info.monitored_addresses()).unwrap_or_default()
    }

    fn watched_outpoints(&self) -> Vec<dashcore::OutPoint> {
        self.watched_outpoints()
    }

    fn monitor_revision(&self) -> u64 {
        self.monitor_revision()
    }

    async fn earliest_required_height(&self) -> CoreBlockHeight {
        self.wallet_infos.values().map(|info| info.birth_height()).min().unwrap_or(0)
    }

    fn last_processed_height(&self) -> CoreBlockHeight {
        self.wallet_infos.values().map(|info| info.last_processed_height()).max().unwrap_or(0)
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.wallet_infos.values().map(|info| info.synced_height()).min().unwrap_or(0)
    }

    fn wallets_behind(&self, height: CoreBlockHeight) -> BTreeSet<WalletId> {
        self.wallet_infos
            .iter()
            .filter_map(|(id, info)| {
                if info.synced_height() < height {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }

    fn wallet_synced_height(&self, wallet_id: &WalletId) -> CoreBlockHeight {
        self.wallet_infos.get(wallet_id).map(|info| info.synced_height()).unwrap_or(0)
    }

    fn update_wallet_synced_height(&mut self, wallet_id: &WalletId, height: CoreBlockHeight) {
        if let Some(info) = self.wallet_infos.get_mut(wallet_id) {
            if height > info.synced_height() {
                info.update_synced_height(height);
                let _ = self.event_sender.send(WalletEvent::SyncHeightAdvanced {
                    wallet_id: *wallet_id,
                    height,
                });
            }
        }
    }

    fn update_wallet_last_processed_height(
        &mut self,
        wallet_id: &WalletId,
        height: CoreBlockHeight,
    ) {
        let wallets = BTreeSet::from([*wallet_id]);
        self.finalize_block_advance(height, &wallets, BTreeMap::new(), BTreeMap::new());
    }

    fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.event_sender.subscribe()
    }

    fn process_instant_send_lock(&mut self, instant_lock: InstantLock) {
        let txid = instant_lock.txid;

        let mut affected_wallets = Vec::new();
        for (wallet_id, info) in self.wallet_infos.iter_mut() {
            if info.mark_instant_send_utxos(&txid, &instant_lock) {
                info.update_balance();
                affected_wallets.push(*wallet_id);
            }
        }

        if affected_wallets.is_empty() {
            return;
        }

        for wallet_id in affected_wallets {
            let Some(info) = self.wallet_infos.get(&wallet_id) else {
                continue;
            };
            let _ = self.event_sender().send(WalletEvent::TransactionInstantLocked {
                wallet_id,
                txid,
                instant_lock: instant_lock.clone(),
                balance: info.balance(),
            });
        }
    }

    async fn describe(&self) -> String {
        let wallet_count = self.wallet_infos.len();
        if wallet_count == 0 {
            return format!("WalletManager: 0 wallets (network {})", self.network);
        }

        let mut details = Vec::with_capacity(wallet_count);
        for (wallet_id, info) in &self.wallet_infos {
            let name = info.name().unwrap_or("unnamed");

            let mut wallet_id_hex = String::with_capacity(wallet_id.len() * 2);
            for byte in wallet_id {
                let _ = write!(&mut wallet_id_hex, "{:02x}", byte);
            }

            let script_count = info.monitored_addresses().len();
            let summary = format!("{} scripts", script_count);

            details.push(format!("{} ({}): {}", name, wallet_id_hex, summary));
        }

        format!(
            "WalletManager: {} wallet(s) on {}\n{}",
            wallet_count,
            self.network,
            details.join("\n")
        )
    }
}

impl<T: WalletInfoInterface + Send + Sync + 'static> WalletManager<T> {
    /// For each wallet in `wallets`: advance `last_processed_height` to
    /// `height` (monotonically — never backwards), refresh the cached balance,
    /// collect matured-coinbase records over the window `(prior, height]`, and
    /// emit a `BlockProcessed` event whose balance reflects the post-advance
    /// state. A wallet whose `last_processed_height` is already at or above
    /// `height` keeps its height but still gets a balance refresh, so rescan
    /// passes that hit blocks below the wallet's checkpoint surface UTXO
    /// changes without dragging the height backwards.
    fn finalize_block_advance(
        &mut self,
        height: CoreBlockHeight,
        wallets: &BTreeSet<WalletId>,
        mut per_wallet_inserted: BTreeMap<WalletId, Vec<TransactionRecord>>,
        mut per_wallet_updated: BTreeMap<WalletId, Vec<TransactionRecord>>,
    ) {
        if wallets.is_empty() {
            return;
        }

        let snapshot = self.snapshot_balances();
        let prior_heights: BTreeMap<WalletId, CoreBlockHeight> = wallets
            .iter()
            .filter_map(|id| {
                self.wallet_infos.get(id).map(|info| (*id, info.last_processed_height()))
            })
            .collect();

        // Collect matured coinbase records before advancing the height so the
        // (old, new] window is well-defined per wallet. Wallets whose height
        // is already at or past `height` contribute no matured records on this
        // pass (their matured window is empty).
        let mut per_wallet_matured: BTreeMap<WalletId, Vec<TransactionRecord>> = BTreeMap::new();
        for wallet_id in wallets {
            let Some(info) = self.wallet_infos.get(wallet_id) else {
                continue;
            };
            let old_height = prior_heights.get(wallet_id).copied().unwrap_or(0);
            if height > old_height {
                let matured = info.matured_coinbase_records(old_height, height);
                if !matured.is_empty() {
                    per_wallet_matured.insert(*wallet_id, matured);
                }
            }
        }

        // Advance heights and refresh balances. Event emission happens below
        // so each wallet's event carries the post-advance balance.
        for wallet_id in wallets {
            if let Some(info) = self.wallet_infos.get_mut(wallet_id) {
                if height > info.last_processed_height() {
                    info.update_last_processed_height(height);
                } else {
                    info.update_balance();
                }
            }
        }

        for wallet_id in wallets {
            let Some(info) = self.wallet_infos.get(wallet_id) else {
                continue;
            };
            let new_balance = info.balance();
            let inserted = per_wallet_inserted.remove(wallet_id).unwrap_or_default();
            let updated = per_wallet_updated.remove(wallet_id).unwrap_or_default();
            let matured = per_wallet_matured.remove(wallet_id).unwrap_or_default();
            let balance_changed = snapshot.get(wallet_id).copied() != Some(new_balance);

            if !inserted.is_empty() || !updated.is_empty() || !matured.is_empty() || balance_changed
            {
                let event = WalletEvent::BlockProcessed {
                    wallet_id: *wallet_id,
                    height,
                    inserted,
                    updated,
                    matured,
                    balance: new_balance,
                };
                let _ = self.event_sender.send(event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;
    use dashcore::block::{Header, Version};
    use dashcore::hashes::Hash;
    use dashcore::pow::CompactTarget;
    use dashcore::{
        BlockHash, Network, OutPoint, ScriptBuf, TxIn, TxMerkleNode, TxOut, Txid, Witness,
    };
    use key_wallet::account::StandardAccountType;
    use key_wallet::mnemonic::Language;
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;
    use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet::{AccountType, Mnemonic};

    fn make_block(txdata: Vec<Transaction>) -> Block {
        Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time: 1000,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata,
        }
    }

    #[tokio::test]
    async fn test_last_processed_height() {
        let mut manager: WalletManager<ManagedWalletInfo> = WalletManager::new(Network::Testnet);
        assert_eq!(manager.last_processed_height(), 0);
        let unknown: WalletId = [0xff; 32];
        manager.update_wallet_last_processed_height(&unknown, 1000);
        assert_eq!(manager.last_processed_height(), 0);
    }

    #[tokio::test]
    async fn test_process_mempool_transaction_emits_event() {
        let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();
        let mut rx = manager.subscribe_events();

        // Relevant tx should emit TransactionDetected carrying the balance
        let tx = create_tx_paying_to(&addr, 0xaa);
        manager.process_mempool_transaction(&tx, None).await;

        let mut found = false;
        while let Ok(event) = rx.try_recv() {
            if let WalletEvent::TransactionDetected {
                balance,
                record,
                ..
            } = event
            {
                assert_eq!(record.txid, tx.txid(), "event should carry the mempool tx");
                assert!(balance.unconfirmed() > 0, "unconfirmed balance should increase");
                found = true;
                break;
            }
        }
        assert!(found, "should emit TransactionDetected for mempool transaction");

        // Irrelevant tx should not emit any events
        let unrelated_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xbb; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: 100_000,
                script_pubkey: ScriptBuf::new_p2pkh(&dashcore::PubkeyHash::from_byte_array(
                    [0xff; 20],
                )),
            }],
            special_transaction_payload: None,
        };
        manager.process_mempool_transaction(&unrelated_tx, None).await;
        assert!(rx.try_recv().is_err(), "should not emit events for irrelevant transaction");
    }

    #[tokio::test]
    async fn test_process_block_emits_block_processed() {
        let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
        let tx = create_tx_paying_to(&addr, 0xcc);
        let block = make_block(vec![tx.clone()]);

        let mut rx = manager.subscribe_events();
        let wallets = BTreeSet::from([wallet_id]);
        manager.process_block_for_wallets(&block, 100, &wallets).await;

        let mut found = false;
        while let Ok(event) = rx.try_recv() {
            if let WalletEvent::BlockProcessed {
                height,
                inserted,
                balance,
                ..
            } = event
            {
                assert_eq!(height, 100);
                assert!(balance.confirmed() > 0, "confirmed balance should increase after block");
                assert_eq!(inserted.len(), 1);
                assert_eq!(inserted[0].txid, tx.txid());
                found = true;
                break;
            }
        }
        assert!(found, "should emit BlockProcessed for block processing");
    }

    #[tokio::test]
    async fn test_update_wallet_synced_height_emits_sync_height_advanced() {
        let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
        let mut rx = manager.subscribe_events();

        manager.update_wallet_synced_height(&wallet_id, 500);

        let mut found = false;
        while let Ok(event) = rx.try_recv() {
            if let WalletEvent::SyncHeightAdvanced {
                wallet_id: evt_wallet_id,
                height,
            } = event
            {
                assert_eq!(evt_wallet_id, wallet_id);
                assert_eq!(height, 500);
                found = true;
            }
        }
        assert!(found, "should emit SyncHeightAdvanced on update_wallet_synced_height");
    }

    #[tokio::test]
    async fn test_process_block_for_wallets_only_touches_listed() {
        let (mut manager, wallet_id1, _) = setup_manager_with_wallet();
        let mnemonic2 = Mnemonic::generate(12, Language::English).unwrap();
        let wallet_id2 = manager
            .create_wallet_from_mnemonic(
                &mnemonic2.to_string(),
                "",
                0,
                WalletAccountCreationOptions::Default,
            )
            .unwrap();

        let block = make_block(vec![]);

        let only_w1 = BTreeSet::from([wallet_id1]);
        manager.process_block_for_wallets(&block, 200, &only_w1).await;
        assert_eq!(manager.get_wallet_info(&wallet_id1).unwrap().last_processed_height(), 200);
        assert_eq!(manager.get_wallet_info(&wallet_id2).unwrap().last_processed_height(), 0);

        let only_w2 = BTreeSet::from([wallet_id2]);
        manager.process_block_for_wallets(&block, 300, &only_w2).await;
        assert_eq!(manager.get_wallet_info(&wallet_id1).unwrap().last_processed_height(), 200);
        assert_eq!(manager.get_wallet_info(&wallet_id2).unwrap().last_processed_height(), 300);

        // Empty wallet set is a no-op even though the height is past both wallets.
        let none = BTreeSet::new();
        manager.process_block_for_wallets(&block, 1000, &none).await;
        assert_eq!(manager.get_wallet_info(&wallet_id1).unwrap().last_processed_height(), 200);
        assert_eq!(manager.get_wallet_info(&wallet_id2).unwrap().last_processed_height(), 300);
    }

    #[tokio::test]
    async fn test_mempool_transaction_result_contains_wallet_effect_data() {
        let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();
        let tx = create_tx_paying_to(&addr, 0xaa);

        let result = manager.process_mempool_transaction(&tx, None).await;

        assert!(result.is_relevant);
        assert_eq!(result.net_amount, TX_AMOUNT as i64);
        assert!(!result.is_outgoing);
        assert!(!result.addresses.is_empty());
    }

    #[tokio::test]
    async fn test_check_transaction_populates_totals() {
        let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();

        let tx = create_tx_paying_to(&addr, 0xf0);
        let result = manager
            .check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, true, true)
            .await;

        assert!(!result.affected_wallets.is_empty());
        assert_eq!(result.total_received, TX_AMOUNT);
        assert_eq!(result.total_sent, 0);
        assert!(
            !result.involved_addresses.is_empty(),
            "involved_addresses should contain the target address"
        );
        assert!(
            result.involved_addresses.contains(&addr),
            "involved_addresses should contain the target address"
        );
    }

    #[tokio::test]
    async fn test_monitor_revision_bumps_and_stability() {
        let mut manager: WalletManager<ManagedWalletInfo> = WalletManager::new(Network::Testnet);
        let mut expected_rev = 0u64;
        assert_eq!(manager.monitor_revision(), expected_rev);

        // create_wallet_from_mnemonic bumps
        let wallet_id = manager
            .create_wallet_from_mnemonic(
                TEST_MNEMONIC,
                "",
                0,
                WalletAccountCreationOptions::Default,
            )
            .unwrap();
        expected_rev += 1;
        assert_eq!(manager.monitor_revision(), expected_rev, "after create_wallet_from_mnemonic");

        // create_account bumps
        manager
            .create_account(
                &wallet_id,
                AccountType::Standard {
                    index: 1,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .unwrap();
        expected_rev += 1;
        assert_eq!(manager.monitor_revision(), expected_rev, "after create_account");

        // get_receive_address bumps (when address is generated)
        let result =
            manager.get_receive_address(&wallet_id, 0, AccountTypePreference::PreferBIP44, true);
        if result.is_ok() && result.unwrap().address.is_some() {
            expected_rev += 1;
            assert_eq!(manager.monitor_revision(), expected_rev, "after get_receive_address");
        }

        // get_change_address bumps (when address is generated)
        let result =
            manager.get_change_address(&wallet_id, 0, AccountTypePreference::PreferBIP44, true);
        if result.is_ok() && result.unwrap().address.is_some() {
            expected_rev += 1;
            assert_eq!(manager.monitor_revision(), expected_rev, "after get_change_address");
        }

        // `update_wallet_last_processed_height` does not bump the monitor revision.
        manager.update_wallet_last_processed_height(&wallet_id, 1000);
        assert_eq!(
            manager.monitor_revision(),
            expected_rev,
            "after update_wallet_last_processed_height"
        );

        // process_mempool_transaction bumps from UTXO changes and possibly
        // new addresses generated via gap limit maintenance
        let rev_before_mempool = manager.monitor_revision();
        let addr = manager.monitored_addresses()[0].clone();
        let tx = create_tx_paying_to(&addr, 0xd0);
        let _result = manager.process_mempool_transaction(&tx, None).await;
        assert!(
            manager.monitor_revision() > rev_before_mempool,
            "mempool tx paying to our address should bump revision (UTXO added)"
        );
        let rev_after_mempool = manager.monitor_revision();

        // process_instant_send_lock does NOT bump (no outpoint set change)
        manager.process_instant_send_lock(dummy_instant_lock(tx.txid()));
        assert_eq!(
            manager.monitor_revision(),
            rev_after_mempool,
            "after process_instant_send_lock"
        );

        // process_block_for_wallets bumps from UTXO changes and possibly new addresses
        let rev_before_block = manager.monitor_revision();
        let tx2 = create_tx_paying_to(&addr, 0xd1);
        let block = make_block(vec![tx2]);
        let block_wallets = BTreeSet::from([wallet_id]);
        let _result = manager.process_block_for_wallets(&block, 100, &block_wallets).await;
        assert!(
            manager.monitor_revision() > rev_before_block,
            "block with tx paying to our address should bump revision (UTXO added)"
        );

        // remove_wallet absorbs the wallet's account-level revision + 1
        let rev_before_remove = manager.monitor_revision();
        manager.remove_wallet(&wallet_id).unwrap();
        assert!(
            manager.monitor_revision() > rev_before_remove,
            "remove_wallet should bump revision"
        );

        // create_wallet_with_random_mnemonic bumps structural revision
        let rev_before = manager.monitor_revision();
        manager.create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default).unwrap();
        assert!(
            manager.monitor_revision() > rev_before,
            "create_wallet_with_random_mnemonic should bump revision"
        );
    }
}
