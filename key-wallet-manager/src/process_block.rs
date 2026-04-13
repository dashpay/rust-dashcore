use crate::wallet_interface::{BlockProcessingResult, MempoolTransactionResult, WalletInterface};
use crate::{WalletEvent, WalletManager};
use async_trait::async_trait;
use core::fmt::Write as _;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, Block, Transaction};
use key_wallet::transaction_checking::{BlockInfo, TransactionContext};
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use tokio::sync::broadcast;

#[async_trait]
impl<T: WalletInfoInterface + Send + Sync + 'static> WalletInterface for WalletManager<T> {
    async fn process_block(
        &mut self,
        block: &Block,
        height: CoreBlockHeight,
    ) -> BlockProcessingResult {
        let mut result = BlockProcessingResult::default();
        let info = BlockInfo::new(height, block.block_hash(), block.header.time);

        // Process each transaction using the base manager
        for tx in &block.txdata {
            let context = TransactionContext::InBlock(info);

            let check_result =
                self.check_transaction_in_all_wallets(tx, context, true, false).await;

            if !check_result.affected_wallets.is_empty() {
                if check_result.is_new_transaction {
                    result.new_txids.push(tx.txid());
                } else {
                    result.existing_txids.push(tx.txid());
                }
            }

            result.new_addresses.extend(check_result.new_addresses);
        }

        self.update_synced_height(height);

        result
    }

    async fn process_mempool_transaction(
        &mut self,
        tx: &Transaction,
        instant_lock: Option<InstantLock>,
    ) -> MempoolTransactionResult {
        let context = match instant_lock {
            Some(lock) => {
                debug_assert_eq!(lock.txid, tx.txid(), "InstantLock txid must match transaction");
                TransactionContext::InstantSend(lock)
            }
            None => TransactionContext::Mempool,
        };
        let snapshot = self.snapshot_balances();
        let check_result = self.check_transaction_in_all_wallets(tx, context, true, false).await;

        let is_relevant = !check_result.affected_wallets.is_empty();
        let net_amount = if is_relevant {
            check_result.total_received as i64 - check_result.total_sent as i64
        } else {
            0
        };

        // Refresh cached balances only for affected wallets
        for wallet_id in &check_result.affected_wallets {
            if let Some(info) = self.wallet_infos.get_mut(wallet_id) {
                info.update_balance();
            }
        }
        self.emit_balance_changes(&snapshot);

        MempoolTransactionResult {
            is_relevant,
            net_amount,
            is_outgoing: net_amount < 0,
            addresses: check_result.involved_addresses,
            new_addresses: check_result.new_addresses,
        }
    }

    fn monitored_addresses(&self) -> Vec<Address> {
        self.monitored_addresses()
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

    fn synced_height(&self) -> CoreBlockHeight {
        self.synced_height
    }

    fn update_synced_height(&mut self, height: CoreBlockHeight) {
        self.synced_height = height;

        let snapshot = self.snapshot_balances();

        for (_wallet_id, info) in self.wallet_infos.iter_mut() {
            info.update_synced_height(height);
        }

        self.emit_balance_changes(&snapshot);
    }

    fn filter_committed_height(&self) -> CoreBlockHeight {
        self.filter_committed_height
    }

    fn update_filter_committed_height(&mut self, height: CoreBlockHeight) {
        self.filter_committed_height = height;
        if height > self.synced_height {
            self.update_synced_height(height);
        }
    }

    fn subscribe_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.event_sender.subscribe()
    }

    fn process_instant_send_lock(&mut self, instant_lock: InstantLock) {
        let txid = instant_lock.txid;
        let snapshot = self.snapshot_balances();

        let mut affected_wallets = Vec::new();
        for (wallet_id, info) in self.wallet_infos.iter_mut() {
            if info.mark_instant_send_utxos(&txid, &instant_lock) {
                affected_wallets.push(*wallet_id);
            }
        }

        if affected_wallets.is_empty() {
            return;
        }

        for wallet_id in &affected_wallets {
            let event = WalletEvent::TransactionStatusChanged {
                wallet_id: *wallet_id,
                txid,
                status: TransactionContext::InstantSend(instant_lock.clone()),
            };
            let _ = self.event_sender().send(event);
        }

        self.emit_balance_changes(&snapshot);
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
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;
    use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet::AccountType;

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
    async fn test_synced_height() {
        let mut manager: WalletManager<ManagedWalletInfo> = WalletManager::new(Network::Testnet);
        // Initial state
        assert_eq!(manager.synced_height(), 0);
        // Inrease synced height
        manager.update_synced_height(1000);
        assert_eq!(manager.synced_height(), 1000);
        //Increase synced height again
        manager.update_synced_height(5000);
        assert_eq!(manager.synced_height(), 5000);
        // Decrease synced height
        manager.update_synced_height(10);
        assert_eq!(manager.synced_height(), 10);
    }

    #[tokio::test]
    async fn test_process_mempool_transaction_balance_events() {
        let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();
        let mut rx = manager.subscribe_events();

        // Relevant tx should emit BalanceUpdated
        let tx = create_tx_paying_to(&addr, 0xaa);
        manager.process_mempool_transaction(&tx, None).await;

        let mut found = false;
        while let Ok(event) = rx.try_recv() {
            if let WalletEvent::BalanceUpdated {
                unconfirmed,
                ..
            } = event
            {
                assert!(unconfirmed > 0, "unconfirmed balance should increase");
                found = true;
                break;
            }
        }
        assert!(found, "should emit BalanceUpdated for mempool transaction");

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
    async fn test_process_block_emits_balance_updated() {
        let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();
        let tx = create_tx_paying_to(&addr, 0xcc);
        let block = make_block(vec![tx]);

        let mut rx = manager.subscribe_events();
        manager.process_block(&block, 100).await;

        let mut found = false;
        while let Ok(event) = rx.try_recv() {
            if let WalletEvent::BalanceUpdated {
                confirmed,
                ..
            } = event
            {
                assert!(confirmed > 0, "confirmed balance should increase after block");
                found = true;
                break;
            }
        }
        assert!(found, "should emit BalanceUpdated for block processing");
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

        // update_synced_height does NOT bump
        manager.update_synced_height(1000);
        assert_eq!(manager.monitor_revision(), expected_rev, "after update_synced_height");

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

        // process_block bumps from UTXO changes and possibly new addresses
        let rev_before_block = manager.monitor_revision();
        let tx2 = create_tx_paying_to(&addr, 0xd1);
        let block = make_block(vec![tx2]);
        let _result = manager.process_block(&block, 100).await;
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
