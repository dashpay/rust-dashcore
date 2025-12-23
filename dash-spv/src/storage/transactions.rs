use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use dashcore::Txid;

use crate::{
    error::StorageResult,
    storage::PersistentStorage,
    types::{MempoolState, UnconfirmedTransaction},
};

#[async_trait]
pub trait TransactionStorage {
    async fn store_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()>;

    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()>;

    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>>;

    async fn get_all_mempool_transactions(
        &self,
    ) -> StorageResult<HashMap<Txid, UnconfirmedTransaction>>;
}

#[async_trait]
pub trait MempoolStateStorage {
    async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()>;

    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>>;
}

pub struct PersistentTransactionStorage {
    mempool_transactions: Arc<RwLock<HashMap<Txid, UnconfirmedTransaction>>>,
    mempool_state: Arc<RwLock<Option<MempoolState>>>,
}

#[async_trait]
impl PersistentStorage for PersistentTransactionStorage {
    async fn load(&self) -> StorageResult<Self> {
        let mempool_transactions = Arc::new(RwLock::new(HashMap::new()));
        let mempool_state = Arc::new(RwLock::new(None));

        Ok(PersistentTransactionStorage {
            mempool_transactions,
            mempool_state,
        })
    }

    async fn persist(&self) {
        // This data is not currently being persisted
    }
}

#[async_trait]
impl TransactionStorage for PersistentTransactionStorage {
    async fn store_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        self.mempool_transactions.write().await.insert(*txid, tx.clone());
        Ok(())
    }

    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()> {
        self.mempool_transactions.write().await.remove(txid);
        Ok(())
    }

    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        Ok(self.mempool_transactions.read().await.get(txid).cloned())
    }

    async fn get_all_mempool_transactions(
        &self,
    ) -> StorageResult<HashMap<Txid, UnconfirmedTransaction>> {
        Ok(self.mempool_transactions.read().await.clone())
    }
}

#[async_trait]
impl MempoolStateStorage for PersistentTransactionStorage {
    async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()> {
        *self.mempool_state.write().await = Some(state.clone());
        Ok(())
    }

    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        Ok(self.mempool_state.read().await.clone())
    }
}
