use std::{collections::HashMap, path::PathBuf};

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
    mempool_transactions: HashMap<Txid, UnconfirmedTransaction>,
    mempool_state: Option<MempoolState>,
}

#[async_trait]
impl PersistentStorage for PersistentTransactionStorage {
    async fn load(_storage_path: impl Into<PathBuf> + Send) -> StorageResult<Self> {
        let mempool_transactions = HashMap::new();
        let mempool_state = None;

        Ok(PersistentTransactionStorage {
            mempool_transactions,
            mempool_state,
        })
    }

    async fn persist(&mut self, _storage_path: impl Into<PathBuf> + Send) -> StorageResult<()> {
        // This data is not currently being persisted
        Ok(())
    }
}

#[async_trait]
impl TransactionStorage for PersistentTransactionStorage {
    async fn store_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        self.mempool_transactions.insert(*txid, tx.clone());
        Ok(())
    }

    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()> {
        self.mempool_transactions.remove(txid);
        Ok(())
    }

    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        Ok(self.mempool_transactions.get(txid).cloned())
    }

    async fn get_all_mempool_transactions(
        &self,
    ) -> StorageResult<HashMap<Txid, UnconfirmedTransaction>> {
        Ok(self.mempool_transactions.clone())
    }
}

#[async_trait]
impl MempoolStateStorage for PersistentTransactionStorage {
    async fn store_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()> {
        self.mempool_state = Some(state.clone());
        Ok(())
    }

    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        Ok(self.mempool_state.clone())
    }
}
