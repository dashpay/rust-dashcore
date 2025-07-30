//! Event-driven storage service for async-safe storage operations
//!
//! This module provides a message-passing based storage system that eliminates
//! the need for mutable references and prevents deadlocks in async contexts.

use super::types::MasternodeState;
use super::{StorageError, StorageResult};
use crate::types::{ChainState, MempoolState, UnconfirmedTransaction};
use crate::wallet::Utxo;
use dashcore::hash_types::FilterHeader;
use dashcore::{block::Header as BlockHeader, Address, BlockHash, OutPoint, Txid};
use std::ops::Range;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// Commands that can be sent to the storage service
#[derive(Debug)]
pub enum StorageCommand {
    // Header operations
    StoreHeader {
        header: BlockHeader,
        height: u32,
        response: oneshot::Sender<StorageResult<()>>,
    },
    StoreHeaders {
        headers: Vec<BlockHeader>,
        response: oneshot::Sender<StorageResult<()>>,
    },
    GetHeader {
        height: u32,
        response: oneshot::Sender<StorageResult<Option<BlockHeader>>>,
    },
    GetHeaderByHash {
        hash: BlockHash,
        response: oneshot::Sender<StorageResult<Option<BlockHeader>>>,
    },
    GetHeaderHeight {
        hash: BlockHash,
        response: oneshot::Sender<StorageResult<Option<u32>>>,
    },
    GetTipHeight {
        response: oneshot::Sender<StorageResult<Option<u32>>>,
    },
    LoadHeaders {
        range: Range<u32>,
        response: oneshot::Sender<StorageResult<Vec<BlockHeader>>>,
    },

    // Filter operations
    StoreFilterHeader {
        header: FilterHeader,
        height: u32,
        response: oneshot::Sender<StorageResult<()>>,
    },
    GetFilterHeader {
        height: u32,
        response: oneshot::Sender<StorageResult<Option<FilterHeader>>>,
    },
    GetFilterTipHeight {
        response: oneshot::Sender<StorageResult<Option<u32>>>,
    },
    StoreFilter {
        filter: Vec<u8>,
        height: u32,
        response: oneshot::Sender<StorageResult<()>>,
    },
    GetFilter {
        height: u32,
        response: oneshot::Sender<StorageResult<Option<Vec<u8>>>>,
    },

    // State operations
    SaveMasternodeState {
        state: MasternodeState,
        response: oneshot::Sender<StorageResult<()>>,
    },
    LoadMasternodeState {
        response: oneshot::Sender<StorageResult<Option<MasternodeState>>>,
    },
    StoreChainState {
        state: ChainState,
        response: oneshot::Sender<StorageResult<()>>,
    },
    LoadChainState {
        response: oneshot::Sender<StorageResult<Option<ChainState>>>,
    },

    // UTXO operations
    StoreUtxo {
        outpoint: OutPoint,
        utxo: Utxo,
        response: oneshot::Sender<StorageResult<()>>,
    },
    RemoveUtxo {
        outpoint: OutPoint,
        response: oneshot::Sender<StorageResult<()>>,
    },
    GetUtxo {
        outpoint: OutPoint,
        response: oneshot::Sender<StorageResult<Option<Utxo>>>,
    },
    GetUtxosForAddress {
        address: Address,
        response: oneshot::Sender<StorageResult<Vec<(OutPoint, Utxo)>>>,
    },
    GetAllUtxos {
        response: oneshot::Sender<StorageResult<Vec<(OutPoint, Utxo)>>>,
    },

    // Mempool operations
    SaveMempoolState {
        state: MempoolState,
        response: oneshot::Sender<StorageResult<()>>,
    },
    LoadMempoolState {
        response: oneshot::Sender<StorageResult<Option<MempoolState>>>,
    },
    AddMempoolTransaction {
        txid: Txid,
        tx: UnconfirmedTransaction,
        response: oneshot::Sender<StorageResult<()>>,
    },
    RemoveMempoolTransaction {
        txid: Txid,
        response: oneshot::Sender<StorageResult<()>>,
    },
    GetMempoolTransaction {
        txid: Txid,
        response: oneshot::Sender<StorageResult<Option<UnconfirmedTransaction>>>,
    },
    ClearMempool {
        response: oneshot::Sender<StorageResult<()>>,
    },
}

/// Backend trait that storage implementations must provide
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync + 'static {
    // Header operations
    async fn store_header(&mut self, header: &BlockHeader, height: u32) -> StorageResult<()>;
    async fn store_headers(&mut self, headers: &[BlockHeader]) -> StorageResult<()>;
    async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>>;
    async fn get_header_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<BlockHeader>>;
    async fn get_header_height(&self, hash: &BlockHash) -> StorageResult<Option<u32>>;
    async fn get_tip_height(&self) -> StorageResult<Option<u32>>;
    async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>>;

    // Filter operations
    async fn store_filter_header(
        &mut self,
        header: &FilterHeader,
        height: u32,
    ) -> StorageResult<()>;
    async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>>;
    async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>>;
    async fn store_filter(&mut self, filter: &[u8], height: u32) -> StorageResult<()>;
    async fn get_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>>;

    // State operations
    async fn save_masternode_state(&mut self, state: &MasternodeState) -> StorageResult<()>;
    async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>>;
    async fn store_chain_state(&mut self, state: &ChainState) -> StorageResult<()>;
    async fn load_chain_state(&self) -> StorageResult<Option<ChainState>>;

    // UTXO operations
    async fn store_utxo(&mut self, outpoint: &OutPoint, utxo: &Utxo) -> StorageResult<()>;
    async fn remove_utxo(&mut self, outpoint: &OutPoint) -> StorageResult<()>;
    async fn get_utxo(&self, outpoint: &OutPoint) -> StorageResult<Option<Utxo>>;
    async fn get_utxos_for_address(
        &self,
        address: &Address,
    ) -> StorageResult<Vec<(OutPoint, Utxo)>>;
    async fn get_all_utxos(&self) -> StorageResult<Vec<(OutPoint, Utxo)>>;

    // Mempool operations
    async fn save_mempool_state(&mut self, state: &MempoolState) -> StorageResult<()>;
    async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>>;
    async fn add_mempool_transaction(
        &mut self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()>;
    async fn remove_mempool_transaction(&mut self, txid: &Txid) -> StorageResult<()>;
    async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>>;
    async fn clear_mempool(&mut self) -> StorageResult<()>;
}

/// The storage service that processes commands
pub struct StorageService {
    command_rx: mpsc::Receiver<StorageCommand>,
    backend: Box<dyn StorageBackend>,
}

impl StorageService {
    /// Create a new storage service with the given backend
    pub fn new(backend: Box<dyn StorageBackend>) -> (Self, StorageClient) {
        let (command_tx, command_rx) = mpsc::channel(1000);

        let service = Self {
            command_rx,
            backend,
        };

        let client = StorageClient {
            command_tx: command_tx.clone(),
        };

        (service, client)
    }

    /// Run the storage service, processing commands until the channel is closed
    pub async fn run(mut self) {
        tracing::info!("Storage service started");

        while let Some(command) = self.command_rx.recv().await {
            tracing::debug!("StorageService: received command {:?}", command);
            self.process_command(command).await;
        }

        tracing::info!("Storage service stopped");
    }

    /// Process a single storage command
    async fn process_command(&mut self, command: StorageCommand) {
        match command {
            // Header operations
            StorageCommand::StoreHeader {
                header,
                height,
                response,
            } => {
                tracing::trace!("StorageService: processing StoreHeader for height {}", height);

                let start = std::time::Instant::now();

                let result = self.backend.store_header(&header, height).await;

                let duration = start.elapsed();
                if duration.as_millis() > 10 {
                    tracing::warn!(
                        "StorageService: slow backend store_header operation at height {} took {:?}",
                        height,
                        duration
                    );
                }

                let _send_result = response.send(result);
            }
            StorageCommand::StoreHeaders {
                headers,
                response,
            } => {
                tracing::trace!(
                    "StorageService: processing StoreHeaders for {} headers",
                    headers.len()
                );

                let start = std::time::Instant::now();

                let result = self.backend.store_headers(&headers).await;

                let duration = start.elapsed();
                if duration.as_millis() > 50 {
                    tracing::warn!(
                        "StorageService: slow backend store_headers operation for {} headers took {:?}",
                        headers.len(),
                        duration
                    );
                }

                let _ = response.send(result);
            }
            StorageCommand::GetHeader {
                height,
                response,
            } => {
                let result = self.backend.get_header(height).await;
                let _ = response.send(result);
            }
            StorageCommand::GetHeaderByHash {
                hash,
                response,
            } => {
                let result = self.backend.get_header_by_hash(&hash).await;
                let _ = response.send(result);
            }
            StorageCommand::GetHeaderHeight {
                hash,
                response,
            } => {
                let result = self.backend.get_header_height(&hash).await;
                let _ = response.send(result);
            }
            StorageCommand::GetTipHeight {
                response,
            } => {
                let result = self.backend.get_tip_height().await;
                let _ = response.send(result);
            }
            StorageCommand::LoadHeaders {
                range,
                response,
            } => {
                let result = self.backend.load_headers(range).await;
                let _ = response.send(result);
            }

            // Filter operations
            StorageCommand::StoreFilterHeader {
                header,
                height,
                response,
            } => {
                let result = self.backend.store_filter_header(&header, height).await;
                let _ = response.send(result);
            }
            StorageCommand::GetFilterHeader {
                height,
                response,
            } => {
                let result = self.backend.get_filter_header(height).await;
                let _ = response.send(result);
            }
            StorageCommand::GetFilterTipHeight {
                response,
            } => {
                // Process without logging to avoid flooding logs
                let result = self.backend.get_filter_tip_height().await;
                let _ = response.send(result);
            }
            StorageCommand::StoreFilter {
                filter,
                height,
                response,
            } => {
                let result = self.backend.store_filter(&filter, height).await;
                let _ = response.send(result);
            }
            StorageCommand::GetFilter {
                height,
                response,
            } => {
                let result = self.backend.get_filter(height).await;
                let _ = response.send(result);
            }

            // State operations
            StorageCommand::SaveMasternodeState {
                state,
                response,
            } => {
                let result = self.backend.save_masternode_state(&state).await;
                let _ = response.send(result);
            }
            StorageCommand::LoadMasternodeState {
                response,
            } => {
                let result = self.backend.load_masternode_state().await;
                let _ = response.send(result);
            }
            StorageCommand::StoreChainState {
                state,
                response,
            } => {
                let result = self.backend.store_chain_state(&state).await;
                let _ = response.send(result);
            }
            StorageCommand::LoadChainState {
                response,
            } => {
                let result = self.backend.load_chain_state().await;
                let _ = response.send(result);
            }

            // UTXO operations
            StorageCommand::StoreUtxo {
                outpoint,
                utxo,
                response,
            } => {
                let result = self.backend.store_utxo(&outpoint, &utxo).await;
                let _ = response.send(result);
            }
            StorageCommand::RemoveUtxo {
                outpoint,
                response,
            } => {
                let result = self.backend.remove_utxo(&outpoint).await;
                let _ = response.send(result);
            }
            StorageCommand::GetUtxo {
                outpoint,
                response,
            } => {
                let result = self.backend.get_utxo(&outpoint).await;
                let _ = response.send(result);
            }
            StorageCommand::GetUtxosForAddress {
                address,
                response,
            } => {
                let result = self.backend.get_utxos_for_address(&address).await;
                let _ = response.send(result);
            }
            StorageCommand::GetAllUtxos {
                response,
            } => {
                let result = self.backend.get_all_utxos().await;
                let _ = response.send(result);
            }

            // Mempool operations
            StorageCommand::SaveMempoolState {
                state,
                response,
            } => {
                let result = self.backend.save_mempool_state(&state).await;
                let _ = response.send(result);
            }
            StorageCommand::LoadMempoolState {
                response,
            } => {
                let result = self.backend.load_mempool_state().await;
                let _ = response.send(result);
            }
            StorageCommand::AddMempoolTransaction {
                txid,
                tx,
                response,
            } => {
                let result = self.backend.add_mempool_transaction(&txid, &tx).await;
                let _ = response.send(result);
            }
            StorageCommand::RemoveMempoolTransaction {
                txid,
                response,
            } => {
                let result = self.backend.remove_mempool_transaction(&txid).await;
                let _ = response.send(result);
            }
            StorageCommand::GetMempoolTransaction {
                txid,
                response,
            } => {
                let result = self.backend.get_mempool_transaction(&txid).await;
                let _ = response.send(result);
            }
            StorageCommand::ClearMempool {
                response,
            } => {
                let result = self.backend.clear_mempool().await;
                let _ = response.send(result);
            }
        }
    }
}

/// Client handle for interacting with the storage service
#[derive(Clone)]
pub struct StorageClient {
    command_tx: mpsc::Sender<StorageCommand>,
}

impl StorageClient {
    // Header operations
    pub async fn store_header(&self, header: &BlockHeader, height: u32) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();

        // Check if receiver is already closed (shouldn't be possible right after creation)
        if tx.is_closed() {
            tracing::error!("Receiver already closed immediately after channel creation!");
        }

        tracing::trace!("StorageClient: sending StoreHeader command for height {}", height);
        let send_start = std::time::Instant::now();

        // Check channel capacity
        if self.command_tx.capacity() == 0 {
            tracing::warn!("Command channel is at full capacity!");
        }

        let send_result = self
            .command_tx
            .send(StorageCommand::StoreHeader {
                header: *header,
                height,
                response: tx,
            })
            .await;

        match send_result {
            Ok(_) => {
                // Give the service a chance to process the command
                tokio::task::yield_now().await;
            }
            Err(e) => {
                tracing::error!(
                    "StorageClient: Failed to send command for height {}: {:?}",
                    height,
                    e
                );
                return Err(StorageError::ServiceUnavailable);
            }
        }

        let send_duration = send_start.elapsed();
        if send_duration.as_millis() > 5 {
            tracing::warn!(
                "StorageClient: slow command send for height {} took {:?}",
                height,
                send_duration
            );
        }

        tracing::trace!("StorageClient: waiting for StoreHeader response for height {}", height);
        let response_start = std::time::Instant::now();

        // Create a drop guard to track when rx is dropped
        struct DropGuard {
            height: u32,
        }

        impl Drop for DropGuard {
            fn drop(&mut self) {
                tracing::error!("DropGuard dropped for height {}!", self.height);
            }
        }

        let _guard = DropGuard {
            height,
        };

        let rx_result = rx.await;

        let result = rx_result.map_err(|e| {
            tracing::error!(
                "StorageClient: Failed to receive response for height {}: {:?}",
                height,
                e
            );
            StorageError::ServiceUnavailable
        })?;

        let response_duration = response_start.elapsed();
        if response_duration.as_millis() > 50 {
            tracing::warn!(
                "StorageClient: slow response wait for height {} took {:?}",
                height,
                response_duration
            );
        }

        result
    }

    pub async fn store_headers(&self, headers: &[BlockHeader]) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();

        tracing::trace!(
            "StorageClient: sending StoreHeaders command for {} headers",
            headers.len()
        );

        let send_result = self
            .command_tx
            .send(StorageCommand::StoreHeaders {
                headers: headers.to_vec(),
                response: tx,
            })
            .await;

        match send_result {
            Ok(_) => {
                // Give the service a chance to process the command
                tokio::task::yield_now().await;
            }
            Err(e) => {
                tracing::error!(
                    "StorageClient: Failed to send StoreHeaders command for {} headers: {:?}",
                    headers.len(),
                    e
                );
                return Err(StorageError::ServiceUnavailable);
            }
        }

        tracing::trace!("StorageClient: waiting for StoreHeaders response");
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_header(&self, height: u32) -> StorageResult<Option<BlockHeader>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetHeader {
                height,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_header_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<BlockHeader>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetHeaderByHash {
                hash: *hash,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_header_height(&self, hash: &BlockHash) -> StorageResult<Option<u32>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetHeaderHeight {
                hash: *hash,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_tip_height(&self) -> StorageResult<Option<u32>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetTipHeight {
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn load_headers(&self, range: Range<u32>) -> StorageResult<Vec<BlockHeader>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::LoadHeaders {
                range,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    // Filter operations
    pub async fn store_filter_header(
        &self,
        header: &FilterHeader,
        height: u32,
    ) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::StoreFilterHeader {
                header: *header,
                height,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_filter_header(&self, height: u32) -> StorageResult<Option<FilterHeader>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetFilterHeader {
                height,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_filter_tip_height(&self) -> StorageResult<Option<u32>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetFilterTipHeight {
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn store_filter(&self, filter: &[u8], height: u32) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::StoreFilter {
                filter: filter.to_vec(),
                height,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_filter(&self, height: u32) -> StorageResult<Option<Vec<u8>>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetFilter {
                height,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    // State operations
    pub async fn save_masternode_state(&self, state: &MasternodeState) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::SaveMasternodeState {
                state: state.clone(),
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn load_masternode_state(&self) -> StorageResult<Option<MasternodeState>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::LoadMasternodeState {
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn store_chain_state(&self, state: &ChainState) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::StoreChainState {
                state: state.clone(),
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn load_chain_state(&self) -> StorageResult<Option<ChainState>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::LoadChainState {
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    // UTXO operations
    pub async fn store_utxo(&self, outpoint: &OutPoint, utxo: &Utxo) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::StoreUtxo {
                outpoint: *outpoint,
                utxo: utxo.clone(),
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn remove_utxo(&self, outpoint: &OutPoint) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::RemoveUtxo {
                outpoint: *outpoint,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_utxo(&self, outpoint: &OutPoint) -> StorageResult<Option<Utxo>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetUtxo {
                outpoint: *outpoint,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_utxos_for_address(
        &self,
        address: &Address,
    ) -> StorageResult<Vec<(OutPoint, Utxo)>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetUtxosForAddress {
                address: address.clone(),
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_all_utxos(&self) -> StorageResult<Vec<(OutPoint, Utxo)>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetAllUtxos {
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    // Mempool operations
    pub async fn save_mempool_state(&self, state: &MempoolState) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::SaveMempoolState {
                state: state.clone(),
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn load_mempool_state(&self) -> StorageResult<Option<MempoolState>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::LoadMempoolState {
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn add_mempool_transaction(
        &self,
        txid: &Txid,
        tx: &UnconfirmedTransaction,
    ) -> StorageResult<()> {
        let (tx_send, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::AddMempoolTransaction {
                txid: *txid,
                tx: tx.clone(),
                response: tx_send,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn remove_mempool_transaction(&self, txid: &Txid) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::RemoveMempoolTransaction {
                txid: *txid,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn get_mempool_transaction(
        &self,
        txid: &Txid,
    ) -> StorageResult<Option<UnconfirmedTransaction>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::GetMempoolTransaction {
                txid: *txid,
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }

    pub async fn clear_mempool(&self) -> StorageResult<()> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(StorageCommand::ClearMempool {
                response: tx,
            })
            .await
            .map_err(|_| StorageError::ServiceUnavailable)?;
        rx.await.map_err(|_| StorageError::ServiceUnavailable)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::MemoryStorageBackend;

    #[tokio::test]
    async fn test_storage_service_basic_operations() {
        // Create a memory backend
        let backend = Box::new(MemoryStorageBackend::new());
        let (service, client) = StorageService::new(backend);

        // Spawn the service
        tokio::spawn(service.run());

        // Test storing and retrieving a header
        let genesis = dashcore::blockdata::constants::genesis_block(dashcore::Network::Dash).header;

        // Store header
        client.store_header(&genesis, 0).await.unwrap();

        // Retrieve header
        let retrieved = client.get_header(0).await.unwrap();
        assert_eq!(retrieved, Some(genesis));

        // Get tip height
        let tip = client.get_tip_height().await.unwrap();
        assert_eq!(tip, Some(0));

        // Test masternode state
        let mn_state = MasternodeState {
            last_height: 100,
            engine_state: vec![],
            terminal_block_hash: None,
        };

        client.save_masternode_state(&mn_state).await.unwrap();
        let loaded = client.load_masternode_state().await.unwrap();
        assert_eq!(loaded, Some(mn_state));
    }
}
