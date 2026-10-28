use std::sync::Arc;

use dashcore::network::message_sml::MnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::error::SmlError;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::Transaction;
use tokio::sync::RwLock;

use crate::sml_engine::FeedError;
use crate::storage::BlockHeaderStorage;

/// Validates a masternode list diff against its block: its merkle proof must
/// prove its coinbase in the stored header, and the list it builds must hash
/// to the roots that coinbase commits to.
pub struct MasternodeListValidator<H: BlockHeaderStorage> {
    headers: Arc<RwLock<H>>,
}

impl<H: BlockHeaderStorage> MasternodeListValidator<H> {
    pub fn new(headers: Arc<RwLock<H>>) -> Self {
        Self {
            headers,
        }
    }

    /// Fails with `HeaderStorage` when the header cannot be read, and refuses
    /// the diff when its block is not the one stored at `height` or its proof
    /// does not match the header's merkle root.
    pub async fn validate_coinbase_proof(
        &self,
        diff: &MnListDiff,
        height: CoreBlockHeight,
    ) -> Result<(), FeedError<SmlError>> {
        let header = self
            .headers
            .read()
            .await
            .get_header(height)
            .await
            .map_err(FeedError::HeaderStorage)?
            .filter(|header| *header.hash() == diff.block_hash)
            .ok_or(SmlError::BlockHashLookupFailed(diff.block_hash))?;

        if diff.coinbase_merkle_root()? != header.header().merkle_root {
            return Err(SmlError::InvalidCoinbaseProof(diff.block_hash).into());
        }

        Ok(())
    }

    pub fn validate_coinbase_roots(
        &self,
        masternode_list: &MasternodeList,
        coinbase_tx: &Transaction,
    ) -> Result<(), SmlError> {
        masternode_list.verify_coinbase_roots(coinbase_tx)
    }
}
