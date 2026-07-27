use dashcore::{CompactTarget, Header, Target};
use dashcore_hashes::Hash as _;

use crate::chain::Checkpoint;

impl Checkpoint {
    pub fn dummy(height: u32) -> Checkpoint {
        let block_header = Header::dummy(height);

        Checkpoint {
            height,
            block_hash: block_header.block_hash(),
            prev_blockhash: block_header.prev_blockhash,
            timestamp: block_header.time,
            target: Target::from_compact(CompactTarget::from_consensus(0x1d00ffff)),
            merkle_root: Some(block_header.block_hash()),
            chain_work: format!("0x{:064x}", height.wrapping_mul(1000)),
            masternode_list_name: if height.is_multiple_of(100000) && height > 0 {
                Some(format!("ML{}__70230", height))
            } else {
                None
            },
            protocol_version: None,
            nonce: block_header.nonce,
        }
    }

    /// Build a checkpoint from `node`'s chain at `height`.
    ///
    /// The values have to be the chain's real ones: the client anchors on
    /// `block_hash` as a trusted hash and links later headers against it, so a
    /// fabricated one breaks header sync instead of exercising it.
    pub fn from_node(node: &crate::test_utils::DashCoreNode, height: u32) -> Checkpoint {
        let block_hash = node.get_block_hash(height);
        let header = node.get_block_header(&block_hash);
        let info = node.get_block_header_info(&block_hash);

        Checkpoint {
            height,
            block_hash,
            prev_blockhash: header.prev_blockhash,
            timestamp: header.time,
            target: Target::from_compact(header.bits),
            // Held in a `BlockHash` (X11) but sourced from a `TxMerkleNode`
            // (sha256d), so it goes through raw bytes — as the client does to
            // convert it back.
            merkle_root: Some(dashcore::BlockHash::from_byte_array(
                header.merkle_root.to_byte_array(),
            )),
            chain_work: format!("0x{}", hex::encode(&info.chainwork)),
            masternode_list_name: None,
            protocol_version: None,
            nonce: header.nonce,
        }
    }
}

impl<W, N, S> crate::client::DashSpvClient<W, N, S>
where
    W: key_wallet_manager::WalletInterface,
    N: crate::network::NetworkManager,
    S: crate::storage::StorageManager,
{
    /// `DashSpvClient::new`, anchored on a checkpoint from `node`'s chain at
    /// `height` instead of the ones bundled for the network. The client then
    /// never downloads the headers below `height`.
    ///
    /// The anchor only takes effect once the client's resolved start height
    /// reaches the checkpoint: `start_from_height`, or failing that the earliest
    /// wallet birth height.
    pub async fn new_anchored_at_checkpoint(
        config: crate::client::ClientConfig,
        network: N,
        storage: S,
        wallet: std::sync::Arc<tokio::sync::RwLock<W>>,
        event_handlers: Vec<std::sync::Arc<dyn crate::client::EventHandler>>,
        node: &crate::test_utils::DashCoreNode,
        height: u32,
    ) -> crate::error::Result<Self> {
        Self::new_with_checkpoints(
            config,
            network,
            storage,
            wallet,
            event_handlers,
            Some(vec![Checkpoint::from_node(node, height)]),
        )
        .await
    }
}
