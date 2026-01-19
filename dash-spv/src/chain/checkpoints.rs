//! Checkpoints are hardcoded blocks at specific heights that help sync from a given height

use dashcore::{
    consensus::{encode, Decodable, Encodable},
    constants::genesis_block,
    prelude::CoreBlockHeight,
    Network,
};

use crate::types::HashedBlockHeader;

// This files must exist in the checkpoint directory. If you don't have them, create
// empty ones and execute ``` cargo test generate_checkpoints_files -- --ignored ```
const MAINNET_CHECKPOINTS_BYTES: &[u8] = include_bytes!("../../checkpoints/mainnet.checkpoints");
const TESTNET_CHECKPOINTS_BYTES: &[u8] = include_bytes!("../../checkpoints/testnet.checkpoints");

// If you modify the heights you must regenerate the checkpoints files by
// executing ``` cargo test generate_checkpoints_files -- --ignored ```
const MAINNET_CHECKPOINTS_HEIGHTS: [CoreBlockHeight; 7] =
    [0, 4991, 107996, 750000, 1700000, 1900000, 2300000];
const TESTNET_CHECKPOINTS_HEIGHTS: [CoreBlockHeight; 4] = [0, 500000, 800000, 1100000];

fn checkpoints_bytes(network: Network) -> &'static [u8] {
    match network {
        Network::Dash => MAINNET_CHECKPOINTS_BYTES,
        Network::Testnet => TESTNET_CHECKPOINTS_BYTES,
        // Other networks do not have hardcoded checkpoints, this will help
        // trigger the CheckpointManager to add genesis as the only checkpoint
        _ => &[],
    }
}

fn checkpoints_heights(network: Network) -> &'static [CoreBlockHeight] {
    match network {
        Network::Dash => &MAINNET_CHECKPOINTS_HEIGHTS,
        Network::Testnet => &TESTNET_CHECKPOINTS_HEIGHTS,
        // Other networks do not have hardcoded checkpoints, this will help
        // trigger the CheckpointManager to add genesis as the only checkpoint
        _ => &[],
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Checkpoint {
    height: CoreBlockHeight,
    hashed_block_header: HashedBlockHeader,
}

impl PartialOrd for Checkpoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.height.cmp(&other.height))
    }
}

impl Checkpoint {
    pub fn new(height: CoreBlockHeight, hashed_block_header: HashedBlockHeader) -> Self {
        Self {
            height,
            hashed_block_header,
        }
    }
}

impl Encodable for Checkpoint {
    #[inline]
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, std::io::Error> {
        Ok(self.height.consensus_encode(writer)?
            + self.hashed_block_header.consensus_encode(writer)?)
    }
}

impl Decodable for Checkpoint {
    #[inline]
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, dashcore::consensus::encode::Error> {
        Ok(Self {
            height: CoreBlockHeight::consensus_decode(reader)?,
            hashed_block_header: HashedBlockHeader::consensus_decode(reader)?,
        })
    }
}

pub struct CheckpointManager {
    // checkpoints collection sorted by height, lowest first
    checkpoints: Vec<Checkpoint>,
}

impl CheckpointManager {
    pub fn new(network: Network) -> Self {
        let bytes = checkpoints_bytes(network);
        let heights_len = checkpoints_heights(network).len();

        let mut checkpoints = {
            let mut items = Vec::with_capacity(heights_len);
            let mut reader = bytes;

            loop {
                match Checkpoint::consensus_decode(&mut reader) {
                    Ok(item) => items.push(item),
                    Err(encode::Error::Io(ref e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        break
                    }
                    Err(_) => {
                        unreachable!("The bytes are hardcoded in the bin, decode cannot fail")
                    }
                }
            }

            items
        };

        debug_assert_eq!(
            checkpoints.len(),
            heights_len,
            "Could not load checkpoints for all lengths, maybe the checkpoints files are not updated"
        );

        #[cfg(debug_assertions)]
        {
            let heights = checkpoints_heights(network);
            for (i, cp) in checkpoints.iter().enumerate() {
                debug_assert_eq!(
                    cp.height,
                    heights[i],
                    "Checkpoint height does not match expected height, maybe the checkpoints files are not updated");
            }
        }

        // If the list is empty (maybe we dont have any checkpoints) but we still
        // want to be able to sync, we add the genesis block of the network as
        // a fallback
        if checkpoints.is_empty() {
            let genesis = HashedBlockHeader::from(genesis_block(network).header);
            let genesis_checkpoint = Checkpoint::new(0, genesis);
            checkpoints.push(genesis_checkpoint);
        }

        Self::new_with_checkpoints(checkpoints)
    }

    /// The input must be sorted by height in ascending order
    pub(crate) fn new_with_checkpoints(checkpoints: Vec<Checkpoint>) -> Self {
        debug_assert!(!checkpoints.is_empty(), "Checkpoints must contain, at least, genesis");

        // We need to ensure the first checkpoint is at height 0, genesis,
        // with it we ensure we have a valid checkpoint for any other height
        // since there is no value lower than 0 for u32 ;D
        debug_assert_eq!(checkpoints[0].height, 0, "The first checkpoint must be at height 0");

        debug_assert!(
            checkpoints.is_sorted(),
            "The checkpoints must be sorted by height in ascending order"
        );

        Self {
            checkpoints,
        }
    }

    /// Get the last checkpoint at or before the given height
    pub fn last_checkpoint_before_height(
        &self,
        height: u32,
    ) -> (CoreBlockHeight, &HashedBlockHeader) {
        match self.checkpoints.binary_search_by_key(&height, |checkpoint| checkpoint.height) {
            Ok(index) => {
                (self.checkpoints[index].height, &self.checkpoints[index].hashed_block_header)
            }
            Err(index) => (
                self.checkpoints[index - 1].height,
                &self.checkpoints[index - 1].hashed_block_header,
            ),
        }
    }

    /// Get the last checkpoint before a given timestamp
    pub fn last_checkpoint_before_timestamp(
        &self,
        timestamp: u32,
    ) -> (CoreBlockHeight, &HashedBlockHeader) {
        let mut checkpoints = self.checkpoints.iter();

        let mut best_checkpoint =
            checkpoints.next().expect("CheckpointManager should never be empty");

        for checkpoint in checkpoints {
            if checkpoint.hashed_block_header.header().time <= timestamp
                && checkpoint.height >= best_checkpoint.height
            {
                best_checkpoint = checkpoint;
            }
        }

        (best_checkpoint.height, &best_checkpoint.hashed_block_header)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::OpenOptions,
        io::{BufWriter, Write},
        path::PathBuf,
        sync::Arc,
    };

    use key_wallet::wallet::ManagedWalletInfo;
    use key_wallet_manager::WalletManager;
    use tokio::sync::RwLock;
    use tokio_util::sync::CancellationToken;
    use tracing::level_filters::LevelFilter;

    use crate::{
        init_console_logging,
        network::PeerNetworkManager,
        storage::{BlockHeaderStorage, DiskStorageManager},
        types::SyncStage,
        ClientConfig, DashSpvClient,
    };

    use super::*;

    // This must be manually executed every time we modify checkpoints heights to allow the library
    // to generate checkpoint files by requesting the block headers using its own client
    #[tokio::test]
    #[ignore = "This tests is meant to re-generate checkpoints files"]
    async fn generate_checkpoints_files() {
        const SUPPORTED_NETWORKS: [Network; 2] = [Network::Dash, Network::Testnet];

        const MAINNET_CHECKPOINTS_FILE: &str = "checkpoints/mainnet.checkpoints";
        const TESTNET_CHECKPOINTS_FILE: &str = "checkpoints/testnet.checkpoints";

        let _logging_guard = init_console_logging(LevelFilter::INFO).unwrap();

        for network in SUPPORTED_NETWORKS {
            generate_checkpoints_file(network)
                .await
                .unwrap_or_else(|_| panic!("Error generating checkpoints for network {network}"));
        }

        async fn generate_checkpoints_file(network: Network) -> crate::error::Result<()> {
            let storage_path = format!("./.tmp/{network}-checkpoints-generation-storage");

            let config = ClientConfig::new(network)
                .with_storage_path(PathBuf::from(&storage_path))
                .without_filters()
                .without_masternodes();

            let network_manager = PeerNetworkManager::new(&config).await?;
            let storage_manager = DiskStorageManager::new(&storage_path).await?;
            let wallet =
                Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));
            let mut client =
                DashSpvClient::new(config, network_manager, storage_manager, wallet).await?;

            client.start().await?;
            let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
            let shutdown_token = CancellationToken::new();

            let mut progress_receiver = client.take_progress_receiver().unwrap();

            {
                let shutdown_token = shutdown_token.clone();
                tokio::spawn(async move {
                    client.run(command_receiver, shutdown_token).await.unwrap();
                });
            }

            while let Some(progress) = progress_receiver.recv().await {
                if matches!(progress.sync_stage, SyncStage::Complete) {
                    shutdown_token.cancel();
                }
            }

            let storage_manager = DiskStorageManager::new(&storage_path).await?;

            let checkpoints_file_path = match network {
                Network::Dash => MAINNET_CHECKPOINTS_FILE,
                Network::Testnet => TESTNET_CHECKPOINTS_FILE,
                _ => panic!("There is no checkpoints file for network {network}"),
            };

            let checkpoints_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(checkpoints_file_path)
                .expect("Should open checkpoints file for writing");
            let mut writer = BufWriter::new(checkpoints_file);

            for height in checkpoints_heights(network) {
                let checkpoint_header =
                    storage_manager.get_header(*height).await?.expect("Should find checkpoint");

                let checkpoint = Checkpoint::new(*height, checkpoint_header.into());
                checkpoint.consensus_encode(&mut writer).expect("Error writing checkpoint to file");
            }

            writer.flush()?;
            Ok(())
        }
    }

    #[test]
    #[should_panic(expected = "height 0")]
    fn test_checkpoint_must_start_at_zero() {
        CheckpointManager::dummy(&[1, 4, 5, 9, 90, 9000]);
    }

    #[test]
    #[should_panic(expected = "ascending")]
    fn test_checkpoints_must_be_ascending() {
        CheckpointManager::dummy(&[0, 1, 2, 3, 2, 1]);
    }

    #[test]
    fn test_last_checkpoint_before() {
        let manager = CheckpointManager::dummy(&MAINNET_CHECKPOINTS_HEIGHTS);

        // Test finding checkpoint before various heights
        assert_eq!(manager.last_checkpoint_before_height(0).0, 0);
        assert_eq!(manager.last_checkpoint_before_height(1000).0, 0);
        assert_eq!(manager.last_checkpoint_before_height(5000).0, 4991);
        assert_eq!(manager.last_checkpoint_before_height(200000).0, 107996);
    }

    #[test]
    fn test_checkpoint_by_timestamp() {
        let manager = CheckpointManager::dummy(&MAINNET_CHECKPOINTS_HEIGHTS);

        // Test finding checkpoint by timestamp
        let checkpoint = manager.last_checkpoint_before_timestamp(1500000000);
        assert!(checkpoint.1.header().time <= 1500000000);
    }
}
