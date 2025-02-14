use std::collections::BTreeMap;
use crate::{BlockHash, Network};
use crate::network::message_sml::MnListDiff;
use crate::sml::error::SmlError;
use crate::sml::llmq_entry_verification::{LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus};
use crate::sml::masternode_list::MasternodeList;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;

pub trait TryFromWithBlockHashLookup<T>: Sized {
    type Error;
    fn try_from_with_block_hash_lookup<F>(
        value: T,
        block_hash_lookup: F,
        network: Network,
    ) -> Result<Self, Self::Error>
    where
        F: Fn(&BlockHash) -> Option<u32>;
}

pub trait TryIntoWithBlockHashLookup<T>: Sized {
    type Error;

    /// Converts `self` into `T`, using a block hash lookup function.
    fn try_into_with_block_hash_lookup<F>(
        self,
        block_hash_lookup: F,
        network: Network,
    ) -> Result<T, Self::Error>
    where
        F: Fn(&BlockHash) -> Option<u32>;
}

impl<T, U> TryIntoWithBlockHashLookup<U> for T
where
    U: TryFromWithBlockHashLookup<T>,
{
    type Error = U::Error;

    fn try_into_with_block_hash_lookup<F>(
        self,
        block_hash_lookup: F,
        network: Network,
    ) -> Result<U, Self::Error>
    where
        F: Fn(&BlockHash) -> Option<u32>,
    {
        U::try_from_with_block_hash_lookup(self, block_hash_lookup, network)
    }
}


impl TryFromWithBlockHashLookup<MnListDiff> for MasternodeList {
    type Error = SmlError;

    fn try_from_with_block_hash_lookup<F>(diff: MnListDiff, block_hash_lookup: F, network: Network) -> Result<Self, Self::Error>
    where
        F: Fn(&BlockHash) -> Option<u32>
    {
        if let Some(genesis_block_hash) = network.known_genesis_block_hash() {
            // Check if the base block is the genesis block
            if diff.base_block_hash != genesis_block_hash {
                return Err(SmlError::BaseBlockNotGenesis(diff.base_block_hash));
            }
        }

        // Lookup block height
        let known_height = block_hash_lookup(&diff.block_hash)
            .ok_or(SmlError::BlockHashLookupFailed(diff.block_hash))?;

        // Ensure the `MnListDiff` is valid
        if diff.merkle_hashes.is_empty() || diff.new_masternodes.is_empty() {
            return Err(SmlError::IncompleteMnListDiff);
        }

        // Populate masternode and quorum maps
        let masternodes = diff
            .new_masternodes
            .into_iter()
            .map(|entry| {
                (entry.pro_reg_tx_hash.reverse(), entry.into())
            })
            .collect::<BTreeMap<_, _>>();

        let quorums = diff
            .new_quorums
            .into_iter()
            .fold(BTreeMap::new(), |mut map, quorum| {
                map.entry(quorum.llmq_type.into())
                    .or_insert_with(BTreeMap::new)
                    .insert(quorum.quorum_hash, {
                        let entry_hash = quorum.calculate_entry_hash();
                        QualifiedQuorumEntry {
                            quorum_entry: quorum,
                            verified: LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::NotMarkedForVerification),
                            commitment_hash: None,
                            entry_hash,
                        }
                    });
                map
            });

        // Construct `MasternodeList`
        Ok(MasternodeList {
            block_hash: diff.block_hash,
            known_height,
            masternode_merkle_root: diff.merkle_hashes.first().cloned(),
            llmq_merkle_root: None, // Adjust based on real data availability
            masternodes,
            quorums,
        })
    }
}