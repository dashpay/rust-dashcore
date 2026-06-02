use crate::bls_sig_utils::BLSSignature;

use crate::Network;
use crate::network::constants::NetworkExt;
use crate::network::message_sml::MnListDiff;
use crate::sml::error::SmlError;
use crate::sml::llmq_entry_verification::{
    LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
};
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::quorum_entry::qualified_quorum_entry::{
    QualifiedQuorumEntry, VerifyingChainLockSignaturesType,
};
use crate::{BlockHash, QuorumHash};
use hashes::Hash;
use std::collections::BTreeMap;

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

    fn try_from_with_block_hash_lookup<F>(
        diff: MnListDiff,
        block_hash_lookup: F,
        network: Network,
    ) -> Result<Self, Self::Error>
    where
        F: Fn(&BlockHash) -> Option<u32>,
    {
        if let Some(genesis_block_hash) = network.known_genesis_block_hash() {
            // Check if the base block is the genesis block
            if diff.base_block_hash != genesis_block_hash
                && diff.base_block_hash.as_byte_array() != &[0; 32]
            {
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

        let coinbase_tx = diff.coinbase_tx.clone();

        // Populate masternode and quorum maps
        let masternodes = diff
            .new_masternodes
            .into_iter()
            .map(|entry| (entry.pro_reg_tx_hash.reverse(), entry.into()))
            .collect::<BTreeMap<_, _>>();

        // Build a vector of optional signatures with slots matching new_quorums length
        let mut quorum_sig_lookup: Vec<Option<&BLSSignature>> = vec![None; diff.new_quorums.len()];

        // Fill each slot with the corresponding signature
        for quorum_sig_obj in &diff.quorums_chainlock_signatures {
            for &index in &quorum_sig_obj.index_set {
                if let Some(slot) = quorum_sig_lookup.get_mut(index as usize) {
                    *slot = Some(&quorum_sig_obj.signature);
                } else {
                    return Err(SmlError::InvalidIndexInSignatureSet(index));
                }
            }
        }

        // quorumsCLSigs only exists after V20 activation (protocol 70230).
        // Pre-V20 blocks have no chainlock signatures. See DIP-0029.
        if known_height >= network.v20_activation_height()
            && quorum_sig_lookup.iter().any(Option::is_none)
        {
            return Err(SmlError::IncompleteSignatureSet);
        }

        let quorums = diff.new_quorums.into_iter().enumerate().fold(
            BTreeMap::new(),
            |mut map: BTreeMap<LLMQType, BTreeMap<QuorumHash, QualifiedQuorumEntry>>,
             (idx, quorum)| {
                map.entry(quorum.llmq_type).or_default().insert(quorum.quorum_hash, {
                    let entry_hash = quorum.calculate_entry_hash();
                    let commitment_hash = quorum.calculate_commitment_hash();

                    QualifiedQuorumEntry {
                        quorum_entry: quorum,
                        verified: LLMQEntryVerificationStatus::Skipped(
                            LLMQEntryVerificationSkipStatus::NotMarkedForVerification,
                        ),
                        commitment_hash,
                        entry_hash,
                        verifying_chain_lock_signature: quorum_sig_lookup
                            .get(idx)
                            .copied()
                            .flatten()
                            .copied()
                            .map(VerifyingChainLockSignaturesType::NonRotating),
                    }
                });
                map
            },
        );

        // Construct `MasternodeList`, recomputing the Merkle roots over the assembled entry set
        // instead of trusting any value carried in the diff.
        let masternode_list =
            MasternodeList::build(masternodes, quorums, diff.block_hash, known_height).build();

        masternode_list.validate_mn_list_root(&coinbase_tx, known_height)?;

        Ok(masternode_list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::deserialize;

    /// Rewrites the diff's coinbase masternode list root to match the list its own
    /// `new_masternodes` set produces. The from-genesis capture fixture commits a root over the
    /// full mainnet list which the captured subset does not reproduce, so without this it would be
    /// rejected by root validation even though the unrelated chainlock-signature behaviour under
    /// test is correct.
    fn make_from_genesis_diff_consistent(diff: &mut MnListDiff, height: u32) {
        let masternodes = diff
            .new_masternodes
            .iter()
            .map(|entry| (entry.pro_reg_tx_hash.reverse(), entry.clone().into()))
            .collect();
        let assembled =
            MasternodeList::build(masternodes, BTreeMap::new(), diff.block_hash, height).build();
        MasternodeList::rewrite_coinbase_mn_list_root(&mut diff.coinbase_tx, &assembled, height);
    }

    #[test]
    fn post_v20_requires_chainlock_signatures() {
        let mn_list_diff_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin");
        let mut diff: MnListDiff =
            deserialize(mn_list_diff_bytes).expect("expected to deserialize");

        // Clear signatures to simulate missing data
        diff.quorums_chainlock_signatures.clear();

        // Height 2227096 is post-V20 on mainnet (1,987,776)
        let post_v20_height = 2_227_096;
        assert!(post_v20_height >= Network::Mainnet.v20_activation_height());

        let result = MasternodeList::try_from_with_block_hash_lookup(
            diff,
            |_| Some(post_v20_height),
            Network::Mainnet,
        );

        assert!(
            matches!(result, Err(SmlError::IncompleteSignatureSet)),
            "Post-V20 blocks should require chainlock signatures"
        );
    }

    #[test]
    fn pre_v20_allows_missing_chainlock_signatures() {
        let mn_list_diff_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin");
        let mut diff: MnListDiff =
            deserialize(mn_list_diff_bytes).expect("expected to deserialize");

        // Clear signatures to simulate pre-V20 data
        diff.quorums_chainlock_signatures.clear();

        // Use a pre-V20 height on mainnet (V20 at 1,987,776)
        let pre_v20_height = 1_900_000;
        assert!(pre_v20_height < Network::Mainnet.v20_activation_height());

        make_from_genesis_diff_consistent(&mut diff, pre_v20_height);

        let result = MasternodeList::try_from_with_block_hash_lookup(
            diff,
            |_| Some(pre_v20_height),
            Network::Mainnet,
        );

        assert!(
            result.is_ok(),
            "Pre-V20 blocks should allow missing chainlock signatures: {:?}",
            result.err()
        );
    }

    #[test]
    fn rejects_coinbase_mn_list_root_mismatch() {
        let mn_list_diff_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin");
        let diff: MnListDiff = deserialize(mn_list_diff_bytes).expect("expected to deserialize");

        // The capture fixture's coinbase commits a root over the full mainnet list that the
        // captured `new_masternodes` subset does not reproduce, so building it must hard-reject.
        let result = MasternodeList::try_from_with_block_hash_lookup(
            diff,
            |_| Some(1_900_000),
            Network::Mainnet,
        );

        assert!(
            matches!(result, Err(SmlError::MasternodeListRootMismatch { .. })),
            "a diff whose coinbase root disagrees with its entry set must be rejected: {:?}",
            result
        );
    }
}
