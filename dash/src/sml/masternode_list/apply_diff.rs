use std::sync::Arc;

use crate::Network;
use crate::bls_sig_utils::BLSSignature;
use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::llmq_entry_verification::{
    LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
};
use crate::sml::masternode_list::MasternodeList;
use crate::sml::quorum_entry::qualified_quorum_entry::{
    QualifiedQuorumEntry, VerifyingChainLockSignaturesType,
};

impl MasternodeList {
    /// Applies an `MnListDiff` to update the current masternode list.
    ///
    /// This function processes a masternode list diff (`MnListDiff`) and applies
    /// the changes to the existing masternode list. It performs the following operations:
    /// - Ensures the base block hash matches the expected value.
    /// - Removes deleted masternodes from the list.
    /// - Adds or updates new masternodes.
    /// - Removes deleted quorums.
    /// - Adds or updates new quorums.
    /// - Checks the resulting list against the diff's coinbase, see
    ///   [`MasternodeList::verify_coinbase_merkle_roots`].
    ///
    /// The coinbase is taken as given. [`MnListDiff::verify_coinbase_merkle_proof`] ties it to
    /// the block header, which only the caller holds.
    ///
    /// # Parameters
    ///
    /// - `diff`: The `MnListDiff` containing the changes to apply.
    /// - `diff_end_height`: The block height at which the diff ends.
    ///
    /// # Returns
    ///
    /// - `Ok(MasternodeList)`: A new `MasternodeList` reflecting the applied changes.
    /// - `Err(SmlError)`: An error if the diff does not apply to this list.
    ///
    /// # Errors
    ///
    /// - Returns `SmlError::BaseBlockHashMismatch` if the `base_block_hash` of the `diff`
    ///   does not match the expected block hash of the current masternode list.
    /// - Returns `SmlError::MissingCoinbasePayload`, `SmlError::MasternodeListMerkleRootMismatch`
    ///   or `SmlError::QuorumMerkleRootMismatch` if the resulting list does not match the
    ///   coinbase commitments.
    pub fn apply_diff(
        &self,
        diff: MnListDiff,
        diff_end_height: CoreBlockHeight,
        previous_chain_lock_sigs: Option<[BLSSignature; 3]>,
        network: Network,
    ) -> Result<(MasternodeList, Option<BLSSignature>), SmlError> {
        // Ensure the base block hash matches
        if self.block_hash != diff.base_block_hash {
            return Err(SmlError::BaseBlockHashMismatch {
                expected: self.block_hash,
                found: diff.base_block_hash,
            });
        }

        let coinbase_tx = diff.coinbase_tx;

        let mut updated_masternodes = Arc::clone(&self.masternodes);
        if !diff.deleted_masternodes.is_empty() || !diff.new_masternodes.is_empty() {
            let masternodes = Arc::make_mut(&mut updated_masternodes);
            for pro_tx_hash in diff.deleted_masternodes {
                masternodes.remove(&pro_tx_hash.reverse());
            }
            for new_mn in diff.new_masternodes {
                masternodes.insert(new_mn.pro_reg_tx_hash.reverse(), Arc::new(new_mn.into()));
            }
        }

        let mut shared_quorums = Arc::clone(&self.quorums);
        if diff.deleted_quorums.is_empty()
            && diff.new_quorums.is_empty()
            && diff.quorums_chainlock_signatures.is_empty()
        {
            let masternode_list = MasternodeList::build(
                updated_masternodes,
                shared_quorums,
                diff.block_hash,
                diff_end_height,
            )
            .build_matching_coinbase(&coinbase_tx)?;
            return Ok((masternode_list, None));
        }
        let updated_quorums = Arc::make_mut(&mut shared_quorums);

        // Remove deleted quorums
        for deleted_quorum in diff.deleted_quorums {
            if let Some(quorum_map) = updated_quorums.get_mut(&deleted_quorum.llmq_type) {
                quorum_map.remove(&deleted_quorum.quorum_hash);
                if quorum_map.is_empty() {
                    updated_quorums.remove(&deleted_quorum.llmq_type);
                }
            }
        }

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
        let signatures_available = !quorum_sig_lookup.iter().any(Option::is_none);
        let signatures_required = diff_end_height >= network.v20_activation_height();

        if signatures_required && !signatures_available {
            return Err(SmlError::IncompleteSignatureSet);
        }

        let mut rotating_sig = None;

        // Add or update new quorums
        for (idx, new_quorum) in diff.new_quorums.into_iter().enumerate() {
            updated_quorums.entry(new_quorum.llmq_type).or_default().insert(
                new_quorum.quorum_hash,
                {
                    let commitment_hash = new_quorum.calculate_commitment_hash();
                    let entry_hash = new_quorum.calculate_entry_hash();
                    let verifying_chain_lock_signature =
                        if new_quorum.llmq_type.is_rotating_quorum_type() {
                            if rotating_sig.is_none()
                                && let Some(sig) = quorum_sig_lookup.get(idx).copied().flatten()
                            {
                                rotating_sig = Some(*sig);
                            }
                            if signatures_available {
                                if let Some(previous_chain_lock_sigs) = previous_chain_lock_sigs {
                                    quorum_sig_lookup.get(idx).copied().flatten().map(|sig| {
                                        VerifyingChainLockSignaturesType::Rotating([
                                            previous_chain_lock_sigs[0],
                                            previous_chain_lock_sigs[1],
                                            previous_chain_lock_sigs[2],
                                            *sig,
                                        ])
                                    })
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            quorum_sig_lookup
                                .get(idx)
                                .copied()
                                .flatten()
                                .copied()
                                .map(VerifyingChainLockSignaturesType::NonRotating)
                        };
                    Arc::new(QualifiedQuorumEntry {
                        quorum_entry: new_quorum,
                        verified: LLMQEntryVerificationStatus::Skipped(
                            LLMQEntryVerificationSkipStatus::NotMarkedForVerification,
                        ),
                        commitment_hash,
                        entry_hash,
                        verifying_chain_lock_signature,
                    })
                },
            );
        }

        // Create the new MasternodeList and return it once the coinbase vouches for it
        let masternode_list = MasternodeList::build(
            updated_masternodes,
            shared_quorums,
            diff.block_hash,
            diff_end_height,
        )
        .build_matching_coinbase(&coinbase_tx)?;

        Ok((masternode_list, rotating_sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sml::masternode_list::from_diff::TryFromWithBlockHashLookup;

    #[test]
    fn apply_diff_post_v20_requires_chainlock_signatures() {
        // Create base list from first diff
        let base_list = MasternodeList::try_from_with_block_hash_lookup(
            MnListDiff::mainnet_fixture_0_2227096(),
            |_| Some(2_227_096),
            Network::Mainnet,
        )
        .expect("expected to create base list");

        // Load second diff and clear signatures
        let mut diff = MnListDiff::mainnet_fixture_2227096_2241332();
        diff.quorums_chainlock_signatures.clear();

        // Height 2241332 is post-V20 on mainnet (1,987,776)
        let post_v20_height = 2_241_332;
        assert!(post_v20_height >= Network::Mainnet.v20_activation_height());

        let result = base_list.apply_diff(diff, post_v20_height, None, Network::Mainnet);

        assert!(
            matches!(result, Err(SmlError::IncompleteSignatureSet)),
            "Post-V20 apply_diff should require chainlock signatures"
        );
    }

    #[test]
    fn apply_diff_pre_v20_allows_missing_chainlock_signatures() {
        // Create base list from first diff at pre-V20 height
        let base_height = 1_800_000u32;
        let base_list = MasternodeList::try_from_with_block_hash_lookup(
            MnListDiff::mainnet_fixture_0_2227096(),
            |_| Some(base_height),
            Network::Mainnet,
        )
        .expect("expected to create base list");

        // Load second diff and clear signatures
        let mut diff = MnListDiff::mainnet_fixture_2227096_2241332();

        // Fix base_block_hash to match our base list
        diff.base_block_hash = base_list.block_hash;
        diff.quorums_chainlock_signatures.clear();

        // Use a pre-V20 height on mainnet
        let pre_v20_height = 1_900_000u32;
        assert!(pre_v20_height < Network::Mainnet.v20_activation_height());

        let result = base_list.apply_diff(diff, pre_v20_height, None, Network::Mainnet);

        assert!(
            result.is_ok(),
            "Pre-V20 apply_diff should allow missing chainlock signatures: {:?}",
            result.err()
        );
    }
}
