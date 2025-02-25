use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::masternode_list::{MasternodeList, MasternodeListBuilder};

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
    ///
    /// # Parameters
    ///
    /// - `diff`: The `MnListDiff` containing the changes to apply.
    /// - `diff_end_height`: The block height at which the diff ends.
    ///
    /// # Returns
    ///
    /// - `Ok(MasternodeList)`: A new `MasternodeList` reflecting the applied changes.
    /// - `Err(SmlError)`: An error if the base block hash does not match the expected value.
    ///
    /// # Errors
    ///
    /// - Returns `SmlError::BaseBlockHashMismatch` if the `base_block_hash` of the `diff`
    ///   does not match the expected block hash of the current masternode list.
    pub fn apply_diff(
        &self,
        diff: MnListDiff,
        diff_end_height: CoreBlockHeight,
    ) -> Result<MasternodeList, SmlError> {
        // Ensure the base block hash matches
        if self.block_hash != diff.base_block_hash {
            return Err(SmlError::BaseBlockHashMismatch {
                expected: self.block_hash,
                found: diff.base_block_hash,
            });
        }

        // Create a new masternodes map by cloning the existing one
        let mut updated_masternodes = self.masternodes.clone();

        // Remove deleted masternodes
        for pro_tx_hash in diff.deleted_masternodes {
            updated_masternodes.remove(&pro_tx_hash.reverse());
        }

        // Add or update new masternodes
        for new_mn in diff.new_masternodes {
            updated_masternodes.insert(new_mn.pro_reg_tx_hash.reverse(), new_mn.into());
        }

        // Create a new quorums map by cloning the existing one
        let mut updated_quorums = self.quorums.clone();

        // Remove deleted quorums
        for deleted_quorum in diff.deleted_quorums {
            if let Some(quorum_map) = updated_quorums.get_mut(&deleted_quorum.llmq_type) {
                quorum_map.remove(&deleted_quorum.quorum_hash);
                if quorum_map.is_empty() {
                    updated_quorums.remove(&deleted_quorum.llmq_type);
                }
            }
        }

        // Add or update new quorums
        for new_quorum in diff.new_quorums {
            updated_quorums
                .entry(new_quorum.llmq_type)
                .or_default()
                .insert(new_quorum.quorum_hash, new_quorum.into());
        }

        // Create and return the new MasternodeList
        let builder = MasternodeListBuilder::new(
            updated_masternodes,
            updated_quorums,
            diff.block_hash,
            diff_end_height, 
        );
        
        Ok(builder.build())
    }
}
