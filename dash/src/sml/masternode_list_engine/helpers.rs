use crate::prelude::CoreBlockHeight;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_engine::MasternodeListEngine;

impl MasternodeListEngine {
    /// Retrieves the closest masternode lists before and after a given core block height.
    ///
    /// This function searches the `masternode_lists` map to find the nearest masternode lists
    /// surrounding the provided `core_block_height`. It returns:
    /// - The highest masternode list at or below the given height.
    /// - The lowest masternode list above the given height.
    ///
    /// # Arguments
    ///
    /// * `core_block_height` - The core block height for which surrounding masternode lists are needed.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `Some(MasternodeList)`: The masternode list at or just below the given height.
    /// - `Some(MasternodeList)`: The masternode list just above the given height.
    /// - `None` values if no corresponding lists exist.
    ///
    /// # Behavior
    ///
    /// - If `core_block_height` matches a key exactly, it may be included in the first return value.
    /// - The function does not mutate the underlying data structure.
    /// - Uses efficient `BTreeMap` traversal to find surrounding heights.
    pub fn masternode_lists_around_height(
        &self,
        core_block_height: CoreBlockHeight,
    ) -> (Option<&MasternodeList>, Option<&MasternodeList>) {
        let mut lower = None;
        let mut upper = None;

        for (&height, list) in self.masternode_lists.range(..=core_block_height).rev() {
            lower = Some(list);
            break;
        }

        for (&height, list) in self.masternode_lists.range(core_block_height + 1..) {
            upper = Some(list);
            break;
        }

        (lower, upper)
    }
}
