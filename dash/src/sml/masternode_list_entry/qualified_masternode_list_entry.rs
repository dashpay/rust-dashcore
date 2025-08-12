use std::cmp::Ordering;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::{Hash, sha256d};

use crate::hash_types::ConfirmedHashHashedWithProRegTx;
use crate::sml::masternode_list_entry::MasternodeListEntry;

/// A structured representation of a masternode list entry with a cached entry hash and a confirmed
/// hash hashed with the pro_reg_tx. These extra fields are often used so it doesn't make sense to
/// recompute them.
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub struct QualifiedMasternodeListEntry {
    /// The underlying masternode list entry
    pub masternode_list_entry: MasternodeListEntry,
    /// The computed entry hash
    pub entry_hash: sha256d::Hash,
    /// The confirmed hash hashed with the pro_reg_tx if the confirmed hash is set
    pub confirmed_hash_hashed_with_pro_reg_tx: Option<ConfirmedHashHashedWithProRegTx>,
}

impl Ord for QualifiedMasternodeListEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.masternode_list_entry.cmp(&other.masternode_list_entry)
    }
}

impl PartialOrd for QualifiedMasternodeListEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<MasternodeListEntry> for QualifiedMasternodeListEntry {
    fn from(masternode_list_entry: MasternodeListEntry) -> Self {
        let entry_hash = masternode_list_entry.calculate_entry_hash();
        let confirmed_hash_hashed_with_pro_reg_tx =
            masternode_list_entry.confirmed_hash.map(|confirmed_hash| {
                ConfirmedHashHashedWithProRegTx::hash(
                    &[
                        masternode_list_entry.pro_reg_tx_hash.to_byte_array(),
                        confirmed_hash.to_byte_array(),
                    ]
                    .concat(),
                )
            });
        QualifiedMasternodeListEntry {
            masternode_list_entry,
            entry_hash,
            confirmed_hash_hashed_with_pro_reg_tx,
        }
    }
}
