use std::cmp::Ordering;
#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::Hash;
use crate::hash_types::ConfirmedHashHashedWithProRegTx;
use crate::sml::masternode_list_entry::MasternodeListEntry;

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct QualifiedMasternodeListEntry {
    pub masternode_list_entry: MasternodeListEntry,
    pub entry_hash: [u8;32],
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
        let confirmed_hash_hashed_with_pro_reg_tx = masternode_list_entry.confirmed_hash.map(|confirmed_hash| ConfirmedHashHashedWithProRegTx::hash(&[masternode_list_entry.pro_reg_tx_hash.to_byte_array(), confirmed_hash.to_byte_array()].concat()));
        QualifiedMasternodeListEntry {
            masternode_list_entry,
            entry_hash,
            confirmed_hash_hashed_with_pro_reg_tx,
        }
    }
}