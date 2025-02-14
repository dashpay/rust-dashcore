use std::cmp::Ordering;
use crate::sml::masternode_list_entry::MasternodeListEntry;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct QualifiedMasternodeListEntry {
    pub masternode_list_entry: MasternodeListEntry,
    pub entry_hash: [u8;32],
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
        QualifiedMasternodeListEntry {
            masternode_list_entry,
            entry_hash,
        }
    }
}