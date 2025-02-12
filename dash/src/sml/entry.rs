use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use hashes::sha256d::Hash;
use crate::internal_macros::impl_consensus_encoding;
use crate::{ProTxHash};
use crate::sml::address::ServiceAddress;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct MasternodeListEntry {
    pub pro_reg_tx_hash: ProTxHash,
    pub confirmed_hash: Hash,
    pub service_address: ServiceAddress,
    pub operator_public_key: OperatorPublicKey,
    pub previous_operator_public_keys: BTreeMap<Block, OperatorPublicKey>,
    pub previous_entry_hashes: BTreeMap<Block, [u8; 32]>,
    pub previous_validity: BTreeMap<Block, bool>,
    pub known_confirmed_at_height: Option<u32>,
    pub update_height: u32,
    pub key_id_voting: [u8; 20],
    pub is_valid: bool,
    pub mn_type: MasternodeType,
    pub platform_http_port: u16,
    pub platform_node_id: [u8; 20],
    pub entry_hash: [u8; 32],
}

impl_consensus_encoding!(MasternodeListEntry, pro_reg_tx_hash, confirmed_hash, confirmed_hash_hashed_with_provider_registration_transaction_hash, socket_address, operator_public_key, previous_operator_public_keys, previous_entry_hashes, previous_validity, known_confirmed_at_height, update_height, key_id_voting, is_valid, mn_type, platform_http_port, platform_node_id, entry_hash)
