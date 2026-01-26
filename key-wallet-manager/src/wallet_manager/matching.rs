use alloc::vec::Vec;
use dashcore::bip158::BlockFilter;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address, BlockHash};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct FilterMatchKey {
    height: CoreBlockHeight,
    hash: BlockHash,
}

impl FilterMatchKey {
    pub fn new(height: CoreBlockHeight, hash: BlockHash) -> Self {
        Self {
            height,
            hash,
        }
    }
    pub fn height(&self) -> CoreBlockHeight {
        self.height
    }
    pub fn hash(&self) -> &BlockHash {
        &self.hash
    }
}

/// Check compact filters for addresses and return the keys that matched.
pub fn check_compact_filters_for_addresses(
    input: &HashMap<FilterMatchKey, BlockFilter>,
    addresses: Vec<Address>,
) -> BTreeSet<FilterMatchKey> {
    let script_pubkey_bytes: Vec<Vec<u8>> =
        addresses.iter().map(|address| address.script_pubkey().to_bytes()).collect();

    input
        .into_par_iter()
        .filter_map(|(key, filter)| {
            filter
                .match_any(key.hash(), script_pubkey_bytes.iter().map(|v| v.as_slice()))
                .unwrap_or(false)
                .then_some(key.clone())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;
    use dashcore::{Block, Transaction};

    #[test]
    fn test_empty_input_returns_empty() {
        let result = check_compact_filters_for_addresses(&HashMap::new(), vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_empty_addresses_returns_empty() {
        let address = Address::dummy(Network::Regtest, 1);
        let tx = Transaction::dummy(&address, 0..0, &[1]);
        let block = Block::dummy(100, vec![tx]);
        let filter = BlockFilter::dummy(&block);
        let key = FilterMatchKey::new(100, block.block_hash());

        let mut input = HashMap::new();
        input.insert(key.clone(), filter);

        let output = check_compact_filters_for_addresses(&input, vec![]);
        assert!(!output.contains(&key));
    }

    #[test]
    fn test_matching_filter() {
        let address = Address::dummy(Network::Regtest, 1);
        let tx = Transaction::dummy(&address, 0..0, &[1]);
        let block = Block::dummy(100, vec![tx]);
        let filter = BlockFilter::dummy(&block);
        let key = FilterMatchKey::new(100, block.block_hash());

        let mut input = HashMap::new();
        input.insert(key.clone(), filter);

        let output = check_compact_filters_for_addresses(&input, vec![address]);
        assert!(output.contains(&key));
    }

    #[test]
    fn test_non_matching_filter() {
        let address = Address::dummy(Network::Regtest, 1);
        let address_other = Address::dummy(Network::Regtest, 2);

        let tx = Transaction::dummy(&address_other, 0..0, &[1]);
        let block = Block::dummy(100, vec![tx]);
        let filter = BlockFilter::dummy(&block);
        let key = FilterMatchKey::new(100, block.block_hash());

        let mut input = HashMap::new();
        input.insert(key.clone(), filter);

        let output = check_compact_filters_for_addresses(&input, vec![address]);
        assert!(!output.contains(&key));
    }

    #[test]
    fn test_batch_mixed_results() {
        let unrelated_address = Address::dummy(Network::Regtest, 0);
        let address_1 = Address::dummy(Network::Regtest, 1);
        let address_2 = Address::dummy(Network::Regtest, 2);

        let tx_1 = Transaction::dummy(&address_1, 0..0, &[1]);
        let block_1 = Block::dummy(100, vec![tx_1]);
        let filter_1 = BlockFilter::dummy(&block_1);
        let key_1 = FilterMatchKey::new(100, block_1.block_hash());

        let tx_2 = Transaction::dummy(&address_2, 0..0, &[2]);
        let block_2 = Block::dummy(200, vec![tx_2]);
        let filter_2 = BlockFilter::dummy(&block_2);
        let key_2 = FilterMatchKey::new(200, block_2.block_hash());

        let tx_3 = Transaction::dummy(&unrelated_address, 0..0, &[10]);
        let block_3 = Block::dummy(300, vec![tx_3]);
        let filter_3 = BlockFilter::dummy(&block_3);
        let key_3 = FilterMatchKey::new(300, block_3.block_hash());

        let mut input = HashMap::new();
        input.insert(key_1.clone(), filter_1);
        input.insert(key_2.clone(), filter_2);
        input.insert(key_3.clone(), filter_3);

        let output = check_compact_filters_for_addresses(&input, vec![address_1, address_2]);
        assert_eq!(output.len(), 2);
        assert!(output.contains(&key_1));
        assert!(output.contains(&key_2));
        assert!(!output.contains(&key_3));
    }

    #[test]
    fn test_output_sorted_by_height() {
        let address = Address::dummy(Network::Regtest, 1);

        // Create blocks at different heights (inserted in non-sorted order)
        let heights = [500, 100, 300, 200, 400];
        let mut input = HashMap::new();

        for (i, &height) in heights.iter().enumerate() {
            let tx = Transaction::dummy(&address, 0..0, &[i as u64]);
            let block = Block::dummy(height, vec![tx]);
            let filter = BlockFilter::dummy(&block);
            let key = FilterMatchKey::new(height, block.block_hash());
            input.insert(key, filter);
        }

        let output = check_compact_filters_for_addresses(&input, vec![address]);

        // Verify output is sorted by height (ascending)
        let heights_out: Vec<CoreBlockHeight> = output.iter().map(|k| k.height()).collect();
        let mut sorted_heights = heights_out.clone();
        sorted_heights.sort();

        assert_eq!(heights_out, sorted_heights);
        assert_eq!(heights_out, vec![100, 200, 300, 400, 500]);
    }
}
