use crate::wallet_interface::FilterMatchKey;
use alloc::vec::Vec;
use dashcore::bip158::BlockFilter;
use dashcore::Address;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::collections::{BTreeSet, HashMap};

pub type FilterMatchInput = HashMap<FilterMatchKey, BlockFilter>;
pub type FilterMatchOutput = BTreeSet<FilterMatchKey>;

/// Check compact filters for addresses and return the keys that matched.
pub fn check_compact_filters_for_addresses(
    input: FilterMatchInput,
    addresses: Vec<Address>,
) -> FilterMatchOutput {
    let script_pubkey_bytes: Vec<Vec<u8>> =
        addresses.iter().map(|address| address.script_pubkey().to_bytes()).collect();

    input
        .into_par_iter()
        .filter_map(|(key, filter)| {
            filter
                .match_any(&key.block_hash, script_pubkey_bytes.iter().map(|v| v.as_slice()))
                .unwrap_or(false)
                .then_some(key)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore_test_utils::{
        create_filter_for_block, create_test_block, create_test_transaction_to_script, test_address,
    };

    #[test]
    fn test_empty_input_returns_empty() {
        let result = check_compact_filters_for_addresses(FilterMatchInput::new(), vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_empty_addresses_returns_empty() {
        let tx = create_test_transaction_to_script(ScriptBuf::new());
        let block = create_test_block(100, vec![tx]);
        let filter = create_filter_for_block(&block);
        let key = FilterMatchKey::new(100, block.block_hash());

        let mut input = FilterMatchInput::new();
        input.insert(key.clone(), filter);

        let output = check_compact_filters_for_addresses(input, vec![]);
        assert!(!output.contains(&key));
    }

    #[test]
    fn test_matching_filter() {
        let address = test_address(0);

        let tx = create_test_transaction_to_script(address.script_pubkey());
        let block = create_test_block(100, vec![tx]);
        let filter = create_filter_for_block(&block);
        let key = FilterMatchKey::new(100, block.block_hash());

        let mut input = FilterMatchInput::new();
        input.insert(key.clone(), filter);

        let output = check_compact_filters_for_addresses(input, vec![address]);
        assert!(output.contains(&key));
    }

    #[test]
    fn test_non_matching_filter() {
        let address = test_address(0);
        let other_address = test_address(1);

        let tx = create_test_transaction_to_script(other_address.script_pubkey());
        let block = create_test_block(100, vec![tx]);
        let filter = create_filter_for_block(&block);
        let key = FilterMatchKey::new(100, block.block_hash());

        let mut input = FilterMatchInput::new();
        input.insert(key.clone(), filter);

        let output = check_compact_filters_for_addresses(input, vec![address]);
        assert!(!output.contains(&key));
    }

    #[test]
    fn test_batch_mixed_results() {
        let address1 = test_address(0);
        let address2 = test_address(1);
        let unrelated_address = test_address(2);

        let tx1 = create_test_transaction_to_script(address1.script_pubkey());
        let block1 = create_test_block(100, vec![tx1]);
        let filter1 = create_filter_for_block(&block1);
        let key1 = FilterMatchKey::new(100, block1.block_hash());

        let tx2 = create_test_transaction_to_script(address2.script_pubkey());
        let block2 = create_test_block(200, vec![tx2]);
        let filter2 = create_filter_for_block(&block2);
        let key2 = FilterMatchKey::new(200, block2.block_hash());

        let tx3 = create_test_transaction_to_script(unrelated_address.script_pubkey());
        let block3 = create_test_block(300, vec![tx3]);
        let filter3 = create_filter_for_block(&block3);
        let key3 = FilterMatchKey::new(300, block3.block_hash());

        let mut input = FilterMatchInput::new();
        input.insert(key1.clone(), filter1);
        input.insert(key2.clone(), filter2);
        input.insert(key3.clone(), filter3);

        let output = check_compact_filters_for_addresses(input, vec![address1, address2]);
        assert_eq!(output.len(), 2);
        assert!(output.contains(&key1));
        assert!(output.contains(&key2));
        assert!(!output.contains(&key3));
    }
}
