use dashcore::bip158::{BlockFilter, FilterQuery};
use dashcore::prelude::CoreBlockHeight;
use dashcore::{BlockHash, ScriptBuf};
#[cfg(feature = "parallel-filters")]
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

/// Check compact filters against a set of scriptPubKeys plus any bare
/// filter elements, returning the keys that matched.
///
/// `extra_elements` carries arbitrary-length elements a peer inserts into the
/// compact filter that are not scriptPubKeys, notably the provider owner/voting
/// key hashes (bare 20-byte `hash160`) from a `ProRegTx`. They fold into the
/// same [`FilterQuery`] as the scripts, landing in its `other` length bucket.
///
/// Entries with `key.height() <= min_height` are skipped. Pass `0` to test
/// every filter in the input.
pub fn check_compact_filters_for_elements(
    input: &HashMap<FilterMatchKey, BlockFilter>,
    script_pubkeys: &[ScriptBuf],
    extra_elements: &[Vec<u8>],
    min_height: CoreBlockHeight,
) -> BTreeSet<FilterMatchKey> {
    // Group the scripts and bare elements by length once; the same query is
    // reused across every filter.
    let mut query: FilterQuery = script_pubkeys.iter().map(|s| s.as_bytes()).collect();
    for element in extra_elements {
        query.push(element);
    }
    let match_filter = |(key, filter): (&FilterMatchKey, &BlockFilter)| {
        if key.height() <= min_height {
            return None;
        }
        match filter.match_any(key.hash(), &query) {
            Ok(true) => Some(key.clone()),
            Ok(false) => None,
            Err(e) => {
                tracing::warn!(
                    "filter match_any error at height {}: {}; treating as non-match",
                    key.height(),
                    e
                );
                None
            }
        }
    };

    #[cfg(feature = "parallel-filters")]
    {
        input.into_par_iter().filter_map(match_filter).collect()
    }

    #[cfg(not(feature = "parallel-filters"))]
    {
        input.iter().filter_map(match_filter).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::address::Payload;
    use dashcore::bip158::BlockFilterWriter;
    use dashcore::{Address, Block, OutPoint, Transaction, Txid};
    use key_wallet::Network;

    fn scripts_for(addresses: &[Address]) -> Vec<ScriptBuf> {
        addresses.iter().map(|a| a.script_pubkey()).collect()
    }

    /// The bare 20-byte `hash160` a peer inserts for a P2PKH address.
    fn hash160_of(address: &Address) -> Vec<u8> {
        match address.payload() {
            Payload::PubkeyHash(hash) => <[u8; 20]>::from(*hash).to_vec(),
            other => panic!("expected P2PKH dummy address, got {other:?}"),
        }
    }

    #[test]
    fn test_empty_input_returns_empty() {
        let result = check_compact_filters_for_elements(&HashMap::new(), &[], &[], 0);
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

        let output = check_compact_filters_for_elements(&input, &[], &[], 0);
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

        let scripts = scripts_for(&[address]);
        let output = check_compact_filters_for_elements(&input, &scripts, &[], 0);
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

        let scripts = scripts_for(&[address]);
        let output = check_compact_filters_for_elements(&input, &scripts, &[], 0);
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

        let scripts = scripts_for(&[address_1, address_2]);
        let output = check_compact_filters_for_elements(&input, &scripts, &[], 0);
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

        let scripts = scripts_for(&[address]);
        let output = check_compact_filters_for_elements(&input, &scripts, &[], 0);

        // Verify output is sorted by height (ascending)
        let heights_out: Vec<CoreBlockHeight> = output.iter().map(|k| k.height()).collect();
        let mut sorted_heights = heights_out.clone();
        sorted_heights.sort();

        assert_eq!(heights_out, sorted_heights);
        assert_eq!(heights_out, vec![100, 200, 300, 400, 500]);
    }

    /// A masternode owner watching only the owner/voting key sees a compact
    /// filter that carries that key as a bare 20-byte `hash160` (the way Dash
    /// Core's `ExtractSpecialTxFilterElements` inserts it), not as a P2PKH
    /// script. The scripts-only query must miss it and the bare-element query
    /// must hit it, which is exactly the gap this change closes.
    #[test]
    fn test_bare_owner_key_hash_requires_extra_element() {
        // The owner key hash a peer inserts as a bare element.
        let owner_address = Address::dummy(Network::Regtest, 7);
        let owner_hash = hash160_of(&owner_address);
        assert_eq!(owner_hash.len(), 20, "provider owner key is a 20-byte hash160");

        // An unrelated output so the filter is realistic.
        let unrelated = Address::dummy(Network::Regtest, 99);
        let tx = Transaction::dummy(&unrelated, 0..0, &[1]);
        let block = Block::dummy(100, vec![tx]);

        // Build the filter like a Dash Core peer: block output scripts plus the
        // owner key hash as a bare element.
        let mut content = Vec::new();
        {
            let mut writer = BlockFilterWriter::new(&mut content, &block);
            writer.add_output_scripts();
            writer.add_element(&owner_hash);
            writer.finish().expect("finish filter");
        }
        let filter = BlockFilter::new(&content);
        let key = FilterMatchKey::new(100, block.block_hash());

        let mut input = HashMap::new();
        input.insert(key.clone(), filter);

        // The P2PKH scriptPubKey form of the owner address does not match the
        // bare 20-byte element.
        let owner_script = scripts_for(&[owner_address]);
        let scripts_only = check_compact_filters_for_elements(&input, &owner_script, &[], 0);
        assert!(!scripts_only.contains(&key), "scripts-only query must miss the bare hash");

        // Carrying the bare hash in `extra_elements` matches.
        let with_element = check_compact_filters_for_elements(&input, &[], &[owner_hash], 0);
        assert!(with_element.contains(&key), "bare-element query must match");
    }

    /// A wallet that owns a masternode's 1000-DASH collateral output but not
    /// its owner/voting keys sees a compact filter that carries the
    /// `ProRegTx`'s `collateralOutpoint` as a bare 36-byte consensus-serialized
    /// element (the way Dash Core's `ExtractSpecialTxFilterElements` inserts
    /// it), not as one of the block's scriptPubKeys. The scripts-only query
    /// must miss it and the query carrying the serialized outpoint must hit it.
    #[test]
    fn test_collateral_outpoint_requires_extra_element() {
        // The collateral outpoint a peer inserts as a bare element.
        let outpoint = OutPoint::new(Txid::from([7u8; 32]), 1);
        let serialized = dashcore::consensus::encode::serialize(&outpoint);
        assert_eq!(serialized.len(), 36, "outpoint serializes to txid ++ le-vout");

        // An unrelated output so the filter is realistic.
        let unrelated = Address::dummy(Network::Regtest, 99);
        let tx = Transaction::dummy(&unrelated, 0..0, &[1]);
        let block = Block::dummy(100, vec![tx]);

        // Build the filter like a Dash Core peer: block output scripts plus the
        // collateral outpoint as a bare element.
        let mut content = Vec::new();
        {
            let mut writer = BlockFilterWriter::new(&mut content, &block);
            writer.add_output_scripts();
            writer.add_element(&serialized);
            writer.finish().expect("finish filter");
        }
        let filter = BlockFilter::new(&content);
        let key = FilterMatchKey::new(100, block.block_hash());

        let mut input = HashMap::new();
        input.insert(key.clone(), filter);

        // A wallet watching only its own addresses (none of them in this block)
        // does not carry the bare 36-byte outpoint element and misses.
        let watched = Address::dummy(Network::Regtest, 7);
        let scripts_only =
            check_compact_filters_for_elements(&input, &scripts_for(&[watched]), &[], 0);
        assert!(!scripts_only.contains(&key), "scripts-only query must miss the outpoint");

        // Carrying the serialized outpoint in `extra_elements` matches.
        let with_element = check_compact_filters_for_elements(&input, &[], &[serialized], 0);
        assert!(with_element.contains(&key), "serialized-outpoint query must match");
    }
}
