//! Tests for address pool management
//!
//! Tests address generation, gap limit enforcement, and pool operations.

use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::managed_account::address_pool::{AddressPool, AddressPoolType, KeySource};
use crate::mnemonic::Mnemonic;
use crate::Network;
use std::collections::HashSet;

fn test_key_source() -> (KeySource, ExtendedPubKey) {
    let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    .unwrap();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivKey::new_master(Network::Testnet, &seed[..]).unwrap();

    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44).unwrap(),
        ChildNumber::from_hardened_idx(1).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    let account_key = master.derive_priv(&path).unwrap();
    let xpub = ExtendedPubKey::from_priv(&account_key);

    (KeySource::Private(account_key), xpub)
}

#[test]
fn test_next_unused_multiple() {
    let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
    let mut pool = AddressPool::new_without_generation(
        base_path,
        AddressPoolType::External,
        20,
        Network::Testnet,
    );
    let (key_source, _) = test_key_source();

    // Test getting multiple unused addresses
    let addresses = pool.next_unused_multiple(5, &key_source, true);
    assert_eq!(addresses.len(), 5);
    assert_eq!(pool.highest_generated, Some(4));

    // Verify all addresses are unique
    let unique_check: HashSet<_> = addresses.iter().collect();
    assert_eq!(unique_check.len(), 5);

    // Mark some as used
    pool.mark_used(&addresses[0]);
    pool.mark_used(&addresses[2]);

    // Reserve the first remaining unused address: it must be skipped too.
    let reserved = pool.next_unused_and_reserve(&key_source, 100).unwrap();
    assert_eq!(reserved, addresses[1]);

    // Request more addresses: should skip used and reserved, returning the
    // remaining generated ones plus freshly derived ones to satisfy the count.
    let more_addresses = pool.next_unused_multiple(5, &key_source, true);
    assert_eq!(more_addresses.len(), 5);
    assert!(!more_addresses.contains(&reserved));
    assert_eq!(more_addresses[0], addresses[3]); // First available
    assert_eq!(more_addresses[1], addresses[4]); // Second available
                                                 // remaining entries are newly generated

    assert_eq!(pool.highest_generated, Some(7)); // Generated 3 more
}

#[test]
fn test_next_unused_multiple_no_key_source() {
    let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
    let mut pool = AddressPool::new_without_generation(
        base_path,
        AddressPoolType::External,
        20,
        Network::Testnet,
    );

    let no_key_source = KeySource::NoKeySource;

    // With NoKeySource and no pre-generated addresses, should return empty vec
    let addresses = pool.next_unused_multiple(5, &no_key_source, true);
    assert_eq!(addresses.len(), 0);

    // Generate some addresses first with a real key source
    let (key_source, _) = test_key_source();
    pool.generate_addresses(3, &key_source, true).unwrap();

    // Now with NoKeySource, should return existing unused addresses
    let addresses = pool.next_unused_multiple(5, &no_key_source, true);
    assert_eq!(addresses.len(), 3); // Only the 3 we generated

    // Mark one as used
    pool.mark_used(&addresses[0]);

    // Should now return only 2 unused addresses
    let addresses = pool.next_unused_multiple(5, &no_key_source, true);
    assert_eq!(addresses.len(), 2);
}

#[test]
fn test_next_unused_multiple_large_batch() {
    let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
    let mut pool = AddressPool::new_without_generation(
        base_path,
        AddressPoolType::External,
        20,
        Network::Testnet,
    );
    let (key_source, _) = test_key_source();

    // Test generating a large batch efficiently
    let addresses = pool.next_unused_multiple(100, &key_source, true);
    assert_eq!(addresses.len(), 100);
    assert_eq!(pool.highest_generated, Some(99));

    // All addresses should be unique
    let unique_check: HashSet<_> = addresses.iter().collect();
    assert_eq!(unique_check.len(), 100);
}

#[test]
fn test_next_unused_multiple_mixed_usage() {
    let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
    let mut pool = AddressPool::new_without_generation(
        base_path,
        AddressPoolType::Internal, // Test with internal pool type
        20,
        Network::Testnet,
    );
    let (key_source, _) = test_key_source();

    // Generate initial batch
    let initial = pool.next_unused_multiple(10, &key_source, true);
    assert_eq!(initial.len(), 10);

    // Mark every other address as used
    for i in (0..10).step_by(2) {
        pool.mark_used(&initial[i]);
    }

    // Request 8 addresses - should get 5 unused + 3 new
    let next_batch = pool.next_unused_multiple(8, &key_source, true);
    assert_eq!(next_batch.len(), 8);

    // First 5 should be the unused ones from initial batch
    assert_eq!(next_batch[0], initial[1]);
    assert_eq!(next_batch[1], initial[3]);
    assert_eq!(next_batch[2], initial[5]);
    assert_eq!(next_batch[3], initial[7]);
    assert_eq!(next_batch[4], initial[9]);

    // Last 3 should be new addresses
    assert!(!initial.contains(&next_batch[5]));
    assert!(!initial.contains(&next_batch[6]));
    assert!(!initial.contains(&next_batch[7]));
}
