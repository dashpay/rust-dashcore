//! Tests for address pool management
//!
//! Tests address generation, gap limit enforcement, and pool operations.

use crate::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use crate::managed_account::address_pool::{AddressPool, AddressPoolType, KeySource};
use crate::mnemonic::{Language, Mnemonic};
use crate::Network;
use secp256k1::Secp256k1;
use std::collections::HashSet;

fn test_key_source() -> (KeySource, ExtendedPubKey) {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    )
    .unwrap();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();

    let secp = Secp256k1::new();
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44).unwrap(),
        ChildNumber::from_hardened_idx(1).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    let account_key = master.derive_priv(&secp, &path).unwrap();
    let xpub = ExtendedPubKey::from_priv(&secp, &account_key);

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

    // Request more addresses - should get 3 unused + 2 new
    let more_addresses = pool.next_unused_multiple(5, &key_source, true);
    assert_eq!(more_addresses.len(), 5);
    assert_eq!(more_addresses[0], addresses[1]); // First unused
    assert_eq!(more_addresses[1], addresses[3]); // Second unused
    assert_eq!(more_addresses[2], addresses[4]); // Third unused
                                                 // more_addresses[3] and [4] should be newly generated

    assert_eq!(pool.highest_generated, Some(6)); // Generated 2 more
}

#[test]
fn test_next_unused_multiple_with_info() {
    let base_path = DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]);
    let mut pool = AddressPool::new_without_generation(
        base_path,
        AddressPoolType::External,
        20,
        Network::Testnet,
    );
    let (key_source, _) = test_key_source();

    // Test getting multiple addresses with info
    let address_infos = pool.next_unused_multiple_with_info(3, &key_source, true);
    assert_eq!(address_infos.len(), 3);

    // Verify the info contains correct data
    for (i, (addr, info)) in address_infos.iter().enumerate() {
        assert_eq!(addr, &info.address);
        assert_eq!(info.index, i as u32);
        assert!(!info.used);
        assert!(info.public_key.is_some());
    }

    // Mark first one as used
    pool.mark_used(&address_infos[0].0);

    // Get more with info - should skip the used one
    let more_infos = pool.next_unused_multiple_with_info(3, &key_source, true);
    assert_eq!(more_infos.len(), 3);
    assert_eq!(more_infos[0].0, address_infos[1].0); // Should skip the first (used) one
    assert_eq!(more_infos[1].0, address_infos[2].0);
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
