//! High-performance UTXO cache for wallet manager
//!
//! This module provides an in-memory cache for UTXOs with address indexing
//! for fast lookups and efficient transaction processing.

use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "std")]
use std::sync::{Arc, RwLock};

use dashcore::{Address, OutPoint};
use key_wallet::Utxo;

/// High-performance UTXO cache with address indexing
pub struct UtxoCache {
    /// In-memory UTXO cache for high performance
    #[cfg(feature = "std")]
    utxo_cache: Arc<RwLock<HashMap<OutPoint, Utxo>>>,
    #[cfg(not(feature = "std"))]
    utxo_cache: BTreeMap<OutPoint, Utxo>,

    /// Index for efficient UTXO lookups by address
    #[cfg(feature = "std")]
    utxo_address_index: Arc<RwLock<HashMap<Address, Vec<OutPoint>>>>,
    #[cfg(not(feature = "std"))]
    utxo_address_index: BTreeMap<Address, Vec<OutPoint>>,

    /// Flag indicating if cache has been modified
    #[cfg(feature = "std")]
    cache_dirty: Arc<AtomicBool>,
    #[cfg(not(feature = "std"))]
    cache_dirty: bool,
}

impl UtxoCache {
    /// Create a new UTXO cache
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            utxo_cache: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(not(feature = "std"))]
            utxo_cache: BTreeMap::new(),

            #[cfg(feature = "std")]
            utxo_address_index: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(not(feature = "std"))]
            utxo_address_index: BTreeMap::new(),

            #[cfg(feature = "std")]
            cache_dirty: Arc::new(AtomicBool::new(false)),
            #[cfg(not(feature = "std"))]
            cache_dirty: false,
        }
    }

    /// Add a UTXO to the cache
    #[cfg(feature = "std")]
    pub fn add_utxo(&self, utxo: Utxo) {
        let outpoint = utxo.outpoint;
        let address = utxo.address.clone();

        // Add to main cache
        {
            let mut cache = self.utxo_cache.write().unwrap();
            cache.insert(outpoint, utxo);
        }

        // Update address index
        {
            let mut index = self.utxo_address_index.write().unwrap();
            index.entry(address).or_insert_with(Vec::new).push(outpoint);
        }

        self.cache_dirty.store(true, Ordering::Relaxed);
    }

    /// Add a UTXO to the cache (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn add_utxo(&mut self, utxo: Utxo) {
        let outpoint = utxo.outpoint;
        let address = utxo.address.clone();

        self.utxo_cache.insert(outpoint, utxo);
        self.utxo_address_index.entry(address).or_insert_with(Vec::new).push(outpoint);
        self.cache_dirty = true;
    }

    /// Remove a UTXO from the cache
    #[cfg(feature = "std")]
    pub fn remove_utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        // Remove from main cache
        let utxo = {
            let mut cache = self.utxo_cache.write().unwrap();
            cache.remove(outpoint)
        };

        // Update address index if UTXO was found
        if let Some(ref utxo) = utxo {
            let mut index = self.utxo_address_index.write().unwrap();
            if let Some(outpoints) = index.get_mut(&utxo.address) {
                outpoints.retain(|op| op != outpoint);
                if outpoints.is_empty() {
                    index.remove(&utxo.address);
                }
            }
            self.cache_dirty.store(true, Ordering::Relaxed);
        }

        utxo
    }

    /// Remove a UTXO from the cache (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn remove_utxo(&mut self, outpoint: &OutPoint) -> Option<Utxo> {
        let utxo = self.utxo_cache.remove(outpoint);

        if let Some(ref utxo) = utxo {
            if let Some(outpoints) = self.utxo_address_index.get_mut(&utxo.address) {
                outpoints.retain(|op| op != outpoint);
                if outpoints.is_empty() {
                    self.utxo_address_index.remove(&utxo.address);
                }
            }
            self.cache_dirty = true;
        }

        utxo
    }

    /// Get UTXOs for a specific address
    #[cfg(feature = "std")]
    pub fn get_utxos_for_address(&self, address: &Address) -> Vec<Utxo> {
        let index = self.utxo_address_index.read().unwrap();
        let cache = self.utxo_cache.read().unwrap();

        if let Some(outpoints) = index.get(address) {
            outpoints.iter().filter_map(|op| cache.get(op).cloned()).collect()
        } else {
            Vec::new()
        }
    }

    /// Get UTXOs for a specific address (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn get_utxos_for_address(&self, address: &Address) -> Vec<Utxo> {
        if let Some(outpoints) = self.utxo_address_index.get(address) {
            outpoints.iter().filter_map(|op| self.utxo_cache.get(op).cloned()).collect()
        } else {
            Vec::new()
        }
    }

    /// Get all UTXOs
    #[cfg(feature = "std")]
    pub fn get_all_utxos(&self) -> HashMap<OutPoint, Utxo> {
        self.utxo_cache.read().unwrap().clone()
    }

    /// Get all UTXOs (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn get_all_utxos(&self) -> BTreeMap<OutPoint, Utxo> {
        self.utxo_cache.clone()
    }

    /// Check if cache is dirty
    #[cfg(feature = "std")]
    pub fn is_dirty(&self) -> bool {
        self.cache_dirty.load(Ordering::Relaxed)
    }

    /// Check if cache is dirty (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn is_dirty(&self) -> bool {
        self.cache_dirty
    }

    /// Mark cache as clean
    #[cfg(feature = "std")]
    pub fn mark_clean(&self) {
        self.cache_dirty.store(false, Ordering::Relaxed);
    }

    /// Mark cache as clean (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn mark_clean(&mut self) {
        self.cache_dirty = false;
    }

    /// Clear the cache
    #[cfg(feature = "std")]
    pub fn clear(&self) {
        self.utxo_cache.write().unwrap().clear();
        self.utxo_address_index.write().unwrap().clear();
        self.cache_dirty.store(false, Ordering::Relaxed);
    }

    /// Clear the cache (no_std version)
    #[cfg(not(feature = "std"))]
    pub fn clear(&mut self) {
        self.utxo_cache.clear();
        self.utxo_address_index.clear();
        self.cache_dirty = false;
    }
}

impl Default for UtxoCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::{TxOut, Txid};
    use dashcore_hashes::Hash;
    use key_wallet::Network;

    #[test]
    fn test_utxo_cache_operations() {
        let mut cache = UtxoCache::new();

        // Create a test UTXO
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        // Create a test address
        let address = Address::p2pkh(
            &dashcore::PublicKey::from_slice(&[
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01,
            ])
            .unwrap(),
            Network::Dash,
        );

        let utxo = Utxo {
            outpoint,
            txout: TxOut {
                value: 100000,
                script_pubkey: ScriptBuf::new(),
            },
            address: address.clone(),
            height: 100,
            is_coinbase: false,
            is_confirmed: true,
            is_instantlocked: false,
            is_locked: false,
        };

        // Add UTXO
        cache.add_utxo(utxo.clone());

        // Get UTXOs for address
        let utxos = cache.get_utxos_for_address(&address);
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].outpoint, outpoint);

        // Remove UTXO
        let removed = cache.remove_utxo(&outpoint);
        assert!(removed.is_some());

        // Verify it's gone
        let utxos = cache.get_utxos_for_address(&address);
        assert_eq!(utxos.len(), 0);
    }
}
