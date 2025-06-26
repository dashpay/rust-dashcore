//! Bloom filter construction utilities

use super::utils::{extract_pubkey_hash, outpoint_to_bytes};
use crate::error::SpvError;
use crate::wallet::Wallet;
use dashcore::address::Address;
use dashcore::bloom::{BloomFilter, BloomFlags};
use dashcore::OutPoint;

/// Builder for constructing bloom filters from wallet state
pub struct BloomFilterBuilder {
    /// Expected number of elements
    elements: u32,
    /// Desired false positive rate
    false_positive_rate: f64,
    /// Random tweak value
    tweak: u32,
    /// Update flags
    flags: BloomFlags,
    /// Addresses to include
    addresses: Vec<Address>,
    /// Outpoints to include
    outpoints: Vec<OutPoint>,
    /// Raw data elements to include
    data_elements: Vec<Vec<u8>>,
}

impl BloomFilterBuilder {
    /// Create a new bloom filter builder
    pub fn new() -> Self {
        Self {
            elements: 100,
            false_positive_rate: 0.001,
            tweak: rand::random::<u32>(),
            flags: BloomFlags::All,
            addresses: Vec::new(),
            outpoints: Vec::new(),
            data_elements: Vec::new(),
        }
    }

    /// Set the expected number of elements
    pub fn elements(mut self, elements: u32) -> Self {
        self.elements = elements;
        self
    }

    /// Set the false positive rate
    pub fn false_positive_rate(mut self, rate: f64) -> Self {
        self.false_positive_rate = rate;
        self
    }

    /// Set the tweak value
    pub fn tweak(mut self, tweak: u32) -> Self {
        self.tweak = tweak;
        self
    }

    /// Set the update flags
    pub fn flags(mut self, flags: BloomFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Add an address to the filter
    pub fn add_address(mut self, address: Address) -> Self {
        self.addresses.push(address);
        self
    }

    /// Add multiple addresses
    pub fn add_addresses(mut self, addresses: impl IntoIterator<Item = Address>) -> Self {
        self.addresses.extend(addresses);
        self
    }

    /// Add an outpoint to the filter
    pub fn add_outpoint(mut self, outpoint: OutPoint) -> Self {
        self.outpoints.push(outpoint);
        self
    }

    /// Add multiple outpoints
    pub fn add_outpoints(mut self, outpoints: impl IntoIterator<Item = OutPoint>) -> Self {
        self.outpoints.extend(outpoints);
        self
    }

    /// Add raw data to the filter
    pub fn add_data(mut self, data: Vec<u8>) -> Self {
        self.data_elements.push(data);
        self
    }

    /// Build a bloom filter from wallet state
    pub async fn from_wallet(wallet: &Wallet) -> Result<Self, SpvError> {
        let mut builder = Self::new();

        // Add all wallet addresses
        let addresses = wallet.get_all_addresses().await?;
        builder = builder.add_addresses(addresses);

        // Add unspent outputs
        let utxos = wallet.get_unspent_outputs().await?;
        let outpoints = utxos.into_iter().map(|utxo| utxo.outpoint);
        builder = builder.add_outpoints(outpoints);

        // Set reasonable parameters based on wallet size
        let total_elements = builder.addresses.len() + builder.outpoints.len();
        builder = builder.elements(std::cmp::max(100, total_elements as u32 * 2));

        Ok(builder)
    }

    /// Build the bloom filter
    pub fn build(self) -> Result<BloomFilter, SpvError> {
        // Calculate actual elements
        let actual_elements =
            self.addresses.len() + self.outpoints.len() + self.data_elements.len();
        let elements = std::cmp::max(self.elements, actual_elements as u32);

        // Create filter
        let mut filter =
            BloomFilter::new(elements, self.false_positive_rate, self.tweak, self.flags).map_err(
                |e| SpvError::General(format!("Failed to create bloom filter: {:?}", e)),
            )?;

        // Add addresses
        for address in self.addresses {
            let script = address.script_pubkey();
            filter.insert(script.as_bytes());

            // For P2PKH, also add the pubkey hash
            if let Some(hash) = extract_pubkey_hash(&script) {
                filter.insert(&hash);
            }
        }

        // Add outpoints
        for outpoint in self.outpoints {
            filter.insert(&outpoint_to_bytes(&outpoint));
        }

        // Add raw data
        for data in self.data_elements {
            filter.insert(&data);
        }

        Ok(filter)
    }
}

impl Default for BloomFilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}
