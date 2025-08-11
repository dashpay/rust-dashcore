//! Address generation and encoding

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use bitcoin_hashes::{hash160, Hash};
use secp256k1::{PublicKey, Secp256k1};

use crate::error::{Error, Result};
use dash_network::Network;

/// Address types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// Pay to public key hash (P2PKH)
    P2PKH,
    /// Pay to script hash (P2SH)
    P2SH,
}

/// Extension trait for Network to add address-specific methods
pub trait NetworkExt {
    /// Get P2PKH version byte
    fn p2pkh_version(&self) -> u8;
    /// Get P2SH version byte
    fn p2sh_version(&self) -> u8;
}

impl NetworkExt for Network {
    /// Get P2PKH version byte
    fn p2pkh_version(&self) -> u8 {
        match self {
            Network::Dash => 76,     // 'X' prefix
            Network::Testnet => 140, // 'y' prefix
            Network::Devnet => 140,  // 'y' prefix
            Network::Regtest => 140, // 'y' prefix
            _ => 140,                // default to testnet version
        }
    }

    /// Get P2SH version byte
    fn p2sh_version(&self) -> u8 {
        match self {
            Network::Dash => 16,    // '7' prefix
            Network::Testnet => 19, // '8' or '9' prefix
            Network::Devnet => 19,  // '8' or '9' prefix
            Network::Regtest => 19, // '8' or '9' prefix
            _ => 19,                // default to testnet version
        }
    }
}

/// A Dash address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// The network this address is valid for
    pub network: Network,
    /// The type of address
    pub address_type: AddressType,
    /// The hash160 of the public key or script
    pub hash: hash160::Hash,
}

impl Address {
    /// Create a P2PKH address from a public key
    pub fn p2pkh(pubkey: &PublicKey, network: Network) -> Self {
        let hash = hash160::Hash::hash(&pubkey.serialize());
        Self {
            network,
            address_type: AddressType::P2PKH,
            hash,
        }
    }

    /// Create a P2SH address from a script hash
    pub fn p2sh(script_hash: hash160::Hash, network: Network) -> Self {
        Self {
            network,
            address_type: AddressType::P2SH,
            hash: script_hash,
        }
    }

    /// Encode the address as a string
    pub fn to_string(&self) -> String {
        let version = match self.address_type {
            AddressType::P2PKH => self.network.p2pkh_version(),
            AddressType::P2SH => self.network.p2sh_version(),
        };

        let mut data = Vec::with_capacity(21);
        data.push(version);
        data.extend_from_slice(&self.hash[..]);

        base58ck::encode_check(&data)
    }

    /// Parse an address from a string (network is inferred from version byte)
    pub fn from_string(s: &str) -> Result<Self> {
        s.parse()
    }

    /// Get the script pubkey for this address
    pub fn script_pubkey(&self) -> Vec<u8> {
        match self.address_type {
            AddressType::P2PKH => {
                let mut script = Vec::with_capacity(25);
                script.push(0x76); // OP_DUP
                script.push(0xa9); // OP_HASH160
                script.push(0x14); // Push 20 bytes
                script.extend_from_slice(&self.hash[..]);
                script.push(0x88); // OP_EQUALVERIFY
                script.push(0xac); // OP_CHECKSIG
                script
            }
            AddressType::P2SH => {
                let mut script = Vec::with_capacity(23);
                script.push(0xa9); // OP_HASH160
                script.push(0x14); // Push 20 bytes
                script.extend_from_slice(&self.hash[..]);
                script.push(0x87); // OP_EQUAL
                script
            }
        }
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let data = base58ck::decode_check(s)
            .map_err(|_| Error::InvalidAddress("Invalid base58 encoding".into()))?;

        if data.len() != 21 {
            return Err(Error::InvalidAddress("Invalid address length".into()));
        }

        let version = data[0];
        let hash = hash160::Hash::from_slice(&data[1..])
            .map_err(|_| Error::InvalidAddress("Invalid hash".into()))?;

        // Infer network and address type from version byte
        let (network, address_type) = match version {
            76 => (Network::Dash, AddressType::P2PKH), // Dash mainnet P2PKH
            16 => (Network::Dash, AddressType::P2SH),  // Dash mainnet P2SH
            140 => {
                // Could be testnet, devnet, or regtest P2PKH
                // Default to testnet, but this is ambiguous
                (Network::Testnet, AddressType::P2PKH)
            }
            19 => {
                // Could be testnet, devnet, or regtest P2SH
                // Default to testnet, but this is ambiguous
                (Network::Testnet, AddressType::P2SH)
            }
            _ => return Err(Error::InvalidAddress(format!("Unknown version byte: {}", version))),
        };

        Ok(Self {
            network,
            address_type,
            hash,
        })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Generate addresses from extended public keys
pub struct AddressGenerator {
    network: Network,
}

impl AddressGenerator {
    /// Create a new address generator
    pub fn new(network: Network) -> Self {
        Self {
            network,
        }
    }

    /// Generate a P2PKH address from an extended public key
    pub fn generate_p2pkh(&self, xpub: &crate::bip32::ExtendedPubKey) -> Address {
        Address::p2pkh(&xpub.public_key, self.network)
    }

    /// Generate addresses for a range of indices
    pub fn generate_range(
        &self,
        account_xpub: &crate::bip32::ExtendedPubKey,
        external: bool,
        start: u32,
        count: u32,
    ) -> Result<Vec<Address>> {
        let secp = Secp256k1::new();
        let mut addresses = Vec::with_capacity(count as usize);

        let change = if external {
            0
        } else {
            1
        };

        for i in start..(start + count) {
            // Create relative path from account
            let path = crate::bip32::DerivationPath::from(vec![
                crate::bip32::ChildNumber::Normal {
                    index: change,
                },
                crate::bip32::ChildNumber::Normal {
                    index: i,
                },
            ]);

            let child_xpub = account_xpub.derive_pub(&secp, &path)?;
            addresses.push(self.generate_p2pkh(&child_xpub));
        }

        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_encoding() {
        // Test vector from Dash
        let pubkey_hex = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";
        let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
        let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();

        let address = Address::p2pkh(&pubkey, Network::Dash);
        let encoded = address.to_string();

        // Verify it starts with 'X' for mainnet P2PKH
        assert!(encoded.starts_with('X'));
    }

    #[test]
    fn test_address_parsing() {
        let address_str = "XmnGSJav3CWVmzDv5U68k7XT9rRPqyavtE";
        let address = Address::from_str(address_str).unwrap();

        assert_eq!(address.address_type, AddressType::P2PKH);
        assert_eq!(address.network, Network::Dash);
        assert_eq!(address.to_string(), address_str);
    }
}
