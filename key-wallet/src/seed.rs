//! BIP32 seed implementation
//!
//! A seed is a 512-bit (64 bytes) value used to derive HD wallet keys.

use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use core::fmt;
use core::str::FromStr;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};
use dashcore_hashes::hex::FromHex;

/// A BIP32 seed (512 bits / 64 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct Seed([u8; 64]);

impl Seed {
    /// Create a new seed from bytes
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Create a seed from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 64 {
            return Err(Error::InvalidParameter(format!(
                "Invalid seed length: expected 64 bytes, got {}",
                slice.len()
            )));
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get the seed as bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Get the seed as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Convert to a byte array
    pub fn to_bytes(self) -> [u8; 64] {
        self.0
    }

    /// Create a seed from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = Vec::<u8>::from_hex(hex_str)
            .map_err(|e| Error::InvalidParameter(format!("Invalid hex: {}", e)))?;
        Self::from_slice(&bytes)
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        use core::fmt::Write;
        let mut s = String::new();
        for byte in &self.0 {
            write!(&mut s, "{:02x}", byte).unwrap();
        }
        s
    }

    /// Check if the seed is all zeros (empty/invalid)
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Generate a random seed (requires getrandom feature)
    #[cfg(feature = "getrandom")]
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; 64];
        getrandom::getrandom(&mut bytes).map_err(|e| {
            Error::InvalidParameter(format!("Failed to generate random seed: {}", e))
        })?;
        Ok(Self(bytes))
    }
}

impl Default for Seed {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl From<[u8; 64]> for Seed {
    fn from(bytes: [u8; 64]) -> Self {
        Self::new(bytes)
    }
}

impl From<Seed> for [u8; 64] {
    fn from(seed: Seed) -> [u8; 64] {
        seed.0
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't expose the actual seed in debug output for security
        write!(f, "Seed(***)")
    }
}

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show first and last 4 bytes in hex
        use core::fmt::Write;
        let mut start = String::new();
        let mut end = String::new();
        for byte in &self.0[..4] {
            write!(&mut start, "{:02x}", byte).unwrap();
        }
        for byte in &self.0[60..] {
            write!(&mut end, "{:02x}", byte).unwrap();
        }
        write!(f, "Seed({}...{})", start, end)
    }
}

impl FromStr for Seed {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Seed {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Seed {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SeedVisitor;

        impl<'de> serde::de::Visitor<'de> for SeedVisitor {
            type Value = Seed;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 64-byte seed")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 64 {
                    return Err(E::custom(format!("expected 64 bytes, got {}", v.len())));
                }
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(v);
                Ok(Seed(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 64];
                for i in 0..64 {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(Seed(bytes))
            }
        }

        deserializer.deserialize_bytes(SeedVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_creation() {
        let bytes = [1u8; 64];
        let seed = Seed::new(bytes);
        assert_eq!(seed.as_bytes(), &bytes);
        assert_eq!(seed.to_bytes(), bytes);
    }

    #[test]
    fn test_seed_from_slice() {
        let bytes = vec![2u8; 64];
        let seed = Seed::from_slice(&bytes).unwrap();
        assert_eq!(seed.as_slice(), &bytes[..]);

        // Test invalid length
        let short = vec![3u8; 32];
        assert!(Seed::from_slice(&short).is_err());

        let long = vec![4u8; 128];
        assert!(Seed::from_slice(&long).is_err());
    }

    #[test]
    fn test_seed_hex() {
        let bytes = [5u8; 64];
        let seed = Seed::new(bytes);
        let hex = seed.to_hex();
        assert_eq!(hex.len(), 128); // 64 bytes * 2 chars per byte

        let seed2 = Seed::from_hex(&hex).unwrap();
        assert_eq!(seed, seed2);

        // Test invalid hex
        assert!(Seed::from_hex("invalid").is_err());
        assert!(Seed::from_hex("00").is_err()); // Too short
    }

    #[test]
    fn test_seed_zero() {
        let zero = Seed::default();
        assert!(zero.is_zero());

        let nonzero = Seed::new([1u8; 64]);
        assert!(!nonzero.is_zero());
    }

    #[test]
    fn test_seed_display() {
        let mut bytes = [0u8; 64];
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        bytes[2] = 0xbe;
        bytes[3] = 0xef;
        bytes[60] = 0xca;
        bytes[61] = 0xfe;
        bytes[62] = 0xba;
        bytes[63] = 0xbe;

        let seed = Seed::new(bytes);
        let display = format!("{}", seed);
        assert_eq!(display, "Seed(deadbeef...cafebabe)");

        let debug = format!("{:?}", seed);
        assert_eq!(debug, "Seed(***)");
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_seed_random() {
        let seed1 = Seed::random().unwrap();
        let seed2 = Seed::random().unwrap();

        // Should be different (extremely unlikely to be the same)
        assert_ne!(seed1, seed2);

        // Should not be zero
        assert!(!seed1.is_zero());
        assert!(!seed2.is_zero());
    }
}
