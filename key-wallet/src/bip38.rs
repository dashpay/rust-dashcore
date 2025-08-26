//! BIP38 password-protected private key encryption
//!
//! This module implements BIP38, which provides a standard way to encrypt
//! private keys with a password using scrypt for key derivation and AES for encryption.
//!
//! BIP38 supports two modes:
//! 1. Non-EC-multiply mode: Simple encryption of existing private keys
//! 2. EC-multiply mode: Generate encrypted keys without knowing the private key
//!
//! Format of encrypted keys:
//! - Prefix: 0x0142 for non-EC-multiply mode (base58 starts with "6P")
//! - Prefix: 0x0143 for EC-multiply mode (base58 starts with "6P")

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::error::{Error, Result};
use crate::Network;
use dashcore::Address;

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

// BIP38 constants
const BIP38_PREFIX_NON_EC: [u8; 2] = [0x01, 0x42];
const BIP38_PREFIX_EC: [u8; 2] = [0x01, 0x43];
const BIP38_FLAG_COMPRESSED: u8 = 0x20;
const BIP38_FLAG_EC_LOT_SEQUENCE: u8 = 0x04;
const _BIP38_FLAG_EC_INVALID: u8 = 0x10;

// Scrypt parameters
#[allow(dead_code)]
const SCRYPT_N: u32 = 16384; // 2^14
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 8;
const SCRYPT_KEY_LEN: usize = 64;

/// BIP38 encryption mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip38Mode {
    /// Non-EC-multiply mode (standard encryption)
    NonEcMultiply,
    /// EC-multiply mode (encryption without private key)
    EcMultiply,
}

/// BIP38 encrypted private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip38EncryptedKey {
    /// The encrypted key data
    data: Vec<u8>,
    /// Encryption mode
    mode: Bip38Mode,
    /// Whether the key is compressed
    compressed: bool,
    /// Network (derived from address)
    network: Network,
}

impl Bip38EncryptedKey {
    /// Create from a base58-encoded BIP38 string
    pub fn from_base58(s: &str) -> Result<Self> {
        let data = bs58::decode(s)
            .with_check(None)
            .into_vec()
            .map_err(|_| Error::InvalidParameter("Invalid base58 encoding".into()))?;

        if data.len() != 39 {
            return Err(Error::InvalidParameter("Invalid BIP38 key length".into()));
        }

        let prefix = [data[0], data[1]];
        let flag = data[2];

        let (mode, compressed) = if prefix == BIP38_PREFIX_NON_EC {
            let compressed = (flag & BIP38_FLAG_COMPRESSED) != 0;
            (Bip38Mode::NonEcMultiply, compressed)
        } else if prefix == BIP38_PREFIX_EC {
            let compressed = (flag & BIP38_FLAG_COMPRESSED) != 0;
            (Bip38Mode::EcMultiply, compressed)
        } else {
            return Err(Error::InvalidParameter("Invalid BIP38 prefix".into()));
        };

        // Try to determine network from address hash
        // In BIP38, bytes 3-6 are the address hash
        // We'll default to mainnet for now
        let network = Network::Dash;

        Ok(Self {
            data,
            mode,
            compressed,
            network,
        })
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.data).with_check().into_string()
    }

    /// Decrypt the key with a password
    pub fn decrypt(&self, password: &str) -> Result<SecretKey> {
        match self.mode {
            Bip38Mode::NonEcMultiply => self.decrypt_non_ec_multiply(password),
            Bip38Mode::EcMultiply => self.decrypt_ec_multiply(password),
        }
    }

    /// Decrypt non-EC-multiply mode
    fn decrypt_non_ec_multiply(&self, password: &str) -> Result<SecretKey> {
        if self.data.len() != 39 {
            return Err(Error::InvalidParameter("Invalid encrypted key length".into()));
        }

        let _flag = self.data[2];
        let address_hash = &self.data[3..7];
        let encrypted = &self.data[7..39];

        // Derive key from password using scrypt
        let mut derived_key = vec![0u8; SCRYPT_KEY_LEN];
        scrypt::scrypt(
            password.as_bytes(),
            address_hash,
            &scrypt::Params::new(14, SCRYPT_R, SCRYPT_P, SCRYPT_KEY_LEN).unwrap(),
            &mut derived_key,
        )
        .map_err(|_| Error::KeyError("Scrypt derivation failed".into()))?;

        // Split derived key
        let derive_half1 = &derived_key[0..32];
        let derive_half2 = &derived_key[32..64];

        // Decrypt with AES
        let decrypted = aes_decrypt(encrypted, derive_half2)?;

        // XOR with derive_half1 to get the private key
        let mut private_key = [0u8; 32];
        for i in 0..32 {
            private_key[i] = decrypted[i] ^ derive_half1[i];
        }

        // Create secret key
        let secret = SecretKey::from_slice(&private_key)
            .map_err(|_| Error::InvalidParameter("Invalid private key".into()))?;

        // Verify by checking address hash
        let address = self.derive_address(&secret)?;
        let computed_hash = address_hash_from_address(&address);

        if &computed_hash[0..4] != address_hash {
            return Err(Error::InvalidParameter("Invalid password".into()));
        }

        Ok(secret)
    }

    /// Decrypt EC-multiply mode
    fn decrypt_ec_multiply(&self, password: &str) -> Result<SecretKey> {
        if self.data.len() != 39 {
            return Err(Error::InvalidParameter("Invalid encrypted key length".into()));
        }

        let flag = self.data[2];
        let has_lot_sequence = (flag & BIP38_FLAG_EC_LOT_SEQUENCE) != 0;

        let address_hash = &self.data[3..7];
        let owner_salt = if has_lot_sequence {
            &self.data[7..11]
        } else {
            &self.data[7..15]
        };

        let encrypted_part1 = &self.data[15..23];
        let encrypted_part2 = &self.data[23..39];

        // Derive intermediate passphrase
        let pass_factor = if has_lot_sequence {
            // Include lot and sequence in derivation
            let lot_sequence = &self.data[11..15];
            let mut pre_factor = Vec::new();
            pre_factor.extend_from_slice(password.as_bytes());
            pre_factor.extend_from_slice(owner_salt);
            pre_factor.extend_from_slice(lot_sequence);

            let mut pass_factor = vec![0u8; 32];
            scrypt::scrypt(
                &pre_factor,
                &[],
                &scrypt::Params::new(14, SCRYPT_R, SCRYPT_P, 32).unwrap(),
                &mut pass_factor,
            )
            .map_err(|_| Error::KeyError("Scrypt derivation failed".into()))?;
            pass_factor
        } else {
            // Simple derivation
            let mut pass_factor = vec![0u8; 32];
            scrypt::scrypt(
                password.as_bytes(),
                owner_salt,
                &scrypt::Params::new(14, SCRYPT_R, SCRYPT_P, 32).unwrap(),
                &mut pass_factor,
            )
            .map_err(|_| Error::KeyError("Scrypt derivation failed".into()))?;
            pass_factor
        };

        // Derive pass_point from pass_factor
        let secp = Secp256k1::new();
        let pass_factor_key = SecretKey::from_slice(&pass_factor)
            .map_err(|_| Error::KeyError("Invalid pass factor".into()))?;
        let pass_point = PublicKey::from_secret_key(&secp, &pass_factor_key);

        // Derive encryption key from pass_point and address_hash
        let mut derived_key = vec![0u8; SCRYPT_KEY_LEN];
        let pass_point_bytes = if self.compressed {
            pass_point.serialize().to_vec()
        } else {
            pass_point.serialize_uncompressed().to_vec()
        };

        scrypt::scrypt(
            &pass_point_bytes,
            address_hash,
            &scrypt::Params::new(10, 1, 1, SCRYPT_KEY_LEN).unwrap(),
            &mut derived_key,
        )
        .map_err(|_| Error::KeyError("Scrypt derivation failed".into()))?;

        // Decrypt seed
        let derive_half2 = &derived_key[32..64];
        let mut decrypted = Vec::new();
        decrypted.extend_from_slice(&aes_decrypt(encrypted_part2, derive_half2)?);
        decrypted.extend_from_slice(&aes_decrypt(
            &[encrypted_part1, &decrypted[0..8]].concat(),
            derive_half2,
        )?);

        let seed_b = &decrypted[0..24];
        let factor_b = double_sha256(seed_b);

        // Multiply to get private key
        let factor_b_key = SecretKey::from_slice(&factor_b)
            .map_err(|_| Error::KeyError("Invalid factor b".into()))?;

        let mut private_key = pass_factor_key;
        private_key = private_key
            .mul_tweak(&factor_b_key.into())
            .map_err(|_| Error::KeyError("Key multiplication failed".into()))?;

        Ok(private_key)
    }

    /// Derive address from secret key
    fn derive_address(&self, secret: &SecretKey) -> Result<Address> {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, secret);
        let dash_pubkey = dashcore::PublicKey::new(public_key);
        Ok(Address::p2pkh(&dash_pubkey, self.network))
    }
}

/// Encrypt a private key with a password (non-EC-multiply mode)
pub fn encrypt_private_key(
    private_key: &SecretKey,
    password: &str,
    compressed: bool,
    network: Network,
) -> Result<Bip38EncryptedKey> {
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, private_key);
    let dash_pubkey = dashcore::PublicKey::new(public_key);
    let address = Address::p2pkh(&dash_pubkey, network);
    let address_hash = address_hash_from_address(&address);

    // Derive encryption key using scrypt
    let mut derived_key = vec![0u8; SCRYPT_KEY_LEN];
    scrypt::scrypt(
        password.as_bytes(),
        &address_hash[0..4],
        &scrypt::Params::new(14, SCRYPT_R, SCRYPT_P, SCRYPT_KEY_LEN).unwrap(),
        &mut derived_key,
    )
    .map_err(|_| Error::KeyError("Scrypt derivation failed".into()))?;

    let derive_half1 = &derived_key[0..32];
    let derive_half2 = &derived_key[32..64];

    // XOR private key with derive_half1
    let private_bytes = private_key.secret_bytes();
    let mut to_encrypt = [0u8; 32];
    for i in 0..32 {
        to_encrypt[i] = private_bytes[i] ^ derive_half1[i];
    }

    // Encrypt with AES
    let encrypted = aes_encrypt(&to_encrypt, derive_half2)?;

    // Build the final encrypted key
    let mut data = Vec::new();
    data.extend_from_slice(&BIP38_PREFIX_NON_EC);
    data.push(if compressed {
        BIP38_FLAG_COMPRESSED
    } else {
        0x00
    });
    data.extend_from_slice(&address_hash[0..4]);
    data.extend_from_slice(&encrypted);

    Ok(Bip38EncryptedKey {
        data,
        mode: Bip38Mode::NonEcMultiply,
        compressed,
        network,
    })
}

/// Generate an intermediate code for EC-multiply mode
pub fn generate_intermediate_code(
    password: &str,
    lot: Option<u32>,
    sequence: Option<u32>,
) -> Result<String> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let (owner_salt, pass_factor) = if let (Some(lot), Some(sequence)) = (lot, sequence) {
        // With lot and sequence
        if lot > 1048575 || sequence > 4095 {
            return Err(Error::InvalidParameter("Lot/sequence out of range".into()));
        }

        let mut owner_salt = [0u8; 4];
        rng.fill(&mut owner_salt);

        let mut lot_sequence = [0u8; 4];
        let combined = (lot * 4096) + sequence;
        lot_sequence[0] = (combined >> 24) as u8;
        lot_sequence[1] = (combined >> 16) as u8;
        lot_sequence[2] = (combined >> 8) as u8;
        lot_sequence[3] = combined as u8;

        let mut pre_factor = Vec::new();
        pre_factor.extend_from_slice(password.as_bytes());
        pre_factor.extend_from_slice(&owner_salt);
        pre_factor.extend_from_slice(&lot_sequence);

        let mut pass_factor = vec![0u8; 32];
        scrypt::scrypt(
            &pre_factor,
            &[],
            &scrypt::Params::new(14, SCRYPT_R, SCRYPT_P, 32).unwrap(),
            &mut pass_factor,
        )
        .map_err(|_| Error::KeyError("Scrypt derivation failed".into()))?;

        (owner_salt.to_vec(), pass_factor)
    } else {
        // Without lot and sequence
        let mut owner_salt = [0u8; 8];
        rng.fill(&mut owner_salt);

        let mut pass_factor = vec![0u8; 32];
        scrypt::scrypt(
            password.as_bytes(),
            &owner_salt,
            &scrypt::Params::new(14, SCRYPT_R, SCRYPT_P, 32).unwrap(),
            &mut pass_factor,
        )
        .map_err(|_| Error::KeyError("Scrypt derivation failed".into()))?;

        (owner_salt.to_vec(), pass_factor)
    };

    // Compute passpoint
    let secp = Secp256k1::new();
    let pass_factor_key = SecretKey::from_slice(&pass_factor)
        .map_err(|_| Error::KeyError("Invalid pass factor".into()))?;
    let pass_point = PublicKey::from_secret_key(&secp, &pass_factor_key);

    // Build intermediate code
    let mut data = Vec::new();
    data.extend_from_slice(&[0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53]);
    data.extend_from_slice(&owner_salt);
    data.extend_from_slice(&pass_point.serialize());

    Ok(bs58::encode(&data).with_check().into_string())
}

// Helper functions

/// Compute address hash for BIP38
fn address_hash_from_address(address: &Address) -> [u8; 4] {
    let address_str = address.to_string();
    let hash = double_sha256(address_str.as_bytes());
    let mut result = [0u8; 4];
    result.copy_from_slice(&hash[0..4]);
    result
}

/// Double SHA256
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// AES-256-ECB encryption
fn aes_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::Aes256;

    if data.len() != 32 || key.len() != 32 {
        return Err(Error::InvalidParameter("Invalid data or key length".into()));
    }

    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut encrypted = Vec::new();

    // Encrypt two blocks (16 bytes each)
    let mut block1 = GenericArray::clone_from_slice(&data[0..16]);
    let mut block2 = GenericArray::clone_from_slice(&data[16..32]);

    cipher.encrypt_block(&mut block1);
    cipher.encrypt_block(&mut block2);

    encrypted.extend_from_slice(&block1);
    encrypted.extend_from_slice(&block2);

    Ok(encrypted)
}

/// AES-256-ECB decryption
fn aes_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    use aes::Aes256;

    if data.len() != 32 || key.len() != 32 {
        return Err(Error::InvalidParameter("Invalid data or key length".into()));
    }

    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut decrypted = Vec::new();

    // Decrypt two blocks (16 bytes each)
    let mut block1 = GenericArray::clone_from_slice(&data[0..16]);
    let mut block2 = GenericArray::clone_from_slice(&data[16..32]);

    cipher.decrypt_block(&mut block1);
    cipher.decrypt_block(&mut block2);

    decrypted.extend_from_slice(&block1);
    decrypted.extend_from_slice(&block2);

    Ok(decrypted)
}

impl fmt::Display for Bip38EncryptedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Builder for BIP38 encryption
pub struct Bip38Builder {
    password: Option<String>,
    compressed: bool,
    network: Network,
    lot: Option<u32>,
    sequence: Option<u32>,
}

impl Bip38Builder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            password: None,
            compressed: false,
            network: Network::Dash,
            lot: None,
            sequence: None,
        }
    }

    /// Set the password
    pub fn password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }

    /// Set compressed flag
    pub fn compressed(mut self, compressed: bool) -> Self {
        self.compressed = compressed;
        self
    }

    /// Set the network
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Set lot and sequence for EC-multiply mode
    pub fn lot_sequence(mut self, lot: u32, sequence: u32) -> Self {
        self.lot = Some(lot);
        self.sequence = Some(sequence);
        self
    }

    /// Encrypt a private key
    pub fn encrypt(&self, private_key: &SecretKey) -> Result<Bip38EncryptedKey> {
        let password =
            self.password.as_ref().ok_or(Error::InvalidParameter("Password required".into()))?;

        encrypt_private_key(private_key, password, self.compressed, self.network)
    }

    /// Generate an intermediate code for EC-multiply mode
    pub fn generate_intermediate(&self) -> Result<String> {
        let password =
            self.password.as_ref().ok_or(Error::InvalidParameter("Password required".into()))?;

        generate_intermediate_code(password, self.lot, self.sequence)
    }
}

impl Default for Bip38Builder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from BIP38 specification
    const _TEST_VECTOR_1_ENCRYPTED: &str =
        "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
    const _TEST_VECTOR_1_PASSWORD: &str = "TestingOneTwoThree";
    const _TEST_VECTOR_1_WIF: &str = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR";

    const _TEST_VECTOR_2_ENCRYPTED: &str =
        "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq";
    const _TEST_VECTOR_2_PASSWORD: &str = "Satoshi";
    const _TEST_VECTOR_2_WIF: &str = "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5";

    #[test]
    #[ignore = "BIP38 tests are slow - run with test_bip38.sh script"]
    fn test_bip38_encryption() {
        // Create a test private key
        let private_key = SecretKey::from_slice(&[
            0x0C, 0x28, 0xFC, 0xA3, 0x86, 0xC7, 0xA2, 0x27, 0x60, 0x0B, 0x2F, 0xE5, 0x0B, 0x7C,
            0xAE, 0x11, 0xEC, 0x86, 0xD3, 0xBF, 0x1F, 0xBE, 0x47, 0x1B, 0xE8, 0x98, 0x27, 0xE1,
            0x9D, 0x72, 0xAA, 0x1D,
        ])
        .unwrap();

        let encrypted =
            encrypt_private_key(&private_key, "TestingOneTwoThree", false, Network::Dash).unwrap();

        // Decrypt and verify
        let decrypted = encrypted.decrypt("TestingOneTwoThree").unwrap();
        assert_eq!(private_key.secret_bytes(), decrypted.secret_bytes());
    }

    #[test]
    #[ignore = "BIP38 tests are slow - run with test_bip38.sh script"]
    fn test_bip38_decryption() {
        // Test with known encrypted key (would need actual test vector)
        // This is a placeholder - in production we'd use actual BIP38 test vectors

        // Create and encrypt a key
        let private_key = SecretKey::from_slice(&[
            0x0C, 0x28, 0xFC, 0xA3, 0x86, 0xC7, 0xA2, 0x27, 0x60, 0x0B, 0x2F, 0xE5, 0x0B, 0x7C,
            0xAE, 0x11, 0xEC, 0x86, 0xD3, 0xBF, 0x1F, 0xBE, 0x47, 0x1B, 0xE8, 0x98, 0x27, 0xE1,
            0x9D, 0x72, 0xAA, 0x1D,
        ])
        .unwrap();

        let password = "MySecretPassword123!";

        let encrypted = encrypt_private_key(
            &private_key,
            password,
            true, // compressed
            Network::Dash,
        )
        .unwrap();

        // Convert to base58 and back
        let base58 = encrypted.to_base58();
        assert!(base58.starts_with("6")); // BIP38 encrypted keys start with 6

        let restored = Bip38EncryptedKey::from_base58(&base58).unwrap();
        assert_eq!(encrypted, restored);

        // Decrypt with correct password
        let decrypted = restored.decrypt(password).unwrap();
        assert_eq!(private_key.secret_bytes(), decrypted.secret_bytes());

        // Try with wrong password (should fail)
        let wrong = restored.decrypt("WrongPassword");
        assert!(wrong.is_err());
    }

    #[test]
    #[ignore = "BIP38 tests are slow - run with test_bip38.sh script"]
    fn test_bip38_compressed_uncompressed() {
        let private_key = SecretKey::from_slice(&[
            0x64, 0x4D, 0xC7, 0x6B, 0x88, 0xDF, 0x64, 0xC3, 0xE4, 0x8A, 0xB6, 0x59, 0x5C, 0xBB,
            0x5C, 0x46, 0x8D, 0x63, 0xF2, 0x0B, 0x5C, 0x8D, 0x17, 0x39, 0xB1, 0x5A, 0x8C, 0x3D,
            0x7F, 0xC9, 0x77, 0x0C,
        ])
        .unwrap();

        let password = "TestPassword";

        // Test uncompressed
        let uncompressed =
            encrypt_private_key(&private_key, password, false, Network::Dash).unwrap();

        assert!(!uncompressed.compressed);
        let decrypted_uncomp = uncompressed.decrypt(password).unwrap();
        assert_eq!(private_key.secret_bytes(), decrypted_uncomp.secret_bytes());

        // Test compressed
        let compressed = encrypt_private_key(&private_key, password, true, Network::Dash).unwrap();

        assert!(compressed.compressed);
        let decrypted_comp = compressed.decrypt(password).unwrap();
        assert_eq!(private_key.secret_bytes(), decrypted_comp.secret_bytes());

        // Encrypted keys should be different
        assert_ne!(uncompressed.to_base58(), compressed.to_base58());
    }

    #[test]
    #[ignore = "BIP38 tests are slow - run with test_bip38.sh script"]
    fn test_bip38_builder() {
        let private_key = SecretKey::from_slice(&[
            0x0C, 0x28, 0xFC, 0xA3, 0x86, 0xC7, 0xA2, 0x27, 0x60, 0x0B, 0x2F, 0xE5, 0x0B, 0x7C,
            0xAE, 0x11, 0xEC, 0x86, 0xD3, 0xBF, 0x1F, 0xBE, 0x47, 0x1B, 0xE8, 0x98, 0x27, 0xE1,
            0x9D, 0x72, 0xAA, 0x1D,
        ])
        .unwrap();

        let encrypted = Bip38Builder::new()
            .password("TestPassword123".to_string())
            .compressed(true)
            .network(Network::Testnet)
            .encrypt(&private_key)
            .unwrap();

        assert!(encrypted.compressed);
        assert_eq!(encrypted.network, Network::Testnet);

        let decrypted = encrypted.decrypt("TestPassword123").unwrap();
        assert_eq!(private_key.secret_bytes(), decrypted.secret_bytes());
    }

    #[test]
    #[ignore = "BIP38 tests are slow - run with test_bip38.sh script"]
    fn test_intermediate_code_generation() {
        let intermediate = generate_intermediate_code("password", None, None).unwrap();

        // Intermediate codes should be valid base58
        // Note: They don't necessarily start with "passphrase" in our implementation
        assert!(!intermediate.is_empty());

        // Test with lot/sequence
        let intermediate_lot =
            generate_intermediate_code("password", Some(100000), Some(1)).unwrap();
        // Just verify it's a valid base58 string
        assert!(!intermediate_lot.is_empty());
    }

    #[test]
    #[ignore = "BIP38 tests are slow - run with test_bip38.sh script"]
    fn test_address_hash() {
        // Test address hash computation
        let secp = Secp256k1::new();
        let private_key = SecretKey::from_slice(&[
            0x0C, 0x28, 0xFC, 0xA3, 0x86, 0xC7, 0xA2, 0x27, 0x60, 0x0B, 0x2F, 0xE5, 0x0B, 0x7C,
            0xAE, 0x11, 0xEC, 0x86, 0xD3, 0xBF, 0x1F, 0xBE, 0x47, 0x1B, 0xE8, 0x98, 0x27, 0xE1,
            0x9D, 0x72, 0xAA, 0x1D,
        ])
        .unwrap();

        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        let dash_pubkey = dashcore::PublicKey::new(public_key);
        let dash_network = dashcore::Network::Dash;
        let address = Address::p2pkh(&dash_pubkey, dash_network);
        let hash = address_hash_from_address(&address);

        assert_eq!(hash.len(), 4);
    }

    #[test]
    #[ignore = "BIP38 tests are slow - run with test_bip38.sh script"]
    fn test_scrypt_parameters() {
        // Verify scrypt parameters match BIP38 spec
        assert_eq!(SCRYPT_N, 16384); // 2^14
        assert_eq!(SCRYPT_R, 8);
        assert_eq!(SCRYPT_P, 8);
        assert_eq!(SCRYPT_KEY_LEN, 64);
    }
}
