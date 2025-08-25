#[cfg(feature = "bls")]
use crate::account::BLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::EdDSAAccount;
use crate::Account;

impl Account {
    /// Serialize account to bytes
    #[cfg(feature = "bincode")]
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    /// Deserialize account from bytes
    #[cfg(feature = "bincode")]
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        bincode::decode_from_slice(data, bincode::config::standard())
            .map(|(account, _)| account)
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }
}

#[cfg(feature = "bls")]
impl BLSAccount {
    /// Serialize BLS account to bytes
    #[cfg(feature = "bincode")]
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    /// Deserialize BLS account from bytes
    #[cfg(feature = "bincode")]
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        bincode::decode_from_slice(data, bincode::config::standard())
            .map(|(account, _)| account)
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }
}

#[cfg(feature = "eddsa")]
impl EdDSAAccount {
    /// Serialize EdDSA account to bytes
    #[cfg(feature = "bincode")]
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }

    /// Deserialize EdDSA account from bytes
    #[cfg(feature = "bincode")]
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        bincode::decode_from_slice(data, bincode::config::standard())
            .map(|(account, _)| account)
            .map_err(|e| crate::error::Error::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "bls")]
    use crate::account::BLSAccount;
    #[cfg(feature = "eddsa")]
    use crate::account::EdDSAAccount;
    use crate::Account;

    #[test]
    #[cfg(feature = "bincode")]
    fn test_serialization() {
        let account = crate::account::tests::test_account();
        let serialized = account.to_bytes().unwrap();
        let deserialized = Account::from_bytes(&serialized).unwrap();

        assert_eq!(account.index(), deserialized.index());
        assert_eq!(account.account_type, deserialized.account_type);
    }

    #[test]
    #[cfg(all(feature = "bincode", feature = "bls"))]
    fn test_bls_serialization() {
        use crate::account::{account_type::StandardAccountType, AccountTrait, AccountType};
        use crate::derivation_bls_bip32::{ExtendedBLSPrivKey, ExtendedBLSPubKey};
        use crate::Network;

        // Create a valid BLS public key
        let seed = [42u8; 32];
        let bls_private = ExtendedBLSPrivKey::new_master(Network::Testnet, &seed)
            .expect("Failed to create BLS private key from seed");
        let bls_public = ExtendedBLSPubKey::from_private_key(&bls_private);
        let public_key_bytes = bls_public.to_bytes();

        let account = BLSAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key_bytes.try_into().expect("Failed to convert BLS public key bytes to array"),
            Network::Testnet,
        )
        .expect("Failed to create BLS account from public key bytes");

        let serialized = account.to_bytes().expect("Failed to serialize BLS account");
        let deserialized =
            BLSAccount::from_bytes(&serialized).expect("Failed to deserialize BLS account");

        assert_eq!(account.index(), deserialized.index());
        assert_eq!(account.account_type, deserialized.account_type);
        assert_eq!(account.network, deserialized.network);
        assert_eq!(account.is_watch_only, deserialized.is_watch_only);
    }

    #[test]
    #[cfg(all(feature = "bincode", feature = "eddsa"))]
    fn test_eddsa_serialization() {
        use crate::account::{account_type::StandardAccountType, AccountTrait, AccountType};
        use crate::derivation_slip10::{ExtendedEd25519PrivKey, ExtendedEd25519PubKey};
        use crate::Network;

        // Create a valid Ed25519 public key
        let seed = [42u8; 32];
        let ed25519_private = ExtendedEd25519PrivKey::new_master(Network::Testnet, &seed)
            .expect("Failed to create Ed25519 private key from seed");
        let ed25519_public = ExtendedEd25519PubKey::from_priv(&ed25519_private)
            .expect("Failed to derive Ed25519 public key from private key");
        let public_key_bytes = ed25519_public.public_key.to_bytes();

        let account = EdDSAAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key_bytes,
            Network::Testnet,
        )
        .expect("Failed to create EdDSA account from public key bytes");

        let serialized = account.to_bytes().expect("Failed to serialize EdDSA account");
        let deserialized =
            EdDSAAccount::from_bytes(&serialized).expect("Failed to deserialize EdDSA account");

        assert_eq!(account.index(), deserialized.index());
        assert_eq!(account.account_type, deserialized.account_type);
        assert_eq!(account.network, deserialized.network);
        assert_eq!(account.is_watch_only, deserialized.is_watch_only);
    }
}
