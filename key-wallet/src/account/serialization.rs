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
        use crate::Network;

        let public_key = [1u8; 48];
        let account = BLSAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key,
            Network::Testnet,
        )
        .unwrap();

        let serialized = account.to_bytes().unwrap();
        let deserialized = BLSAccount::from_bytes(&serialized).unwrap();

        assert_eq!(account.index(), deserialized.index());
        assert_eq!(account.account_type, deserialized.account_type);
        assert_eq!(account.network, deserialized.network);
        assert_eq!(account.is_watch_only, deserialized.is_watch_only);
    }

    #[test]
    #[cfg(all(feature = "bincode", feature = "eddsa"))]
    fn test_eddsa_serialization() {
        use crate::account::{account_type::StandardAccountType, AccountTrait, AccountType};
        use crate::Network;

        let public_key = [1u8; 32];
        let account = EdDSAAccount::from_public_key_bytes(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            public_key,
            Network::Testnet,
        )
        .unwrap();

        let serialized = account.to_bytes().unwrap();
        let deserialized = EdDSAAccount::from_bytes(&serialized).unwrap();

        assert_eq!(account.index(), deserialized.index());
        assert_eq!(account.account_type, deserialized.account_type);
        assert_eq!(account.network, deserialized.network);
        assert_eq!(account.is_watch_only, deserialized.is_watch_only);
    }
}
