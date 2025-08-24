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

#[cfg(test)]
mod tests {
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
}