//! Tests for AccountCollection with different account types

#[cfg(test)]
mod tests {
    use crate::account::{
        Account, AccountCollection, AccountType, BLSAccount, EdDSAAccount, StandardAccountType,
    };
    use crate::bip32::{ExtendedPrivKey, ExtendedPubKey};
    use crate::mnemonic::{Language, Mnemonic};
    use crate::Network;
    use secp256k1::Secp256k1;

    #[test]
    fn test_account_collection_with_all_types() {
        let mut collection = AccountCollection::new();

        // Create test keys
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
        let secp = Secp256k1::new();
        let xpub = ExtendedPubKey::from_priv(&secp, &master);

        // 1. Insert regular ECDSA account
        let ecdsa_account = Account::new(
            None,
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            xpub,
            Network::Testnet,
        )
        .unwrap();

        assert!(collection.insert(ecdsa_account.clone()).is_ok());
        assert!(collection.contains_account_type(&AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        }));

        // 2. Try to insert BLS account using regular insert (should fail)
        let bls_account_as_ecdsa =
            Account::new(None, AccountType::ProviderOperatorKeys, xpub, Network::Testnet).unwrap();

        let result = collection.insert(bls_account_as_ecdsa);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "ProviderOperatorKeys requires BLSAccount, use insert_bls_account"
        );

        // 3. Insert BLS account correctly
        let bls_account = BLSAccount::from_private_key(
            None,
            AccountType::ProviderOperatorKeys,
            [42u8; 32],
            Network::Testnet,
        )
        .unwrap();

        assert!(collection.insert_bls_account(bls_account).is_ok());
        assert!(collection.contains_account_type(&AccountType::ProviderOperatorKeys));

        // 4. Insert EdDSA account correctly
        let eddsa_account = EdDSAAccount::from_seed(
            None,
            AccountType::ProviderPlatformKeys,
            [99u8; 32],
            Network::Testnet,
        )
        .unwrap();

        assert!(collection.insert_eddsa_account(eddsa_account).is_ok());
        assert!(collection.contains_account_type(&AccountType::ProviderPlatformKeys));

        // 5. Verify retrieval
        // ECDSA account should be retrievable via account_of_type
        let retrieved_ecdsa = collection.account_of_type(AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        });
        assert!(retrieved_ecdsa.is_some());

        // BLS account should NOT be retrievable via account_of_type
        let retrieved_bls_wrong = collection.account_of_type(AccountType::ProviderOperatorKeys);
        assert!(retrieved_bls_wrong.is_none());

        // BLS account should be retrievable via bls_account_of_type
        let retrieved_bls = collection.bls_account_of_type(AccountType::ProviderOperatorKeys);
        assert!(retrieved_bls.is_some());
        assert_eq!(retrieved_bls.unwrap().bls_public_key.len(), 48);

        // EdDSA account should be retrievable via eddsa_account_of_type
        let retrieved_eddsa = collection.eddsa_account_of_type(AccountType::ProviderPlatformKeys);
        assert!(retrieved_eddsa.is_some());
        assert_eq!(retrieved_eddsa.unwrap().ed25519_public_key.len(), 32);

        // 6. Verify count
        assert_eq!(collection.count(), 3); // 1 ECDSA + 1 BLS + 1 EdDSA

        // 7. Verify all_accounts only returns ECDSA accounts
        let all_ecdsa = collection.all_accounts();
        assert_eq!(all_ecdsa.len(), 1); // Only the ECDSA account
    }

    #[test]
    fn test_wrong_account_type_for_bls() {
        let mut collection = AccountCollection::new();

        // Try to insert BLS account with wrong type
        let bls_account = BLSAccount::from_private_key(
            None,
            AccountType::ProviderVotingKeys, // Wrong! Should be ProviderOperatorKeys
            [42u8; 32],
            Network::Testnet,
        )
        .unwrap();

        let result = collection.insert_bls_account(bls_account);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "BLS account must have ProviderOperatorKeys type");
    }

    #[test]
    fn test_wrong_account_type_for_eddsa() {
        let mut collection = AccountCollection::new();

        // Try to insert EdDSA account with wrong type
        let eddsa_account = EdDSAAccount::from_seed(
            None,
            AccountType::IdentityRegistration, // Wrong! Should be ProviderPlatformKeys
            [99u8; 32],
            Network::Testnet,
        )
        .unwrap();

        let result = collection.insert_eddsa_account(eddsa_account);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "EdDSA account must have ProviderPlatformKeys type");
    }
}
