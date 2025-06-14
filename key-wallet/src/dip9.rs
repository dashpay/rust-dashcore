#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum DerivationPathReference {
    Unknown = 0,
    BIP32 = 1,
    BIP44 = 2,
    BlockchainIdentities = 3,
    ProviderFunds = 4,
    ProviderVotingKeys = 5,
    ProviderOperatorKeys = 6,
    ProviderOwnerKeys = 7,
    ContactBasedFunds = 8,
    ContactBasedFundsRoot = 9,
    ContactBasedFundsExternal = 10,
    BlockchainIdentityCreditRegistrationFunding = 11,
    BlockchainIdentityCreditTopupFunding = 12,
    BlockchainIdentityCreditInvitationFunding = 13,
    ProviderPlatformNodeKeys = 14,
    CoinJoin = 15,
    Root = 255,
}

use bitflags::bitflags;
use secp256k1::Secp256k1;

use crate::bip32::{ChildNumber, DerivationPath, Error, ExtendedPrivKey, ExtendedPubKey};
use dash_network::Network;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
    pub struct DerivationPathType: u32 {
        const UNKNOWN = 0;
        const CLEAR_FUNDS = 1;
        const ANONYMOUS_FUNDS = 1 << 1;
        const VIEW_ONLY_FUNDS = 1 << 2;
        const SINGLE_USER_AUTHENTICATION = 1 << 3;
        const MULTIPLE_USER_AUTHENTICATION = 1 << 4;
        const PARTIAL_PATH = 1 << 5;
        const PROTECTED_FUNDS = 1 << 6;
        const CREDIT_FUNDING = 1 << 7;

        // Composite flags
        const IS_FOR_AUTHENTICATION = Self::SINGLE_USER_AUTHENTICATION.bits() | Self::MULTIPLE_USER_AUTHENTICATION.bits();
        const IS_FOR_FUNDS = Self::CLEAR_FUNDS.bits()
            | Self::ANONYMOUS_FUNDS.bits()
            | Self::VIEW_ONLY_FUNDS.bits()
            | Self::PROTECTED_FUNDS.bits();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct IndexConstPath<const N: usize> {
    pub indexes: [ChildNumber; N],
    pub reference: DerivationPathReference,
    pub path_type: DerivationPathType,
}

impl<const N: usize> AsRef<[ChildNumber]> for IndexConstPath<N> {
    fn as_ref(&self) -> &[ChildNumber] {
        self.indexes.as_ref()
    }
}

impl<const N: usize> From<IndexConstPath<N>> for DerivationPath {
    fn from(value: IndexConstPath<N>) -> Self {
        DerivationPath::from(value.indexes.as_ref())
    }
}

impl<const N: usize> IndexConstPath<N> {
    pub fn append_path(&self, derivation_path: DerivationPath) -> DerivationPath {
        let root_derivation_path = DerivationPath::from(self.indexes.as_ref());
        root_derivation_path.extend(derivation_path);
        root_derivation_path
    }

    pub fn append(&self, child_number: ChildNumber) -> DerivationPath {
        let root_derivation_path = DerivationPath::from(self.indexes.as_ref());
        root_derivation_path.extend(&[child_number]);
        root_derivation_path
    }

    pub fn derive_priv_ecdsa_for_master_seed(
        &self,
        seed: &[u8],
        add_derivation_path: DerivationPath,
        network: Network,
    ) -> Result<ExtendedPrivKey, Error> {
        let secp = Secp256k1::new();
        let sk = ExtendedPrivKey::new_master(network, seed)?;
        let path = self.append_path(add_derivation_path);
        sk.derive_priv(&secp, &path)
    }

    pub fn derive_pub_ecdsa_for_master_seed(
        &self,
        seed: &[u8],
        add_derivation_path: DerivationPath,
        network: Network,
    ) -> Result<ExtendedPubKey, Error> {
        let secp = Secp256k1::new();
        let sk = self.derive_priv_ecdsa_for_master_seed(seed, add_derivation_path, network)?;
        Ok(ExtendedPubKey::from_priv(&secp, &sk))
    }

    pub fn derive_pub_for_master_extended_public_key(
        &self,
        master_extended_public_key: ExtendedPubKey,
        add_derivation_path: DerivationPath,
    ) -> Result<ExtendedPubKey, Error> {
        let secp = Secp256k1::new();
        let path = self.append_path(add_derivation_path);
        master_extended_public_key.derive_pub(&secp, &path)
    }
}

// Constants for feature purposes and sub-features
pub const BIP44_PURPOSE: u32 = 44;
// Constants for feature purposes and sub-features
pub const FEATURE_PURPOSE: u32 = 9;
pub const DASH_COIN_TYPE: u32 = 5;
pub const DASH_TESTNET_COIN_TYPE: u32 = 1;
pub const FEATURE_PURPOSE_COINJOIN: u32 = 4;
pub const FEATURE_PURPOSE_IDENTITIES: u32 = 5;
pub const FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_AUTHENTICATION: u32 = 0;
pub const FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_REGISTRATION: u32 = 1;
pub const FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_TOPUP: u32 = 2;
pub const FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_INVITATIONS: u32 = 3;
pub const FEATURE_PURPOSE_DASHPAY: u32 = 15;
pub const DASH_BIP44_PATH_MAINNET: IndexConstPath<2> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: BIP44_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_COIN_TYPE,
        },
    ],
    reference: DerivationPathReference::BIP44,
    path_type: DerivationPathType::CLEAR_FUNDS,
};

pub const DASH_BIP44_PATH_TESTNET: IndexConstPath<2> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: BIP44_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_TESTNET_COIN_TYPE,
        },
    ],
    reference: DerivationPathReference::BIP44,
    path_type: DerivationPathType::CLEAR_FUNDS,
};
// CoinJoin Paths

pub const COINJOIN_PATH_MAINNET: IndexConstPath<3> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_COINJOIN,
        },
    ],
    reference: DerivationPathReference::CoinJoin,
    path_type: DerivationPathType::ANONYMOUS_FUNDS,
};
pub const COINJOIN_PATH_TESTNET: IndexConstPath<3> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_TESTNET_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_COINJOIN,
        },
    ],
    reference: DerivationPathReference::CoinJoin,
    path_type: DerivationPathType::ANONYMOUS_FUNDS,
};

pub const IDENTITY_REGISTRATION_PATH_MAINNET: IndexConstPath<4> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_REGISTRATION,
        },
    ],
    reference: DerivationPathReference::BlockchainIdentityCreditRegistrationFunding,
    path_type: DerivationPathType::CREDIT_FUNDING,
};

pub const IDENTITY_REGISTRATION_PATH_TESTNET: IndexConstPath<4> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_TESTNET_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_REGISTRATION,
        },
    ],
    reference: DerivationPathReference::BlockchainIdentityCreditRegistrationFunding,
    path_type: DerivationPathType::CREDIT_FUNDING,
};

// Identity Top-Up Paths
pub const IDENTITY_TOPUP_PATH_MAINNET: IndexConstPath<4> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_TOPUP,
        },
    ],
    reference: DerivationPathReference::BlockchainIdentityCreditTopupFunding,
    path_type: DerivationPathType::CREDIT_FUNDING,
};

pub const IDENTITY_TOPUP_PATH_TESTNET: IndexConstPath<4> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_TESTNET_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_TOPUP,
        },
    ],
    reference: DerivationPathReference::BlockchainIdentityCreditTopupFunding,
    path_type: DerivationPathType::CREDIT_FUNDING,
};

// Identity Invitation Paths
pub const IDENTITY_INVITATION_PATH_MAINNET: IndexConstPath<4> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_INVITATIONS,
        },
    ],
    reference: DerivationPathReference::BlockchainIdentityCreditInvitationFunding,
    path_type: DerivationPathType::CREDIT_FUNDING,
};

pub const IDENTITY_INVITATION_PATH_TESTNET: IndexConstPath<4> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_TESTNET_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_INVITATIONS,
        },
    ],
    reference: DerivationPathReference::BlockchainIdentityCreditInvitationFunding,
    path_type: DerivationPathType::CREDIT_FUNDING,
};

// Authentication Keys Paths
pub const IDENTITY_AUTHENTICATION_PATH_MAINNET: IndexConstPath<4> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_AUTHENTICATION,
        },
    ],
    reference: DerivationPathReference::BlockchainIdentities,
    path_type: DerivationPathType::SINGLE_USER_AUTHENTICATION,
};

pub const IDENTITY_AUTHENTICATION_PATH_TESTNET: IndexConstPath<4> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_TESTNET_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_AUTHENTICATION,
        },
    ],
    reference: DerivationPathReference::BlockchainIdentities,
    path_type: DerivationPathType::SINGLE_USER_AUTHENTICATION,
};
