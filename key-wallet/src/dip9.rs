use crate::bip32::{ChildNumber, DerivationPath, Error, ExtendedPrivKey, ExtendedPubKey};
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use bitflags::bitflags;
use dashcore::Network;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
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
    PlatformPayment = 16,
    BlockchainAssetLockAddressTopupFunding = 17,
    BlockchainAssetLockShieldedAddressTopupFunding = 18,
    Root = 255,
    // Declared after `Root` so the bincode variant index of every earlier variant is unchanged.
    ApplicationSessionAuthentication = 19,
    ApplicationEncryption = 20,
}

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
        root_derivation_path.extend([child_number]);
        root_derivation_path
    }

    pub fn derive_priv_ecdsa_for_master_seed(
        &self,
        seed: &[u8],
        add_derivation_path: DerivationPath,
        network: Network,
    ) -> Result<ExtendedPrivKey, Error> {
        let sk = ExtendedPrivKey::new_master(network, seed)?;
        let path = self.append_path(add_derivation_path);
        sk.derive_priv(&path)
    }

    pub fn derive_pub_ecdsa_for_master_seed(
        &self,
        seed: &[u8],
        add_derivation_path: DerivationPath,
        network: Network,
    ) -> Result<ExtendedPubKey, Error> {
        let sk = self.derive_priv_ecdsa_for_master_seed(seed, add_derivation_path, network)?;
        Ok(ExtendedPubKey::from_priv(&sk))
    }

    pub fn derive_pub_for_master_extended_public_key(
        &self,
        master_extended_public_key: ExtendedPubKey,
        add_derivation_path: DerivationPath,
    ) -> Result<ExtendedPubKey, Error> {
        let path = self.append_path(add_derivation_path);
        master_extended_public_key.derive_pub(&path)
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
pub const FEATURE_PURPOSE_ASSET_LOCK_SUBFEATURE_ADDRESS_TOPUP: u32 = 4;
pub const FEATURE_PURPOSE_ASSET_LOCK_SUBFEATURE_SHIELDED_ADDRESS_TOPUP: u32 = 5;
/// DIP-13 application session authentication sub-feature:
/// `m/9'/coin_type'/5'/6'/key_type'/identity_id'/request_id'`.
pub const FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_APPLICATION_SESSION_AUTHENTICATION: u32 = 6;
/// DIP-13 application encryption sub-feature:
/// `m/9'/coin_type'/5'/7'/key_type'/identity_id'/contract_id'/key_purpose'`.
pub const FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_APPLICATION_ENCRYPTION: u32 = 7;
pub const FEATURE_PURPOSE_DASHPAY: u32 = 15;
/// DIP-15 auto-accept feature index: the derivation family
/// `m/9'/coin_type'/16'/expiry'` holding the shareable, expiry-bounded
/// bearer keys that a DashPay user embeds in an auto-accept QR (`dapk`) so a
/// scanned contact request auto-establishes. Consumers (the platform wallet's
/// auto-accept path builder and the FFI signer's raw-key export gate) must
/// reference this constant rather than a local literal.
pub const FEATURE_PURPOSE_DASHPAY_AUTO_ACCEPT: u32 = 16;
/// DIP-15 contactInfo `encToUserId` hardened child (`root / 65536' / index'`,
/// where `root` is the owner's identity-authentication path): derives the
/// AES key that encrypts the contact id in a `contactInfo` document.
pub const DASHPAY_CONTACT_INFO_ENC_TO_USER_ID_CHILD: u32 = 1 << 16;
/// DIP-15 contactInfo `privateData` hardened child (`root / 65537' / index'`):
/// derives the AES key that encrypts the private-data blob in a `contactInfo`
/// document.
pub const DASHPAY_CONTACT_INFO_PRIVATE_DATA_CHILD: u32 = (1 << 16) + 1;
/// DIP-17: Platform Payment Addresses feature index
pub const FEATURE_PURPOSE_PLATFORM_PAYMENT: u32 = 17;
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

// DashPay Root Paths
pub const DASHPAY_ROOT_PATH_MAINNET: IndexConstPath<3> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_DASHPAY,
        },
    ],
    reference: DerivationPathReference::ContactBasedFunds,
    path_type: DerivationPathType::CLEAR_FUNDS,
};

pub const DASHPAY_ROOT_PATH_TESTNET: IndexConstPath<3> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_TESTNET_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_DASHPAY,
        },
    ],
    reference: DerivationPathReference::ContactBasedFunds,
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

// Asset Lock Address Top-Up Paths
pub const ASSET_LOCK_ADDRESS_TOPUP_PATH_MAINNET: IndexConstPath<4> = IndexConstPath {
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
            index: FEATURE_PURPOSE_ASSET_LOCK_SUBFEATURE_ADDRESS_TOPUP,
        },
    ],
    reference: DerivationPathReference::BlockchainAssetLockAddressTopupFunding,
    path_type: DerivationPathType::CREDIT_FUNDING,
};

pub const ASSET_LOCK_ADDRESS_TOPUP_PATH_TESTNET: IndexConstPath<4> = IndexConstPath {
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
            index: FEATURE_PURPOSE_ASSET_LOCK_SUBFEATURE_ADDRESS_TOPUP,
        },
    ],
    reference: DerivationPathReference::BlockchainAssetLockAddressTopupFunding,
    path_type: DerivationPathType::CREDIT_FUNDING,
};

// Asset Lock Shielded Address Top-Up Paths
pub const ASSET_LOCK_SHIELDED_ADDRESS_TOPUP_PATH_MAINNET: IndexConstPath<4> = IndexConstPath {
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
            index: FEATURE_PURPOSE_ASSET_LOCK_SUBFEATURE_SHIELDED_ADDRESS_TOPUP,
        },
    ],
    reference: DerivationPathReference::BlockchainAssetLockShieldedAddressTopupFunding,
    path_type: DerivationPathType::CREDIT_FUNDING,
};

pub const ASSET_LOCK_SHIELDED_ADDRESS_TOPUP_PATH_TESTNET: IndexConstPath<4> = IndexConstPath {
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
            index: FEATURE_PURPOSE_ASSET_LOCK_SUBFEATURE_SHIELDED_ADDRESS_TOPUP,
        },
    ],
    reference: DerivationPathReference::BlockchainAssetLockShieldedAddressTopupFunding,
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

// Application Session Authentication Keys Paths
pub const APPLICATION_SESSION_AUTHENTICATION_PATH_MAINNET: IndexConstPath<4> = IndexConstPath {
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
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_APPLICATION_SESSION_AUTHENTICATION,
        },
    ],
    reference: DerivationPathReference::ApplicationSessionAuthentication,
    path_type: DerivationPathType::SINGLE_USER_AUTHENTICATION,
};

pub const APPLICATION_SESSION_AUTHENTICATION_PATH_TESTNET: IndexConstPath<4> = IndexConstPath {
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
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_APPLICATION_SESSION_AUTHENTICATION,
        },
    ],
    reference: DerivationPathReference::ApplicationSessionAuthentication,
    path_type: DerivationPathType::SINGLE_USER_AUTHENTICATION,
};

// Application Encryption Keys Paths
pub const APPLICATION_ENCRYPTION_PATH_MAINNET: IndexConstPath<4> = IndexConstPath {
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
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_APPLICATION_ENCRYPTION,
        },
    ],
    reference: DerivationPathReference::ApplicationEncryption,
    path_type: DerivationPathType::SINGLE_USER_AUTHENTICATION,
};

pub const APPLICATION_ENCRYPTION_PATH_TESTNET: IndexConstPath<4> = IndexConstPath {
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
            index: FEATURE_PURPOSE_IDENTITIES_SUBFEATURE_APPLICATION_ENCRYPTION,
        },
    ],
    reference: DerivationPathReference::ApplicationEncryption,
    path_type: DerivationPathType::SINGLE_USER_AUTHENTICATION,
};

// DIP-17: Platform Payment Address Paths
// Path: m/9'/coin_type'/17'/account'/key_class'/index
// Note: The full path includes account'/key_class'/index which is appended during derivation

/// Platform Payment root path for mainnet: m/9'/5'/17'
pub const PLATFORM_PAYMENT_ROOT_PATH_MAINNET: IndexConstPath<3> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_PLATFORM_PAYMENT,
        },
    ],
    reference: DerivationPathReference::PlatformPayment,
    path_type: DerivationPathType::CLEAR_FUNDS,
};

/// Platform Payment root path for testnet: m/9'/1'/17'
pub const PLATFORM_PAYMENT_ROOT_PATH_TESTNET: IndexConstPath<3> = IndexConstPath {
    indexes: [
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE,
        },
        ChildNumber::Hardened {
            index: DASH_TESTNET_COIN_TYPE,
        },
        ChildNumber::Hardened {
            index: FEATURE_PURPOSE_PLATFORM_PAYMENT,
        },
    ],
    reference: DerivationPathReference::PlatformPayment,
    path_type: DerivationPathType::CLEAR_FUNDS,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u32)]
pub enum KeyDerivationType {
    ECDSA = 0,
    BLS = 1,
}

impl From<KeyDerivationType> for u32 {
    fn from(val: KeyDerivationType) -> Self {
        match val {
            KeyDerivationType::ECDSA => 0,
            KeyDerivationType::BLS => 1,
        }
    }
}

/// The `key_purpose'` level of a DIP-13 application encryption path: the Platform identity key
/// purpose the derived key is registered with.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u32)]
pub enum ApplicationKeyPurpose {
    Encryption = 1,
    Decryption = 2,
}

impl From<ApplicationKeyPurpose> for u32 {
    fn from(val: ApplicationKeyPurpose) -> Self {
        match val {
            ApplicationKeyPurpose::Encryption => 1,
            ApplicationKeyPurpose::Decryption => 2,
        }
    }
}

impl DerivationPath {
    pub fn bip_44_account(network: Network, account: u32) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => DASH_BIP44_PATH_MAINNET,
            _ => DASH_BIP44_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([ChildNumber::Hardened {
            index: account,
        }])
    }
    pub fn bip_44_payment_path(
        network: Network,
        account: u32,
        change: bool,
        address_index: u32,
    ) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => DASH_BIP44_PATH_MAINNET,
            _ => DASH_BIP44_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([
            ChildNumber::Hardened {
                index: account,
            },
            ChildNumber::Normal {
                index: change.into(),
            },
            ChildNumber::Normal {
                index: address_index,
            },
        ])
    }
    pub fn coinjoin_path(network: Network, account: u32) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => COINJOIN_PATH_MAINNET,
            _ => COINJOIN_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([ChildNumber::Hardened {
            index: account,
        }])
    }

    /// This might have been used in the past
    pub fn identity_registration_path_child_non_hardened(network: Network, index: u32) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => IDENTITY_REGISTRATION_PATH_MAINNET,
            _ => IDENTITY_REGISTRATION_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([ChildNumber::Normal {
            index,
        }])
    }

    pub fn identity_registration_path(network: Network, index: u32) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => IDENTITY_REGISTRATION_PATH_MAINNET,
            _ => IDENTITY_REGISTRATION_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([ChildNumber::Hardened {
            index,
        }])
    }

    pub fn identity_top_up_path(network: Network, identity_index: u32, top_up_index: u32) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => IDENTITY_TOPUP_PATH_MAINNET,
            _ => IDENTITY_TOPUP_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([
            ChildNumber::Hardened {
                index: identity_index,
            },
            ChildNumber::Normal {
                index: top_up_index,
            },
        ])
    }

    pub fn identity_invitation_path(network: Network, index: u32) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => IDENTITY_INVITATION_PATH_MAINNET,
            _ => IDENTITY_INVITATION_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([ChildNumber::Hardened {
            index,
        }])
    }

    pub fn asset_lock_address_top_up_path(network: Network, index: u32) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => ASSET_LOCK_ADDRESS_TOPUP_PATH_MAINNET,
            _ => ASSET_LOCK_ADDRESS_TOPUP_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([ChildNumber::Hardened {
            index,
        }])
    }

    pub fn asset_lock_shielded_address_top_up_path(network: Network, index: u32) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => ASSET_LOCK_SHIELDED_ADDRESS_TOPUP_PATH_MAINNET,
            _ => ASSET_LOCK_SHIELDED_ADDRESS_TOPUP_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([ChildNumber::Hardened {
            index,
        }])
    }

    pub fn identity_authentication_path(
        network: Network,
        key_type: KeyDerivationType,
        identity_index: u32,
        key_index: u32,
    ) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => IDENTITY_AUTHENTICATION_PATH_MAINNET,
            _ => IDENTITY_AUTHENTICATION_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([
            ChildNumber::Hardened {
                index: key_type.into(),
            },
            ChildNumber::Hardened {
                index: identity_index,
            },
            ChildNumber::Hardened {
                index: key_index,
            },
        ])
    }

    /// DIP-13 application session authentication key path,
    /// `m/9'/coin_type'/5'/6'/0'/identity_id'/request_id'`. The identity id and request id are
    /// DIP-14 256-bit hardened children, which only secp256k1 derivation defines, so the key type
    /// level is always ECDSA (`0'`).
    pub fn application_session_authentication_path(
        network: Network,
        identity_id: [u8; 32],
        request_id: [u8; 32],
    ) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => APPLICATION_SESSION_AUTHENTICATION_PATH_MAINNET,
            _ => APPLICATION_SESSION_AUTHENTICATION_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([
            ChildNumber::Hardened {
                index: KeyDerivationType::ECDSA.into(),
            },
            ChildNumber::Hardened256 {
                index: identity_id,
            },
            ChildNumber::Hardened256 {
                index: request_id,
            },
        ])
    }

    /// DIP-13 application encryption key path,
    /// `m/9'/coin_type'/5'/7'/0'/identity_id'/contract_id'/key_purpose'`. The identity id and
    /// contract id are DIP-14 256-bit hardened children, which only secp256k1 derivation defines,
    /// so the key type level is always ECDSA (`0'`).
    pub fn application_encryption_path(
        network: Network,
        identity_id: [u8; 32],
        contract_id: [u8; 32],
        key_purpose: ApplicationKeyPurpose,
    ) -> Self {
        let root_derivation_path: DerivationPath = match network {
            Network::Mainnet => APPLICATION_ENCRYPTION_PATH_MAINNET,
            _ => APPLICATION_ENCRYPTION_PATH_TESTNET,
        }
        .into();
        root_derivation_path.extend([
            ChildNumber::Hardened {
                index: KeyDerivationType::ECDSA.into(),
            },
            ChildNumber::Hardened256 {
                index: identity_id,
            },
            ChildNumber::Hardened256 {
                index: contract_id,
            },
            ChildNumber::Hardened {
                index: key_purpose.into(),
            },
        ])
    }
}
