//! Account type definitions
//!
//! This module contains the various account type enumerations.

#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Account types supported by the wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum AccountType {
    /// Standard BIP44 account for regular transactions
    Standard,
    /// CoinJoin account for private transactions
    CoinJoin,
    /// Special purpose account (e.g., for identity funding)
    SpecialPurpose(SpecialPurposeType),
}

/// Special purpose account types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum SpecialPurposeType {
    /// Identity registration funding
    IdentityRegistration,
    /// Identity top-up funding
    IdentityTopUp,
    /// Identity invitation funding
    IdentityInvitation,
    /// Masternode collateral
    MasternodeCollateral,
    /// Provider funds
    ProviderFunds,
}
