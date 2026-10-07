//
// This file is a part of rust-dashcore. Contains portions from rust-bitcoin.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Signature hash types.

use hashes::{hash_newtype, sha256d, sha256t_hash_newtype};

hash_newtype! {
    /// Hash of a transaction according to the legacy signature algorithm.
    #[hash_newtype(forward)]
    pub struct LegacySighash(sha256d::Hash);

    /// Hash of a transaction according to the segwit version 0 signature algorithm.
    #[hash_newtype(forward)]
    pub struct SegwitV0Sighash(sha256d::Hash);
}

sha256t_hash_newtype! {
    pub struct TapSighashTag = hash_str("TapSighash");

    /// Taproot-tagged hash with tag \"TapSighash\".
    ///
    /// This hash type is used for computing taproot signature hash."
    #[hash_newtype(forward)]
    pub struct TapSighash(_);
}

pub use bitcoin_crypto::sighash::{
    EcdsaSighashType, InvalidSighashTypeError, NonStandardSighashType, NonStandardSighashTypeError,
    SighashTypeParseError, TapSighashType,
};

/// Splits a sighash flag into the "real" flag and the `SIGHASH_ANYONECANPAY` bit.
pub trait SplitAnyoneCanPay {
    /// Splits the flag into the "real" sighash flag and the ANYONECANPAY boolean.
    fn split_anyonecanpay_flag(self) -> (Self, bool)
    where
        Self: Sized;
}

impl SplitAnyoneCanPay for EcdsaSighashType {
    fn split_anyonecanpay_flag(self) -> (EcdsaSighashType, bool) {
        use EcdsaSighashType::*;
        match self {
            All => (All, false),
            None => (None, false),
            Single => (Single, false),
            AllPlusAnyoneCanPay => (All, true),
            NonePlusAnyoneCanPay => (None, true),
            SinglePlusAnyoneCanPay => (Single, true),
            // Core reads SINGLE/NONE from the low five bits and treats anything
            // else as ALL. ANYONECANPAY is the 0x80 bit.
            NonStandard(n) => {
                let acp = n.to_u32() & 0x80 == 0x80;
                match n.to_u32() & 0x1f {
                    0x02 => (None, acp),
                    0x03 => (Single, acp),
                    _ => (All, acp),
                }
            }
        }
    }
}

impl SplitAnyoneCanPay for TapSighashType {
    fn split_anyonecanpay_flag(self) -> (TapSighashType, bool) {
        use TapSighashType::*;
        match self {
            Default => (Default, false),
            All => (All, false),
            None => (None, false),
            Single => (Single, false),
            AllPlusAnyoneCanPay => (All, true),
            NonePlusAnyoneCanPay => (None, true),
            SinglePlusAnyoneCanPay => (Single, true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_follows_core() {
        for n in 0..=0x1ffu32 {
            let ty = match n & 0x1f {
                0x02 => EcdsaSighashType::None,
                0x03 => EcdsaSighashType::Single,
                _ => EcdsaSighashType::All,
            };
            let got = EcdsaSighashType::from_consensus(n).split_anyonecanpay_flag();
            assert_eq!(got, (ty, n & 0x80 != 0), "sighash flag {n:#04x}");
        }
    }
}
