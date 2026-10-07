// Rust Bitcoin Library - Written by the rust-dash developers.
// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.
//!
//! Provides the [`Work`] and [`Target`] types that are use in proof-of-work calculations. The
//! functions here are designed to be fast, by that we mean it is safe to use them to check headers.
//!

use core::fmt;
use core::ops::{Add, Sub};

use dash_num::Arith256;
use dash_types::Numeric;

#[cfg(doc)]
use crate::consensus::Params;
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::hash_types::BlockHash;
use crate::io::{self, Read, Write};
use crate::prelude::String;
use crate::string::FromHexStr;

/// Implement traits and methods shared by `Target` and `Work`.
macro_rules! do_impl {
    ($ty:ident) => {
        impl $ty {
            /// Creates `Self` from a big-endian byte array.
            #[inline]
            pub fn from_be_bytes(bytes: [u8; 32]) -> $ty {
                $ty(Arith256::from_bendian(bytes))
            }

            /// Creates `Self` from a little-endian byte array.
            #[inline]
            pub fn from_le_bytes(bytes: [u8; 32]) -> $ty {
                $ty(Arith256::from_lendian(bytes))
            }

            /// Converts `self` to a big-endian byte array.
            #[inline]
            pub fn to_be_bytes(self) -> [u8; 32] {
                self.0.to_bendian()
            }

            /// Converts `self` to a little-endian byte array.
            #[inline]
            pub fn to_le_bytes(self) -> [u8; 32] {
                self.0.to_lendian()
            }
        }

        impl fmt::Display for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::LowerHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::UpperHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::UpperHex::fmt(&self.0, f)
            }
        }

        // Encoded as (high, low) 128-bit halves.
        #[cfg(feature = "bincode")]
        impl bincode::Encode for $ty {
            fn encode<E: bincode::enc::Encoder>(
                &self,
                encoder: &mut E,
            ) -> Result<(), bincode::error::EncodeError> {
                let (high, low) = split_in_half(self.to_be_bytes());
                bincode::Encode::encode(
                    &(u128::from_be_bytes(high), u128::from_be_bytes(low)),
                    encoder,
                )
            }
        }

        #[cfg(feature = "bincode")]
        impl<C> bincode::Decode<C> for $ty {
            fn decode<D: bincode::de::Decoder<Context = C>>(
                decoder: &mut D,
            ) -> Result<Self, bincode::error::DecodeError> {
                let (high, low) = <(u128, u128) as bincode::Decode<C>>::decode(decoder)?;
                let mut bytes = [0; 32];
                bytes[..16].copy_from_slice(&high.to_be_bytes());
                bytes[16..].copy_from_slice(&low.to_be_bytes());
                Ok(Self::from_be_bytes(bytes))
            }
        }

        #[cfg(feature = "bincode")]
        bincode::impl_borrow_decode!($ty);

        #[cfg(feature = "serde")]
        impl crate::serde::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.collect_str(&format_args!("{:x}", self))
                } else {
                    serializer.serialize_bytes(&self.to_be_bytes())
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> crate::serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                use crate::serde::de;

                if d.is_human_readable() {
                    struct HexVisitor;

                    impl<'de> de::Visitor<'de> for HexVisitor {
                        type Value = $ty;

                        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                            f.write_str("a 32 byte ASCII hex string")
                        }

                        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                        where
                            E: de::Error,
                        {
                            if s.len() != 64 {
                                return Err(de::Error::invalid_length(s.len(), &self));
                            }

                            let b = hex_conservative::decode_to_array::<32>(s).map_err(|_| {
                                de::Error::invalid_value(de::Unexpected::Str(s), &self)
                            })?;

                            Ok(<$ty>::from_be_bytes(b))
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                        where
                            E: de::Error,
                        {
                            if let Ok(hex) = core::str::from_utf8(v) {
                                let b =
                                    hex_conservative::decode_to_array::<32>(hex).map_err(|_| {
                                        de::Error::invalid_value(de::Unexpected::Str(hex), &self)
                                    })?;

                                Ok(<$ty>::from_be_bytes(b))
                            } else {
                                Err(E::invalid_value(de::Unexpected::Bytes(v), &self))
                            }
                        }
                    }
                    d.deserialize_str(HexVisitor)
                } else {
                    struct BytesVisitor;

                    impl<'de> de::Visitor<'de> for BytesVisitor {
                        type Value = $ty;

                        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                            f.write_str("a sequence of bytes")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                        where
                            E: de::Error,
                        {
                            let b = v
                                .try_into()
                                .map_err(|_| de::Error::invalid_length(v.len(), &self))?;
                            Ok(<$ty>::from_be_bytes(b))
                        }
                    }

                    d.deserialize_bytes(BytesVisitor)
                }
            }
        }
    };
}

/// Splits a 32 byte array into two 16 byte arrays.
#[cfg(feature = "bincode")]
fn split_in_half(a: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut high = [0_u8; 16];
    let mut low = [0_u8; 16];

    high.copy_from_slice(&a[..16]);
    low.copy_from_slice(&a[16..]);

    (high, low)
}

/// A 256-bit integer representing work.
///
/// Work is a measure of how difficult it is to find a hash below a given [`Target`].
///
/// ref: <https://en.bitcoin.it/wiki/Work>
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Work(Arith256);

impl Work {
    /// Lowest possible work value for Mainnet. See comment on [`Params::pow_limit`] for more info.
    pub const MAINNET_MIN: Work =
        Work(from_high_u128(0x0000_0000_ffff_0000_0000_0000_0000_0000_u128));

    /// Lowest possible work value for Testnet. See comment on [`Params::pow_limit`] for more info.
    pub const TESTNET_MIN: Work =
        Work(from_high_u128(0x0000_0000_ffff_0000_0000_0000_0000_0000_u128));

    /// Lowest possible work value for Devnet. See comment on [`Params::pow_limit`] for more info.
    pub const DEVNET_MIN: Work =
        Work(from_high_u128(0x0000_0377_ae00_0000_0000_0000_0000_0000_u128));

    /// Lowest possible work value for Regtest. See comment on [`Params::pow_limit`] for more info.
    pub const REGTEST_MIN: Work =
        Work(from_high_u128(0x7fff_ff00_0000_0000_0000_0000_0000_0000_u128));

    /// Converts this [`Work`] to [`Target`].
    pub fn to_target(self) -> Target {
        Target(inverse(self.0))
    }

    /// Returns log2 of this work.
    ///
    /// The result inherently suffers from a loss of precision and is, therefore, meant to be
    /// used mainly for informative and displaying purposes, similarly to Bitcoin Core's
    /// `log2_work` output in its logs.
    pub fn log2(self) -> f64 {
        self.0.to_f64().log2()
    }
}
do_impl!(Work);

impl Add for Work {
    type Output = Work;
    fn add(self, rhs: Self) -> Self {
        Work(self.0 + rhs.0)
    }
}

impl Sub for Work {
    type Output = Work;
    fn sub(self, rhs: Self) -> Self {
        Work(self.0 - rhs.0)
    }
}

/// A 256-bit integer representing target.
///
/// The SHA-256 hash of a block's header must be lower than or equal to the current target for the
/// block to be accepted by the network. The lower the target, the more difficult it is to generate
/// a block. (See also [`Work`].)
///
/// ref: <https://en.bitcoin.it/wiki/Target>
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Target(Arith256);

impl Target {
    /// When parsing nBits, Bitcoin Core converts a negative target threshold into a target of zero.
    pub const ZERO: Target = Target(Arith256::ZERO);
    /// The maximum possible target.
    ///
    /// This value is used to calculate difficulty, which is defined as how difficult the current
    /// target makes it to find a block relative to how difficult it would be at the highest
    /// possible target. Remember `highest target` == `lowest difficulty`.
    ///
    /// ref: <https://en.bitcoin.it/wiki/Target>
    // In Bitcoind this is ~(u256)0 >> 32 stored as a floating-point type so it gets truncated, hence
    // the low 208 bits are all zero.
    pub const MAX: Self = Target(from_high_u128(0xFFFF_u128 << (208 - 128)));

    /// The maximum possible target (see [`Target::MAX`]).
    ///
    /// This is provided for consistency with Rust 1.41.1, newer code should use [`Target::MAX`].
    pub const fn max_value() -> Self {
        Target::MAX
    }

    /// Computes the [`Target`] value from a compact representation.
    ///
    /// A negative or overflowing compact value yields [`Target::ZERO`].
    ///
    /// ref: <https://developer.bitcoin.org/reference/block_chain.html#target-nbits>
    pub fn from_compact(c: CompactTarget) -> Target {
        let decoded = dash_num::CompactTarget::new(c.0).expand();
        if decoded.negative || decoded.overflow {
            Target::ZERO
        } else {
            Target(decoded.value)
        }
    }

    /// Computes the compact value from a [`Target`] representation.
    ///
    /// The compact form is by definition lossy, this means that
    /// `t == Target::from_compact(t.to_compact_lossy())` does not always hold.
    pub fn to_compact_lossy(self) -> CompactTarget {
        let mut size = self.0.bits().div_ceil(8);
        let mut compact = if size <= 3 {
            (self.0.low_u64() << (8 * (3 - size))) as u32
        } else {
            let bn = self.0.wrapping_shr(8 * (size - 3));
            bn.low_u32()
        };

        if (compact & 0x0080_0000) != 0 {
            compact >>= 8;
            size += 1;
        }

        CompactTarget(compact | (size << 24))
    }

    /// Returns true if block hash is less than or equal to this [`Target`].
    ///
    /// Proof-of-work validity for a block requires the hash of the block to be less than or equal
    /// to the target.
    pub fn is_met_by(&self, hash: BlockHash) -> bool {
        use hashes::Hash;
        let hash = Arith256::from_lendian(hash.to_byte_array());
        hash <= self.0
    }

    /// Converts this [`Target`] to [`Work`].
    ///
    /// "Work" is defined as the work done to mine a block with this target value (recorded in the
    /// block header in compact form as nBits). This is not the same as the difficulty to mine a
    /// block with this target (see `Self::difficulty`).
    pub fn to_work(self) -> Work {
        Work(inverse(self.0))
    }

    /// Computes the popular "difficulty" measure for mining.
    ///
    /// Difficulty represents how difficult the current target makes it to find a block, relative to
    /// how difficult it would be at the highest possible target (highest target == lowest difficulty).
    ///
    /// For example, a difficulty of 6,695,826 means that at a given hash rate, it will, on average,
    /// take ~6.6 million times as long to find a valid block as it would at a difficulty of 1, or
    /// alternatively, it will take, again on average, ~6.6 million times as many hashes to find a
    /// valid block
    ///
    /// # Note
    ///
    /// Difficulty is calculated using the following algorithm `max / current` where [max] is
    /// defined for the Bitcoin network and `current` is the current [target] for this block. As
    /// such, a low target implies a high difficulty. Since [`Target`] is represented as a 256-bit
    /// integer but `difficulty()` returns only 128 bits this means for targets below approximately
    /// `0xffff_ffff_ffff_ffff_ffff_ffff` `difficulty()` will saturate at `u128::MAX`.
    ///
    /// [max]: Target::max
    /// [target]: crate::blockdata::block::Header::target
    pub fn difficulty(&self) -> u128 {
        let d = Target::MAX.0 / self.0;
        d.saturating_to_u128()
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    ///
    /// See [`difficulty`] for details.
    ///
    /// [`difficulty`]: Target::difficulty
    pub fn difficulty_float(&self) -> f64 {
        TARGET_MAX_F64 / self.0.to_f64()
    }
}
do_impl!(Target);

/// Encoding of 256-bit target as 32-bit float.
///
/// This is used to encode a target into the block header. Satoshi made this part of consensus code
/// in the original version of Bitcoin, likely copying an idea from OpenSSL.
///
/// OpenSSL's bignum (BN) type has an encoding, which is even called "compact" as in dash, which
/// is exactly this format.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CompactTarget(u32);

impl CompactTarget {
    /// Creates a [`CompactTarget`] from a consensus encoded `u32`.
    pub fn from_consensus(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the consensus encoded `u32` representation of this [`CompactTarget`].
    pub fn to_consensus(self) -> u32 {
        self.0
    }
}

impl From<CompactTarget> for Target {
    fn from(c: CompactTarget) -> Self {
        Target::from_compact(c)
    }
}

impl FromHexStr for CompactTarget {
    type Error = crate::parse::ParseIntError;

    fn from_hex_str_no_prefix<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, Self::Error> {
        let compact_target = crate::parse::hex_u32(s)?;
        Ok(Self::from_consensus(compact_target))
    }
}

impl Encodable for CompactTarget {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for CompactTarget {
    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        u32::consensus_decode(r).map(CompactTarget)
    }
}

// Target::MAX as a float value. Calculated with `Arith256::to_f64`.
// This is validated in the unit tests as well.
const TARGET_MAX_F64: f64 = 2.695953529101131e67;

/// Creates an [`Arith256`] from its high 128 bits, with the low 128 bits zero.
const fn from_high_u128(high: u128) -> Arith256 {
    let high = high.to_be_bytes();
    let mut be = [0; 32];
    let mut i = 0;
    while i < 16 {
        be[i] = high[i];
        i += 1;
    }
    Arith256::from_bendian(be)
}

/// Calculates 2^256 / (x + 1) where x is a 256 bit unsigned integer.
///
/// 2**256 / (x + 1) == ~x / (x + 1) + 1
///
/// (Equation shamelessly stolen from bitcoind)
fn inverse(x: Arith256) -> Arith256 {
    // We should never have a target/work of zero so this doesn't matter
    // that much, but we define the inverse of 0 as max.
    if x == Arith256::ZERO {
        return Arith256::MAX;
    }
    // We define the inverse of 1 as max.
    if x == Arith256::ONE {
        return Arith256::MAX;
    }
    // We define the inverse of max as 1.
    if x == Arith256::MAX {
        return Arith256::ONE;
    }

    let ret = !x / x.wrapping_add(Arith256::ONE);
    ret.wrapping_add(Arith256::ONE)
}

/// Error from `TryFrom<signed type>` implementations, occurs when input is negative.
#[derive(Debug)]
pub struct TryFromError(i128);

impl fmt::Display for TryFromError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "attempt to create unsigned integer type from negative number: {}", self.0)
    }
}

impl std::error::Error for TryFromError {}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    impl<T: Into<u128>> From<T> for Target {
        fn from(x: T) -> Self {
            Self(Arith256::from_u128(x.into()))
        }
    }

    impl<T: Into<u128>> From<T> for Work {
        fn from(x: T) -> Self {
            Self(Arith256::from_u128(x.into()))
        }
    }

    #[test]
    fn compact_target_from_hex_str_happy_path() {
        let actual = CompactTarget::from_hex_str("0x01003456").unwrap();
        let expected = CompactTarget(0x01003456);
        assert_eq!(actual, expected);
    }

    #[test]
    fn compact_target_from_hex_str_no_prefix_happy_path() {
        let actual = CompactTarget::from_hex_str_no_prefix("01003456").unwrap();
        let expected = CompactTarget(0x01003456);
        assert_eq!(actual, expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn compact_target_serde() {
        let compact = CompactTarget::from_consensus(0x1d00_ffff);
        assert_eq!(serde_json::to_string(&compact).unwrap(), "486604799");
        assert_eq!(serde_json::from_str::<CompactTarget>("486604799").unwrap(), compact);
        assert!(serde_json::from_str::<CompactTarget>("\"0x1d00ffff\"").is_err());

        let config = bincode::config::standard();
        let encoded = bincode::serde::encode_to_vec(compact, config).unwrap();
        assert_eq!(encoded, crate::internal_macros::hex!("fcffff001d"));
        assert_eq!(
            bincode::serde::decode_from_slice::<CompactTarget, _>(&encoded, config).unwrap().0,
            compact
        );
    }

    #[test]
    fn compact_target_from_hex_invalid_hex_should_err() {
        let hex = "0xzbf9";
        let result = CompactTarget::from_hex_str(hex);
        assert!(result.is_err());
    }

    #[test_case(0x0100_3456, 0x00; "high bit set")]
    #[test_case(0x0112_3456, 0x12)]
    #[test_case(0x0200_8000, 0x80)]
    #[test_case(0x0500_9234, 0x9234_0000)]
    #[test_case(0x0492_3456, 0x00; "high bit set in 0x92")]
    #[test_case(0x0412_3456, 0x1234_5600; "inverse of above, no high bit")]
    #[test_case(0x0180_0000, 0x00; "sign bit shifted out of a short mantissa")]
    #[test_case(0x2300_0001, 0x00; "overflow")]
    fn target_from_compact(n_bits: u32, target: u64) {
        let want = Target::from(target);
        let got = Target::from_compact(CompactTarget::from_consensus(n_bits));
        assert_eq!(got, want);
    }

    #[test]
    fn target_is_met_by_for_target_equals_hash() {
        use std::str::FromStr;

        use hashes::Hash;

        let hash =
            BlockHash::from_str("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c")
                .expect("failed to parse block hash");
        let target = Target(Arith256::from_lendian(hash.to_byte_array()));
        assert!(target.is_met_by(hash));
    }

    #[test]
    fn max_target_from_compact() {
        // The highest possible target is defined as 0x1d00ffff
        let bits = 0x1d00ffff_u32;
        let want = Target::MAX;
        let got = Target::from_compact(CompactTarget::from_consensus(bits));
        assert_eq!(got, want)
    }

    #[test_case(0x1d00_ffff, 1.0; "max target")]
    #[test_case(0x1c00_ffff, 256.0)]
    #[test_case(0x1b00_ffff, 65536.0)]
    #[test_case(0x1a00_f3a2, 17628585.065897066)]
    fn target_difficulty_float(n_bits: u32, difficulty: f64) {
        let target = Target::from_compact(CompactTarget::from_consensus(n_bits));
        assert_eq!(target.difficulty_float(), difficulty);
    }

    #[test]
    fn target_max_f64() {
        assert_eq!(Target::MAX.0.to_f64(), TARGET_MAX_F64);
    }

    #[test]
    fn roundtrip_compact_target() {
        let consensus = 0x1d00_ffff;
        let compact = CompactTarget::from_consensus(consensus);
        let t = Target::from_compact(CompactTarget::from_consensus(consensus));
        assert_eq!(t, Target::from(compact)); // From/Into sanity check.

        let back = t.to_compact_lossy();
        assert_eq!(back, compact); // From/Into sanity check.

        assert_eq!(back.to_consensus(), consensus);
    }

    #[test]
    fn roundtrip_target_work() {
        let target = Target::from(0xdeadbeef_u32);
        let work = target.to_work();
        let back = work.to_target();
        assert_eq!(back, target)
    }

    // Compare work log2 to historical Bitcoin Core values found in Core logs.
    #[test_case(0x200020002, 33.000022; "height 1")]
    #[test_case(0xa97d67041c5e51596ee7, 79.405055; "height 308004")]
    #[test_case(0x1dc45d79394baa8ab18b20, 84.895644; "height 418141")]
    #[test_case(0x8c85acb73287e335d525b98, 91.134654; "height 596624")]
    #[test_case(0x2ef447e01d1642c40a184ada, 93.553183; "height 738965")]
    fn work_log2(chainwork: u128, core_log2: f64) {
        // Core log2 in the logs is rounded to 6 decimal places.
        let log2 = (Work::from(chainwork).log2() * 1e6).round() / 1e6;
        assert_eq!(log2, core_log2)
    }

    #[test]
    fn work_log2_bounds() {
        assert_eq!(Work(Arith256::ONE).log2(), 0.0);
        assert_eq!(Work(Arith256::MAX).log2(), 256.0);
    }

    #[test]
    fn u256_zero_min_max_inverse() {
        assert_eq!(inverse(Arith256::MAX), Arith256::ONE);
        assert_eq!(inverse(Arith256::ONE), Arith256::MAX);
        assert_eq!(inverse(Arith256::ZERO), Arith256::MAX);
    }

    #[test]
    fn u256_max_min_inverse_roundtrip() {
        let max = Arith256::MAX;

        for min in [Arith256::ZERO, Arith256::ONE].iter() {
            // lower target means more work required.
            assert_eq!(Target(max).to_work(), Work(Arith256::ONE));
            assert_eq!(Target(*min).to_work(), Work(max));

            assert_eq!(Work(max).to_target(), Target(Arith256::ONE));
            assert_eq!(Work(*min).to_target(), Target(max));
        }
    }

    #[cfg(feature = "serde")]
    #[test_case("0000000000000000000000000000000000000000000000000000000000000000"; "zero")]
    #[test_case("00000000000000000000000000000000000000000000000000000000deadbeef"; "low word")]
    #[test_case("000000000000dd44000000000000cc33000000000000bb22000000000000aa11"; "every word")]
    #[test_case("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; "max")]
    #[test_case("deadbeeaa69b455cd41bb662a69b4550a69b455cd41bb662a69b4555deadbeef"; "mixed")]
    fn u256_serde(hex: &str) {
        let be = hex_conservative::decode_to_array::<32>(hex).unwrap();
        let json = format!("\"{}\"", hex);
        let config = bincode::config::standard();

        let work = Work::from_be_bytes(be);
        assert_eq!(serde_json::to_string(&work).unwrap(), json);
        assert_eq!(serde_json::from_str::<Work>(&json).unwrap(), work);

        let bin_encoded = bincode::encode_to_vec(work, config).unwrap();
        let bin_decoded: Work = bincode::decode_from_slice(&bin_encoded, config).unwrap().0;
        assert_eq!(bin_decoded, work);

        let target = Target::from_be_bytes(be);
        assert_eq!(serde_json::to_string(&target).unwrap(), json);
        assert_eq!(serde_json::from_str::<Target>(&json).unwrap(), target);

        let bin_encoded = bincode::encode_to_vec(target, config).unwrap();
        let bin_decoded: Target = bincode::decode_from_slice(&bin_encoded, config).unwrap().0;
        assert_eq!(bin_decoded, target);
    }

    #[cfg(feature = "serde")]
    #[test_case(
        "\"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffg\"";
        "invalid char"
    )]
    #[test_case(
        "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"";
        "too short"
    )]
    #[test_case(
        "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"";
        "too long"
    )]
    fn u256_serde_rejects(json: &str) {
        assert!(serde_json::from_str::<Work>(json).is_err());
    }

    #[cfg(feature = "bincode")]
    #[test_case(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000";
        "zero"
    )]
    #[test_case(
        "00000000000000000000000000000000000000000000000000000000deadbeef",
        "00fcefbeadde";
        "low word"
    )]
    #[test_case(
        "1badcafedeadbeefdeafbabe2bedfeedbaadf00ddefaceda11fed2bad1c0ffe0",
        "feedfeed2bbebaafdeefbeaddefecaad1bfee0ffc0d1bad2fe11dacefade0df0adba";
        "mixed"
    )]
    #[test_case(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "fefffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffff";
        "max"
    )]
    fn u256_bincode(value: &str, encoded: &str) {
        let config = bincode::config::standard();
        let be = hex_conservative::decode_to_array::<32>(value).unwrap();
        let encoded = hex_conservative::decode_to_vec(encoded).unwrap();

        let work = Work::from_be_bytes(be);
        assert_eq!(bincode::encode_to_vec(work, config).unwrap(), encoded);
        assert_eq!(bincode::decode_from_slice::<Work, _>(&encoded, config).unwrap().0, work);

        let target = Target::from_be_bytes(be);
        assert_eq!(bincode::encode_to_vec(target, config).unwrap(), encoded);
        assert_eq!(bincode::decode_from_slice::<Target, _>(&encoded, config).unwrap().0, target);
    }
}
