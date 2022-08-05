#[cfg(feature = "std")] use std::error;
use std::{fmt};

/// This type is consensus valid but an input including it would prevent the transaction from
/// being relayed on today's Dash network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonStandardSighashType(pub u32);

impl fmt::Display for NonStandardSighashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Non standard sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl error::Error for NonStandardSighashType {}

/// Legacy Hashtype of an input's signature
#[deprecated(since = "0.28.0", note = "Please use [`EcdsaSighashType`] instead")]
pub type SigHashType = EcdsaSighashType;

/// Hashtype of an input's signature, encoded in the last byte of the signature.
///
/// Fixed values so they can be cast as integer types for encoding (see also
/// [`SchnorrSighashType`]).
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum EcdsaSighashType {
    /// 0x1: Sign all outputs.
    All		= 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None	= 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single	= 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay		= 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay	= 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay	= 0x83
}
serde_string_impl!(EcdsaSighashType, "a EcdsaSighashType data");

impl fmt::Display for EcdsaSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EcdsaSighashType::All => "SIGHASH_ALL",
            EcdsaSighashType::None => "SIGHASH_NONE",
            EcdsaSighashType::Single => "SIGHASH_SINGLE",
            EcdsaSighashType::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            EcdsaSighashType::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            EcdsaSighashType::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for EcdsaSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SIGHASH_ALL" => Ok(EcdsaSighashType::All),
            "SIGHASH_NONE" => Ok(EcdsaSighashType::None),
            "SIGHASH_SINGLE" => Ok(EcdsaSighashType::Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(EcdsaSighashType::AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(EcdsaSighashType::NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(EcdsaSighashType::SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_owned() }),
        }
    }
}

impl EcdsaSighashType {
    /// Splits the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean.
    pub(crate) fn split_anyonecanpay_flag(self) -> (EcdsaSighashType, bool) {
        match self {
            EcdsaSighashType::All => (EcdsaSighashType::All, false),
            EcdsaSighashType::None => (EcdsaSighashType::None, false),
            EcdsaSighashType::Single => (EcdsaSighashType::Single, false),
            EcdsaSighashType::AllPlusAnyoneCanPay => (EcdsaSighashType::All, true),
            EcdsaSighashType::NonePlusAnyoneCanPay => (EcdsaSighashType::None, true),
            EcdsaSighashType::SinglePlusAnyoneCanPay => (EcdsaSighashType::Single, true)
        }
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    #[deprecated(since="0.28.0", note="please use `from_consensus`")]
    pub fn from_u32_consensus(n: u32) -> EcdsaSighashType {
        EcdsaSighashType::from_consensus(n)
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// **Note**: this replicates consensus behaviour, for current standardness rules correctness
    /// you probably want [`Self::from_standard`].
    ///
    /// This might cause unexpected behavior because it does not roundtrip. That is,
    /// `EcdsaSighashType::from_consensus(n) as u32 != n` for non-standard values of `n`. While
    /// verifying signatures, the user should retain the `n` and use it compute the signature hash
    /// message.
    pub fn from_consensus(n: u32) -> EcdsaSighashType {
        // In Bitcoin Core, the SignatureHash function will mask the (int32) value with
        // 0x1f to (apparently) deactivate ACP when checking for SINGLE and NONE bits.
        // We however want to be matching also against on ACP-masked ALL, SINGLE, and NONE.
        // So here we re-activate ACP.
        let mask = 0x1f | 0x80;
        match n & mask {
            // "real" sighashes
            0x01 => EcdsaSighashType::All,
            0x02 => EcdsaSighashType::None,
            0x03 => EcdsaSighashType::Single,
            0x81 => EcdsaSighashType::AllPlusAnyoneCanPay,
            0x82 => EcdsaSighashType::NonePlusAnyoneCanPay,
            0x83 => EcdsaSighashType::SinglePlusAnyoneCanPay,
            // catchalls
            x if x & 0x80 == 0x80 => EcdsaSighashType::AllPlusAnyoneCanPay,
            _ => EcdsaSighashType::All
        }
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    #[deprecated(since="0.28.0", note="please use `from_standard`")]
    pub fn from_u32_standard(n: u32) -> Result<EcdsaSighashType, NonStandardSighashType> {
        EcdsaSighashType::from_standard(n)
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// # Errors
    ///
    /// If `n` is a non-standard sighash value.
    pub fn from_standard(n: u32) -> Result<EcdsaSighashType, NonStandardSighashType> {
        match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => Ok(EcdsaSighashType::All),
            0x02 => Ok(EcdsaSighashType::None),
            0x03 => Ok(EcdsaSighashType::Single),
            0x81 => Ok(EcdsaSighashType::AllPlusAnyoneCanPay),
            0x82 => Ok(EcdsaSighashType::NonePlusAnyoneCanPay),
            0x83 => Ok(EcdsaSighashType::SinglePlusAnyoneCanPay),
            non_standard => Err(NonStandardSighashType(non_standard))
        }
    }

    /// Converts [`EcdsaSighashType`] to a `u32` sighash flag.
    ///
    /// The returned value is guaranteed to be a valid according to standardness rules.
    pub fn to_u32(self) -> u32 { self as u32 }
}

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone)]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl ::std::error::Error for SighashTypeParseError {}