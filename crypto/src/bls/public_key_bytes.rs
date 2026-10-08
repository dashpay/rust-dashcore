//! BLS public key bytes with compatibility for persisted binary Serde keys.

use core::{array::TryFromSliceError, fmt, str::FromStr};

use dash_types::{impl_bytes, type_cvrt, type_id::TypeId, ParseHexError};

use super::BLS_PK_LEN;

// Keep dash-types' byte API, formatting and codecs; only Serde decoding differs.
mod raw {
    use super::BLS_PK_LEN;

    dash_types::make_bytes! {
        /// BLS public key bytes.
        BlsPkBytes, BLS_PK_LEN
    }
}

/// BLS public key (48 bytes, unvalidated).
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, TypeId)]
pub struct BlsPkBytes(raw::BlsPkBytes);

impl BlsPkBytes {
    /// Wraps raw bytes without validation.
    pub const fn from_bytes(bytes: [u8; BLS_PK_LEN]) -> Self {
        Self(raw::BlsPkBytes::from_bytes(bytes))
    }

    /// Copies out the inner byte array.
    pub const fn to_bytes(&self) -> [u8; BLS_PK_LEN] {
        self.0.to_bytes()
    }

    /// Borrows the inner byte array.
    pub const fn as_bytes(&self) -> &[u8; BLS_PK_LEN] {
        self.0.as_bytes()
    }

    /// Returns `true` when every byte is zero.
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl_bytes!(BlsPkBytes, BLS_PK_LEN);
type_cvrt!(From<[u8; BLS_PK_LEN]> for BlsPkBytes, |bytes| Self::from_bytes(*bytes));

impl From<BlsPkBytes> for [u8; BLS_PK_LEN] {
    fn from(key: BlsPkBytes) -> Self {
        key.to_bytes()
    }
}

impl TryFrom<&[u8]> for BlsPkBytes {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        raw::BlsPkBytes::try_from(bytes).map(Self)
    }
}

impl AsRef<[u8]> for BlsPkBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<[u8; BLS_PK_LEN]> for BlsPkBytes {
    fn as_ref(&self) -> &[u8; BLS_PK_LEN] {
        self.as_bytes()
    }
}

impl FromStr for BlsPkBytes {
    type Err = ParseHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

macro_rules! delegate_format {
    ($($trait:ident),+ $(,)?) => {$(
        impl fmt::$trait for BlsPkBytes {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::$trait::fmt(&self.0, f)
            }
        }
    )+};
}
delegate_format!(Display, Debug, LowerHex, UpperHex);

#[cfg(feature = "serde")]
impl serde::Serialize for BlsPkBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for BlsPkBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            return raw::BlsPkBytes::deserialize(deserializer).map(Self);
        }

        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = BlsPkBytes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("48 raw bytes or 96 ASCII hex digits for a BLS public key")
            }

            fn visit_str<E: serde::de::Error>(self, hex: &str) -> Result<Self::Value, E> {
                hex.parse().map_err(E::custom)
            }

            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                match bytes.len() {
                    BLS_PK_LEN => BlsPkBytes::try_from(bytes).map_err(E::custom),
                    // Binary Serde strings and byte buffers share a length prefix in bincode.
                    len if len == 2 * BLS_PK_LEN => {
                        let hex = core::str::from_utf8(bytes).map_err(E::custom)?;
                        BlsPkBytes::from_hex(hex).map_err(E::custom)
                    }
                    len => Err(E::invalid_length(len, &self)),
                }
            }
        }

        deserializer.deserialize_byte_buf(Visitor)
    }
}
