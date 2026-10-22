//! Various macros used by the Rust Bitcoin ecosystem.
//!

/// Implements standard array methods for a given wrapper type.
#[macro_export]
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:expr) => {
        impl<'a> core::convert::From<[$ty; $len]> for $thing {
            fn from(data: [$ty; $len]) -> Self {
                $thing(data)
            }
        }

        impl<'a> core::convert::TryFrom<&'a [$ty]> for $thing {
            type Error = core::array::TryFromSliceError;

            fn try_from(data: &'a [$ty]) -> Result<Self, Self::Error> {
                use core::convert::TryInto;

                Ok($thing(data.try_into()?))
            }
        }

        impl AsRef<[$ty; $len]> for $thing {
            fn as_ref(&self) -> &[$ty; $len] {
                &self.0
            }
        }

        impl AsMut<[$ty; $len]> for $thing {
            fn as_mut(&mut self) -> &mut [$ty; $len] {
                &mut self.0
            }
        }

        impl AsRef<[$ty]> for $thing {
            fn as_ref(&self) -> &[$ty] {
                &self.0
            }
        }

        impl AsMut<[$ty]> for $thing {
            fn as_mut(&mut self) -> &mut [$ty] {
                &mut self.0
            }
        }

        impl<I> core::ops::Index<I> for $thing
        where
            [$ty]: core::ops::Index<I>,
        {
            type Output = <[$ty] as core::ops::Index<I>>::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output {
                &self.0[index]
            }
        }
    };
}

/// Implements `Debug` by calling through to `Display`.
#[macro_export]
macro_rules! debug_from_display {
    ($thing:ident) => {
        impl core::fmt::Debug for $thing {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                core::fmt::Display::fmt(self, f)
            }
        }
    };
}

/// Formats `$len` bytes as hex in integer style.
///
/// Right aligned by default and `0x` under `{:#}`, with precision ignored.
/// Formatting through `hex_conservative` directly would pad like a string and
/// change how these types print with a width.
#[macro_export]
macro_rules! fmt_hex_exact {
    ($f:expr, $len:expr, $bytes:expr, $case:expr) => {{
        let mut encoder = ::hex_conservative::buf_encoder::BufEncoder::<{ $len * 2 }>::new($case);
        encoder.put_bytes($bytes);
        $f.pad_integral(true, "0x", encoder.as_str())
    }};
}

/// Implements several traits for byte-based newtypes.
/// Implements:
/// - core::fmt::LowerHex
/// - core::fmt::UpperHex
/// - core::fmt::Display
/// - core::str::FromStr
///
/// The serde impls need `dash_types` and `TryFrom<&[u8]>` on the type.
#[macro_export]
macro_rules! impl_bytes_newtype {
    ($t:ident, $len:expr) => {
        impl $t {
            /// Returns a reference the underlying bytes.
            #[inline]
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Returns the underlying bytes.
            #[inline]
            pub fn to_bytes(self) -> [u8; $len] {
                // We rely on `Copy` being implemented for $t so conversion
                // methods use the correct Rust naming conventions.
                fn check_copy<T: Copy>() {}
                check_copy::<$t>();

                self.0
            }
        }

        impl core::fmt::LowerHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                $crate::fmt_hex_exact!(f, $len, &self.0, ::hex_conservative::Case::Lower)
            }
        }

        impl core::fmt::UpperHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                $crate::fmt_hex_exact!(f, $len, &self.0, ::hex_conservative::Case::Upper)
            }
        }

        impl core::fmt::Display for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl core::str::FromStr for $t {
            type Err = ::hex_conservative::DecodeFixedLengthBytesError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok($t(::hex_conservative::decode_to_array(s)?))
            }
        }

        #[cfg(feature = "serde")]
        impl ::serde::Serialize for $t {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                ::dash_types::serialize::hex::serialize_as(&self.0, self, s)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> ::serde::Deserialize<'de> for $t {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<$t, D::Error> {
                ::dash_types::serialize::hex::deserialize_as(d, str::parse::<$t>)
            }
        }
    };
}
