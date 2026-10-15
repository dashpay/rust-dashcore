//! Various macros used by the Rust Bitcoin ecosystem.
//!

/// Implements standard array methods for a given wrapper type.
#[macro_export]
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:literal) => {
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
                if s.is_human_readable() {
                    s.collect_str(self)
                } else {
                    s.serialize_bytes(&self[..])
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> ::serde::Deserialize<'de> for $t {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<$t, D::Error> {
                if d.is_human_readable() {
                    struct HexVisitor;

                    impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
                        type Value = $t;

                        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                            f.write_str("an ASCII hex string")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                        where
                            E: ::serde::de::Error,
                        {
                            use ::serde::de::Unexpected;

                            if let Ok(hex) = core::str::from_utf8(v) {
                                hex.parse().map_err(E::custom)
                            } else {
                                return Err(E::invalid_value(Unexpected::Bytes(v), &self));
                            }
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: ::serde::de::Error,
                        {
                            v.parse().map_err(E::custom)
                        }
                    }

                    d.deserialize_str(HexVisitor)
                } else {
                    struct BytesVisitor;

                    impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                        type Value = $t;

                        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                            f.write_str("a bytestring")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                        where
                            E: ::serde::de::Error,
                        {
                            if v.len() != $len {
                                Err(E::invalid_length(v.len(), &stringify!($len)))
                            } else {
                                let mut ret = [0; $len];
                                ret.copy_from_slice(v);
                                Ok($t(ret))
                            }
                        }
                    }

                    d.deserialize_bytes(BytesVisitor)
                }
            }
        }
    };
}
