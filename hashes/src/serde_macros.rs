// Bitcoin Hashes Library
// Written in 2018 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Macros for serde trait implementations, and supporting code.
//!

/// Functions used by serde impls of all hashes.
#[cfg(feature = "serde")]
pub mod serde_details {
    use core::marker::PhantomData;
    use core::str::FromStr;
    use core::{fmt, ops, str};

    use crate::Error;
    use serde::{de, Deserializer, Serializer};

    /// Single visitor that accepts every shape a hash can arrive in: an ASCII
    /// hex string (`visit_str`), a UTF-8 byte slice that decodes as hex
    /// (`visit_bytes` of length `2*N` — note `N` is in BYTES per the macro,
    /// see `serde_impl!` invocation in `internal_macros.rs`), a raw byte
    /// slice of the hash's length-in-bytes (`visit_bytes` of length `N`),
    /// or a length-prefixed sequence of `u8` from non-self-describing
    /// formats (`visit_seq`, used by bincode).
    ///
    /// Required to interoperate with serde's `ContentDeserializer`, the
    /// format-agnostic intermediate buffer serde uses to dispatch
    /// internally-tagged enums (`#[serde(tag = "...")]`), `flatten`, and
    /// untagged enums. `ContentDeserializer` always reports
    /// `is_human_readable() == true` regardless of the upstream format. This
    /// is intentional in serde's source — see long-standing upstream issues;
    /// the maintainers consider it working-as-intended and the recommended
    /// pattern is **"don't branch on `is_human_readable()` for shape dispatch
    /// — accept any shape."** A value originally written by a
    /// non-human-readable encoder (raw bytes) can therefore be replayed into
    /// the human-readable branch as bytes / a byte-buf and must be accepted
    /// there. See the regression tests in
    /// `dash/src/hash_types.rs::serde_round_trip_through_internally_tagged_enum`.
    struct AnyShapeVisitor<ValueT>(PhantomData<ValueT>);

    impl<'de, ValueT> de::Visitor<'de> for AnyShapeVisitor<ValueT>
    where
        ValueT: SerdeHash,
        <ValueT as FromStr>::Err: fmt::Display,
    {
        type Value = ValueT;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an ASCII hex string or a byte string of the hash length")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Self::Value::from_str(v).map_err(E::custom)
        }

        fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Self::Value::from_str(v).map_err(E::custom)
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            // Disambiguate by length. A correctly-sized raw hash byte string
            // is exactly `N` bytes (`N` is in bytes per the macro — see
            // `serde_impl!` invocation in `internal_macros.rs`); a hex-encoded
            // form of that hash is `2*N` ASCII bytes. Any other length is
            // rejected.
            let raw_len_bytes = ValueT::N;
            let hex_len_bytes = raw_len_bytes * 2;
            if v.len() == raw_len_bytes {
                SerdeHash::from_slice_delegated(v)
                    .map_err(|_| E::invalid_length(v.len(), &stringify!(N)))
            } else if v.len() == hex_len_bytes {
                if let Ok(hex) = str::from_utf8(v) {
                    Self::Value::from_str(hex).map_err(E::custom)
                } else {
                    Err(E::invalid_value(de::Unexpected::Bytes(v), &self))
                }
            } else {
                Err(E::invalid_length(v.len(), &self))
            }
        }

        fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_bytes(v)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            // Used by bincode and any non-self-describing format that emits a
            // length-prefixed sequence of u8. Use a stack buffer sized to fit
            // the largest hash this trait services (sha512 / Hmac<sha512> at
            // 64 bytes) so we keep `no_std`-compatible (no `Vec`/`alloc`).
            // Bumping `MAX_HASH_BYTES` is only needed if a wider digest type
            // is added — `debug_assert!` catches that in tests.
            const MAX_HASH_BYTES: usize = 64;
            let raw_len_bytes = ValueT::N;
            debug_assert!(
                raw_len_bytes <= MAX_HASH_BYTES,
                "hash byte-length {} exceeds AnyShapeVisitor stack buffer ({}); bump MAX_HASH_BYTES",
                raw_len_bytes,
                MAX_HASH_BYTES,
            );
            let mut buf = [0u8; MAX_HASH_BYTES];
            let mut len: usize = 0;
            while let Some(b) = seq.next_element::<u8>()? {
                if len == raw_len_bytes {
                    return Err(de::Error::invalid_length(len + 1, &stringify!(N)));
                }
                buf[len] = b;
                len += 1;
            }
            if len != raw_len_bytes {
                return Err(de::Error::invalid_length(len, &stringify!(N)));
            }
            SerdeHash::from_slice_delegated(&buf[..len])
                .map_err(|_| de::Error::invalid_length(len, &stringify!(N)))
        }
    }

    /// Default serialization/deserialization methods.
    pub trait SerdeHash
    where
        Self: Sized
            + FromStr
            + fmt::Display
            + ops::Index<usize, Output = u8>
            + ops::Index<ops::RangeFull, Output = [u8]>,
        <Self as FromStr>::Err: fmt::Display,
    {
        /// Size of the hash, in bytes.
        const N: usize;

        /// Helper function to turn a deserialized slice into the correct hash type.
        fn from_slice_delegated(sl: &[u8]) -> Result<Self, Error>;

        /// Do serde serialization.
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            if s.is_human_readable() {
                s.collect_str(self)
            } else {
                s.serialize_bytes(&self[..])
            }
        }

        /// Do serde deserialization.
        ///
        /// Uses a single visitor that accepts every shape a hash can arrive
        /// in (ASCII hex string, raw byte slice, length-prefixed `u8`
        /// sequence). The HR branch dispatches via `deserialize_any` to
        /// handle both true human-readable deserializers (where the visitor
        /// receives `visit_str`) and serde's `ContentDeserializer` (which
        /// reports `is_human_readable() == true` even when wrapping bytes
        /// from a non-HR source — internally-tagged enums, `flatten`, and
        /// untagged enums all route through it). The non-HR branch keeps
        /// `deserialize_bytes` because bincode is non-self-describing and
        /// does not support `deserialize_any`.
        fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            if d.is_human_readable() {
                d.deserialize_any(AnyShapeVisitor::<Self>(PhantomData))
            } else {
                d.deserialize_bytes(AnyShapeVisitor::<Self>(PhantomData))
            }
        }
    }
}

/// Implements `Serialize` and `Deserialize` for a type `$t` which
/// represents a newtype over a byte-slice over length `$len`.
#[macro_export]
#[cfg(feature = "serde")]
macro_rules! serde_impl(
    ($t:ident, $len:expr $(, $gen:ident: $gent:ident)*) => (
        impl<$($gen: $gent),*> $crate::serde_macros::serde_details::SerdeHash for $t<$($gen),*> {
            const N : usize = $len;
            fn from_slice_delegated(sl: &[u8]) -> Result<Self, $crate::Error> {
                #[allow(unused_imports)]
                use $crate::Hash as _;
                $t::from_slice(sl)
            }
        }

        impl<$($gen: $gent),*> $crate::serde::Serialize for $t<$($gen),*> {
            fn serialize<S: $crate::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                $crate::serde_macros::serde_details::SerdeHash::serialize(self, s)
            }
        }

        impl<'de $(, $gen: $gent)*> $crate::serde::Deserialize<'de> for $t<$($gen),*> {
            fn deserialize<D: $crate::serde::Deserializer<'de>>(d: D) -> Result<$t<$($gen),*>, D::Error> {
                $crate::serde_macros::serde_details::SerdeHash::deserialize(d)
            }
        }
));

/// Does an "empty" serde implementation for the configuration without serde feature.
#[macro_export]
#[cfg(not(feature = "serde"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "serde"))))]
macro_rules! serde_impl(
        ($t:ident, $len:expr $(, $gen:ident: $gent:ident)*) => ()
);
