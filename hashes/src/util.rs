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

/// Writes already encoded hex in the style of `hex-conservative` 0.2.
///
/// Right aligned by default, `0x` under `{:#}`, and precision cuts the digits.
/// `hex-conservative` 1.x pads like a string, so going through it directly
/// would change how hashes print with a width.
#[doc(hidden)]
pub fn pad_hex(f: &mut core::fmt::Formatter, encoded: &str) -> core::fmt::Result {
    match f.precision() {
        Some(precision) if encoded.len() > precision => {
            f.pad_integral(true, "0x", &encoded[..precision])
        }
        _ => f.pad_integral(true, "0x", encoded),
    }
}

/// Attempted to create a hash from an invalid length slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromSliceError {
    expected: usize,
    got: usize,
}

impl FromSliceError {
    /// Returns the expected slice length.
    pub fn expected_length(&self) -> usize {
        self.expected
    }

    /// Returns the invalid slice length.
    pub fn invalid_length(&self) -> usize {
        self.got
    }
}

impl core::fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "invalid slice length {} (expected {})", self.got, self.expected)
    }
}

impl std::error::Error for FromSliceError {}

/// Copies `sl` into an array, failing unless it is exactly `N` bytes long.
#[doc(hidden)]
pub fn slice_to_array<const N: usize>(sl: &[u8]) -> Result<[u8; N], FromSliceError> {
    sl.try_into().map_err(|_| FromSliceError {
        expected: N,
        got: sl.len(),
    })
}

#[macro_export]
/// Adds hexadecimal formatting implementation of a trait `$imp` to a given type `$ty`.
macro_rules! hex_fmt_impl(
    ($reverse:expr, $len:expr, $ty:ident) => (
        $crate::hex_fmt_impl!($reverse, $len, $ty, );
    );
    ($reverse:expr, $len:expr, $ty:ident, $($generator:ident: $gent:ident),*) => (
        impl<$($generator: $gent),*> $crate::_export::_core::fmt::LowerHex for $ty<$($generator),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                let mut encoder = $crate::_export::hex_conservative::buf_encoder::BufEncoder::<{ $len * 2 }>::new($crate::_export::hex_conservative::Case::Lower);
                let bytes = $crate::Hash::as_byte_array(self);
                if $reverse {
                    encoder.put_bytes(bytes.iter().rev());
                } else {
                    encoder.put_bytes(bytes.iter());
                }
                $crate::_export::pad_hex(f, encoder.as_str())
            }
        }

        impl<$($generator: $gent),*> $crate::_export::_core::fmt::UpperHex for $ty<$($generator),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                let mut encoder = $crate::_export::hex_conservative::buf_encoder::BufEncoder::<{ $len * 2 }>::new($crate::_export::hex_conservative::Case::Upper);
                let bytes = $crate::Hash::as_byte_array(self);
                if $reverse {
                    encoder.put_bytes(bytes.iter().rev());
                } else {
                    encoder.put_bytes(bytes.iter());
                }
                $crate::_export::pad_hex(f, encoder.as_str())
            }
        }

        impl<$($generator: $gent),*> $crate::_export::_core::fmt::Display for $ty<$($generator),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::_export::_core::fmt::LowerHex::fmt(&self, f)
            }
        }

        impl<$($generator: $gent),*> $crate::_export::_core::fmt::Debug for $ty<$($generator),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                write!(f, "{:#}", self)
            }
        }
    );
);

/// Adds slicing traits implementations to a given type `$ty`
#[macro_export]
macro_rules! borrow_slice_impl(
    ($ty:ident) => (
        $crate::borrow_slice_impl!($ty, );
    );
    ($ty:ident, $($generator:ident: $gent:ident),*) => (
        impl<$($generator: $gent),*> $crate::_export::_core::borrow::Borrow<[u8]> for $ty<$($generator),*>  {
            fn borrow(&self) -> &[u8] {
                &self[..]
            }
        }

        impl<$($generator: $gent),*> $crate::_export::_core::convert::AsRef<[u8]> for $ty<$($generator),*>  {
            fn as_ref(&self) -> &[u8] {
                &self[..]
            }
        }
    )
);

/// Creates a new newtype around a [`Hash`] type.
///
/// The syntax is similar to the usual tuple struct syntax:
///
/// ```
/// # use dashcore_hashes::{hash_newtype, sha256};
///
/// hash_newtype! {
///     /// Hash of `Foo`.
///     pub struct MyNewtype(pub sha256::Hash);
/// }
/// ```
///
/// You can use any valid visibility specifier in place of `pub` or you can omit either or both, if
/// you want the type or its field to be private.
///
/// Whether the hash is reversed or not when displaying depends on the inner type. However you can
/// override it like this:
///
/// ```
/// # use dashcore_hashes::{hash_newtype, sha256};
///
/// hash_newtype! {
///     #[hash_newtype(backward)]
///     struct MyNewtype(sha256::Hash);
/// }
/// ```
///
/// This will display the hash backwards regardless of what the inner type does. Use `forward`
/// instead of `backward` to force displaying forward.
///
/// You can add arbitrary doc comments or other attributes to the struct or it's field. Note that
/// the macro already derives [`Copy`], [`Clone`], [`Eq`], [`PartialEq`],
/// [`Hash`](core::hash::Hash), [`Ord`], [`PartialOrd`]. With the `serde` feature on, this also adds
/// [`Serialize`](serde::Serialize) and [`Deserialize](serde::Deserialize) implementations.
///
/// You can also define multiple newtypes within one macro call:
///
/// ```
/// # use dashcore_hashes::{hash_newtype, sha256, hash160};
///
/// hash_newtype! {
///     /// My custom type 1
///     pub struct Newtype1(sha256::Hash);
///
///     /// My custom type 2
///     struct Newtype2(hash160::Hash);
/// }
/// ```
///
/// Note: the macro is internally recursive. If you use too many attributes (> 256 tokens) you may
/// hit recursion limit. If you have so many attributes for a good reason, just raising the limit
/// should be OK. Note however that attribute-processing part has to use [TT muncher] which has
/// quadratic complexity, so having many attributes may blow up compile time. This should be rare.
///
/// [TT muncher]: https://danielkeep.github.io/tlborm/book/pat-incremental-tt-munchers.html
///
// Ever heard of legendary comments warning developers to not touch the code? Yep, here's another
// one. The following code is written the way it is for some specific reasons. If you think you can
// simplify it, I suggest spending your time elsewhere.
//
// If you looks at the code carefully you might ask these questions:
//
// * Why are attributes using `tt` and not `meta`?!
// * Why are the macros split like that?!
// * Why use recursion instead of `$()*`?
//
// None of these are here by accident. For some reason unknown to me, if you accept an argument to
// macro with any fragment specifier other than `tt` it will **not** match any of the rules
// requiring a specific token. Yep, I tried it, I literally got error that `hash_newtype` doesn't
// match `hash_newtype`. So all input attributes must be `tt`.
//
// Originally I wanted to define a bunch of macros that would filter-out hash_type attributes. Then
// I remembered (by seeing compiler error) that calling macros is not allowed inside attributes.
// And no, you can't bypass it by calling a helper macro and passing "output of another macro" into
// it. The whole macro gets passed, not the resulting value. So we have to generate the entire
// attributes. And you can't just place an attribute-producing macro above struct - they are
// considered separate items. This is not C.
//
// Thus struct is generated in a separate macro together with attributes. And since the macro needs
// attributes as the input and I didn't want to create confusion by using `#[]` syntax *after*
// struct, I opted to use `{}` as a separator. Yes, a separator is required because an attribute
// may be composed of multiple token trees - that's the point of "double repetition".
#[macro_export]
macro_rules! hash_newtype {
    ($($(#[$($type_attrs:tt)*])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:tt])* $field_vis:vis $hash:path);)+) => {
        $(
        $($crate::hash_newtype_known_attrs!(#[ $($type_attrs)* ]);)*

        $crate::hash_newtype_struct! {
            $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);

            $({ $($type_attrs)* })*
        }

        $crate::hex_fmt_impl!(
            <$newtype as $crate::Hash>::DISPLAY_BACKWARD,
            <$newtype as $crate::Hash>::LEN,
            $newtype
        );
        $crate::serde_impl!($newtype, <$newtype as $crate::Hash>::LEN);
        $crate::bincode_impl!($newtype, <$newtype as $crate::Hash>::LEN);
        $crate::borrow_slice_impl!($newtype);

        impl $newtype {
            /// Constructs a new hash from the underlying byte array.
            #[allow(unused)] // the user of macro may not need this
            pub const fn from_byte_array(bytes: <$hash as $crate::Hash>::Bytes) -> Self {
                $newtype(<$hash>::from_byte_array(bytes))
            }

            /// Returns the underlying byte array.
            #[allow(unused)] // the user of macro may not need this
            pub const fn to_byte_array(self) -> <$hash as $crate::Hash>::Bytes {
                self.0.to_byte_array()
            }

            /// Returns a reference to the underlying byte array.
            #[allow(unused)] // the user of macro may not need this
            pub const fn as_byte_array(&self) -> &<$hash as $crate::Hash>::Bytes {
                self.0.as_byte_array()
            }

            /// Constructs a new hash from a slice, failing unless it has the hash's length.
            #[allow(unused)] // the user of macro may not need this
            pub fn from_slice(sl: &[u8]) -> Result<Self, $crate::FromSliceError> {
                $crate::_export::slice_to_array(sl).map(Self::from_byte_array)
            }

            /// Returns the hash with every byte set to zero.
            #[allow(unused)] // the user of macro may not need this
            pub const fn all_zeros() -> Self {
                Self::from_byte_array([0; <$hash as $crate::Hash>::LEN])
            }

            /// Creates this wrapper type from the inner hash type.
            #[allow(unused)] // the user of macro may not need this
            pub fn from_raw_hash(inner: $hash) -> $newtype {
                $newtype(inner)
            }

            /// Returns the inner hash (sha256, sh256d etc.).
            #[allow(unused)] // the user of macro may not need this
            pub fn to_raw_hash(self) -> $hash {
                self.0
            }

            /// Returns a reference to the inner hash (sha256, sh256d etc.).
            #[allow(unused)] // the user of macro may not need this
            pub fn as_raw_hash(&self) -> &$hash {
                &self.0
            }

            /// Reverses the bytes of the hash
            #[allow(unused)]
            pub fn reverse(&self) -> Self {
                let mut reversed_bytes = self.to_byte_array();
                reversed_bytes.reverse();
                Self::from_byte_array(reversed_bytes)
            }
        }

        impl $crate::_export::_core::convert::From<$hash> for $newtype {
            fn from(inner: $hash) -> $newtype {
                // Due to rust 1.22 we have to use this instead of simple `Self(inner)`
                Self { 0: inner }
            }
        }

        impl $crate::_export::_core::convert::From<$newtype> for $hash {
            fn from(hashtype: $newtype) -> $hash {
                hashtype.0
            }
        }

        impl $crate::Hash for $newtype {
            type Bytes = <$hash as $crate::Hash>::Bytes;

            const DISPLAY_BACKWARD: bool = $crate::hash_newtype_get_direction!($hash, $(#[$($type_attrs)*])*);

            #[inline]
            fn from_byte_array(bytes: Self::Bytes) -> Self {
                Self::from_byte_array(bytes)
            }

            #[inline]
            fn to_byte_array(self) -> Self::Bytes {
                self.to_byte_array()
            }

            #[inline]
            fn as_byte_array(&self) -> &Self::Bytes {
                self.as_byte_array()
            }
        }

        impl $crate::_export::_core::str::FromStr for $newtype {
            type Err = $crate::_export::hex_conservative::DecodeFixedLengthBytesError;
            fn from_str(s: &str) -> $crate::_export::_core::result::Result<$newtype, Self::Err> {
                let mut bytes: [u8; <Self as $crate::Hash>::LEN] = $crate::_export::hex_conservative::decode_to_array(s)?;
                if <Self as $crate::Hash>::DISPLAY_BACKWARD {
                    bytes.reverse();
                }
                Ok($newtype(<$hash as $crate::Hash>::from_byte_array(bytes)))
            }
        }

        impl $crate::_export::_core::convert::AsRef<[u8; <$hash as $crate::Hash>::LEN]> for $newtype {
            fn as_ref(&self) -> &[u8; <$hash as $crate::Hash>::LEN] {
                AsRef::<[u8; <$hash as $crate::Hash>::LEN]>::as_ref(&self.0)
            }
        }

        impl<I: $crate::_export::_core::slice::SliceIndex<[u8]>> $crate::_export::_core::ops::Index<I> for $newtype {
            type Output = I::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output {
                &self.as_byte_array()[index]
            }
        }

        impl From<[u8; <$hash as $crate::Hash>::LEN]> for $newtype {
            fn from(bytes: [u8; <$hash as $crate::Hash>::LEN]) -> Self {
                $newtype(<$hash as $crate::Hash>::from_byte_array(bytes))
            }
        }

        impl From<$newtype> for [u8; <$hash as $crate::Hash>::LEN] {
            fn from(value: $newtype) -> Self { $crate::Hash::to_byte_array(value.0) }
        }
        )+
    };
}

/// Same as newtype without ord
#[macro_export]
macro_rules! hash_newtype_no_ord {
    ($($(#[$($type_attrs:tt)*])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:tt])* $field_vis:vis $hash:path);)+) => {
        $(
        $($crate::hash_newtype_known_attrs!(#[ $($type_attrs)* ]);)*

        $crate::hash_newtype_struct_no_ord! {
            $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);

            $({ $($type_attrs)* })*
        }

        $crate::hex_fmt_impl!(
            <$newtype as $crate::Hash>::DISPLAY_BACKWARD,
            <$newtype as $crate::Hash>::LEN,
            $newtype
        );
        $crate::serde_impl!($newtype, <$newtype as $crate::Hash>::LEN);
        $crate::borrow_slice_impl!($newtype);

        impl $newtype {
            /// Constructs a new hash from the underlying byte array.
            #[allow(unused)] // the user of macro may not need this
            pub const fn from_byte_array(bytes: <$hash as $crate::Hash>::Bytes) -> Self {
                $newtype(<$hash>::from_byte_array(bytes))
            }

            /// Returns the underlying byte array.
            #[allow(unused)] // the user of macro may not need this
            pub const fn to_byte_array(self) -> <$hash as $crate::Hash>::Bytes {
                self.0.to_byte_array()
            }

            /// Returns a reference to the underlying byte array.
            #[allow(unused)] // the user of macro may not need this
            pub const fn as_byte_array(&self) -> &<$hash as $crate::Hash>::Bytes {
                self.0.as_byte_array()
            }

            /// Constructs a new hash from a slice, failing unless it has the hash's length.
            #[allow(unused)] // the user of macro may not need this
            pub fn from_slice(sl: &[u8]) -> Result<Self, $crate::FromSliceError> {
                $crate::_export::slice_to_array(sl).map(Self::from_byte_array)
            }

            /// Returns the hash with every byte set to zero.
            #[allow(unused)] // the user of macro may not need this
            pub const fn all_zeros() -> Self {
                Self::from_byte_array([0; <$hash as $crate::Hash>::LEN])
            }

            /// Creates this wrapper type from the inner hash type.
            #[allow(unused)] // the user of macro may not need this
            pub fn from_raw_hash(inner: $hash) -> $newtype {
                $newtype(inner)
            }

            /// Returns the inner hash (sha256, sh256d etc.).
            #[allow(unused)] // the user of macro may not need this
            pub fn to_raw_hash(self) -> $hash {
                self.0
            }

            /// Returns a reference to the inner hash (sha256, sh256d etc.).
            #[allow(unused)] // the user of macro may not need this
            pub fn as_raw_hash(&self) -> &$hash {
                &self.0
            }
        }

        impl $crate::_export::_core::convert::From<$hash> for $newtype {
            fn from(inner: $hash) -> $newtype {
                // Due to rust 1.22 we have to use this instead of simple `Self(inner)`
                Self { 0: inner }
            }
        }

        impl $crate::_export::_core::convert::From<$newtype> for $hash {
            fn from(hashtype: $newtype) -> $hash {
                hashtype.0
            }
        }

        impl $crate::Hash for $newtype {
            type Bytes = <$hash as $crate::Hash>::Bytes;

            const DISPLAY_BACKWARD: bool = $crate::hash_newtype_get_direction!($hash, $(#[$($type_attrs)*])*);

            #[inline]
            fn from_byte_array(bytes: Self::Bytes) -> Self {
                Self::from_byte_array(bytes)
            }

            #[inline]
            fn to_byte_array(self) -> Self::Bytes {
                self.to_byte_array()
            }

            #[inline]
            fn as_byte_array(&self) -> &Self::Bytes {
                self.as_byte_array()
            }
        }

        impl $crate::_export::_core::str::FromStr for $newtype {
            type Err = $crate::_export::hex_conservative::DecodeFixedLengthBytesError;
            fn from_str(s: &str) -> $crate::_export::_core::result::Result<$newtype, Self::Err> {
                let mut bytes: [u8; <Self as $crate::Hash>::LEN] = $crate::_export::hex_conservative::decode_to_array(s)?;
                if <Self as $crate::Hash>::DISPLAY_BACKWARD {
                    bytes.reverse();
                }
                Ok($newtype(<$hash as $crate::Hash>::from_byte_array(bytes)))
            }
        }

        impl $crate::_export::_core::convert::AsRef<[u8; <$hash as $crate::Hash>::LEN]> for $newtype {
            fn as_ref(&self) -> &[u8; <$hash as $crate::Hash>::LEN] {
                AsRef::<[u8; <$hash as $crate::Hash>::LEN]>::as_ref(&self.0)
            }
        }

        impl<I: $crate::_export::_core::slice::SliceIndex<[u8]>> $crate::_export::_core::ops::Index<I> for $newtype {
            type Output = I::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output {
                &self.as_byte_array()[index]
            }
        }

        impl From<[u8; <$hash as $crate::Hash>::LEN]> for $newtype {
            fn from(bytes: [u8; <$hash as $crate::Hash>::LEN]) -> Self {
                $newtype(<$hash as $crate::Hash>::from_byte_array(bytes))
            }
        }

        impl From<$newtype> for [u8; <$hash as $crate::Hash>::LEN] {
            fn from(value: $newtype) -> Self { $crate::Hash::to_byte_array(value.0) }
        }
        )+
    };
}

// Generates the struct only (no impls)
//
// This is a separate macro to make it more readable and have a separate interface that allows for
// two groups of type attributes: processed and not-yet-processed ones (think about it like
// computation via recursion). The macro recursively matches unprocessed attributes, popping them
// one at a time and either ignoring them (`hash_newtype`) or appending them to the list of
// processed attributes to be added to the struct.
//
// Once the list of not-yet-processed attributes is empty the struct is generated with processed
// attributes added.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_struct {
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:meta])* $field_vis:vis $hash:path);) => {
        $(#[$other_attrs])*
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);
    };
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:meta])* $field_vis:vis $hash:path); { hash_newtype($($ignore:tt)*) } $($type_attrs:tt)*) => {
        $crate::hash_newtype_struct! {
            $(#[$other_attrs])*
            $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);

            $($type_attrs)*
        }
    };
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:meta])* $field_vis:vis $hash:path); { $other_attr:meta } $($type_attrs:tt)*) => {
        $crate::hash_newtype_struct! {
            $(#[$other_attrs])*
            #[$other_attr]
            $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);

            $($type_attrs)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_struct_no_ord {
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:meta])* $field_vis:vis $hash:path);) => {
        $(#[$other_attrs])*
        #[derive(Copy, Clone, PartialEq, Eq, Hash)]
        $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);
    };
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:meta])* $field_vis:vis $hash:path); { hash_newtype($($ignore:tt)*) } $($type_attrs:tt)*) => {
        $crate::hash_newtype_struct! {
            $(#[$other_attrs])*
            $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);

            $($type_attrs)*
        }
    };
    ($(#[$other_attrs:meta])* $type_vis:vis struct $newtype:ident($(#[$field_attrs:meta])* $field_vis:vis $hash:path); { $other_attr:meta } $($type_attrs:tt)*) => {
        $crate::hash_newtype_struct! {
            $(#[$other_attrs])*
            #[$other_attr]
            $type_vis struct $newtype($(#[$field_attrs])* $field_vis $hash);

            $($type_attrs)*
        }
    };
}

// Extracts `hash_newtype(forward)` and `hash_newtype(backward)` attributes if any and turns them
// into bool, defaulting to `DISPLAY_BACKWARD` of the wrapped type if the attribute is omitted.
//
// Once an appropriate attribute is found we pass the remaining ones into another macro to detect
// duplicates/conflicts and report an error.
//
// FYI, no, we can't use a helper macro to first filter all `hash_newtype` attributes. We would be
// attempting to match on macros instead. So we must write `hashe_newtype` in each branch.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_get_direction {
    ($hash:ty, ) => { <$hash as $crate::Hash>::DISPLAY_BACKWARD };
    ($hash:ty, #[hash_newtype(forward)] $($others:tt)*) => { { $crate::hash_newtype_forbid_direction!(forward, $($others)*); false } };
    ($hash:ty, #[hash_newtype(backward)] $($others:tt)*) => { { $crate::hash_newtype_forbid_direction!(backward, $($others)*); true } };
    ($hash:ty, #[$($ignore:tt)*]  $($others:tt)*) => { $crate::hash_newtype_get_direction!($hash, $($others)*) };
}

// Reports an error if any of the attributes is `hash_newtype($direction)`.
//
// This is used for detection of duplicates/conflicts, see the macro above.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_forbid_direction {
    ($direction:ident, ) => {};
    ($direction:ident, #[hash_newtype(forward)] $(others:tt)*) => {
        compile_error!(concat!("Cannot set display direction to forward: ", stringify!($direction), " was already specified"));
    };
    ($direction:ident, #[hash_newtype(backward)] $(others:tt)*) => {
        compile_error!(concat!("Cannot set display direction to backward: ", stringify!($direction), " was already specified"));
    };
    ($direction:ident, #[$($ignore:tt)*] $(#[$others:tt])*) => {
        $crate::hash_newtype_forbid_direction!($direction, $(#[$others])*)
    };
}

// Checks (at compile time) that all `hash_newtype` attributes are known.
//
// An unknown attribute could be a typo that could cause problems - e.g. wrong display direction if
// it's missing. To prevent this, we call this macro above. The macro produces nothing unless an
// unknown attribute is found in which case it produces `compile_error!`.
#[doc(hidden)]
#[macro_export]
macro_rules! hash_newtype_known_attrs {
    (#[hash_newtype(forward)]) => {};
    (#[hash_newtype(backward)]) => {};
    (#[hash_newtype($($unknown:tt)*)]) => { compile_error!(concat!("Unrecognized attribute ", stringify!($($unknown)*))); };
    ($($ignore:tt)*) => {};
}

#[cfg(test)]
mod tests {
    use crate::{sha256, sha256d, sha256t};

    crate::hash_newtype! {
        /// Displayed backward, like `sha256d`.
        struct Backward(sha256d::Hash);
        /// Displayed forward, like `sha256`.
        struct Forward(sha256::Hash);
    }

    // The TapLeaf midstate.
    const TEST_MIDSTATE: [u8; 32] = [
        156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147,
        108, 71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
    ];

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
    struct TestTag;

    impl sha256t::Tag for TestTag {
        const MIDSTATE: sha256::Midstate = sha256::Midstate::new(TEST_MIDSTATE, 64);
    }

    crate::hash_newtype! {
        #[hash_newtype(backward)]
        struct Tagged(sha256t::Hash<TestTag>);
    }

    #[test]
    fn newtype_formatting_matches_hex_conservative_0_2() {
        let backward = Backward::from_raw_hash(sha256d::Hash::hash(b"backward"));
        let forward = Forward::from_raw_hash(sha256::Hash::hash(b"forward"));
        // The expected strings are what `bitcoin_hashes` 0.14 printed for the inner hashes.
        macro_rules! check {
            ($(($spec:literal, $backward:literal, $forward:literal),)*) => {$(
                assert_eq!(format!($spec, backward), $backward, "{}", $spec);
                assert_eq!(format!($spec, forward), $forward, "{}", $spec);
            )*};
        }
        check!(
            (
                "{}",
                "b6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215",
                "9dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7"
            ),
            (
                "{:?}",
                "0xb6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215",
                "0x9dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7"
            ),
            (
                "{:x}",
                "b6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215",
                "9dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7"
            ),
            (
                "{:X}",
                "B6A9BD9F13DFD91AE11BFEAA6184DD3A5E82E67997A560CCBC831A410C531215",
                "9DC08E4033827C93F48CABC2F61E3F9817B51A7F1BCFA513A7537DCBC5D162E7"
            ),
            (
                "{:#}",
                "0xb6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215",
                "0x9dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7"
            ),
            (
                "{:#x}",
                "0xb6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215",
                "0x9dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7"
            ),
            (
                "{:#X}",
                "0xB6A9BD9F13DFD91AE11BFEAA6184DD3A5E82E67997A560CCBC831A410C531215",
                "0x9DC08E4033827C93F48CABC2F61E3F9817B51A7F1BCFA513A7537DCBC5D162E7"
            ),
            (
                "{:70}",
                "      b6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215",
                "      9dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7"
            ),
            (
                "{:<70}",
                "b6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215      ",
                "9dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7      "
            ),
            (
                "{:>70}",
                "      b6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215",
                "      9dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7"
            ),
            (
                "{:^70}",
                "   b6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215   ",
                "   9dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7   "
            ),
            (
                "{:*^70}",
                "***b6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215***",
                "***9dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7***"
            ),
            (
                "{:070}",
                "000000b6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215",
                "0000009dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7"
            ),
            (
                "{:#070x}",
                "0x0000b6a9bd9f13dfd91ae11bfeaa6184dd3a5e82e67997a560ccbc831a410c531215",
                "0x00009dc08e4033827c93f48cabc2f61e3f9817b51a7f1bcfa513a7537dcbc5d162e7"
            ),
            ("{:.10}", "b6a9bd9f13", "9dc08e4033"),
            ("{:#.10}", "0xb6a9bd9f13", "0x9dc08e4033"),
            ("{:20.10}", "          b6a9bd9f13", "          9dc08e4033"),
        );
    }

    #[test]
    fn newtype_from_slice_and_all_zeros() {
        let hash = sha256d::Hash::hash(b"slice");
        assert_eq!(Backward::from_slice(hash.as_byte_array()), Ok(Backward::from_raw_hash(hash)));

        let err = Backward::from_slice(&[0; 31]).unwrap_err();
        assert_eq!((err.expected_length(), err.invalid_length()), (32, 31));
        assert_eq!(err.to_string(), "invalid slice length 31 (expected 32)");

        assert_eq!(Forward::all_zeros().to_byte_array(), [0; 32]);
    }

    #[test]
    fn newtype_wraps_tagged_hash() {
        let tagged = Tagged::from_raw_hash(sha256t::Hash::<TestTag>::hash(&[0]));
        assert_eq!(
            tagged.to_string(),
            "29589d5122ec666ab5b4695070b6debc63881a4f85d88d93ddc90078038213ed"
        );
    }
}
