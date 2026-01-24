/// Implements `bincode::Encode`, `bincode::Decode`, and `bincode::BorrowDecode`
/// for types that represent fixed-length byte arrays.
///
/// This macro is intended to be used with types that:
/// - Are wrappers around a fixed-size `[u8; N]` array
/// - Implement `as_byte_array() -> &[u8; N]`
/// - Implement `from_byte_array([u8; N]) -> Self`
///
/// It generates the necessary trait implementations to support binary encoding
/// and decoding with the [`bincode`](https://docs.rs/bincode) crate.
///
/// # Features
/// This macro is only available when the `bincode` feature is enabled.
///
/// # Parameters
/// - `$t`: The target type to implement the traits for
/// - `$len`: The fixed length of the internal byte array
/// - `$gen`: Optional generic parameters (e.g., `T: SomeTrait`)
///
/// # Trait Implementations
/// - [`bincode::Encode`]: Encodes the value by serializing its internal byte array.
/// - [`bincode::Decode`]: Decodes a `[u8; N]` array and reconstructs the type using `from_byte_array`.
/// - [`bincode::BorrowDecode`]: Borrow-decodes a byte slice, checks its length, and uses `from_byte_array`.
#[macro_export]
#[cfg(feature = "bincode")]
macro_rules! bincode_impl {
    ($t:ident, $len:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> bincode::Encode for $t<$($gen),*> {
            fn encode<E: bincode::enc::Encoder>(&self, encoder: &mut E) -> Result<(), bincode::error::EncodeError> {
                // Use the as_byte_array method so that we encode the inner byte array
                self.as_byte_array().encode(encoder)
            }
        }

        impl<C $(, $gen: $gent)*> bincode::Decode<C> for $t<$($gen),*> {
            fn decode<D: bincode::de::Decoder<Context = C>>(decoder: &mut D) -> Result<Self, bincode::error::DecodeError> {
                // Decode a fixed-length byte array and then reconstruct via from_byte_array
                let bytes: [u8; $len] = <[u8; $len]>::decode(decoder)?;
                Ok(Self::from_byte_array(bytes))
            }
        }

        impl<'de, C $(, $gen: $gent)*> bincode::BorrowDecode<'de, C> for $t<$($gen),*> {
            fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(decoder: &mut D) -> Result<Self, bincode::error::DecodeError> {
                // Decode a borrowed reference, then use from_bytes_ref (and clone, since our type is Copy)
                use std::convert::TryInto;

                // Decode a borrowed reference to a byte slice
                let bytes: &[u8] = bincode::BorrowDecode::borrow_decode(decoder)?;

                // Convert the slice into a fixed-size array
                let bytes: [u8; $len] = bytes.try_into()
                    .map_err(|_| bincode::error::DecodeError::Other("Incorrect byte length".into()))?;

                // Construct the hash from the reference (cloned since the type is Copy)
                Ok(Self::from_byte_array(bytes))
            }
        }
    };
}

/// Does an "empty" serde implementation for the configuration without serde feature.
#[macro_export]
#[cfg(not(feature = "bincode"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "bincode"))))]
macro_rules! bincode_impl(
        ($t:ident, $len:expr $(, $gen:ident: $gent:ident)*) => ()
);
