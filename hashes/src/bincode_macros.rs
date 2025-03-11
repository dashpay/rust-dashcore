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

        impl<$($gen: $gent),*> bincode::Decode for $t<$($gen),*> {
            fn decode<D: bincode::de::Decoder>(decoder: &mut D) -> Result<Self, bincode::error::DecodeError> {
                // Decode a fixed-length byte array and then reconstruct via from_byte_array
                let bytes: [u8; $len] = <[u8; $len]>::decode(decoder)?;
                Ok(Self::from_byte_array(bytes))
            }
        }

        impl<'de, $($gen: $gent),*> bincode::BorrowDecode<'de> for $t<$($gen),*> {
            fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, bincode::error::DecodeError> {
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
