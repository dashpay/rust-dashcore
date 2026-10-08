#![cfg(all(feature = "serde", feature = "bincode"))]

use dashcore_crypto::bls::BlsPkBytes;

#[test]
fn should_decode_both_bls_public_key_formats() {
    let legacy = include_bytes!("data/legacy-serde/bls-public-key.bin");
    let expected = BlsPkBytes::from_bytes(std::array::from_fn(|i| i as u8));
    let (key, consumed): (BlsPkBytes, _) =
        bincode::serde::decode_from_slice(legacy, bincode::config::standard()).unwrap();
    assert_eq!(key, expected);
    assert_eq!(consumed, legacy.len());
    let current = bincode::serde::encode_to_vec(key, bincode::config::standard()).unwrap();
    assert_eq!(current[0], 48);
    assert_eq!(&current[1..], expected.as_bytes());
    let (key, consumed): (BlsPkBytes, _) =
        bincode::serde::decode_from_slice(&current, bincode::config::standard()).unwrap();
    assert_eq!(key, expected);
    assert_eq!(consumed, current.len());
    assert_eq!(
        serde_json::from_str::<BlsPkBytes>(&serde_json::to_string(&key).unwrap()).unwrap(),
        key
    );
}

#[test]
fn should_reject_malformed_legacy_bls_public_keys() {
    for bytes in [vec![b'g'; 96], vec![0xff; 96], vec![b'0'; 95], vec![b'0'; 97], vec![]] {
        let encoded = bincode::serde::encode_to_vec(bytes, bincode::config::standard()).unwrap();
        assert!(bincode::serde::decode_from_slice::<BlsPkBytes, _>(
            &encoded,
            bincode::config::standard()
        )
        .is_err());
    }
}

#[test]
fn should_not_interpret_raw_bls_public_key_as_hex() {
    let bytes = [b'a'; 48];
    let encoded =
        bincode::serde::encode_to_vec(bytes.as_slice(), bincode::config::standard()).unwrap();
    let (key, _): (BlsPkBytes, _) =
        bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
    assert_eq!(key.as_bytes(), &bytes);
}

#[test]
fn should_decode_legacy_bls_with_fixed_big_endian_lengths() {
    let config = bincode::config::standard().with_fixed_int_encoding().with_big_endian();
    let key = BlsPkBytes::from_bytes([0xab; 48]);
    let bytes = bincode::serde::encode_to_vec(key.to_string().to_uppercase(), config).unwrap();
    let (decoded, consumed): (BlsPkBytes, _) =
        bincode::serde::decode_from_slice(&bytes, config).unwrap();
    assert_eq!(decoded, key);
    assert_eq!(consumed, bytes.len());
}

#[test]
fn should_preserve_native_bincode_public_key_encoding() {
    let key = BlsPkBytes::from_bytes(std::array::from_fn(|i| i as u8));
    let bytes = bincode::encode_to_vec(key, bincode::config::standard()).unwrap();
    assert_eq!(bytes, key.as_bytes());
    let (decoded, consumed): (BlsPkBytes, _) =
        bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(decoded, key);
    assert_eq!(consumed, 48);
}

#[test]
fn should_reject_truncated_keys_and_respect_limits() {
    let bytes = include_bytes!("data/legacy-serde/bls-public-key.bin");
    for end in 0..bytes.len() {
        assert!(bincode::serde::decode_from_slice::<BlsPkBytes, _>(
            &bytes[..end],
            bincode::config::standard()
        )
        .is_err());
    }
    assert!(bincode::serde::decode_from_slice::<BlsPkBytes, _>(
        bytes,
        bincode::config::standard().with_limit::<16>()
    )
    .is_err());
}

#[test]
fn should_decode_legacy_key_between_other_fields() {
    let key = BlsPkBytes::from_bytes([0xab; 48]);
    let config = bincode::config::standard();
    let bytes = bincode::serde::encode_to_vec((7_u32, key.to_string(), 1234_u64), config).unwrap();
    let (decoded, consumed): ((u32, BlsPkBytes, u64), _) =
        bincode::serde::decode_from_slice(&bytes, config).unwrap();
    assert_eq!(decoded, (7, key, 1234));
    assert_eq!(consumed, bytes.len());
}

#[test]
fn should_accept_binary_deserializers_that_deliver_strings() {
    struct BinaryString<'a>(&'a str);

    impl<'de> serde::Deserializer<'de> for BinaryString<'de> {
        type Error = serde::de::value::Error;

        fn is_human_readable(&self) -> bool {
            false
        }

        fn deserialize_any<V: serde::de::Visitor<'de>>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error> {
            visitor.visit_borrowed_str(self.0)
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map struct enum identifier ignored_any
        }
    }

    let hex = "ab".repeat(48);
    let key = <BlsPkBytes as serde::Deserialize>::deserialize(BinaryString(&hex)).unwrap();
    assert_eq!(key.as_bytes(), &[0xab; 48]);
    assert!(<BlsPkBytes as serde::Deserialize>::deserialize(BinaryString("invalid")).is_err());
}
