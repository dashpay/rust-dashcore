//! Module contains helper functions for signing and verification the ECDSA signatures

use core::convert::TryInto;

use anyhow::{anyhow, bail};
use hashes::{Hash, ripemd160, sha256, sha256d};

use crate::PublicKey as ECDSAPublicKey;
use crate::prelude::Vec;
use crate::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use crate::secp256k1::{Message, Secp256k1, SecretKey};

/// verifies the ECDSA signature
/// The provided signature must be recoverable. Which means: it must contain the recovery byte as a prefix
pub fn verify_data_signature(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), anyhow::Error> {
    let data_hash = double_sha(data);

    let msg =
        Message::from_digest(data_hash.try_into().map_err(|_| anyhow!("Invalid hash length"))?);
    let sig: RecoverableSignature = RecoverableSignature::from_compact_signature(signature)?;

    let pub_key = ECDSAPublicKey::from_slice(public_key).map_err(anyhow::Error::msg)?;
    let secp = Secp256k1::new();

    secp.verify_ecdsa(&msg, &sig.to_standard(), &pub_key.inner).map_err(anyhow::Error::msg)
}

/// verifies the the hash signature. From provided signature and hash recovers the public key
/// and compares with the provided one
/// The the `public_key_id` should be hash generated on the top of COMPRESSED key
pub fn verify_hash_signature(
    data_hash: &[u8],
    data_signature: &[u8],
    public_key_id: &[u8],
) -> Result<(), anyhow::Error> {
    let signature: RecoverableSignature =
        RecoverableSignature::from_compact_signature(data_signature)?;

    let secp = Secp256k1::new();
    let msg =
        Message::from_digest(data_hash.try_into().map_err(|_| anyhow!("Invalid hash length"))?);
    let recovered_public_key = secp.recover_ecdsa(&msg, &signature).map_err(anyhow::Error::msg)?;

    let recovered_compressed_public_key = recovered_public_key.serialize();
    let hash_recovered_key = ripemd160_sha256(&recovered_compressed_public_key);
    let are_equal = public_key_id == hash_recovered_key;

    if are_equal {
        Ok(())
    } else {
        bail!("the signature isn't valid")
    }
}

/// sign and get the ECDSA signature
pub fn sign(data: &[u8], private_key: &[u8]) -> Result<[u8; 65], anyhow::Error> {
    let data_hash = double_sha(data);
    sign_hash(&data_hash, private_key)
}

/// signs the hash of data and get the ECDSA signature
pub fn sign_hash(data_hash: &[u8], private_key: &[u8]) -> Result<[u8; 65], anyhow::Error> {
    let pk = SecretKey::from_slice(private_key)
        .map_err(|e| anyhow!("Invalid ECDSA private key: {}", e))?;

    // TODO enable support for features in rust-dpp and allow to use global objects (SECP256K1)
    let secp = Secp256k1::new();
    let msg =
        Message::from_digest(data_hash.try_into().map_err(|_| anyhow!("Invalid hash length"))?);

    let signature = secp
        .sign_ecdsa_recoverable(&msg, &pk)
        // TODO the compression flag should be obtained from the private key type
        .to_compact_signature(true);
    Ok(signature)
}

/// converts the signature from/to compact format. Compact format is when the signature
/// is prefixed by the recovery byte
pub trait CompactSignature
where
    Self: Sized,
{
    /// Converts the Signature with Recovery byte to the compact format where
    /// the first byte of signature is occupied by the recovery byte
    fn to_compact_signature(&self, is_compressed: bool) -> [u8; 65];
    /// Creates the Self from compacted version of signature
    fn from_compact_signature(signature: impl AsRef<[u8]>) -> Result<Self, anyhow::Error>;
}

impl CompactSignature for RecoverableSignature {
    fn from_compact_signature(signature: impl AsRef<[u8]>) -> Result<Self, anyhow::Error> {
        if signature.as_ref().len() != 65 {
            bail!("the signature must be 65 bytes long")
        }

        let recovery_byte = signature.as_ref()[0];
        let number = u8::from_be(recovery_byte) as i32;
        let mut i = number - 27 - 4;
        if i < 0 {
            i += 4;
        }
        if !((i == 0) || (i == 1) || (i == 2) || (i == 3)) {
            bail!("the recovery number must be between 0..4, got: '{}'", i);
        }

        RecoverableSignature::from_compact(
            &signature.as_ref()[1..],
            RecoveryId::try_from(i).unwrap(),
        )
        .map_err(anyhow::Error::msg)
    }

    fn to_compact_signature(&self, is_compressed: bool) -> [u8; 65] {
        let (recovery_byte, signature) = self.serialize_compact();
        let mut val = <RecoveryId as Into<i32>>::into(recovery_byte) + 27 + 4;
        if !is_compressed {
            val -= 4;
        }
        let prefix = val.to_le_bytes()[0];
        let compact_signature = [&[prefix], signature.as_slice()].concat();
        compact_signature.try_into().unwrap()
    }
}

/// calculates double sha256 on data
pub fn double_sha(payload: impl AsRef<[u8]>) -> Vec<u8> {
    sha256d::Hash::hash(payload.as_ref()).as_byte_array().to_vec()
}

/// calculates the RIPEMD169(SHA256(data))
pub fn ripemd160_sha256(data: &[u8]) -> Vec<u8> {
    let hash = sha256::Hash::hash(data).to_byte_array();
    ripemd160::Hash::hash(&hash).to_byte_array().to_vec()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::internal_macros::hex;
    use crate::{PublicKey, assert_error_contains};

    struct Keys {
        private_key: Vec<u8>,
        public_key_uncompressed: Vec<u8>,
        public_key_compressed: Vec<u8>,
    }

    fn get_keys() -> Keys {
        let private_key_string = "032f352abd3fb62c3c5b543bb6eae515a1b99a202b367ab9c6e155ba689d0ff4";
        let public_key_compressed =
            "02716899be7008396a0b34dd49d9707b01e86265f9556ab54a493e712d42946e7a";
        let private_key_bytes = hex!(private_key_string);
        let public_key_compressed_bytes = hex!(public_key_compressed);

        let mut public_key = PublicKey::from_slice(&public_key_compressed_bytes).unwrap();
        public_key.compressed = false;
        let public_key_uncompressed_bytes = public_key.to_bytes();

        Keys {
            private_key: private_key_bytes,
            public_key_compressed: public_key_compressed_bytes,
            public_key_uncompressed: public_key_uncompressed_bytes,
        }
    }

    #[test]
    fn sign_and_verify_data() {
        let k = get_keys();
        let data = hex!("fafafa");

        let signature = sign(&data, &k.private_key).unwrap();

        verify_data_signature(&data, &signature, &k.public_key_compressed)
            .expect("verification shouldn't fail")
    }

    #[test]
    fn invalid_signature_for_different_data() {
        let k = get_keys();
        let data = hex!("fafafafa");
        let incorrect_data = hex!("fefefe");

        let signature = sign(&data, &k.private_key).expect("singing shouldn't fail");
        let verification_result =
            verify_data_signature(&incorrect_data, &signature, &k.public_key_compressed);
        assert_error_contains!(verification_result, "signature failed verification");
    }

    #[test]
    fn signature_not_verified_with_different_public_key() {
        let k = get_keys();
        let mut rng = crate::secp256k1::rand::thread_rng();
        let secp = Secp256k1::new();
        let (_, different_public_key) = secp.generate_keypair(&mut rng);
        let data = hex!("fafafa");

        let signature = sign(&data, &k.private_key).expect("signing shouldn't fail");
        let verification_result =
            verify_data_signature(&data, &signature, &different_public_key.serialize());

        assert_error_contains!(verification_result, "signature failed verification")
    }

    #[test]
    fn should_verify_against_signature_with_uncompressed_pk() {
        let k = get_keys();
        let data = hex!("fafafa");

        let signature = sign(&data, &k.private_key).expect("signing shouldn't fail");
        verify_data_signature(&data, &signature, &k.public_key_uncompressed)
            .expect("verification shouldn't fail")
    }

    #[test]
    fn should_validate_the_hash_signature() {
        let k = get_keys();
        let data = hex!("fafafa");
        let signature = sign(&data, &k.private_key).expect("signing shouldn't fail");

        let data_hash = double_sha(data);
        verify_hash_signature(&data_hash, &signature, &ripemd160_sha256(&k.public_key_compressed))
            .expect("verification shouldn't fail for compressed public key");

        // verify_hash_signature(&data_hash, &signature, &k.public_key_uncompressed)
        //     .expect("verification shouldn't fail for uncompressed public key");
    }

    #[test]
    fn should_fail_validation_with_hash_coming_from_uncompressed_public_key() {
        let k = get_keys();
        let data = hex!("fafafa");
        let signature = sign(&data, &k.private_key).expect("signing shouldn't fail");

        let data_hash = double_sha(data);
        let validation_result = verify_hash_signature(
            &data_hash,
            &signature,
            &ripemd160_sha256(&k.public_key_uncompressed),
        );

        assert_error_contains!(validation_result, "the signature isn't valid")
    }

    #[test]
    fn should_fail_validation_with_incorrect_public_key() {
        let k = get_keys();
        let mut rng = crate::secp256k1::rand::thread_rng();
        let secp = Secp256k1::new();
        let (_, different_public_key) = secp.generate_keypair(&mut rng);
        let data = hex!("fafafa");
        let signature = sign(&data, &k.private_key).expect("signing shouldn't fail");

        let data_hash = double_sha(data);

        let validation_result = verify_hash_signature(
            &data_hash,
            &signature,
            &ripemd160_sha256(&different_public_key.serialize()),
        );

        assert_error_contains!(validation_result, "the signature isn't valid")
    }

    #[test]
    fn should_fail_with_non_recoverable_signature() {
        let k = get_keys();
        let secp = Secp256k1::new();
        let data = hex!("fafafa");
        let data_hash = double_sha(&data);
        let secret_key = SecretKey::from_slice(&k.private_key).unwrap();

        let unrecoverable_signature =
            secp.sign_ecdsa(&Message::from_digest(data_hash.try_into().unwrap()), &secret_key);
        let unrecoverable_signature_bytes = unrecoverable_signature.serialize_compact();
        let validation_result =
            verify_data_signature(&data, &unrecoverable_signature_bytes, &k.public_key_compressed);

        assert_error_contains!(validation_result, "the signature must be 65 bytes long")
    }
}
