//! Module contains helper functions for signing and verification the ECDSA signatures

use core::convert::TryInto;

use anyhow::{anyhow, ensure};
use hashes::{Hash, hash160, sha256d};

use crate::PublicKey as ECDSAPublicKey;
use crate::crypto::ecdsa::{ECDSA_REC_SIG_LEN, EcdsaPublicKey, EcdsaSecretKey};
use crate::prelude::Vec;
use crate::sign_message;

/// verifies the ECDSA signature
/// The provided signature must be recoverable. Which means: it must contain the recovery byte as a prefix
pub fn verify_data_signature(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), anyhow::Error> {
    let data_hash: [u8; 32] =
        double_sha(data).try_into().map_err(|_| anyhow!("Invalid hash length"))?;
    let sig = sign_message::from_slice(signature)?;

    let pub_key = ECDSAPublicKey::from_slice(public_key).map_err(anyhow::Error::msg)?;

    pub_key.inner.verify(&data_hash, sig.signature()?).map_err(anyhow::Error::msg)
}

/// verifies the the hash signature. From provided signature and hash recovers the public key
/// and compares with the provided one
/// The the `public_key_id` should be hash generated on the top of COMPRESSED key
pub fn verify_hash_signature(
    data_hash: &[u8],
    data_signature: &[u8],
    public_key_id: &[u8],
) -> Result<(), anyhow::Error> {
    let signature = sign_message::from_slice(data_signature)?;

    let data_hash: &[u8; 32] = data_hash.try_into().map_err(|_| anyhow!("Invalid hash length"))?;
    let recovered_public_key =
        EcdsaPublicKey::recover(data_hash, &signature).map_err(anyhow::Error::msg)?;

    let hash_recovered_key = ECDSAPublicKey::new(recovered_public_key).pubkey_hash();
    ensure!(public_key_id == hash_recovered_key.as_byte_array(), "the signature isn't valid");
    Ok(())
}

/// sign and get the ECDSA signature
pub fn sign(data: &[u8], private_key: &[u8]) -> Result<[u8; ECDSA_REC_SIG_LEN], anyhow::Error> {
    let data_hash = double_sha(data);
    sign_hash(&data_hash, private_key)
}

/// signs the hash of data and get the ECDSA signature
pub fn sign_hash(
    data_hash: &[u8],
    private_key: &[u8],
) -> Result<[u8; ECDSA_REC_SIG_LEN], anyhow::Error> {
    // Borrow the caller's bytes; a by-value `[u8; 32]` would leave an unwiped
    // copy of the secret key on the stack.
    let private_key: &[u8; 32] = private_key
        .try_into()
        .map_err(|_| anyhow!("Invalid ECDSA private key: must be 32 bytes"))?;
    let pk = EcdsaSecretKey::from_bytes(private_key)
        .map_err(|e| anyhow!("Invalid ECDSA private key: {}", e))?;

    let data_hash: &[u8; 32] = data_hash.try_into().map_err(|_| anyhow!("Invalid hash length"))?;

    Ok(pk.sign_recoverable(data_hash).to_bytes())
}

/// calculates double sha256 on data
pub fn double_sha(payload: impl AsRef<[u8]>) -> Vec<u8> {
    sha256d::Hash::hash(payload.as_ref()).as_byte_array().to_vec()
}

/// calculates the RIPEMD169(SHA256(data))
pub fn ripemd160_sha256(data: &[u8]) -> Vec<u8> {
    hash160::Hash::hash(data).to_byte_array().to_vec()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::PublicKey;
    use crate::crypto::ecdsa::EcdsaSecretKey;
    use crate::internal_macros::hex;

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

    /// Pins the deterministic (RFC 6979) signature so the key handling in
    /// `sign_hash` can change without changing its output.
    #[test]
    fn sign_hash_output_is_unchanged() {
        let k = get_keys();
        let data_hash = double_sha(hex!("fafafa"));

        let signature = sign_hash(&data_hash, &k.private_key).expect("signing shouldn't fail");

        assert_eq!(
            signature.to_vec(),
            hex!(
                "208f7395d4f8d36f8b53c3b8b34edfda5b618f3ec53e8b9f1f508e75dc8fc8569329909bd47bcd17bd19eab6c0027f66dbbb7b76f7abb7ee4ed89f97212b0e37cf"
            )
        );
    }

    #[test]
    fn sign_hash_rejects_wrong_private_key_length() {
        let k = get_keys();
        let data_hash = double_sha(hex!("fafafa"));

        let result = sign_hash(&data_hash, &k.private_key[..31]);

        assert_error_contains!(result, "must be 32 bytes");
    }

    #[test]
    fn invalid_signature_for_different_data() {
        let k = get_keys();
        let data = hex!("fafafafa");
        let incorrect_data = hex!("fefefe");

        let signature = sign(&data, &k.private_key).expect("singing shouldn't fail");
        let verification_result =
            verify_data_signature(&incorrect_data, &signature, &k.public_key_compressed);
        assert_error_contains!(verification_result, "signature verification failed");
    }

    #[test]
    fn signature_not_verified_with_different_public_key() {
        let k = get_keys();
        let different_public_key = EcdsaSecretKey::generate().public_key();
        let data = hex!("fafafa");

        let signature = sign(&data, &k.private_key).expect("signing shouldn't fail");
        let verification_result =
            verify_data_signature(&data, &signature, &different_public_key.to_compressed());

        assert_error_contains!(verification_result, "signature verification failed")
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
        let different_public_key = EcdsaSecretKey::generate().public_key();
        let data = hex!("fafafa");
        let signature = sign(&data, &k.private_key).expect("signing shouldn't fail");

        let data_hash = double_sha(data);

        let validation_result = verify_hash_signature(
            &data_hash,
            &signature,
            &ripemd160_sha256(&different_public_key.to_compressed()),
        );

        assert_error_contains!(validation_result, "the signature isn't valid")
    }

    #[test]
    fn should_fail_with_non_recoverable_signature() {
        let k = get_keys();
        let data = hex!("fafafa");
        let data_hash = double_sha(&data);
        let secret_key =
            EcdsaSecretKey::from_bytes(k.private_key.as_slice().try_into().unwrap()).unwrap();

        let unrecoverable_signature = secret_key.sign(data_hash.as_slice().try_into().unwrap());
        let unrecoverable_signature_bytes = unrecoverable_signature.to_bytes();
        let validation_result =
            verify_data_signature(&data, &unrecoverable_signature_bytes, &k.public_key_compressed);

        assert_error_contains!(validation_result, "length not 65 bytes")
    }
}
