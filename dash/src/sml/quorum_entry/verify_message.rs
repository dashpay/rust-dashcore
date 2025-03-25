use blsful::Bls12381G2Impl;
use hashes::{sha256d, Hash};

use crate::bls_sig_utils::BLSSignature;
use crate::sml::message_verification_error::MessageVerificationError;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;

impl QualifiedQuorumEntry {
    /// Verifies a message digest using a BLS threshold signature.
    ///
    /// This function checks whether the provided BLS signature is valid for the given
    /// `message_digest` using the quorum's public key. It converts the stored quorum public key
    /// and the provided BLS signature into the appropriate types before performing the verification.
    ///
    /// # Arguments
    ///
    /// * `message_digest` - A SHA-256 double-hashed (`sha256d::Hash`) digest of the message to be verified.
    /// * `signature` - The BLS signature (`BLSSignature`) that should authenticate the message.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the signature is valid for the given digest and quorum public key.
    /// * `Err(MessageVerificationError::ThresholdSignatureNotValid)` if the signature verification fails.
    ///
    /// # Errors
    ///
    /// Returns `MessageVerificationError::ThresholdSignatureNotValid` if:
    /// - The quorum's public key cannot be converted to the required `blsful::PublicKey<Bls12381G2Impl>`.
    /// - The provided signature cannot be converted to `blsful::Signature<Bls12381G2Impl>`.
    /// - The BLS verification process determines that the signature is invalid.
    ///
    /// # Implementation Details
    ///
    /// - The function retrieves the quorum's public key and attempts to convert it into the expected `blsful::PublicKey` type.
    /// - It converts the provided `BLSSignature` into a `blsful::Signature`.
    /// - It then calls the `verify` method, which checks if the signature is valid for the given message digest.
    /// - If verification fails, it returns a `MessageVerificationError::ThresholdSignatureNotValid` with relevant details.
    ///
    pub fn verify_message_digest(
        &self,
        message_digest: [u8; 32],
        signature: BLSSignature,
    ) -> Result<(), MessageVerificationError> {
        let public_key: blsful::PublicKey<Bls12381G2Impl> =
            self.quorum_entry.quorum_public_key.try_into()?;
        let bls_signature: blsful::Signature<Bls12381G2Impl> = signature.try_into()?;
        bls_signature.verify(&public_key, message_digest).map_err(|e| {
            MessageVerificationError::ThresholdSignatureNotValid(
                signature,
                sha256d::Hash::from_byte_array(message_digest),
                self.quorum_entry.quorum_public_key,
                self.quorum_entry.quorum_hash,
                self.quorum_entry.llmq_type,
                e.to_string(),
            )
        })
    }
}
