use bls_signatures::{BasicSchemeMPL, G1Element, G2Element, Scheme};
use blsful::Bls12381G2Impl;
use hashes::{Hash, sha256d};

use crate::bls_sig_utils::BLSSignature;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::sml::message_verification_error::MessageVerificationError;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_validation_error::QuorumValidationError;

impl QualifiedQuorumEntry {
    /// Verifies the aggregated commitment signature for the quorum.
    ///
    /// This function checks whether the aggregated BLS signature over the quorum's commitment hash
    /// is valid using the operator public keys of the participating masternodes.
    ///
    /// # Arguments
    ///
    /// * `operator_keys` - An iterator over `MasternodeListEntry` items, representing the operator public keys.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the aggregated commitment signature is valid.
    /// * `Err(QuorumValidationError)` - If the signature is invalid or if any errors occur during verification.
    ///
    /// # Notes
    ///
    /// * Supports both legacy and modern BLS key formats.
    /// * Prints an error message if a public key fails to parse.
    /// * Uses `BasicSchemeMPL` for secure signature verification.
    /// * This method will transition to `blsful` in the future once it supports secure aggregated verification.
    pub fn verify_aggregated_commitment_signature<'a, I>(
        &self,
        operator_keys: I,
    ) -> Result<(), QuorumValidationError>
    where
        I: IntoIterator<Item = &'a MasternodeListEntry>,
    {
        let mut message = self.commitment_hash.to_byte_array();
        let message = message.as_slice();
        let public_keys2 = operator_keys
            .into_iter()
            .filter_map(|masternode_list_entry| {
                let result = if masternode_list_entry.use_legacy_bls_keys() {
                    G1Element::from_bytes_legacy(masternode_list_entry.operator_public_key.as_ref())
                } else {
                    G1Element::from_bytes(masternode_list_entry.operator_public_key.as_ref())
                };
                match result {
                    Ok(public_key) => Some(public_key),
                    Err(e) => {
                        println!(
                            "error {} with key for masternode {}",
                            e, masternode_list_entry.pro_reg_tx_hash
                        );
                        None
                    }
                }
            })
            .collect::<Vec<_>>();
        let sig =
            G2Element::from_bytes(self.quorum_entry.all_commitment_aggregated_signature.as_bytes())
                .map_err(|e| {
                    QuorumValidationError::AllCommitmentAggregatedSignatureNotValid(e.to_string())
                })?;
        let verified = BasicSchemeMPL::new().verify_secure(public_keys2.iter(), message, &sig);
        if verified {
            Ok(())
        } else {
            Err(QuorumValidationError::AllCommitmentAggregatedSignatureNotValid(
                "signature is not valid for keys and message".to_string(),
            ))
        }
        // This will be the code when we move to blsful
        // Currently we can't because blsful doesn't support verify secure aggregated nor does it support our legacy serializations.
        // let public_keys : Vec<(blsful::PublicKey<Bls12381G2Impl>)> = operator_keys
        //     .into_iter().enumerate()
        //     .map(|(i, key)| {
        //         println!("{},", key);
        //         key.try_into()
        //     })
        //     .collect::<Result<Vec<(blsful::PublicKey<Bls12381G2Impl>)>, QuorumValidationError>>()?;
        // let signature: MultiSignature<Bls12381G2Impl> = self.quorum_entry.all_commitment_aggregated_signature.try_into()?;
        // let multi_public_key = MultiPublicKey::<Bls12381G2Impl>::from_public_keys(public_keys);
        //
        // println!("{} serialized {}", multi_public_key.0, hex::encode(multi_public_key.0.to_compressed()));
        // signature.verify(multi_public_key, message).map_err(|e| QuorumValidationError::AllCommitmentAggregatedSignatureNotValid(e.to_string()))
    }

    /// Verifies the quorum's threshold signature.
    ///
    /// This function checks the validity of the quorum's threshold signature against the commitment hash
    /// using the quorum's public key.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the threshold signature is valid.
    /// * `Err(QuorumValidationError)` - If the signature is invalid or cannot be verified.
    ///
    /// # Notes
    ///
    /// * Uses `blsful::Signature` and `blsful::PublicKey` for verification.
    /// * Converts the quorum's public key and signature into `blsful` types before verification.
    pub fn verify_quorum_signature(&self) -> Result<(), QuorumValidationError> {
        let message = &self.commitment_hash;
        let public_key: blsful::PublicKey<Bls12381G2Impl> =
            self.quorum_entry.quorum_public_key.try_into()?;
        let signature: blsful::Signature<Bls12381G2Impl> =
            self.quorum_entry.threshold_sig.try_into()?;
        signature
            .verify(&public_key, message)
            .map_err(|e| QuorumValidationError::ThresholdSignatureNotValid(e.to_string()))
    }

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
        message_digest: sha256d::Hash,
        signature: BLSSignature,
    ) -> Result<(), MessageVerificationError> {
        let public_key: blsful::PublicKey<Bls12381G2Impl> =
            self.quorum_entry.quorum_public_key.try_into()?;
        let bls_signature: blsful::Signature<Bls12381G2Impl> = signature.try_into()?;
        bls_signature.verify(&public_key, message_digest).map_err(|e| {
            MessageVerificationError::ThresholdSignatureNotValid(
                signature,
                message_digest,
                self.quorum_entry.quorum_public_key,
                self.quorum_entry.quorum_hash,
                self.quorum_entry.llmq_type,
                e.to_string(),
            )
        })
    }

    /// Performs full quorum validation by verifying all necessary signatures.
    ///
    /// This function validates the quorum by checking:
    /// 1. The aggregated commitment signature using valid masternodes.
    /// 2. The quorum's threshold signature.
    ///
    /// # Arguments
    ///
    /// * `valid_masternodes` - An iterator over `MasternodeListEntry` items representing the set of valid masternodes.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the quorum is valid.
    /// * `Err(QuorumValidationError)` - If any signature verification fails.
    ///
    /// # Notes
    ///
    /// * Calls `verify_aggregated_commitment_signature` first.
    /// * Calls `verify_quorum_signature` second.
    pub fn validate<'a, I>(&self, valid_masternodes: I) -> Result<(), QuorumValidationError>
    where
        I: IntoIterator<Item = &'a MasternodeListEntry>,
    {
        self.verify_aggregated_commitment_signature(valid_masternodes)?;
        self.verify_quorum_signature()?;

        Ok(())
    }
}
