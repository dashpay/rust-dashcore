use crate::bls_sig_utils::BlsScheme;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_validation_error::QuorumValidationError;
use hashes::Hash;

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
    /// * Applies the rogue-key binding of secure aggregated verification.
    pub fn verify_aggregated_commitment_signature<'a, I>(
        &self,
        operator_keys: I,
        scheme: BlsScheme,
    ) -> Result<(), QuorumValidationError>
    where
        I: IntoIterator<Item = &'a MasternodeListEntry>,
    {
        let message = self.commitment_hash.to_byte_array();

        // A key's encoding follows its own entry's version; the scheme the
        // aggregate is verified in is one value for the whole quorum.
        let keys = operator_keys.into_iter().map(|entry| {
            let encoding = if entry.use_legacy_bls_keys() {
                BlsScheme::Legacy
            } else {
                BlsScheme::Modern
            };
            (encoding, &entry.operator_public_key)
        });

        self.quorum_entry
            .all_commitment_aggregated_signature
            .as_scheme(scheme)
            .verify_secure_aggregate(&message, keys)
            .map_err(|e| {
                QuorumValidationError::AllCommitmentAggregatedSignatureNotValid(e.to_string())
            })
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
    /// * Reads the quorum's public key and signature under `scheme`.
    pub fn verify_quorum_signature(&self, scheme: BlsScheme) -> Result<(), QuorumValidationError> {
        self.quorum_entry
            .quorum_public_key
            .as_scheme(scheme)
            .verify(&self.commitment_hash.to_byte_array(), &self.quorum_entry.threshold_sig)
            .map_err(|e| QuorumValidationError::ThresholdSignatureNotValid(e.to_string()))
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
    pub fn validate<'a, I>(
        &self,
        valid_masternodes: I,
        scheme: BlsScheme,
    ) -> Result<(), QuorumValidationError>
    where
        I: IntoIterator<Item = &'a MasternodeListEntry>,
    {
        self.verify_aggregated_commitment_signature(valid_masternodes, scheme)?;
        self.verify_quorum_signature(scheme)?;

        Ok(())
    }
}
