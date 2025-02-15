use blsful::{AggregateSignature, Bls12381G2Impl};
use crate::bls_sig_utils::BLSPublicKey;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_validation_error::QuorumValidationError;

impl QualifiedQuorumEntry {
    pub fn verify_aggregated_commitment_signature<I>(&self, operator_keys: I) -> Result<(), QuorumValidationError>
    where
        I: IntoIterator<Item = &BLSPublicKey>,
    {
        let message = self.commitment_hash.as_ref().ok_or(QuorumValidationError::CommitmentHashNotPresent)?;
        let public_keys : Vec<(blsful::PublicKey<Bls12381G2Impl>, &[u8])> = operator_keys
            .iter()
            .map(|key| (key.try_into(), message))
            .collect::<Result<Vec<_>, QuorumValidationError>>()?;
        let signature: AggregateSignature<Bls12381G2Impl> = self.quorum_entry.all_commitment_aggregated_signature.try_into()?;
        signature.verify(&public_keys).map_err(|e| QuorumValidationError::AllCommitmentAggregatedSignatureNotValid(e.to_string()))
    }

    pub fn verify_quorum_signature(&self) -> Result<(), QuorumValidationError>  {
        let message = self.commitment_hash.as_ref().ok_or(QuorumValidationError::CommitmentHashNotPresent)?;
        let public_key : blsful::PublicKey<Bls12381G2Impl> = self.quorum_entry.quorum_public_key.try_into()?;
        let signature: blsful::Signature<Bls12381G2Impl> = self.quorum_entry.threshold_sig.try_into()?;
        signature.verify(&public_key, message).map_err(|e| QuorumValidationError::ThresholdSignatureNotValid(e.to_string()))
    }

    pub fn validate<I>(&self, valid_masternodes: I) -> Result<(), QuorumValidationError>
    where
        I: IntoIterator<Item = &MasternodeListEntry>,
    {
        let operator_keys = valid_masternodes
            .into_iter()
            .filter_map(|node| {
                if !node.is_valid {
                    None
                } else {
                    Some(node.operator_public_key)
                }
            });

        self.verify_aggregated_commitment_signature(operator_keys)?;
        self.verify_quorum_signature()?;

        Ok(())
    }
}