use blsful::{Bls12381G2Impl, MultiPublicKey, MultiSignature};
use hashes::Hash;
use crate::bls_sig_utils::BLSPublicKey;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_validation_error::QuorumValidationError;

impl QualifiedQuorumEntry {
    pub fn verify_aggregated_commitment_signature<'a, I>(&self, operator_keys: I) -> Result<(), QuorumValidationError>
    where
        I: IntoIterator<Item = &'a BLSPublicKey>,
    {
        let mut message = self.commitment_hash.to_byte_array();
        message.reverse();
        println!("quorum {}", self.quorum_entry.quorum_hash);
        println!("using message {}", hex::encode(message));
        let message = message.as_slice();
        let public_keys : Vec<(blsful::PublicKey<Bls12381G2Impl>)> = operator_keys
            .into_iter().enumerate()
            .map(|(i, key)| {
                println!("using operator key {}. {}", i, key);
                key.try_into()
            })
            .collect::<Result<Vec<(blsful::PublicKey<Bls12381G2Impl>)>, QuorumValidationError>>()?;
        let signature: MultiSignature<Bls12381G2Impl> = self.quorum_entry.all_commitment_aggregated_signature.try_into()?;
        let multi_public_key = MultiPublicKey::<Bls12381G2Impl>::from_public_keys(public_keys);
        signature.verify(multi_public_key, message).map_err(|e| QuorumValidationError::AllCommitmentAggregatedSignatureNotValid(e.to_string()))
    }

    pub fn verify_quorum_signature(&self) -> Result<(), QuorumValidationError>  {
        let message = &self.commitment_hash;
        let public_key : blsful::PublicKey<Bls12381G2Impl> = self.quorum_entry.quorum_public_key.try_into()?;
        let signature: blsful::Signature<Bls12381G2Impl> = self.quorum_entry.threshold_sig.try_into()?;
        signature.verify(&public_key, message).map_err(|e| QuorumValidationError::ThresholdSignatureNotValid(e.to_string()))
    }

    pub fn validate<'a, I>(&self, valid_masternodes: I) -> Result<(), QuorumValidationError>
    where
        I: IntoIterator<Item = &'a MasternodeListEntry>,
    {
        let operator_keys = valid_masternodes
            .into_iter()
            .filter_map(|node| {
                if !node.is_valid {
                    None
                } else {
                    Some(&node.operator_public_key)
                }
            });

        self.verify_aggregated_commitment_signature(operator_keys)?;
        self.verify_quorum_signature()?;

        Ok(())
    }
}