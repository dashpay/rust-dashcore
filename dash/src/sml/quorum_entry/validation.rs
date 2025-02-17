use std::collections::{BTreeMap, BTreeSet};
use bls_signatures::{BasicSchemeMPL, BlsError, G1Element, G2Element, Scheme};
use blsful::{Bls12381G2Impl, MultiPublicKey, MultiSignature};
use hashes::Hash;
use crate::bls_sig_utils::BLSPublicKey;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_validation_error::QuorumValidationError;

impl QualifiedQuorumEntry {
    pub fn verify_aggregated_commitment_signature<'a, I>(&self, operator_keys: I) -> Result<(), QuorumValidationError>
    where
        I: IntoIterator<Item = &'a MasternodeListEntry>,
    {
        let mut message = self.commitment_hash.to_byte_array();
        // println!("quorum {}", self.quorum_entry.quorum_hash);
         println!("using message {}", hex::encode(message));
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
                        println!("error {} with key for masternode {}", e, masternode_list_entry.pro_reg_tx_hash);
                        None
                    }
                }
            })
            .collect::<Vec<_>>();
        let sig = G2Element::from_bytes(self.quorum_entry.all_commitment_aggregated_signature.as_bytes()).expect("expected sig");
        let verified = BasicSchemeMPL::new().verify_secure(public_keys2.iter(), message, &sig);
        if verified {
            Ok(())
        } else {
            Err(QuorumValidationError::AllCommitmentAggregatedSignatureNotValid("signature is not valid for keys and message".to_string()))
        }
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
        self.verify_aggregated_commitment_signature(valid_masternodes)?;
        self.verify_quorum_signature()?;

        Ok(())
    }
}