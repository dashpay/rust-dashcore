use std::collections::BTreeMap;

use dashcore::bls_sig_utils::BlsScheme;
use dashcore::sml::message_verification_error::MessageVerificationError;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::{InstantLock, QuorumSigningRequestId};
use dashcore_hashes::Hash;

use crate::error::{ValidationError, ValidationResult};
use crate::validation::Validator;

/// Validates InstantLock messages against the rotated quorums of their cycle.
/// Never accept InstantLocks from the network without full signature
/// verification.
///
/// A malformed lock fails with [`ValidationError::InvalidInstantLock`], one
/// whose signature does not verify, or whose quorum is not in the cycle, with
/// [`ValidationError::InvalidSignature`].
pub struct InstantLockValidator<'a> {
    /// The rotated quorums of the lock's cycle, by quorum index.
    cycle_quorums: &'a BTreeMap<u16, QualifiedQuorumEntry>,
}

impl Validator<&InstantLock> for InstantLockValidator<'_> {
    fn validate(&self, instant_lock: &InstantLock) -> ValidationResult<()> {
        self.validate_structure(instant_lock)?;
        self.validate_signature(instant_lock).map_err(|e| {
            ValidationError::InvalidSignature(format!(
                "InstantLock BLS signature verification failed: {e}"
            ))
        })
    }
}

impl<'a> InstantLockValidator<'a> {
    pub fn new(cycle_quorums: &'a BTreeMap<u16, QualifiedQuorumEntry>) -> Self {
        Self {
            cycle_quorums,
        }
    }

    fn validate_structure(&self, instant_lock: &InstantLock) -> ValidationResult<()> {
        if instant_lock.txid == dashcore::Txid::all_zeros() {
            return Err(ValidationError::InvalidInstantLock(
                "InstantLock transaction ID cannot be zero".to_string(),
            ));
        }

        if instant_lock.signature.is_zeroed() {
            return Err(ValidationError::InvalidInstantLock(
                "InstantLock signature cannot be zero".to_string(),
            ));
        }

        if instant_lock.inputs.is_empty() {
            return Err(ValidationError::InvalidInstantLock(
                "InstantLock must have at least one input".to_string(),
            ));
        }

        if let Some(idx) =
            instant_lock.inputs.iter().position(|input| input.txid == dashcore::Txid::all_zeros())
        {
            return Err(ValidationError::InvalidInstantLock(format!(
                "InstantLock input {idx} has null transaction ID"
            )));
        }

        Ok(())
    }

    /// The quorum of the cycle that signs the lock (DIP-24), with the lock's
    /// request id and the quorum index it selects.
    fn signing_quorum(
        &self,
        instant_lock: &InstantLock,
    ) -> Result<(&'a QualifiedQuorumEntry, QuorumSigningRequestId, u16), MessageVerificationError>
    {
        let cycle_hash = instant_lock.cyclehash;
        let quorums = self.cycle_quorums;
        let llmq_type = quorums
            .values()
            .next()
            .ok_or(MessageVerificationError::CycleHashNotPresent(cycle_hash))?
            .quorum_entry
            .llmq_type;

        let request_id = instant_lock.request_id().map_err(|e| e.to_string())?;
        // `selectionHash.GetUint64(3)` and the index bits as Dash Core takes them.
        let selection_hash_64 =
            u64::from_le_bytes(request_id.to_byte_array()[24..32].try_into().unwrap());
        let n = llmq_type.active_quorum_count().ilog2();
        let quorum_index = (((1 << n) - 1) & (selection_hash_64 >> (64 - n - 1))) as u16;

        let quorum = quorums
            .get(&quorum_index)
            .ok_or(MessageVerificationError::QuorumIndexNotFound(quorum_index, cycle_hash))?;
        Ok((quorum, request_id, quorum_index))
    }

    fn validate_signature(
        &self,
        instant_lock: &InstantLock,
    ) -> Result<(), MessageVerificationError> {
        let (quorum, request_id, quorum_index) = self.signing_quorum(instant_lock)?;
        let quorum_hash = quorum.quorum_entry.quorum_hash;

        let sign_id = instant_lock
            .sign_id(quorum.quorum_entry.llmq_type, quorum_hash, Some(request_id))
            .map_err(|e| e.to_string())?;

        let result = quorum.verify_message_digest(
            sign_id.to_byte_array(),
            instant_lock.signature,
            BlsScheme::Modern,
        );
        match &result {
            Ok(()) => tracing::info!(
                "IS lock {} verified by quorum {quorum_hash} (index {quorum_index})",
                instant_lock.txid
            ),
            Err(e) => tracing::warn!(
                "IS lock {} failed against quorum {quorum_hash} (index {quorum_index}): {e}",
                instant_lock.txid
            ),
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sml_engine::test_support::TestEngine;
    use dashcore::consensus::deserialize;
    use dashcore::sml::llmq_type::LLMQType;
    use dashcore::QuorumHash;
    use test_case::test_case;

    /// An IS lock of the mainnet fixture's cycle, signed by its quorum at index 23.
    fn fixture_is_lock() -> InstantLock {
        deserialize(&hex::decode("01018d53e7997ead57409750942af0d5e0aafc06f852a9a52308f4781b6a8220298f00000000c6f9d8c63dd15937ea70aaddb7890daad42c91bf6818e2bf76d183d6f2d9215b4b5f84978fad9dde7ab52bdcc0674be891e9029cc1ef0cb01200000000000000a27c98836c4c04653ab81eb4e07ddfc2c8c2c1036b75247969c05a4f25451cd78913a971f1899d9f2bddec9cf8e0104004f72f20c2856453e5aa3bcd2a8200670ec28feda38f67cc400fc72ef1966956656ec0765478c9d16e9a9e470c07f9ed").unwrap()).unwrap()
    }

    #[test]
    fn a_well_formed_lock_passes_the_structure_check() {
        assert!(InstantLockValidator::new(&BTreeMap::new())
            .validate_structure(&InstantLock::dummy(0..3))
            .is_ok());
    }

    #[test_case(|lock| lock.inputs.clear(), "at least one input"; "no inputs")]
    #[test_case(|lock| lock.signature = dashcore::bls_sig_utils::BLSSignature::from([0; 96]), "signature cannot be zero"; "zero signature")]
    #[test_case(|lock| lock.txid = dashcore::Txid::all_zeros(), "transaction ID cannot be zero"; "null txid")]
    #[test_case(|lock| lock.inputs[1].txid = dashcore::Txid::all_zeros(), "input 1 has null transaction ID"; "null input txid")]
    fn a_malformed_lock_fails_the_structure_check(malform: fn(&mut InstantLock), reason: &str) {
        let mut is_lock = InstantLock::dummy(0..3);
        malform(&mut is_lock);

        match InstantLockValidator::new(&BTreeMap::new()).validate_structure(&is_lock) {
            Err(ValidationError::InvalidInstantLock(message)) => assert!(message.contains(reason)),
            other => panic!("expected InvalidInstantLock({reason}), got {other:?}"),
        }
    }

    #[test]
    fn a_lock_verifies_against_the_quorum_its_request_id_selects() {
        let engine = TestEngine::mainnet_fixture();
        let lock = fixture_is_lock();
        let validator =
            InstantLockValidator::new(engine.rotated_quorums_of_cycle(&lock.cyclehash).unwrap());

        let request_id = lock.request_id().expect("expected to make request id");
        assert_eq!(
            hex::encode(request_id),
            "481ca36cf80fde8fda333915e33c27014dad65fa9f3b54bc4d8bc45be7c81ddf"
        );
        let quorum_hash = QuorumHash::from_slice(
            hex::decode("00000000000000197368b224f2f01031991dd07aad0b43b2293a51fce8853ba0")
                .expect("expected bytes")
                .as_slice(),
        )
        .expect("expected quorum hash")
        .reverse();
        let (quorum, _, index) = validator.signing_quorum(&lock).expect("expected to get quorum");
        assert_eq!(index, 23);
        assert_eq!(quorum.quorum_entry.quorum_hash, quorum_hash);
        let sign_id =
            lock.sign_id(LLMQType::Llmqtype60_75, quorum_hash, None).expect("expected sign id");
        assert_eq!(
            hex::encode(sign_id),
            "6fcbf58004b118d865a448bf89d9299c64d4ecedd754dabec655090224de91cd"
        );
        validator.validate(&lock).expect("expected to verify is lock");

        // Without its quorum index in the cycle, the lock cannot be resolved.
        let mut quorums = engine.rotated_quorums_of_cycle(&lock.cyclehash).unwrap().clone();
        quorums.remove(&23);
        match InstantLockValidator::new(&quorums).signing_quorum(&lock) {
            Err(MessageVerificationError::QuorumIndexNotFound(23, hash)) => {
                assert_eq!(hash, lock.cyclehash)
            }
            other => panic!("expected QuorumIndexNotFound(23), got: {:?}", other.map(|_| ())),
        }
    }
}
