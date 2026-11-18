use std::collections::HashSet;

use dashcore::bls_sig_utils::BlsScheme;
use dashcore::constants::MAX_BLOCK_SIZE;
use dashcore::sml::message_verification_error::MessageVerificationError;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::{InstantLock, QuorumSigningRequestId};

use crate::error::{ValidationError, ValidationResult};
use crate::sml_engine::InstantSendCycle;
use crate::validation::Validator;

/// The most inputs a valid InstantLock can carry, as Dash Core caps them.
/// Its transaction fits in a block, and every input takes at least 41 bytes.
const MAX_INSTANT_LOCK_INPUTS: usize = MAX_BLOCK_SIZE as usize / 41;

/// Rejects malformed InstantLocks. Needs no quorum data, so it runs before a
/// lock is looked up, queued or cached.
///
/// A malformed lock fails with [`ValidationError::InvalidInstantLock`].
pub struct InstantLockStructureValidator;

impl Validator<&InstantLock> for InstantLockStructureValidator {
    fn validate(&self, instant_lock: &InstantLock) -> ValidationResult<()> {
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

        if instant_lock.inputs.len() > MAX_INSTANT_LOCK_INPUTS {
            return Err(ValidationError::InvalidInstantLock(format!(
                "InstantLock has more than {MAX_INSTANT_LOCK_INPUTS} inputs"
            )));
        }

        let mut seen = HashSet::with_capacity(instant_lock.inputs.len());
        if let Some(idx) = instant_lock.inputs.iter().position(|input| !seen.insert(input)) {
            return Err(ValidationError::InvalidInstantLock(format!(
                "InstantLock input {idx} repeats an earlier input"
            )));
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
}

/// Verifies an InstantLock's signature against the rotated quorums of its
/// cycle. It does not check the lock's structure: run
/// [`InstantLockStructureValidator`] first. Never accept InstantLocks from the
/// network without both.
///
/// Missing quorum data defers validation. Only a complete cycle can refute a signature.
pub(crate) struct InstantLockValidator<'a> {
    cycle: InstantSendCycle<'a>,
}

impl Validator<&InstantLock> for InstantLockValidator<'_> {
    fn validate(&self, instant_lock: &InstantLock) -> ValidationResult<()> {
        match self.validate_signature(instant_lock) {
            Ok(()) => Ok(()),
            Err(
                MessageVerificationError::CycleHashNotPresent(_)
                | MessageVerificationError::QuorumIndexNotFound(..),
            ) => Err(ValidationError::MissingQuorumData),
            Err(_) if !self.cycle.complete => Err(ValidationError::MissingQuorumData),
            Err(error) => Err(ValidationError::InvalidSignature(format!(
                "InstantLock BLS signature verification failed: {error}"
            ))),
        }
    }
}

impl<'a> InstantLockValidator<'a> {
    pub(crate) fn new(cycle: InstantSendCycle<'a>) -> Self {
        Self {
            cycle,
        }
    }

    /// The quorum of the cycle that signs the lock (DIP-24), with the lock's
    /// request id and the quorum index it selects.
    fn signing_quorum(
        &self,
        instant_lock: &InstantLock,
    ) -> Result<(&'a QualifiedQuorumEntry, QuorumSigningRequestId, u16), MessageVerificationError>
    {
        let cycle_hash = instant_lock.cyclehash;
        let quorums = self.cycle.quorums;
        let llmq_type = quorums
            .values()
            .next()
            .ok_or(MessageVerificationError::CycleHashNotPresent(cycle_hash))?
            .quorum_entry
            .llmq_type;

        let request_id = instant_lock.request_id().map_err(|e| e.to_string())?;
        // `selectionHash.GetUint64(3)` and the index bits as Dash Core takes them.
        let mut selection_bytes = [0; 8];
        selection_bytes.copy_from_slice(&request_id.as_byte_array()[24..32]);
        let selection_hash_64 = u64::from_le_bytes(selection_bytes);
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
    use crate::sml_engine::test_support::{mainnet_fixture_is_lock, TestEngine};
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::sml::llmq_type::LLMQType;
    use dashcore::{OutPoint, QuorumHash};
    use hex_conservative::DisplayHex;
    use std::collections::BTreeMap;
    use test_case::test_case;

    #[test]
    fn a_well_formed_lock_passes_the_structure_check() {
        assert!(InstantLockStructureValidator.validate(&InstantLock::dummy(0..3)).is_ok());
        let mut largest = InstantLock::dummy(0..1);
        let txid = largest.inputs[0].txid;
        largest.inputs =
            (0..MAX_INSTANT_LOCK_INPUTS as u32).map(|vout| OutPoint::new(txid, vout)).collect();
        assert!(InstantLockStructureValidator.validate(&largest).is_ok());
    }

    #[test_case(|lock| lock.inputs.clear(), "at least one input"; "no inputs")]
    #[test_case(|lock| lock.signature = dashcore::bls_sig_utils::BLSSignature::from([0; 96]), "signature cannot be zero"; "zero signature")]
    #[test_case(|lock| lock.txid = dashcore::Txid::all_zeros(), "transaction ID cannot be zero"; "null txid")]
    #[test_case(|lock| lock.inputs[1].txid = dashcore::Txid::all_zeros(), "input 1 has null transaction ID"; "null input txid")]
    #[test_case(|lock| lock.inputs = vec![lock.inputs[0]; MAX_INSTANT_LOCK_INPUTS + 1], "more than 48780 inputs"; "too many inputs")]
    #[test_case(|lock| lock.inputs[2] = lock.inputs[0], "input 2 repeats an earlier input"; "repeated input")]
    fn a_malformed_lock_fails_the_structure_check(malform: fn(&mut InstantLock), reason: &str) {
        let mut is_lock = InstantLock::dummy(0..3);
        malform(&mut is_lock);

        match InstantLockStructureValidator.validate(&is_lock) {
            Err(ValidationError::InvalidInstantLock(message)) => assert!(message.contains(reason)),
            other => panic!("expected InvalidInstantLock({reason}), got {other:?}"),
        }
    }

    #[test]
    fn a_lock_without_its_quorum_is_not_refuted() {
        let quorums = BTreeMap::new();
        let result = InstantLockValidator::new(InstantSendCycle {
            quorums: &quorums,
            complete: false,
        })
        .validate(&mainnet_fixture_is_lock());
        assert!(matches!(result, Err(ValidationError::MissingQuorumData)));
    }

    #[test_case(false; "partial cycle")]
    #[test_case(true; "complete cycle")]
    fn only_a_complete_cycle_refutes_a_signature(complete: bool) {
        let engine = TestEngine::mainnet_fixture();
        let mut lock = mainnet_fixture_is_lock();
        let cycle = InstantSendCycle {
            quorums: &engine.rotated_quorums_per_cycle()[&lock.cyclehash],
            complete,
        };
        let validator = InstantLockValidator::new(cycle);
        validator.validate(&lock).unwrap();
        lock.signature = BLSSignature::from([1; 96]);
        match validator.validate(&lock) {
            Err(ValidationError::InvalidSignature(_)) if complete => {}
            Err(ValidationError::MissingQuorumData) if !complete => {}
            result => panic!("unexpected validation result: {result:?}"),
        }
    }

    #[test]
    fn a_lock_verifies_against_the_quorum_its_request_id_selects() {
        let engine = TestEngine::mainnet_fixture();
        let lock = mainnet_fixture_is_lock();
        let validator =
            InstantLockValidator::new(engine.instant_send_cycle(&lock.cyclehash).unwrap());

        let request_id = lock.request_id().expect("expected to make request id");
        assert_eq!(
            request_id.as_byte_array().to_lower_hex_string(),
            "481ca36cf80fde8fda333915e33c27014dad65fa9f3b54bc4d8bc45be7c81ddf"
        );
        let quorum_hash = QuorumHash::from_slice(
            hex_conservative::decode_to_vec(
                "00000000000000197368b224f2f01031991dd07aad0b43b2293a51fce8853ba0",
            )
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
            sign_id.as_byte_array().to_lower_hex_string(),
            "6fcbf58004b118d865a448bf89d9299c64d4ecedd754dabec655090224de91cd"
        );
        validator.validate(&lock).expect("expected to verify is lock");

        // Without its quorum index in the cycle, the lock cannot be resolved.
        let mut quorums = engine.rotated_quorums_per_cycle()[&lock.cyclehash].clone();
        quorums.remove(&23);
        let validator = InstantLockValidator::new(InstantSendCycle {
            quorums: &quorums,
            complete: false,
        });
        assert!(matches!(validator.validate(&lock), Err(ValidationError::MissingQuorumData)));
        match validator.signing_quorum(&lock) {
            Err(MessageVerificationError::QuorumIndexNotFound(23, hash)) => {
                assert_eq!(hash, lock.cyclehash)
            }
            other => panic!("expected QuorumIndexNotFound(23), got: {:?}", other.map(|_| ())),
        }
    }
}
