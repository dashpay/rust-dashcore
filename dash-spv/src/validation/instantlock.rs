use std::collections::BTreeMap;

use dashcore::bls_sig_utils::BlsScheme;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use dashcore::sml::message_verification_error::MessageVerificationError;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::{InstantLock, QuorumSigningRequestId, Transaction, Txid};

use crate::error::{ValidationError, ValidationResult};
use crate::sml_engine::MasternodeListEngine;
use crate::storage::BlockHeaderStorage;
use crate::validation::Validator;

/// An InstantLock authenticated against the client's synchronized quorum state.
///
/// This evidence is process-local: persisted locks must be verified again on load.
/// Obtain it with `DashSpvClient::verify_instant_lock`; a stored context is not proof.
#[derive(Debug, Clone)]
pub struct VerifiedInstantLock {
    instant_lock: InstantLock,
}

/// A stored or received InstantLock failed authentication.
#[derive(Debug, thiserror::Error)]
pub enum InstantLockVerificationError {
    /// The lock's fields are malformed.
    #[error("malformed InstantLock: {0}")]
    Malformed(#[source] ValidationError),
    /// The lock is not signed by the selected quorum.
    #[error("InstantLock authentication failed: {0}")]
    InvalidSignature(#[source] ValidationError),
}

impl VerifiedInstantLock {
    /// The authenticated lock, including its signed inputs.
    pub fn instant_lock(&self) -> &InstantLock {
        &self.instant_lock
    }

    /// The transaction ID covered by the quorum signature.
    pub fn txid(&self) -> Txid {
        self.instant_lock.txid
    }

    /// Binds the evidence to the complete transaction and its ordered inputs.
    ///
    /// No wallet arithmetic or transaction consensus validation is performed.
    pub fn matches_transaction(&self, transaction: &Transaction) -> bool {
        self.txid() == transaction.txid()
            && self
                .instant_lock
                .inputs
                .iter()
                .copied()
                .eq(transaction.input.iter().map(|input| input.previous_output))
    }

    pub(crate) fn verify<H: BlockHeaderStorage>(
        instant_lock: &InstantLock,
        engine: Option<&MasternodeListEngine<H>>,
    ) -> Result<Option<Self>, InstantLockVerificationError> {
        InstantLockStructureValidator
            .validate(instant_lock)
            .map_err(InstantLockVerificationError::Malformed)?;
        let Some(quorums) =
            engine.and_then(|engine| engine.rotated_quorums_of_cycle(&instant_lock.cyclehash))
        else {
            return Ok(None);
        };
        if quorums.values().any(|quorum| quorum.verified != LLMQEntryVerificationStatus::Verified) {
            return Ok(None);
        }
        let validator = InstantLockValidator::new(quorums);
        if matches!(
            validator.signing_quorum(instant_lock),
            Err(MessageVerificationError::CycleHashNotPresent(_)
                | MessageVerificationError::QuorumIndexNotFound(..))
        ) {
            return Ok(None);
        }
        validator.validate(instant_lock).map_err(InstantLockVerificationError::InvalidSignature)?;
        Ok(Some(Self {
            instant_lock: instant_lock.clone(),
        }))
    }
}

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
/// A lock whose signature does not verify, or whose quorum is not in the
/// cycle, fails with [`ValidationError::InvalidSignature`].
pub struct InstantLockValidator<'a> {
    /// The rotated quorums of the lock's cycle, by quorum index.
    cycle_quorums: &'a BTreeMap<u16, QualifiedQuorumEntry>,
}

impl Validator<&InstantLock> for InstantLockValidator<'_> {
    fn validate(&self, instant_lock: &InstantLock) -> ValidationResult<()> {
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
    use hex_conservative::DisplayHex;
    use test_case::test_case;

    /// An IS lock of the mainnet fixture's cycle, signed by its quorum at index 23.
    fn fixture_is_lock() -> InstantLock {
        deserialize(&hex_conservative::decode_to_vec("01018d53e7997ead57409750942af0d5e0aafc06f852a9a52308f4781b6a8220298f00000000c6f9d8c63dd15937ea70aaddb7890daad42c91bf6818e2bf76d183d6f2d9215b4b5f84978fad9dde7ab52bdcc0674be891e9029cc1ef0cb01200000000000000a27c98836c4c04653ab81eb4e07ddfc2c8c2c1036b75247969c05a4f25451cd78913a971f1899d9f2bddec9cf8e0104004f72f20c2856453e5aa3bcd2a8200670ec28feda38f67cc400fc72ef1966956656ec0765478c9d16e9a9e470c07f9ed").unwrap()).unwrap()
    }

    #[test]
    fn should_authenticate_stored_lock_only_with_available_cycle() {
        let engine = TestEngine::mainnet_fixture();
        let lock = fixture_is_lock();
        assert!(VerifiedInstantLock::verify::<crate::test_utils::MockHeaderStorage>(&lock, None,)
            .unwrap()
            .is_none());
        let empty = TestEngine::empty(dashcore::Network::Mainnet);
        assert!(VerifiedInstantLock::verify(&lock, Some(&empty)).unwrap().is_none());
        let verified = VerifiedInstantLock::verify(&lock, Some(&engine)).unwrap().unwrap();
        assert_eq!(verified.txid(), lock.txid);
        assert_eq!(verified.instant_lock(), &lock);
        let mut unknown_cycle = lock.clone();
        unknown_cycle.cyclehash = dashcore::BlockHash::all_zeros();
        assert!(VerifiedInstantLock::verify(&unknown_cycle, Some(&engine)).unwrap().is_none());
        let mut invalid = lock.clone();
        invalid.txid = dashcore::Txid::from_byte_array([7; 32]);
        assert!(matches!(
            VerifiedInstantLock::verify(&invalid, Some(&engine)),
            Err(InstantLockVerificationError::InvalidSignature(_))
        ));
        let mut changed_input = lock.clone();
        changed_input.inputs[0].vout += 1;
        assert!(matches!(
            VerifiedInstantLock::verify(&changed_input, Some(&engine)),
            Err(InstantLockVerificationError::InvalidSignature(_))
        ));
        let mut changed_signature = lock.clone();
        changed_signature.signature = dashcore::bls_sig_utils::BLSSignature::from([1; 96]);
        assert!(matches!(
            VerifiedInstantLock::verify(&changed_signature, Some(&engine)),
            Err(InstantLockVerificationError::InvalidSignature(_))
        ));
        let mut malformed = lock;
        malformed.inputs.clear();
        assert!(matches!(
            VerifiedInstantLock::verify(&malformed, Some(&empty)),
            Err(InstantLockVerificationError::Malformed(_))
        ));
    }

    #[test]
    fn should_bind_verified_evidence_without_wallet_arithmetic() {
        let transaction = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![dashcore::TxIn {
                previous_output: dashcore::OutPoint::new(Txid::from_byte_array([3; 32]), 0),
                ..Default::default()
            }],
            output: vec![
                dashcore::TxOut {
                    value: u64::MAX,
                    script_pubkey: dashcore::ScriptBuf::new(),
                };
                2
            ],
            special_transaction_payload: None,
        };
        // This unit tests binding only; authentication is exercised with the signed fixture.
        let mut lock = fixture_is_lock();
        lock.txid = transaction.txid();
        lock.inputs = transaction.input.iter().map(|input| input.previous_output).collect();
        let verified = VerifiedInstantLock {
            instant_lock: lock,
        };
        assert!(verified.matches_transaction(&transaction));
        let mut changed = transaction.clone();
        changed.output[0].value -= 1;
        assert!(!verified.matches_transaction(&changed));
        let mut wrong_inputs = verified.clone();
        wrong_inputs.instant_lock.inputs[0].vout += 1;
        assert!(!wrong_inputs.matches_transaction(&transaction));
    }

    #[test]
    fn a_well_formed_lock_passes_the_structure_check() {
        assert!(InstantLockStructureValidator.validate(&InstantLock::dummy(0..3)).is_ok());
    }

    #[test_case(|lock| lock.inputs.clear(), "at least one input"; "no inputs")]
    #[test_case(|lock| lock.signature = dashcore::bls_sig_utils::BLSSignature::from([0; 96]), "signature cannot be zero"; "zero signature")]
    #[test_case(|lock| lock.txid = dashcore::Txid::all_zeros(), "transaction ID cannot be zero"; "null txid")]
    #[test_case(|lock| lock.inputs[1].txid = dashcore::Txid::all_zeros(), "input 1 has null transaction ID"; "null input txid")]
    fn a_malformed_lock_fails_the_structure_check(malform: fn(&mut InstantLock), reason: &str) {
        let mut is_lock = InstantLock::dummy(0..3);
        malform(&mut is_lock);

        match InstantLockStructureValidator.validate(&is_lock) {
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
