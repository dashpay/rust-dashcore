use hashes::{Hash, HashEngine, sha256d};

use crate::InstantLock;
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::message_verification_error::MessageVerificationError;

impl MasternodeListEngine {
    /// Verifies an Instant Lock (`InstantLock`) using the appropriate quorum from the rotated quorums.
    ///
    /// This function checks that the `InstantLock` was signed by a valid quorum in the cycle.
    /// It selects the correct quorum based on the request ID and verifies the message digest
    /// using the quorum's signature verification mechanism.
    ///
    /// # Arguments
    ///
    /// * `instant_lock` - A reference to an `InstantLock` that needs to be verified.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the `InstantLock` is valid and correctly signed by a quorum.
    /// * `Err(MessageVerificationError)` if verification fails due to:
    ///   - The cycle hash being missing (`CycleHashNotPresent`).
    ///   - The cycle hash having no quorums (`CycleHashEmpty`).
    ///   - Issues retrieving the request ID.
    ///   - Signature verification failure.
    ///
    /// # Errors
    ///
    /// Returns a `MessageVerificationError` in the following cases:
    /// - `CycleHashNotPresent`: The provided cycle hash is not found in `rotated_quorums_per_cycle`.
    /// - `CycleHashEmpty`: The cycle hash exists but has no quorums.
    /// - `MessageVerificationError`: If the request ID is invalid or signature verification fails.
    ///
    ///
    /// # Implementation Details
    ///
    /// - The function retrieves the set of quorums corresponding to the cycle hash of the `InstantLock`.
    /// - It selects the quorum with the minimum ordering hash for the given request ID.
    /// - Constructs a `sha256d` message digest using the quorum type, quorum hash, request ID, and `txid`.
    /// - The selected quorum verifies the message digest against the provided signature in `InstantLock`.
    pub fn verify_is_lock(
        &self,
        instant_lock: &InstantLock,
    ) -> Result<(), MessageVerificationError> {
        let cycle_hash = instant_lock.cyclehash;

        let quorums = self
            .rotated_quorums_per_cycle
            .get(&cycle_hash)
            .ok_or(MessageVerificationError::CycleHashNotPresent(cycle_hash))?;

        if quorums.is_empty() {
            return Err(MessageVerificationError::CycleHashEmpty(cycle_hash));
        }

        let request_id = instant_lock.request_id().map_err(|e| e.to_string())?;

        let quorum = quorums
            .iter()
            .min_by_key(|quorum| {
                let mut ordering_hash =
                    quorum.ordering_hash_for_request_id(request_id.to_byte_array());
                ordering_hash.reverse(); // Reverse for correct comparison
                ordering_hash
            })
            .expect("there must be a quorum");

        let mut engine = sha256d::Hash::engine();

        engine.input(&[quorum.quorum_entry.llmq_type as u8]);
        engine.input(quorum.quorum_entry.quorum_hash.reverse().as_byte_array());
        engine.input(request_id.as_byte_array());
        engine.input(instant_lock.txid.as_byte_array());

        let message_digest = sha256d::Hash::from_engine(engine);

        quorum.verify_message_digest(message_digest, instant_lock.signature)?;

        Ok(())
    }
}
