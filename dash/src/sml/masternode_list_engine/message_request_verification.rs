use hashes::{Hash, HashEngine};

use crate::{ChainLock, InstantLock, QuorumSigningRequestId};
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::message_verification_error::MessageVerificationError;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;

impl MasternodeListEngine {
    /// Determines the quorum responsible for an Instant Lock (`InstantLock`).
    ///
    /// This function identifies the correct quorum that should have signed the given `InstantLock`
    /// based on the cycle hash and request ID. It selects the quorum with the lowest ordering hash
    /// for the computed request ID.
    ///
    /// # Arguments
    ///
    /// * `instant_lock` - A reference to an `InstantLock` that needs to be verified against the correct quorum.
    ///
    /// # Returns
    ///
    /// * `Ok((&QualifiedQuorumEntry, QuorumSigningRequestId))` if a matching quorum is found:
    ///   - `QualifiedQuorumEntry` - The quorum that should have signed the Instant Lock.
    ///   - `QuorumSigningRequestId` - The computed request ID used for quorum selection.
    ///
    /// * `Err(MessageVerificationError)` if:
    ///   - The cycle hash is not present in `rotated_quorums_per_cycle`.
    ///   - No quorums are found for the given cycle hash.
    ///   - The request ID computation fails.
    ///
    /// # Errors
    ///
    /// This function returns a `MessageVerificationError` in the following cases:
    ///
    /// * `CycleHashNotPresent` - The cycle hash is missing in `rotated_quorums_per_cycle`.
    /// * `CycleHashEmpty` - The cycle hash exists but has no associated quorums.
    /// * `Other` - The request ID computation fails (converted to a string error).
    ///
    /// # Implementation Details
    ///
    /// - The function first retrieves the set of quorums for the given cycle hash.
    /// - It ensures that at least one quorum exists for the cycle.
    /// - The request ID is computed from the `InstantLock`.
    /// - It selects the quorum with the **smallest** ordering hash, ensuring correct signature verification order.
    /// - The function returns a reference to the selected quorum along with the computed request ID.
    pub fn is_lock_quorum(
        &self,
        instant_lock: &InstantLock,
    ) -> Result<(&QualifiedQuorumEntry, QuorumSigningRequestId), MessageVerificationError> {
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

        Ok((quorum, request_id))
    }

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
        let (quorum, request_id) = self.is_lock_quorum(instant_lock)?;

        let sign_id = instant_lock.sign_id(quorum.quorum_entry.llmq_type, quorum.quorum_entry.quorum_hash, Some(request_id)).map_err(|e| e.to_string())?;

        quorum.verify_message_digest(sign_id.to_byte_array(), instant_lock.signature)?;

        Ok(())
    }

    pub fn verify_chain_lock(
        &self,
        chain_lock: &ChainLock,
    ) -> Result<(), MessageVerificationError> {
        // todo maybe we can know for sure based on height so we don't need to check 2?
        let (before, after) = self.masternode_lists_around_height(chain_lock.block_height - 8);

        let request_id = chain_lock.request_id().map_err(|e| e.to_string())?;
        let chain_lock_quorum_type = self.network.chain_locks_type();
        if let Some(before) = before {
            let quorums_of_type = before.quorums.get(&chain_lock_quorum_type).ok_or(MessageVerificationError::MasternodeListHasNoQuorums(before.known_height))?;
            let quorum = quorums_of_type.values()
                .min_by_key(|quorum| {
                    let mut ordering_hash =
                        quorum.ordering_hash_for_request_id(request_id.to_byte_array());
                    ordering_hash.reverse(); // Reverse for correct comparison
                    ordering_hash
                }).ok_or(MessageVerificationError::MasternodeListHasNoQuorums(before.known_height))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::consensus::deserialize;
    use crate::{InstantLock, QuorumHash};
    use crate::sml::llmq_type::LLMQType;
    use crate::hashes::Hash;
    #[test]
    pub fn is_lock_verification() {
        let lock_data = hex::decode("0101497915895c30eebfad0c5fcfb9e0e72308c7e92cd3749be2fd49c8320c4c58b6010000005b9d05c613c2a5f8ca60800f65f47f46bebbc934571b9ceae813a6ff8e96337bd674ea572a713d6b07deef085b9ce97e1e354055b91b0bbd0b00000000000000997d0b36738a9eef46ceeb4405998ff7235317708f277402799ffe05258015cae9b6bae43683f992b2f50f70f8f0cb9c0f26af340b00903e93995c1345d1b2c5b697ebecdbe5811dd112e11889101dcb4553b2bc206ab304026b96c07dec4f24").expect("expected valid hex");
        let lock : InstantLock = deserialize(lock_data.as_slice()).expect("expected to deserialize");
        let request_id = lock.request_id().expect("expected to make request id");
        assert_eq!(hex::encode(request_id), "dc77845e6592b624514eb8fb2297e03e3809a8b1cc9fdaa92f826955fe2689f6");
        let quorum_hash: QuorumHash = QuorumHash::from_slice(hex::decode("000000000000000bbd0b1bb95540351e7ee99c5b08efde076b3d712a57ea74d6").expect("expected bytes").as_slice()).expect("expected quorum hash");
        let sign_id = lock.sign_id(LLMQType::Llmqtype60_75, quorum_hash, None).expect("expected sign id");
        assert_eq!(hex::encode(sign_id), "2f8d1cfbd081a04b2dab3207c44b871e29bbe0e384b796a2617cae2392a9d482");
    }
}