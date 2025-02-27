use hashes::{Hash, HashEngine};

use crate::hash_types::QuorumOrderingHash;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::message_verification_error::MessageVerificationError;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::{ChainLock, InstantLock, QuorumSigningRequestId};

impl MasternodeListEngine {
    fn is_lock_potential_quorums(
        &self,
        instant_lock: &InstantLock,
    ) -> Result<&Vec<QualifiedQuorumEntry>, MessageVerificationError> {
        // Retrieve the cycle hash from the Instant Lock
        let cycle_hash = instant_lock.cyclehash;

        // Get the list of quorums associated with this cycle hash
        let quorums = self
            .rotated_quorums_per_cycle
            .get(&cycle_hash)
            .ok_or(MessageVerificationError::CycleHashNotPresent(cycle_hash))?;

        // Ensure that at least one quorum exists for this cycle
        if quorums.is_empty() {
            return Err(MessageVerificationError::CycleHashEmpty(cycle_hash));
        }

        Ok(quorums)
    }
    /// Determines the quorum responsible for signing an Instant Lock (`InstantLock`).
    ///
    /// This function identifies the correct quorum that should have signed the given `InstantLock`
    /// based on the **cycle hash** and **request ID**, as outlined in **DIP 24**.
    ///
    /// # Selection Process (DIP 24)
    ///
    /// To determine the responsible LLMQ (Long-Living Masternode Quorum) for signing:
    ///
    /// 1. Retrieve the active **LLMQ set** at the signing height (which is **8 blocks before the tip**).
    /// 2. Compute the **quorum index** `i`:
    ///     - Extract the **last `n` bits** of the `request_id`, where `n = log2(quorum count)`.
    ///     - Convert this bit segment to an integer `i` representing the quorum index.
    /// 3. Select the **i-th quorum** from the list.
    ///
    /// # Arguments
    ///
    /// * `instant_lock` - A reference to an `InstantLock` that needs to be mapped to the correct quorum.
    ///
    /// # Returns
    ///
    /// * `Ok((&QualifiedQuorumEntry, QuorumSigningRequestId))` if a matching quorum is found:
    ///   - `QualifiedQuorumEntry` - The quorum that should have signed the Instant Lock.
    ///   - `QuorumSigningRequestId` - The computed request ID used for quorum selection.
    ///
    /// * `Err(MessageVerificationError)` if:
    ///   - The **cycle hash is missing** from `rotated_quorums_per_cycle`.
    ///   - The **cycle hash exists but contains no quorums**.
    ///   - The **request ID computation fails**.
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
    /// - It extracts the **lowest log2-bit segment** of the request ID to determine the quorum index.
    /// - The function returns a reference to the selected quorum along with the computed request ID.
    ///
    pub fn is_lock_quorum(
        &self,
        instant_lock: &InstantLock,
    ) -> Result<(&QualifiedQuorumEntry, QuorumSigningRequestId, usize), MessageVerificationError>
    {
        // Get the list of quorums associated with this cycle hash
        let quorums = self.is_lock_potential_quorums(instant_lock)?;

        // Compute the signing request ID from the Instant Lock
        let request_id = instant_lock.request_id().map_err(|e| e.to_string())?;

        // Extract the last 64 bits of the selection hash (equivalent to `selectionHash.GetUint64(3)` in C++)
        let request_id_bytes = request_id.to_byte_array();
        // Just copying the core implementation
        let selection_hash_64 = u64::from_le_bytes(request_id_bytes[24..32].try_into().unwrap());

        // Determine the quorum index based on DIP 24
        let quorum_count = self.network.isd_llmq_type().active_quorum_count();
        let n = quorum_count.ilog2();
        let quorum_index_mask = (1 << n) - 1; // Extracts the last log2(quorum_count) bits
        // Extract the last `n` bits from the selection hash
        // Only God and maybe Odysseus knows why (64 - n - 1)
        let quorum_index = quorum_index_mask & (selection_hash_64 >> (64 - n - 1)) as usize;

        // Retrieve the selected quorum
        let quorum = quorums.get(quorum_index).expect("quorum index should always be within range");

        Ok((quorum, request_id, quorum_index))
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
        let (quorum, request_id, _) = self.is_lock_quorum(instant_lock)?;

        let sign_id = instant_lock
            .sign_id(
                quorum.quorum_entry.llmq_type,
                quorum.quorum_entry.quorum_hash,
                Some(request_id),
            )
            .map_err(|e| e.to_string())?;

        quorum.verify_message_digest(sign_id.to_byte_array(), instant_lock.signature)?;

        Ok(())
    }

    /// Retrieves the potential quorum for verifying a ChainLock from the masternode list **before or at**
    /// block height **(chain_lock.block_height - 8)**.
    ///
    /// This function attempts to find the quorum responsible for signing the ChainLock by looking at
    /// the masternode list at or before the signing height, following DIP 24 logic.
    ///
    /// # Arguments
    /// * `chain_lock` - A reference to the `ChainLock` for which the quorum is needed.
    ///
    /// # Returns
    /// * `Ok(Some(&QualifiedQuorumEntry))` - The quorum responsible for signing the ChainLock.
    /// * `Ok(None)` - No suitable quorum was found.
    /// * `Err(MessageVerificationError)` - If request ID computation fails or quorum retrieval fails.
    ///
    /// # Errors
    /// - **Masternode list missing**: If no masternode list is found at the required height.
    /// - **Invalid request ID**: If computing the request ID for the ChainLock fails.
    /// - **Quorum retrieval failure**: If the quorum for the request ID cannot be determined.
    pub fn chain_lock_potential_quorum_under(
        &self,
        chain_lock: &ChainLock,
    ) -> Result<Option<&QualifiedQuorumEntry>, MessageVerificationError> {
        // Retrieve the masternode list at or before (block_height - 8)
        let (before, _) = self.masternode_lists_around_height(chain_lock.block_height - 8);

        // Compute the signing request ID
        let request_id = chain_lock.request_id().map_err(|e| e.to_string())?;

        // Get the ChainLock quorum type for the current network
        let chain_lock_quorum_type = self.network.chain_locks_type();

        // Retrieve the responsible quorum if the masternode list exists
        if let Some(before) = before {
            let quorum = before.quorum_for_request(chain_lock_quorum_type, &request_id)?;
            Ok(Some(quorum))
        } else {
            Ok(None)
        }
    }

    /// Retrieves the potential quorum for verifying a ChainLock from the masternode list **after**
    /// block height **(chain_lock.block_height - 8)**.
    ///
    /// This function looks at the next available masternode list to determine if a quorum exists
    /// for signing the ChainLock, following DIP 24.
    ///
    /// # Arguments
    /// * `chain_lock` - A reference to the `ChainLock` for which the quorum is needed.
    ///
    /// # Returns
    /// * `Ok(Some(&QualifiedQuorumEntry))` - The quorum responsible for signing the ChainLock.
    /// * `Ok(None)` - No suitable quorum was found.
    /// * `Err(MessageVerificationError)` - If request ID computation fails or quorum retrieval fails.
    ///
    /// # Errors
    /// - **Masternode list missing**: If no masternode list is found at the required height.
    /// - **Invalid request ID**: If computing the request ID for the ChainLock fails.
    /// - **Quorum retrieval failure**: If the quorum for the request ID cannot be determined.
    pub fn chain_lock_potential_quorum_over(
        &self,
        chain_lock: &ChainLock,
    ) -> Result<Option<&QualifiedQuorumEntry>, MessageVerificationError> {
        // Retrieve the masternode list after (block_height - 8)
        let (_, after) = self.masternode_lists_around_height(chain_lock.block_height - 8);

        // Compute the signing request ID
        let request_id = chain_lock.request_id().map_err(|e| e.to_string())?;

        // Get the ChainLock quorum type for the current network
        let chain_lock_quorum_type = self.network.chain_locks_type();

        // Retrieve the responsible quorum if the masternode list exists
        if let Some(after) = after {
            let quorum = after.quorum_for_request(chain_lock_quorum_type, &request_id)?;
            Ok(Some(quorum))
        } else {
            Ok(None)
        }
    }

    /// Verifies a ChainLock (`ChainLock`) by checking its signature against the responsible quorum.
    ///
    /// This function attempts to validate the `ChainLock` signature using the correct quorum at
    /// **block height - 8**, as required by DIP 24. If the verification fails for the "before" masternode
    /// list, it retries using the "after" masternode list (if available).
    ///
    /// # Arguments
    /// * `chain_lock` - A reference to the `ChainLock` that needs to be verified.
    ///
    /// # Returns
    /// * `Ok(())` if the `ChainLock` is verified successfully.
    /// * `Err(MessageVerificationError)` if:
    ///   - The masternode lists do not contain the required quorum.
    ///   - Signature verification fails for both "before" and "after" masternode lists.
    ///
    /// # Errors
    /// - `MasternodeListHasNoQuorums`: The masternode list at a given height does not contain any quorums of the required type.
    /// - `Other`: If computing the request ID or signing ID fails.
    ///
    /// # Implementation Details
    /// - Retrieves masternode lists **before and after** `chain_lock.block_height - 8`.
    /// - Finds the **quorum with the lowest ordering hash** for the signing request.
    /// - Computes the **signing ID** and verifies the ChainLock signature.
    /// - If verification fails with the "before" list, it attempts verification with the "after" list.
    pub fn verify_chain_lock(
        &self,
        chain_lock: &ChainLock,
    ) -> Result<(), MessageVerificationError> {
        // Retrieve masternode lists surrounding the signing height (block_height - 8)
        let (before, after) = self.masternode_lists_around_height(chain_lock.block_height - 8);

        if before.is_none() && after.is_none() {
            return Err(MessageVerificationError::NoMasternodeLists);
        }
        // Compute the signing request ID
        let request_id = chain_lock.request_id().map_err(|e| e.to_string())?;

        // Attempt verification using the "before" masternode list
        let initial_error = if let Some(before) = before {
            let Err(e) =
                self.verify_chain_lock_with_masternode_list(chain_lock, &before, &request_id)
            else {
                return Ok(());
            };
            Some(e)
        } else {
            None
        };

        let chain_lock_quorum_type = self.network.chain_locks_type();

        // If "before" verification fails, attempt verification using the "after" masternode list
        if let Some(after) = after {
            // Only do this verification if the quorums actually changed
            let do_check = if let Some(before) = before {
                before.quorums.get(&chain_lock_quorum_type)
                    != after.quorums.get(&chain_lock_quorum_type)
            } else {
                true
            };
            if do_check {
                return self.verify_chain_lock_with_masternode_list(
                    chain_lock,
                    &after,
                    &request_id,
                );
            } else {
                if let Some(initial_error) = initial_error {
                    return Err(initial_error);
                }
            }
        }

        Ok(())
    }

    /// Helper function to verify a ChainLock using a specific masternode list.
    fn verify_chain_lock_with_masternode_list(
        &self,
        chain_lock: &ChainLock,
        masternode_list: &MasternodeList,
        request_id: &QuorumSigningRequestId,
    ) -> Result<(), MessageVerificationError> {
        // Get the quorum type for ChainLocks in the current network
        let chain_lock_quorum_type = self.network.chain_locks_type();

        let quorums_of_type = masternode_list.quorums.get(&chain_lock_quorum_type).ok_or(
            MessageVerificationError::MasternodeListHasNoQuorums(masternode_list.known_height),
        )?;

        let quorum = quorums_of_type
            .values()
            .min_by_key(|quorum| QuorumOrderingHash::create(&quorum.quorum_entry, request_id))
            .ok_or(MessageVerificationError::MasternodeListHasNoQuorums(
                masternode_list.known_height,
            ))?;

        let sign_id = chain_lock
            .sign_id(
                quorum.quorum_entry.llmq_type,
                quorum.quorum_entry.quorum_hash,
                Some(*request_id),
            )
            .map_err(|e| e.to_string())?;

        quorum.verify_message_digest(sign_id.to_byte_array(), chain_lock.signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::bls_sig_utils::BLSSignature;
    use crate::consensus::deserialize;
    use crate::hashes::Hash;
    use crate::hashes::hex::FromHex;
    use crate::sml::llmq_type::LLMQType;
    use crate::sml::masternode_list_engine::MasternodeListEngine;
    use crate::{BlockHash, ChainLock, InstantLock, QuorumHash};

    #[test]
    pub fn is_lock_verification() {
        let block_hex =
            include_str!("../../../tests/data/test_DML_diffs/masternode_list_engine.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let mn_list_engine: MasternodeListEngine =
            bincode::decode_from_slice(&data, bincode::config::standard())
                .expect("expected to decode")
                .0;

        let lock_data = hex::decode("010133c404bebbf34c153816d26553bcec8c9b876354a68b952ab2c1c514c04baf9800000000578de219b47300c1d43985e1ee7af2faa773b87729df3cb48f2c522937c7b070d674ea572a713d6b07deef085b9ce97e1e354055b91b0bbd0b00000000000000a846486b3f75da24e3d04b62eadd7dffe589736f13ab222c208d0f3880dce5d287b8542dc1e1f0e271749e70e939262704f8611aafcdeb20ed70c5bc78fdf737a1bd6409d061fcf6a591b117ada7ba92567959544c090a05cdd955268d22be6b").expect("expected valid hex");
        let lock: InstantLock = deserialize(lock_data.as_slice()).expect("expected to deserialize");
        let request_id = lock.request_id().expect("expected to make request id");
        assert_eq!(
            hex::encode(request_id),
            "94dd5c8d946cb34dda43ebf424b385ae898159827385a48d8b1fae15dbf21a12"
        );
        let quorum_hash: QuorumHash = QuorumHash::from_slice(
            hex::decode("0000000000000019756ecc9c9c5f476d3f66876b1dcfa5dde1ea82f0d99334a2")
                .expect("expected bytes")
                .as_slice(),
        )
        .expect("expected quorum hash")
        .reverse();

        let (quorum, _, index) =
            mn_list_engine.is_lock_quorum(&lock).expect("expected to get quorum");
        assert_eq!(index, 4);
        assert_eq!(quorum.quorum_entry.quorum_hash, quorum_hash);

        let sign_id =
            lock.sign_id(LLMQType::Llmqtype60_75, quorum_hash, None).expect("expected sign id");
        assert_eq!(
            hex::encode(sign_id),
            "0eaeba3a982f59144913b8d8150b2dfbb2dd2ba43bbcb54a3964a0d8d7ead62b"
        );
        mn_list_engine.verify_is_lock(&lock).expect("expected to verify is lock");
    }

    #[test]
    pub fn chain_lock_verification() {
        let block_hex =
            include_str!("../../../tests/data/test_DML_diffs/masternode_list_engine.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let mn_list_engine: MasternodeListEngine =
            bincode::decode_from_slice(&data, bincode::config::standard())
                .expect("expected to decode")
                .0;

        let height = mn_list_engine.latest_masternode_list().expect("height").known_height;

        assert_eq!(height, 2229204);

        let chain_lock = ChainLock {
            block_height: 2229204,
            block_hash: BlockHash::from_slice(hex::decode("000000000000000c0568e1ffe5d14ed34cd19fccda425bc5923fc119c131ee0c").unwrap().as_slice()).unwrap().reverse(),
            signature: BLSSignature::from_hex("b6366341f97e1fd5a8dbc81e7f6c5c67acbed02bac2b7e10316f5c97fd07767e3544214386312687b7646d1b92539acc1069ecb3640e37d97fd2e5fdb2d37a3b6bf16b511bf22a41aa87038145caaeb38485d58d72b31add18deaf7e8c07684e").unwrap(),
        };

        let request_id = chain_lock.request_id().expect("expected to make request id");
        assert_eq!(
            hex::encode(request_id),
            "88346d49ddf5c06528f3ede253e01a8ab54048935ff944d88bb149aaeef956f2"
        );

        let quorum = mn_list_engine
            .chain_lock_potential_quorum_under(&chain_lock)
            .expect("expected under")
            .expect("expected");

        let expected_quorum_hash: QuorumHash = QuorumHash::from_slice(
            hex::decode("000000000000001de4e594585627fb5e2612ef983c913ee13add9a454e5faa6d")
                .expect("expected bytes")
                .as_slice(),
        )
        .expect("expected quorum hash")
        .reverse();

        assert_eq!(quorum.quorum_entry.quorum_hash, expected_quorum_hash);

        mn_list_engine.verify_chain_lock(&chain_lock).expect("expected to verify chain lock");

        // let's do another to make sure it wasn't a 1/4 fluke

        let chain_lock = ChainLock {
            block_height: 2229203,
            block_hash: BlockHash::from_slice(hex::decode("0000000000000009ea873df6f4ab3bb1ea744e5630928cb8a4b4bd68aa16b18a").unwrap().as_slice()).unwrap().reverse(),
            signature: BLSSignature::from_hex("8723bf0a12abf41830936d8702ae57bb4f5ef7f816522f72e6da414081402d50a747a6307c91b15c0ee97fcfda60a7c50cdafa394c06b77299d9b9e4826fa1625c5436a2e3dc2e98df071dce92bbfc4445c87f7015b1914b17954b139dd8eafe").unwrap(),
        };

        let request_id = chain_lock.request_id().expect("expected to make request id");
        assert_eq!(
            hex::encode(request_id),
            "10a808c18307e3993dd4aa996d032b6b5d9d30a5d75ddf64fa10ea35ee63b2bb"
        );

        let quorum = mn_list_engine
            .chain_lock_potential_quorum_under(&chain_lock)
            .expect("expected under")
            .expect("expected");

        let expected_quorum_hash: QuorumHash = QuorumHash::from_slice(
            hex::decode("000000000000001de4e594585627fb5e2612ef983c913ee13add9a454e5faa6d")
                .expect("expected bytes")
                .as_slice(),
        )
        .expect("expected quorum hash")
        .reverse();

        //assert_eq!(quorum.quorum_entry.quorum_hash, expected_quorum_hash);

        mn_list_engine.verify_chain_lock(&chain_lock).expect("expected to verify chain lock");
    }
}
