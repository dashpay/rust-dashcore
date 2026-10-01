use dashcore::hashes::Hash;

use crate::sml_engine::MasternodeListEngine;
use crate::storage::BlockHeaderStorage;
use dashcore::bls_sig_utils::BlsScheme;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::message_verification_error::MessageVerificationError;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::{ChainLock, InstantLock, QuorumSigningRequestId};

impl<H: BlockHeaderStorage> MasternodeListEngine<H> {
    /// The quorum of the lock's cycle that signs it (DIP-24), with the lock's
    /// request id and the quorum index it selects.
    fn is_lock_quorum(
        &self,
        instant_lock: &InstantLock,
    ) -> Result<(&QualifiedQuorumEntry, QuorumSigningRequestId, usize), MessageVerificationError>
    {
        let cycle_hash = instant_lock.cyclehash;
        let quorums = self
            .rotated_quorums_per_cycle
            .get(&cycle_hash)
            .ok_or(MessageVerificationError::CycleHashNotPresent(cycle_hash))?;

        let request_id = instant_lock.request_id().map_err(|e| e.to_string())?;
        // `selectionHash.GetUint64(3)` and the index bits as Dash Core takes them.
        let selection_hash_64 =
            u64::from_le_bytes(request_id.to_byte_array()[24..32].try_into().unwrap());
        let n = self.network.isd_llmq_type().active_quorum_count().ilog2();
        let quorum_index = ((1 << n) - 1) & (selection_hash_64 >> (64 - n - 1)) as usize;

        let quorum = quorums.get(&(quorum_index as u16)).ok_or(
            MessageVerificationError::QuorumIndexNotFound(quorum_index as u16, cycle_hash),
        )?;
        Ok((quorum, request_id, quorum_index))
    }

    /// Verifies an InstantLock against the quorum of its cycle that signs it.
    pub fn verify_is_lock(
        &self,
        instant_lock: &InstantLock,
    ) -> Result<(), MessageVerificationError> {
        let (quorum, request_id, quorum_index) = self.is_lock_quorum(instant_lock)?;

        let sign_id = instant_lock
            .sign_id(
                quorum.quorum_entry.llmq_type,
                quorum.quorum_entry.quorum_hash,
                Some(request_id),
            )
            .map_err(|e| e.to_string())?;

        let result = quorum.verify_message_digest(
            sign_id.to_byte_array(),
            instant_lock.signature,
            BlsScheme::Modern,
        );
        let quorum_hash = quorum.quorum_entry.quorum_hash;
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

    /// Verifies a ChainLock against the list at or below its signing height,
    /// and against the next list up when that one holds other ChainLock
    /// quorums.
    pub fn verify_chain_lock(
        &self,
        chain_lock: &ChainLock,
    ) -> Result<(), MessageVerificationError> {
        let request_id = chain_lock.request_id().map_err(|e| e.to_string())?;
        let signing_height = chain_lock.signing_height();
        let before = self.masternode_lists.range(..=signing_height).next_back().map(|(_, l)| l);
        let after = self.masternode_lists.range(signing_height + 1..).next().map(|(_, l)| l);

        match (before, after) {
            (None, None) => Err(MessageVerificationError::NoMasternodeLists),
            (Some(list), None) | (None, Some(list)) => {
                self.verify_chain_lock_with_masternode_list(chain_lock, list, &request_id)
            }
            (Some(before), Some(after)) => {
                let Err(initial_error) =
                    self.verify_chain_lock_with_masternode_list(chain_lock, before, &request_id)
                else {
                    return Ok(());
                };
                let quorum_type = self.network.chain_locks_type();
                if before.quorums.get(&quorum_type) != after.quorums.get(&quorum_type) {
                    self.verify_chain_lock_with_masternode_list(chain_lock, after, &request_id)
                } else {
                    Err(initial_error)
                }
            }
        }
    }

    /// Verifies a ChainLock with the quorum of `masternode_list` that has the
    /// lowest ordering hash for its request id.
    fn verify_chain_lock_with_masternode_list(
        &self,
        chain_lock: &ChainLock,
        masternode_list: &MasternodeList,
        request_id: &QuorumSigningRequestId,
    ) -> Result<(), MessageVerificationError> {
        let quorum =
            masternode_list.quorum_for_request(self.network.chain_locks_type(), request_id)?;

        let sign_id = chain_lock
            .sign_id(
                quorum.quorum_entry.llmq_type,
                quorum.quorum_entry.quorum_hash,
                Some(*request_id),
            )
            .map_err(|e| e.to_string())?;

        quorum.verify_message_digest(
            sign_id.to_byte_array(),
            chain_lock.signature,
            BlsScheme::Modern,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::sml_engine::test_support::TestEngine;
    use dashcore::consensus::deserialize;
    use dashcore::hashes::Hash;
    use dashcore::sml::llmq_type::LLMQType;
    use dashcore::{ChainLock, InstantLock, QuorumHash};

    /// An IS lock of the fixture's cycle, signed by its quorum at index 23.
    fn fixture_is_lock() -> InstantLock {
        deserialize(&hex::decode("01018d53e7997ead57409750942af0d5e0aafc06f852a9a52308f4781b6a8220298f00000000c6f9d8c63dd15937ea70aaddb7890daad42c91bf6818e2bf76d183d6f2d9215b4b5f84978fad9dde7ab52bdcc0674be891e9029cc1ef0cb01200000000000000a27c98836c4c04653ab81eb4e07ddfc2c8c2c1036b75247969c05a4f25451cd78913a971f1899d9f2bddec9cf8e0104004f72f20c2856453e5aa3bcd2a8200670ec28feda38f67cc400fc72ef1966956656ec0765478c9d16e9a9e470c07f9ed").unwrap()).unwrap()
    }

    #[test]
    pub fn is_lock_verification() {
        let mn_list_engine = TestEngine::mainnet_fixture();

        let lock = fixture_is_lock();
        let request_id = lock.request_id().expect("expected to make request id");
        assert_eq!(
            hex::encode(request_id),
            "481ca36cf80fde8fda333915e33c27014dad65fa9f3b54bc4d8bc45be7c81ddf"
        );
        let quorum_hash: QuorumHash = QuorumHash::from_slice(
            hex::decode("00000000000000197368b224f2f01031991dd07aad0b43b2293a51fce8853ba0")
                .expect("expected bytes")
                .as_slice(),
        )
        .expect("expected quorum hash")
        .reverse();

        let (quorum, _, index) =
            mn_list_engine.is_lock_quorum(&lock).expect("expected to get quorum");
        assert_eq!(index, 23);
        assert_eq!(quorum.quorum_entry.quorum_hash, quorum_hash);

        let sign_id =
            lock.sign_id(LLMQType::Llmqtype60_75, quorum_hash, None).expect("expected sign id");
        assert_eq!(
            hex::encode(sign_id),
            "6fcbf58004b118d865a448bf89d9299c64d4ecedd754dabec655090224de91cd"
        );
        mn_list_engine.verify_is_lock(&lock).expect("expected to verify is lock");
    }

    /// A genuine ChainLock replayed at a height signed by the newest list: its
    /// signature no longer matches the request id, and with no list above to
    /// retry against, that failure has to stand.
    #[test]
    fn chain_lock_replayed_above_the_newest_list_is_rejected() {
        let mn_list_engine = TestEngine::mainnet_fixture();
        let newest = mn_list_engine.latest_masternode_list().expect("newest").known_height;

        let [genuine, _] = ChainLock::mainnet_fixture_pair();
        mn_list_engine.verify_chain_lock(&genuine).expect("verifies at its own height");

        let replayed = ChainLock {
            block_height: newest + 1_000,
            ..genuine
        };
        assert!(mn_list_engine.verify_chain_lock(&replayed).is_err());
    }

    #[test]
    pub fn chain_lock_verification() {
        let mn_list_engine = TestEngine::mainnet_fixture();

        let height = mn_list_engine.latest_masternode_list().expect("height").known_height;

        assert_eq!(height, 2243493);

        let [chain_lock, next_chain_lock] = ChainLock::mainnet_fixture_pair();

        let request_id = chain_lock.request_id().expect("expected to make request id");
        assert_eq!(
            hex::encode(request_id),
            "969ab4a945632f5fba1331f3d2556d317682142cf8aaa6544e407e683c61a177"
        );

        mn_list_engine.verify_chain_lock(&chain_lock).expect("expected to verify chain lock");

        // let's do another to make sure it wasn't a 1/4 fluke

        let chain_lock = next_chain_lock;

        let request_id = chain_lock.request_id().expect("expected to make request id");
        assert_eq!(
            hex::encode(request_id),
            "675aed91d6098cdf575cc09bfd1ff4f750acde1e793f385c3c72bbb400068d28"
        );

        mn_list_engine.verify_chain_lock(&chain_lock).expect("expected to verify chain lock");
    }

    /// Test that QuorumIndexNotFound error is returned when the required quorum index is missing.
    #[test]
    pub fn is_lock_quorum_not_found_error() {
        use dashcore::sml::message_verification_error::MessageVerificationError;

        let mut mn_list_engine = TestEngine::mainnet_fixture();

        let lock = fixture_is_lock();

        // The lock should resolve to quorum_index 23
        let (_, _, index) = mn_list_engine.is_lock_quorum(&lock).expect("expected quorum");
        assert_eq!(index, 23);

        // Remove the quorum with index 23 from the cycle
        let cycle_hash = lock.cyclehash;
        if let Some(quorums) = mn_list_engine.rotated_quorums_per_cycle.get_mut(&cycle_hash) {
            quorums.remove(&23);
        }

        // Now the lookup should return QuorumIndexNotFound
        let result = mn_list_engine.is_lock_quorum(&lock);
        assert!(result.is_err());
        match result.unwrap_err() {
            MessageVerificationError::QuorumIndexNotFound(idx, hash) => {
                assert_eq!(idx, 23);
                assert_eq!(hash, cycle_hash);
            }
            other => panic!("expected QuorumIndexNotFound error, got: {:?}", other),
        }
    }
}
