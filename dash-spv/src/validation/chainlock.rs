use dashcore::bls_sig_utils::BlsScheme;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::message_verification_error::MessageVerificationError;
use dashcore::{ChainLock, QuorumSigningRequestId};
use dashcore_hashes::Hash;

use crate::error::{ValidationError, ValidationResult};
use crate::validation::Validator;

/// Validates ChainLock signatures against the masternode lists around their
/// signing height: the list at or below it, and the next list up when that
/// one holds other ChainLock quorums.
pub struct ChainLockValidator<'a> {
    quorum_type: LLMQType,
    before: Option<&'a MasternodeList>,
    after: Option<&'a MasternodeList>,
}

impl Validator<&ChainLock> for ChainLockValidator<'_> {
    fn validate(&self, chain_lock: &ChainLock) -> ValidationResult<()> {
        self.verify(chain_lock).map_err(|e| {
            ValidationError::InvalidSignature(format!(
                "ChainLock signature verification failed for height {}: {e}",
                chain_lock.block_height
            ))
        })
    }
}

impl<'a> ChainLockValidator<'a> {
    /// `before` and `after` are the lists at or below the ChainLock's signing
    /// height and the next one above it.
    pub fn new(
        quorum_type: LLMQType,
        before: Option<&'a MasternodeList>,
        after: Option<&'a MasternodeList>,
    ) -> Self {
        Self {
            quorum_type,
            before,
            after,
        }
    }

    fn verify(&self, chain_lock: &ChainLock) -> Result<(), MessageVerificationError> {
        let request_id = chain_lock.request_id().map_err(|e| e.to_string())?;
        match (self.before, self.after) {
            (None, None) => Err(MessageVerificationError::NoMasternodeLists),
            (Some(list), None) | (None, Some(list)) => {
                self.verify_with_list(chain_lock, list, &request_id)
            }
            (Some(before), Some(after)) => {
                let Err(initial_error) = self.verify_with_list(chain_lock, before, &request_id)
                else {
                    return Ok(());
                };
                if before.quorums.get(&self.quorum_type) != after.quorums.get(&self.quorum_type) {
                    self.verify_with_list(chain_lock, after, &request_id)
                } else {
                    Err(initial_error)
                }
            }
        }
    }

    /// Verifies with the quorum of `masternode_list` that has the lowest
    /// ordering hash for the request id.
    fn verify_with_list(
        &self,
        chain_lock: &ChainLock,
        masternode_list: &MasternodeList,
        request_id: &QuorumSigningRequestId,
    ) -> Result<(), MessageVerificationError> {
        let quorum = masternode_list.quorum_for_request(self.quorum_type, request_id)?;

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
    use dashcore::ChainLock;

    #[test]
    fn chain_locks_verify_against_the_newest_list() {
        let engine = TestEngine::mainnet_fixture();
        let height = engine.latest_masternode_list().expect("height").known_height;
        assert_eq!(height, 2243493);

        let [chain_lock, next_chain_lock] = ChainLock::mainnet_fixture_pair();
        assert_eq!(
            hex::encode(chain_lock.request_id().expect("expected to make request id")),
            "969ab4a945632f5fba1331f3d2556d317682142cf8aaa6544e407e683c61a177"
        );
        engine.verify_chain_lock(&chain_lock).expect("expected to verify chain lock");

        // Another one, so the first was not a 1/4 fluke.
        assert_eq!(
            hex::encode(next_chain_lock.request_id().expect("expected to make request id")),
            "675aed91d6098cdf575cc09bfd1ff4f750acde1e793f385c3c72bbb400068d28"
        );
        engine.verify_chain_lock(&next_chain_lock).expect("expected to verify chain lock");
    }

    /// A genuine ChainLock replayed at a height signed by the newest list: its
    /// signature no longer matches the request id, and with no list above to
    /// retry against, that failure has to stand.
    #[test]
    fn a_chain_lock_replayed_above_the_newest_list_is_rejected() {
        let engine = TestEngine::mainnet_fixture();
        let newest = engine.latest_masternode_list().expect("newest").known_height;

        let [genuine, _] = ChainLock::mainnet_fixture_pair();
        let replayed = ChainLock {
            block_height: newest + 1_000,
            ..genuine
        };
        assert!(engine.verify_chain_lock(&replayed).is_err());
    }

    #[test]
    fn a_chain_lock_without_lists_is_rejected() {
        let [chain_lock, _] = ChainLock::mainnet_fixture_pair();
        assert!(TestEngine::empty(dashcore::Network::Mainnet)
            .verify_chain_lock(&chain_lock)
            .is_err());
    }
}
