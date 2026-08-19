use core::fmt::{Display, Formatter};

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use crate::prelude::CoreBlockHeight;
use crate::sml::quorum_validation_error::QuorumValidationError;
use crate::{BlockHash, QuorumHash};

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LLMQEntryVerificationSkipStatus {
    NotMarkedForVerification,
    MissedList(CoreBlockHeight),
    UnknownBlock(BlockHash),
    /// The snapshot required to validate this quorum entry was not provided
    /// by the caller. Distinct from `UnknownBlock` so retry/back-off logic
    /// can target snapshot fetches separately from block fetches.
    MissingSnapshot(BlockHash),
    /// The chain lock at the given height/block hash was not provided by the
    /// caller. The block itself may be known; the chain-lock signature for
    /// it just hasn't been fetched yet. Distinct from `UnknownBlock` so
    /// retry logic can dispatch to a chain-lock fetch instead of a block
    /// fetch.
    MissingChainLock(CoreBlockHeight, BlockHash),
    /// The quorum entry came through without an attached
    /// `VerifyingChainLockSignaturesType::Rotating`. Each of the four quarter
    /// signatures is looked up by the work height of its quarter in the
    /// `quorumsCLSigs` mapping the QRInfo's diffs carry, so a QRInfo that
    /// covers none of a quorum's quarter work blocks, or whose quorum hash
    /// heights are unknown, leaves the 4-sig tuple unpopulated.
    MissingRotationChainLockSigs(QuorumHash),
    /// A specific rotation chain-lock signature at offset `h - n` was not
    /// present for the masternode diff at the given block hash. The first
    /// field is the rotation offset, the second is the diff block hash.
    /// Distinct from `MissingRotationChainLockSigs`, which covers the case
    /// where the entire 4-sig tuple is absent.
    MissingRotationChainLockSig(u8, BlockHash),
    OtherContext(String),
    /// At least one of the quarter chain-lock signatures used to reconstruct
    /// this quorum was keyed by elimination rather than by a known quorum
    /// height, so a verification failure says nothing about the quorum data
    /// itself. Retry logic can resolve it by feeding the heights of the
    /// rotated quorum hashes the QRInfo carries.
    InferredRotationChainLockSigs(QuorumHash),
}

impl Display for LLMQEntryVerificationSkipStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            match self {
                LLMQEntryVerificationSkipStatus::NotMarkedForVerification => {
                    "NotMarkedForVerification".to_string()
                }
                LLMQEntryVerificationSkipStatus::MissedList(block_height) => {
                    format!("MissedList({})", block_height)
                }
                LLMQEntryVerificationSkipStatus::UnknownBlock(block_hash) => {
                    format!("UnknownBlock({})", block_hash)
                }
                LLMQEntryVerificationSkipStatus::MissingSnapshot(block_hash) => {
                    format!("MissingSnapshot({})", block_hash)
                }
                LLMQEntryVerificationSkipStatus::MissingChainLock(height, block_hash) => {
                    format!("MissingChainLock({}, {})", height, block_hash)
                }
                LLMQEntryVerificationSkipStatus::MissingRotationChainLockSigs(quorum_hash) => {
                    format!("MissingRotationChainLockSigs({})", quorum_hash)
                }
                LLMQEntryVerificationSkipStatus::MissingRotationChainLockSig(
                    offset,
                    block_hash,
                ) => {
                    format!("MissingRotationChainLockSig(h - {}, {})", offset, block_hash)
                }
                LLMQEntryVerificationSkipStatus::OtherContext(message) => {
                    format!("OtherContext({message})")
                }
                LLMQEntryVerificationSkipStatus::InferredRotationChainLockSigs(quorum_hash) => {
                    format!("InferredRotationChainLockSigs({})", quorum_hash)
                }
            }
            .as_str(),
        )
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LLMQEntryVerificationStatus {
    #[default]
    Unknown,
    Verified,
    Skipped(LLMQEntryVerificationSkipStatus),
    Invalid(QuorumValidationError),
}
impl From<QuorumValidationError> for LLMQEntryVerificationStatus {
    /// Classify a validation error as either `Skipped` (missing infrastructure
    /// data that the caller should have provided) or `Invalid` (the quorum
    /// data itself is genuinely bad).
    fn from(error: QuorumValidationError) -> Self {
        match error {
            QuorumValidationError::RequiredBlockNotPresent(block_hash, _) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::UnknownBlock(block_hash))
            }
            // `VerifyingMasternodeListNotPresent` is grouped here because the
            // verifying masternode list at the validation height is caller-
            // supplied infrastructure, not quorum data. Treating it as
            // `Skipped` mirrors the sibling `RequiredMasternodeListNotPresent`
            // case and lets the caller refetch instead of rejecting the quorum.
            QuorumValidationError::RequiredMasternodeListNotPresent(height)
            | QuorumValidationError::RequiredBlockHeightNotPresent(height)
            | QuorumValidationError::VerifyingMasternodeListNotPresent(height) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::MissedList(height))
            }
            QuorumValidationError::RequiredSnapshotNotPresent(hash) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::MissingSnapshot(hash))
            }
            QuorumValidationError::RequiredChainLockNotPresent(height, block_hash) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::MissingChainLock(height, block_hash))
            }
            QuorumValidationError::RequiredRotatedChainLockSigsNotPresent(quorum_hash) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::MissingRotationChainLockSigs(
                    quorum_hash,
                ))
            }
            QuorumValidationError::RequiredRotatedChainLockSigNotPresent(offset, block_hash) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::MissingRotationChainLockSig(
                    offset, block_hash,
                ))
            }
            // A cycle base sitting below the depth a rotation reconstruction
            // reaches back to means the quarter lists cannot exist yet. That
            // is missing history like its siblings above, so it degrades the
            // one quorum instead of rejecting everything served with it.
            QuorumValidationError::CycleBaseHeightTooLow(height) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::MissedList(height))
            }
            // The quorum index is not signature-covered, so a peer can rewrite
            // it, and an out-of-range index only means this engine cannot locate
            // the quorum's cycle from what it holds — a fresh QRInfo from an
            // honest peer resolves it. Classifying it `Skipped`, not `Invalid`,
            // keeps a tampered index from aborting `feed_qr_info` and wedging
            // masternode sync. This never marks the entry `Verified`, and the
            // rotated-cycle stores (`rotated_quorums_per_cycle`) still retain
            // only `Verified` entries. However, it does leave the entry
            // reachable through `quorum_entry_for_hash_at_or_before_height`
            // (masternode_list_engine/helpers.rs), which excludes only
            // `Invalid` entries and is the lookup dash-spv-ffi's
            // platform_integration uses to serve quorum public keys. That
            // lookup already serves `Skipped` entries routinely —
            // `Skipped(NotMarkedForVerification)` is the default status for
            // quorums entering a stored list — so this reclassification
            // neither creates that exposure nor widens it beyond entries
            // already present in stored lists. Tightening that lookup to
            // require `Verified` is a behavioral change deliberately left as
            // a follow-up. (#934)
            QuorumValidationError::InvalidQuorumIndex {
                quorum_hash,
                index,
            } => Self::Skipped(LLMQEntryVerificationSkipStatus::OtherContext(format!(
                "invalid quorum index {index} for {quorum_hash}"
            ))),
            other => Self::Invalid(other),
        }
    }
}

impl Display for LLMQEntryVerificationStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            match self {
                LLMQEntryVerificationStatus::Unknown => "unknown".to_string(),
                LLMQEntryVerificationStatus::Verified => "verified".to_string(),
                LLMQEntryVerificationStatus::Invalid(error) => format!("Invalid({error})"),
                LLMQEntryVerificationStatus::Skipped(reason) => format!("Skipped({reason})"),
            }
            .as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use hashes::Hash;

    use super::*;

    fn dummy_hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    #[test]
    fn from_quorum_validation_error_classifies_each_arm() {
        let h1 = dummy_hash(1);
        let h2 = dummy_hash(2);
        let h3 = dummy_hash(3);
        let h4 = dummy_hash(4);
        let h5 = dummy_hash(5);

        let cases: Vec<(QuorumValidationError, LLMQEntryVerificationStatus)> = vec![
            (
                QuorumValidationError::RequiredBlockNotPresent(h1, "ctx".to_string()),
                LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::UnknownBlock(h1),
                ),
            ),
            (
                QuorumValidationError::RequiredMasternodeListNotPresent(42),
                LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissedList(
                    42,
                )),
            ),
            (
                QuorumValidationError::RequiredBlockHeightNotPresent(99),
                LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissedList(
                    99,
                )),
            ),
            (
                QuorumValidationError::VerifyingMasternodeListNotPresent(123),
                LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissedList(
                    123,
                )),
            ),
            (
                QuorumValidationError::RequiredSnapshotNotPresent(h2),
                LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::MissingSnapshot(h2),
                ),
            ),
            (
                QuorumValidationError::RequiredChainLockNotPresent(7, h5),
                LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::MissingChainLock(7, h5),
                ),
            ),
            (
                QuorumValidationError::RequiredRotatedChainLockSigsNotPresent(h3),
                LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::MissingRotationChainLockSigs(h3),
                ),
            ),
            (
                QuorumValidationError::RequiredRotatedChainLockSigNotPresent(2, h4),
                LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::MissingRotationChainLockSig(2, h4),
                ),
            ),
            (
                QuorumValidationError::CycleBaseHeightTooLow(5),
                LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissedList(
                    5,
                )),
            ),
            // A wire-supplied quorum index is not signature-covered, so an
            // out-of-range one degrades the single quorum (Skipped), never
            // aborts the feed (Invalid).
            {
                let quorum_hash = crate::QuorumHash::from_byte_array([6; 32]);
                (
                    QuorumValidationError::InvalidQuorumIndex {
                        quorum_hash,
                        index: 42,
                    },
                    LLMQEntryVerificationStatus::Skipped(
                        LLMQEntryVerificationSkipStatus::OtherContext(format!(
                            "invalid quorum index {} for {}",
                            42, quorum_hash
                        )),
                    ),
                )
            },
            (
                QuorumValidationError::InvalidQuorumPublicKey,
                LLMQEntryVerificationStatus::Invalid(QuorumValidationError::InvalidQuorumPublicKey),
            ),
        ];

        for (error, expected) in cases {
            let actual: LLMQEntryVerificationStatus = error.clone().into();
            assert_eq!(actual, expected, "case: {error:?}");
        }
    }

    #[test]
    fn skip_status_display_formats_new_variants() {
        let h = dummy_hash(1);
        let cases: Vec<(LLMQEntryVerificationSkipStatus, String)> = vec![
            (LLMQEntryVerificationSkipStatus::MissingSnapshot(h), format!("MissingSnapshot({h})")),
            (
                LLMQEntryVerificationSkipStatus::MissingChainLock(42, h),
                format!("MissingChainLock(42, {h})"),
            ),
            (
                LLMQEntryVerificationSkipStatus::MissingRotationChainLockSigs(h),
                format!("MissingRotationChainLockSigs({h})"),
            ),
            (
                LLMQEntryVerificationSkipStatus::MissingRotationChainLockSig(2, h),
                format!("MissingRotationChainLockSig(h - 2, {h})"),
            ),
            (
                LLMQEntryVerificationSkipStatus::InferredRotationChainLockSigs(h),
                format!("InferredRotationChainLockSigs({h})"),
            ),
        ];

        for (status, expected) in cases {
            assert_eq!(status.to_string(), expected, "case: {status:?}");
        }
    }
}
