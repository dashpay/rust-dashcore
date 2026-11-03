//! The block the engine holds as final, and the trust in quorums it grants.
//!
//! A list is anchored once it sits at or below that block on the header chain,
//! and a quorum once an anchored list holds it. The anchor moves up with every
//! ChainLock an anchored quorum signs, from a compiled-in checkpoint, or on a
//! network without checkpoints from the first ChainLock a DIP-6 verified quorum
//! signs.

use super::helpers::QUORUM_WALK_BACK_ACTIVE_WINDOWS;
use crate::chain::CheckpointManager;
use crate::error::StorageResult;
use crate::sml_engine::{FeedError, MasternodeListEngine};
use crate::storage::BlockHeaderStorage;
use dashcore::bls_sig_utils::{BLSSignature, BlsScheme};
use dashcore::hashes::Hash;
use dashcore::network::message_sml::MnListDiff;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::error::SmlError;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::transaction::special_transaction::TransactionPayload;
use dashcore::{BlockHash, ChainLock, Network, QuorumHash};
use serde::{Deserialize, Serialize};

/// Where the chain of trust behind an anchor starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AnchorRoot {
    /// The compiled-in checkpoint at this height.
    Checkpoint(CoreBlockHeight),
    /// The first ChainLock a DIP-6 verified quorum signed, on a network
    /// without checkpoints.
    FirstChainLock,
}

impl AnchorRoot {
    /// Whether `network` starts trust from this root: a checkpoint trust may
    /// start at, or on a network without checkpoints, a first ChainLock.
    pub(crate) fn starts_trust_on(self, network: Network) -> bool {
        match self {
            AnchorRoot::Checkpoint(height) => may_root_at_checkpoint(network, height),
            AnchorRoot::FirstChainLock => trusts_first_chain_lock(network),
        }
    }
}

/// A block the engine holds as final, with the root its trust descends from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ChainLockAnchor {
    pub(crate) height: CoreBlockHeight,
    pub(crate) block_hash: BlockHash,
    pub(crate) root: AnchorRoot,
}

/// What [`MasternodeListEngine::accept_chain_lock`] made of a ChainLock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ChainLockVerdict {
    /// An anchored quorum signed it and its block is stored: the block is final.
    Accepted,
    /// An anchored quorum signed it, but its block is not stored yet.
    AwaitingHeader,
    /// Not decidable yet: the lists around its signing height are still
    /// coming, its signer is not anchored yet, the anchor's own block is not
    /// stored yet, or, before trust has a root, its signer is not DIP-6
    /// verified or it is too far below the tip.
    Deferred(String),
    /// It cannot be final: no ChainLock quorum was active at its signing
    /// height, its signer was not active there although the anchor covers that
    /// height, its signature does not verify, or its block conflicts with the
    /// stored one.
    Rejected(String),
}

/// What the anchored lists say about a quorum signing at a height.
#[derive(Clone, Debug)]
enum Vouched {
    /// It was active there, with its anchored entry.
    Active(Box<QualifiedQuorumEntry>),
    /// An anchored list holds exactly the quorums active there, and not it.
    Inactive,
    /// No anchored list says which quorums were active there, and none
    /// vouches for this one.
    Unknown,
}

#[cfg(test)]
impl Vouched {
    fn active(self) -> Option<QualifiedQuorumEntry> {
        match self {
            Vouched::Active(quorum) => Some(*quorum),
            Vouched::Inactive | Vouched::Unknown => None,
        }
    }
}

/// Whether `network` roots trust in its first ChainLock, for want of
/// compiled-in checkpoints.
pub(crate) fn trusts_first_chain_lock(network: Network) -> bool {
    matches!(network, Network::Regtest | Network::Devnet)
}

/// Whether trust may start at height `height`: a compiled-in checkpoint past
/// V20, whose coinbases carry ChainLocks. A checkpoint is the real header of
/// its block, so its masternode list is proven against the block's own merkle
/// root.
pub(crate) fn may_root_at_checkpoint(network: Network, height: CoreBlockHeight) -> bool {
    height >= network.v20_activation_height()
        && CheckpointManager::for_network(network)
            .last_checkpoint_before_height(height)
            .is_some_and(|checkpoint| checkpoint.height() == height)
}

/// The number of `llmq_type` mining windows with a block in `(from, to]`. Only
/// they can change the set of active `llmq_type` quorums.
pub(crate) fn mining_windows_between(
    llmq_type: LLMQType,
    from: CoreBlockHeight,
    to: CoreBlockHeight,
) -> u32 {
    if to <= from {
        return 0;
    }
    let interval = llmq_type.dkg_interval();
    if interval == 0 {
        return to - from;
    }
    // The window of cycle `c` spans `[c·interval + start, c·interval + end]`,
    // so it has a block in `(from, to]` when it ends above `from` and starts
    // at or below `to`.
    let window = llmq_type.dkg_window_at_cycle(0);
    let interval = i64::from(interval);
    let first = (i64::from(from) - i64::from(window.mining_end)).div_euclid(interval) + 1;
    let last = (i64::from(to) - i64::from(window.mining_start)).div_euclid(interval);
    u32::try_from((last - first + 1).max(0)).unwrap_or(u32::MAX)
}

/// Whether the `llmq_type` quorums of a list at `list_height` are the ones
/// active at `height`: no mining window has a block between the two.
fn holds_the_quorums_active_at(
    llmq_type: LLMQType,
    list_height: CoreBlockHeight,
    height: CoreBlockHeight,
) -> bool {
    mining_windows_between(llmq_type, list_height.min(height), list_height.max(height)) == 0
}

/// Whether a ChainLock at `height` is recent enough to root trust on a network
/// without checkpoints: the quorums active at it can still sign at the header
/// `tip`, so the anchor it starts can move up with the ChainLocks to come.
/// Without a stored tip there is nothing to be behind.
fn may_root_trust(
    chain_locks_type: LLMQType,
    height: CoreBlockHeight,
    tip: Option<CoreBlockHeight>,
) -> bool {
    tip.is_none_or(|tip| height.saturating_add(chain_locks_type.active_window()) >= tip)
}

/// The height and signature of the ChainLock the coinbase of the block at
/// `carrier_height` carries for its ancestor `bestCLHeightDiff + 1` blocks
/// below (DIP-29), read as Dash Core reads it for member selection. `None`
/// before CbTx v3, for a payload of another height, for the null signature of
/// a chain without ChainLocks yet, and for a height difference reaching below
/// genesis.
fn carried_chain_lock(
    diff: &MnListDiff,
    carrier_height: CoreBlockHeight,
) -> Option<(CoreBlockHeight, BLSSignature)> {
    let Some(TransactionPayload::CoinbasePayloadType(payload)) =
        &diff.coinbase_tx.special_transaction_payload
    else {
        return None;
    };
    let signature = payload.chain_lock_candidate(carrier_height)?;
    // Despite its name, the field holds `bestCLHeightDiff`.
    let height_diff = payload.best_cl_height?;
    let height = carrier_height.checked_sub(height_diff.checked_add(1)?)?;
    Some((height, signature))
}

impl<H: BlockHeaderStorage> MasternodeListEngine<H> {
    /// Sets the checkpoint the chain of trust starts from, if it is higher than
    /// the one set before.
    pub(crate) fn set_root_anchor(&mut self, anchor: ChainLockAnchor) {
        if self.root_anchor.is_none_or(|root| anchor.height > root.height) {
            self.root_anchor = Some(anchor);
        }
    }

    /// The best ChainLock accepted so far, as persisted for the next start.
    pub(crate) fn chain_lock_anchor(&self) -> Option<ChainLockAnchor> {
        self.chain_lock_anchor
    }

    /// Restores a persisted anchor if its root is one this network starts
    /// trust from: a checkpoint trust may start at, or on a network without
    /// checkpoints, a first ChainLock.
    pub(crate) fn restore_chain_lock_anchor(&mut self, anchor: ChainLockAnchor) {
        if !anchor.root.starts_trust_on(self.network) {
            tracing::warn!(
                "Ignoring the persisted ChainLock anchor at {}: {:?} roots no trust on {}",
                anchor.height,
                anchor.root,
                self.network
            );
            return;
        }
        if self.chain_lock_anchor.is_none_or(|current| anchor.height > current.height) {
            self.chain_lock_anchor = Some(anchor);
        }
    }

    /// The highest anchor whose block the header chain holds at its height.
    /// Below one whose header is not stored yet the chain may still be made
    /// of any headers, so it waits for its header.
    pub(crate) async fn usable_anchor(&self) -> Option<ChainLockAnchor> {
        let mut candidates: Vec<_> =
            [self.chain_lock_anchor, self.root_anchor].into_iter().flatten().collect();
        candidates.sort_by_key(|anchor| std::cmp::Reverse(anchor.height));
        for anchor in candidates {
            if self.stored_hash_is(anchor.height, anchor.block_hash).await {
                return Some(anchor);
            }
        }
        None
    }

    /// Whether the header chain holds `block_hash` at `height`. A header
    /// storage that cannot be read vouches for nothing, which only ever takes
    /// trust away; the error is logged.
    async fn stored_hash_is(&self, height: CoreBlockHeight, block_hash: BlockHash) -> bool {
        match self.hash_at(height).await {
            Ok(stored) => stored == Some(block_hash),
            Err(e) => {
                tracing::warn!("Could not look up the block at {height}: {e}");
                false
            }
        }
    }

    /// Whether `list` is at or below `anchor`, on the header chain. Fails when
    /// the header storage cannot be read.
    async fn try_is_anchored(
        &self,
        list: &MasternodeList,
        anchor: &ChainLockAnchor,
    ) -> StorageResult<bool> {
        Ok(list.known_height <= anchor.height
            && self.hash_at(list.known_height).await? == Some(list.block_hash))
    }

    /// Forgets an accepted ChainLock whose height the header chain holds
    /// another block at. It cannot be final there, so trust falls back to
    /// what is below it.
    async fn forget_conflicting_anchor(&mut self) {
        let Some(anchor) = self.chain_lock_anchor else {
            return;
        };
        // Only a block the header chain holds there tells the anchor apart;
        // an unreadable storage says nothing about it.
        if self
            .hash_at(anchor.height)
            .await
            .is_ok_and(|hash| hash.is_some_and(|hash| hash != anchor.block_hash))
        {
            tracing::error!(
                "The header chain holds another block than the ChainLock anchor {} at {}, forgetting the anchor",
                anchor.block_hash,
                anchor.height
            );
            self.chain_lock_anchor = None;
        }
    }

    /// [`Self::try_is_anchored`], with a header storage that cannot be read
    /// vouching for nothing.
    async fn is_anchored(&self, list: &MasternodeList, anchor: &ChainLockAnchor) -> bool {
        list.known_height <= anchor.height
            && self.stored_hash_is(list.known_height, list.block_hash).await
    }

    /// The newest list at or below `height` that the usable anchor covers.
    pub(crate) async fn latest_anchored_list(
        &self,
        height: CoreBlockHeight,
    ) -> Option<&MasternodeList> {
        let anchor = self.usable_anchor().await?;
        self.newest_anchored_list(height, &anchor).await
    }

    async fn newest_anchored_list(
        &self,
        height: CoreBlockHeight,
        anchor: &ChainLockAnchor,
    ) -> Option<&MasternodeList> {
        self.try_newest_anchored_list(height, anchor).await.unwrap_or_else(|e| {
            tracing::warn!("Could not read the header chain for an anchored list: {e}");
            None
        })
    }

    async fn try_newest_anchored_list(
        &self,
        height: CoreBlockHeight,
        anchor: &ChainLockAnchor,
    ) -> StorageResult<Option<&MasternodeList>> {
        for (_, list) in self.masternode_lists.range(..=height.min(anchor.height)).rev() {
            if self.try_is_anchored(list, anchor).await? {
                return Ok(Some(list));
            }
        }
        Ok(None)
    }

    /// The quorum as the newest anchored list at or below `height` holding it
    /// has it, with that list. Like
    /// [`Self::quorum_entry_for_hash_at_or_before_height`] the walk goes back
    /// `QUORUM_WALK_BACK_ACTIVE_WINDOWS` and skips `Invalid` entries. The entry
    /// comes from the anchored list, never from a list above the anchor, which
    /// may carry another commitment under the same hash.
    pub(crate) async fn anchored_quorum(
        &self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
        height: CoreBlockHeight,
    ) -> Option<(&MasternodeList, &QualifiedQuorumEntry)> {
        let anchor = self.usable_anchor().await?;
        let top = height.min(anchor.height);
        let floor = top.saturating_sub(
            llmq_type.active_window().saturating_mul(QUORUM_WALK_BACK_ACTIVE_WINDOWS),
        );
        for (_, list) in self.masternode_lists.range(floor..=top).rev() {
            let Some(quorum) =
                list.quorum_entry_of_type_for_quorum_hash(llmq_type, quorum_hash).filter(
                    |quorum| !matches!(quorum.verified, LLMQEntryVerificationStatus::Invalid(_)),
                )
            else {
                continue;
            };
            if self.is_anchored(list, &anchor).await {
                return Some((list, quorum));
            }
        }
        None
    }

    /// The entry of `quorum_hash` in the anchored list that vouches for it as
    /// an active `llmq_type` quorum at `height`:
    /// - an anchored list around `height` whose `llmq_type` quorums are the
    ///   ones active there vouches for all of them. The two lists around it
    ///   hold those when they hold the same quorums, since a commitment only
    ///   adds a quorum no list held before; that counts only when both are
    ///   anchored, as a list above the anchor can copy the set of the one below;
    /// - the first list above `height`, if anchored, vouches for all of its
    ///   quorums: one still active there and mined before `height` was active
    ///   at it, and one mined after is newer than any `height` retired;
    /// - the newest anchored list below `height` vouches for those of its
    ///   quorums `height` cannot have retired. Each mining window in between
    ///   adds at most one quorum, and once more than `active` are known the
    ///   oldest retire. A quorum whose base block is below the stored chain is
    ///   older than every other, but cannot be aged against its like, so it is
    ///   vouched for only while fewer than `active` windows passed above the
    ///   stored chain's start, by when it is retired.
    ///
    /// Only an anchored list that holds exactly the quorums active at `height`
    /// can tell that one was not active there.
    async fn anchored_signer(
        &self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
        height: CoreBlockHeight,
        anchor: &ChainLockAnchor,
    ) -> StorageResult<Vouched> {
        let (before, after) = self.masternode_lists_around_height(height);
        let before = match before {
            Some(list) if self.try_is_anchored(list, anchor).await? => Some(list),
            _ => None,
        };
        let after = match after {
            Some(list) if self.try_is_anchored(list, anchor).await? => Some(list),
            _ => None,
        };
        let same_quorums = before.zip(after).is_some_and(|(before, after)| {
            before.quorums.get(&llmq_type) == after.quorums.get(&llmq_type)
        });
        for list in [before, after].into_iter().flatten() {
            if same_quorums || holds_the_quorums_active_at(llmq_type, list.known_height, height) {
                return Ok(list
                    .quorum_entry_of_type_for_quorum_hash(llmq_type, quorum_hash)
                    .map_or(Vouched::Inactive, |quorum| {
                        Vouched::Active(Box::new(quorum.clone()))
                    }));
            }
        }
        if let Some(quorum) =
            after.and_then(|list| list.quorum_entry_of_type_for_quorum_hash(llmq_type, quorum_hash))
        {
            return Ok(Vouched::Active(Box::new(quorum.clone())));
        }

        let Some(list) = self.try_newest_anchored_list(height, anchor).await? else {
            return Ok(Vouched::Unknown);
        };
        let Some(quorum) = list.quorum_entry_of_type_for_quorum_hash(llmq_type, quorum_hash) else {
            return Ok(Vouched::Unknown);
        };
        let active = llmq_type.active_quorum_count();
        let held: Vec<QuorumHash> = list
            .quorums
            .get(&llmq_type)
            .map(|quorums| quorums.keys().copied().collect())
            .unwrap_or_default();
        let crossed = mining_windows_between(llmq_type, list.known_height, height);
        let retired = (held.len() as u32).saturating_add(crossed).saturating_sub(active);
        let vouched = |active: bool| {
            if active {
                Vouched::Active(Box::new(quorum.clone()))
            } else {
                Vouched::Unknown
            }
        };
        if retired == 0 {
            return Ok(vouched(true));
        }
        let Some(base) = self.height_of(&quorum_hash).await? else {
            let start = self.headers.read().await.get_start_height().await.unwrap_or(0);
            return Ok(vouched(mining_windows_between(llmq_type, start, height) < active));
        };
        let mut older = 0;
        for other in &held {
            if self.height_of(other).await?.is_none_or(|other_base| other_base < base) {
                older += 1;
            }
        }
        Ok(vouched(older >= retired))
    }

    /// Whether the usable anchor, or no anchor at all, lets `selected`, a
    /// quorum DIP-8 selects for `chain_lock`, have signed it. With an anchor,
    /// it must be anchored as active at the signing height, and its anchored
    /// entry's key verifies. With none known, on a network without
    /// checkpoints, a DIP-6 verified quorum may root trust.
    async fn verify_signed_by(
        &self,
        chain_lock: &ChainLock,
        selected: &QualifiedQuorumEntry,
        anchor: Option<&ChainLockAnchor>,
    ) -> Result<(), ChainLockVerdict> {
        let chain_locks_type = self.network.chain_locks_type();
        let signing_height = chain_lock.signing_height();
        let quorum_hash = selected.quorum_entry.quorum_hash;
        let signer = match anchor {
            Some(anchor) => {
                match self
                    .anchored_signer(chain_locks_type, quorum_hash, signing_height, anchor)
                    .await
                {
                    Ok(Vouched::Active(signer)) => *signer,
                    Ok(Vouched::Inactive) if signing_height <= anchor.height => {
                        return Err(ChainLockVerdict::Rejected(format!(
                            "its signing quorum {quorum_hash} was not active at {signing_height}"
                        )));
                    }
                    // A list holding the quorums active there may still come,
                    // or the anchor may yet cover one.
                    Ok(_) => {
                        return Err(ChainLockVerdict::Deferred(format!(
                            "its signing quorum {quorum_hash} is not anchored at {}",
                            anchor.height
                        )));
                    }
                    Err(e) => {
                        return Err(ChainLockVerdict::Deferred(format!(
                            "the header chain could not be read: {e}"
                        )))
                    }
                }
            }
            None if self.chain_lock_anchor.is_some() || self.root_anchor.is_some() => {
                return Err(ChainLockVerdict::Deferred(
                    "the anchor's block is not stored yet".to_string(),
                ));
            }
            None if trusts_first_chain_lock(self.network) => {
                if selected.verified != LLMQEntryVerificationStatus::Verified {
                    return Err(ChainLockVerdict::Deferred(format!(
                        "its signing quorum {quorum_hash} is {}",
                        selected.verified
                    )));
                }
                let tip = self.headers.read().await.get_tip_height().await;
                if !may_root_trust(chain_locks_type, chain_lock.block_height, tip) {
                    return Err(ChainLockVerdict::Deferred(
                        "too far below the tip to root trust in".to_string(),
                    ));
                }
                selected.clone()
            }
            None => {
                return Err(ChainLockVerdict::Deferred("no anchor to verify against".to_string()))
            }
        };

        let sign_id = chain_lock
            .sign_id(chain_locks_type, quorum_hash, None)
            .map_err(|e| ChainLockVerdict::Rejected(format!("no sign id: {e}")))?;
        signer
            .verify_message_digest(sign_id.to_byte_array(), chain_lock.signature, BlsScheme::Modern)
            .map_err(|e| ChainLockVerdict::Rejected(e.to_string()))
    }

    /// Verifies `chain_lock` and, once it is final, raises the anchor to it.
    ///
    /// The signing quorum is the one DIP-8 selects among those active at
    /// `height − 8`, read from a list holding exactly that set, or from both
    /// lists around it when a ChainLock quorum was mined between them. It must
    /// be anchored, see [`Self::verify_signed_by`].
    pub(crate) async fn accept_chain_lock(&mut self, chain_lock: &ChainLock) -> ChainLockVerdict {
        self.forget_conflicting_anchor().await;
        let chain_locks_type = self.network.chain_locks_type();
        let signing_height = chain_lock.signing_height();
        let request_id = match chain_lock.request_id() {
            Ok(request_id) => request_id,
            Err(e) => return ChainLockVerdict::Rejected(format!("no request id: {e}")),
        };

        let (before, after) = self.masternode_lists_around_height(signing_height);
        let same_quorums = before.zip(after).is_some_and(|(before, after)| {
            before.quorums.get(&chain_locks_type) == after.quorums.get(&chain_locks_type)
        });
        let exact: Vec<&MasternodeList> = [before, after]
            .into_iter()
            .flatten()
            .filter(|list| {
                same_quorums
                    || holds_the_quorums_active_at(
                        chain_locks_type,
                        list.known_height,
                        signing_height,
                    )
            })
            .collect();
        let lists = if !exact.is_empty() {
            exact
        } else if after.is_none() && before.is_some() {
            // Lists are only ever added on top of the newest one, so a list
            // holding exactly those quorums may still come.
            return ChainLockVerdict::Deferred(format!(
                "no list holds the ChainLock quorums active at {signing_height} yet"
            ));
        } else {
            // A ChainLock quorum was mined between the two, before or after the
            // signing height, so one of them holds the quorums active at it.
            [before, after].into_iter().flatten().collect()
        };
        let mut candidates: Vec<QualifiedQuorumEntry> = Vec::new();
        for list in lists {
            if let Ok(selected) = list.quorum_for_request(chain_locks_type, &request_id) {
                let quorum_hash = selected.quorum_entry.quorum_hash;
                if candidates
                    .iter()
                    .all(|candidate| candidate.quorum_entry.quorum_hash != quorum_hash)
                {
                    candidates.push(selected.clone());
                }
            }
        }

        let anchor = self.usable_anchor().await;
        let (mut deferred, mut rejected) = (None, None);
        let mut verified = false;
        for selected in &candidates {
            match self.verify_signed_by(chain_lock, selected, anchor.as_ref()).await {
                Ok(()) => {
                    verified = true;
                    break;
                }
                Err(verdict @ ChainLockVerdict::Deferred(_)) => {
                    deferred = deferred.or(Some(verdict))
                }
                Err(verdict) => rejected = rejected.or(Some(verdict)),
            }
        }
        if !verified {
            // One that may still verify outweighs one that never will.
            return deferred.or(rejected).unwrap_or_else(|| {
                ChainLockVerdict::Rejected(format!(
                    "no ChainLock quorum is active at {signing_height}"
                ))
            });
        }

        match self.hash_at(chain_lock.block_height).await {
            Err(e) => {
                return ChainLockVerdict::Deferred(format!(
                    "the block at {} could not be read: {e}",
                    chain_lock.block_height
                ))
            }
            Ok(None) => return ChainLockVerdict::AwaitingHeader,
            Ok(Some(stored)) if stored != chain_lock.block_hash => {
                return ChainLockVerdict::Rejected(format!(
                    "the header chain holds {stored} at {}, not the locked block",
                    chain_lock.block_height
                ))
            }
            Ok(Some(_)) => {}
        }

        let higher = |current: Option<ChainLockAnchor>| {
            current.is_none_or(|current| chain_lock.block_height > current.height)
        };
        if higher(anchor) && higher(self.chain_lock_anchor) {
            self.chain_lock_anchor = Some(ChainLockAnchor {
                height: chain_lock.block_height,
                block_hash: chain_lock.block_hash,
                root: anchor.map_or(AnchorRoot::FirstChainLock, |anchor| anchor.root),
            });
        }
        ChainLockVerdict::Accepted
    }

    /// The ChainLock the coinbase of `diff`'s block carries for its ancestor,
    /// with the locked block read from the header chain, once the stored header
    /// of that block proves the coinbase, as for any list the engine builds.
    /// `None` when it carries none for a stored block. Refused when the header
    /// chain does not hold the block or does not prove the coinbase, and fails
    /// when the header storage cannot be read, which says nothing about the
    /// coinbase.
    pub(crate) async fn proven_coinbase_chain_lock(
        &self,
        diff: &MnListDiff,
    ) -> Result<Option<ChainLock>, FeedError<SmlError>> {
        let carrier_height = self.required_height_of(&diff.block_hash).await?;
        if let Some(validator) = &self.validator {
            validator.validate_coinbase_proof(diff, carrier_height).await?;
        }
        let Some((block_height, signature)) = carried_chain_lock(diff, carrier_height) else {
            return Ok(None);
        };
        Ok(self.hash_at(block_height).await?.map(|block_hash| ChainLock {
            block_height,
            block_hash,
            signature,
        }))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use crate::sml_engine::test_support::{quorum_entry, TestEngine};
    use crate::sml_engine::{AnchorRoot, ChainLockAnchor};
    use dash_pkc::bls::{BlsScIetf, BlsSecretKey};
    use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
    use dashcore::hashes::Hash;
    use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
    use dashcore::sml::llmq_type::network::NetworkLLMQExt;
    use dashcore::sml::llmq_type::{LLMQType, LLMQ_SIGN_HEIGHT_OFFSET};
    use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
    use dashcore::{BlockHash, ChainLock, InstantLock, QuorumHash};

    /// The DKG interval and mining window offsets of an LLMQ type.
    #[derive(Clone, Copy)]
    pub(crate) struct Dkg {
        pub(crate) interval: u32,
        pub(crate) mining_window_start: u32,
        pub(crate) mining_window_end: u32,
    }

    pub(crate) fn dkg(llmq_type: LLMQType) -> Dkg {
        let window = llmq_type.dkg_window_at_cycle(0);
        Dkg {
            interval: llmq_type.dkg_interval(),
            mining_window_start: window.mining_start,
            mining_window_end: window.mining_end,
        }
    }

    /// Roots trust at the engine's newest list, as a checkpoint there would.
    pub(crate) fn anchor_at_newest_list(engine: &mut TestEngine) {
        let newest = engine.latest_masternode_list().expect("a list to anchor at");
        let anchor = ChainLockAnchor {
            height: newest.known_height,
            block_hash: newest.block_hash,
            root: AnchorRoot::Checkpoint(newest.known_height),
        };
        engine.set_root_anchor(anchor);
    }

    /// An IS lock of the mainnet fixture's cycle, signed by its quorum at index 23.
    pub(crate) fn mainnet_fixture_is_lock() -> InstantLock {
        dashcore::consensus::deserialize(&hex_conservative::decode_to_vec("01018d53e7997ead57409750942af0d5e0aafc06f852a9a52308f4781b6a8220298f00000000c6f9d8c63dd15937ea70aaddb7890daad42c91bf6818e2bf76d183d6f2d9215b4b5f84978fad9dde7ab52bdcc0674be891e9029cc1ef0cb01200000000000000a27c98836c4c04653ab81eb4e07ddfc2c8c2c1036b75247969c05a4f25451cd78913a971f1899d9f2bddec9cf8e0104004f72f20c2856453e5aa3bcd2a8200670ec28feda38f67cc400fc72ef1966956656ec0765478c9d16e9a9e470c07f9ed").unwrap()).unwrap()
    }

    /// The root of an anchor persisted on `network`: its newest checkpoint
    /// trust may start at.
    pub(crate) fn checkpoint_root(network: dashcore::Network) -> AnchorRoot {
        let checkpoints = crate::chain::CheckpointManager::for_network(network);
        let height = checkpoints
            .checkpoints()
            .map(|checkpoint| checkpoint.height())
            .filter(|height| crate::sml_engine::may_root_at_checkpoint(network, *height))
            .last()
            .expect("a checkpoint trust may start at");
        AnchorRoot::Checkpoint(height)
    }

    /// Roots trust at the engine's newest list at or below `height`.
    pub(crate) fn anchor_at_newest_list_below(engine: &mut TestEngine, height: u32) {
        let (_, list) = engine.masternode_lists.range(..=height).next_back().expect("a list");
        let anchor = ChainLockAnchor {
            height: list.known_height,
            block_hash: list.block_hash,
            root: AnchorRoot::Checkpoint(list.known_height),
        };
        engine.set_root_anchor(anchor);
    }

    /// The block a forger made up at `height`.
    fn forged_block(height: u32) -> BlockHash {
        let mut bytes = [0xf0; 32];
        bytes[..4].copy_from_slice(&height.to_le_bytes());
        BlockHash::from_byte_array(bytes)
    }

    /// The secret only the test holds, behind every forged quorum.
    fn forger_secret() -> BlsSecretKey<BlsScIetf> {
        BlsSecretKey::from_ikm(&[7; 32]).expect("valid key material")
    }

    /// A ChainLock quorum keyed by the forger's secret, `Verified` as DIP-6
    /// would mark it against members from a list the forger made up.
    pub(crate) fn forged_chain_lock_quorum(
        chain_locks_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> QualifiedQuorumEntry {
        let mut entry = quorum_entry(chain_locks_type, quorum_hash, None);
        entry.quorum_public_key = BLSPublicKey::from(forger_secret().public_key().to_bytes());
        let mut quorum: QualifiedQuorumEntry = entry.into();
        quorum.verified = LLMQEntryVerificationStatus::Verified;
        quorum
    }

    /// Puts a list ten blocks above the engine's newest one, on headers no
    /// ChainLock covers, holding a new forged ChainLock quorum whose hash is
    /// ground so DIP-8 selection picks it. Returns the ChainLock that quorum
    /// signs for the block eight above that list, so selection reads the
    /// forged list.
    pub(crate) fn forge_chain_lock_above_the_newest_list(engine: &mut TestEngine) -> ChainLock {
        let chain_locks_type = engine.network().chain_locks_type();
        let newest = engine.latest_masternode_list().expect("a list to build on").clone();
        let list_height = newest.known_height + 10;
        let list_hash = forged_block(list_height);
        let mut chain_lock = ChainLock {
            block_height: list_height + LLMQ_SIGN_HEIGHT_OFFSET,
            block_hash: forged_block(list_height + LLMQ_SIGN_HEIGHT_OFFSET),
            signature: BLSSignature::from([0; 96]),
        };
        let request_id = chain_lock.request_id().expect("request id");

        let (list, quorum_hash) = (1..=u8::MAX)
            .find_map(|byte| {
                let quorum_hash = QuorumHash::from_byte_array([byte; 32]);
                if newest
                    .quorum_entry_of_type_for_quorum_hash(chain_locks_type, quorum_hash)
                    .is_some()
                {
                    return None;
                }
                let mut list = newest.clone();
                list.block_hash = list_hash;
                list.known_height = list_height;
                Arc::make_mut(&mut list.quorums).entry(chain_locks_type).or_default().insert(
                    quorum_hash,
                    Arc::new(forged_chain_lock_quorum(chain_locks_type, quorum_hash)),
                );
                let selected = list.quorum_for_request(chain_locks_type, &request_id).ok()?;
                (selected.quorum_entry.quorum_hash == quorum_hash).then_some((list, quorum_hash))
            })
            .expect("a ground hash that selection picks");

        engine.feed_block_height(list_height, list_hash);
        engine.feed_block_height(chain_lock.block_height, chain_lock.block_hash);
        engine.masternode_lists.insert(list_height, list);

        chain_lock.signature = sign_as_forger(&chain_lock, chain_locks_type, quorum_hash);
        chain_lock
    }

    /// The signature a forged quorum `quorum_hash` gives `chain_lock`.
    pub(crate) fn sign_as_forger(
        chain_lock: &ChainLock,
        chain_locks_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> BLSSignature {
        let sign_id = chain_lock.sign_id(chain_locks_type, quorum_hash, None).expect("sign id");
        BLSSignature::from(forger_secret().sign_digest(&sign_id.to_byte_array()).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::test_support::{
        anchor_at_newest_list, anchor_at_newest_list_below, checkpoint_root, dkg,
        forge_chain_lock_above_the_newest_list, forged_chain_lock_quorum, sign_as_forger,
    };
    use super::*;
    use crate::sml_engine::test_support::{quorum_entry, TestEngine};
    use dashcore::consensus::deserialize;
    use dashcore::hash_types::QuorumOrderingHash;
    use dashcore::sml::llmq_type::LLMQ_SIGN_HEIGHT_OFFSET;
    use dashcore::sml::masternode_list::MasternodeList;
    use test_case::test_case;

    #[tokio::test]
    async fn a_chain_lock_an_anchored_quorum_signs_raises_the_anchor() {
        let mut engine = TestEngine::mainnet_fixture();
        anchor_at_newest_list(&mut engine);
        let root = engine.usable_anchor().await.expect("anchored").root;

        for chain_lock in ChainLock::mainnet_fixture_pair() {
            engine.feed_block_height(chain_lock.block_height, chain_lock.block_hash);
            assert_eq!(engine.accept_chain_lock(&chain_lock).await, ChainLockVerdict::Accepted);
            assert_eq!(
                engine.usable_anchor().await,
                Some(ChainLockAnchor {
                    height: chain_lock.block_height,
                    block_hash: chain_lock.block_hash,
                    root,
                })
            );
        }
    }

    /// The anchor is persisted at once while headers flush later, so after a
    /// crash it can sit above the stored chain. Until its block is stored the
    /// chain below it may be made of any headers, so trust stays at what is
    /// below; another block at its height means it was never final there.
    #[tokio::test]
    async fn an_anchor_above_the_stored_chain_waits_for_its_block() {
        let mut engine = TestEngine::mainnet_fixture();
        anchor_at_newest_list(&mut engine);
        let root = engine.usable_anchor().await.expect("anchored");
        let ahead = ChainLockAnchor {
            height: root.height + 100,
            block_hash: BlockHash::from_byte_array([0xab; 32]),
            root: checkpoint_root(Network::Mainnet),
        };
        engine.restore_chain_lock_anchor(ahead);
        assert_eq!(engine.usable_anchor().await, Some(root), "its block is not stored yet");

        engine.feed_block_height(ahead.height, ahead.block_hash);
        assert_eq!(engine.usable_anchor().await, Some(ahead));

        engine.forget_block(&ahead.block_hash);
        engine.feed_block_height(ahead.height, BlockHash::from_byte_array([0xcd; 32]));
        assert_eq!(engine.usable_anchor().await, Some(root), "another block at its height");
        let undecidable = ChainLock {
            block_height: ahead.height + 1_000,
            ..ChainLock::mainnet_fixture_pair()[0]
        };
        assert!(matches!(
            engine.accept_chain_lock(&undecidable).await,
            ChainLockVerdict::Deferred(_)
        ));
        assert_eq!(engine.chain_lock_anchor(), None, "the conflicting anchor is forgotten");
    }

    /// On a network with checkpoints, nothing is trusted before a checkpoint
    /// roots it, however the quorum DIP-6 marked.
    #[tokio::test]
    async fn without_an_anchor_a_mainnet_chain_lock_is_not_accepted() {
        let mut engine = TestEngine::mainnet_fixture();
        let [chain_lock, _] = ChainLock::mainnet_fixture_pair();

        assert!(matches!(
            engine.accept_chain_lock(&chain_lock).await,
            ChainLockVerdict::Deferred(_)
        ));
        assert_eq!(engine.usable_anchor().await, None);
    }

    /// A list above the anchor proves nothing, so the quorum a peer minted in
    /// it signs no ChainLock, and its list is not anchored, until a ChainLock
    /// an anchored quorum signs covers it.
    #[tokio::test]
    async fn a_quorum_minted_above_the_anchor_does_not_sign() {
        let mut engine = TestEngine::mainnet_fixture();
        anchor_at_newest_list(&mut engine);
        let anchor = engine.usable_anchor().await;
        let forged = forge_chain_lock_above_the_newest_list(&mut engine);

        assert!(matches!(engine.accept_chain_lock(&forged).await, ChainLockVerdict::Deferred(_)));
        assert_eq!(engine.usable_anchor().await, anchor);
        assert_eq!(
            engine.latest_anchored_list(u32::MAX).await.map(|list| list.known_height),
            anchor.map(|anchor| anchor.height)
        );
    }

    /// A list above the anchor proves nothing, so the quorum a peer minted in
    /// it does not resolve as anchored.
    #[tokio::test]
    async fn a_quorum_minted_above_the_anchor_does_not_resolve() {
        let mut engine = TestEngine::mainnet_fixture();
        anchor_at_newest_list(&mut engine);
        let forged = forge_chain_lock_above_the_newest_list(&mut engine);
        let chain_locks_type = engine.network().chain_locks_type();
        let forged_list = engine.latest_masternode_list().expect("the forged list").clone();
        let request_id = forged.request_id().expect("request id");
        let minted = forged_list
            .quorum_for_request(chain_locks_type, &request_id)
            .expect("selected")
            .quorum_entry
            .quorum_hash;

        assert!(engine.anchored_quorum(chain_locks_type, minted, u32::MAX).await.is_none());
    }

    /// A list above the anchor can carry another commitment under the hash of
    /// an anchored quorum. The anchored entry, and its key, is the one used.
    #[tokio::test]
    async fn an_unanchored_list_cannot_swap_the_key_of_an_anchored_quorum() {
        let mut engine = TestEngine::mainnet_fixture();
        anchor_at_newest_list(&mut engine);
        let chain_locks_type = engine.network().chain_locks_type();
        let mut list = engine.latest_masternode_list().expect("anchored list").clone();
        let (quorum_hash, genuine) = list.quorums[&chain_locks_type]
            .iter()
            .next()
            .map(|(hash, quorum)| (*hash, quorum.quorum_entry.quorum_public_key))
            .expect("a ChainLock quorum");

        let mut swapped = quorum_entry(chain_locks_type, quorum_hash, None);
        swapped.quorum_public_key = dashcore::bls_sig_utils::BLSPublicKey::from([9; 48]);
        let height = list.known_height + 1;
        list.known_height = height;
        list.block_hash = BlockHash::from_byte_array([0xee; 32]);
        Arc::make_mut(&mut list.quorums)
            .get_mut(&chain_locks_type)
            .expect("ChainLock quorums")
            .insert(quorum_hash, Arc::new(swapped.into()));
        engine.feed_block_height(height, list.block_hash);
        engine.masternode_lists.insert(height, list);

        let (anchored_list, quorum) = engine
            .anchored_quorum(chain_locks_type, quorum_hash, u32::MAX)
            .await
            .expect("the anchored entry");
        assert_eq!(quorum.quorum_entry.quorum_public_key, genuine);
        assert!(anchored_list.known_height < height);
    }

    /// Each ChainLock mining window between the newest anchored list and the
    /// signing height may retire that list's oldest quorum, so a list with no
    /// exact anchored list around the signing height vouches only for its
    /// newest `active − windows` quorums.
    #[tokio::test]
    async fn an_anchored_quorum_the_crossed_windows_may_have_retired_does_not_sign() {
        let chain_locks_type = Network::Mainnet.chain_locks_type();
        let interval = dkg(chain_locks_type).interval;
        let window_end = dkg(chain_locks_type).mining_window_end;
        let anchored_height = 100 * interval + window_end + 1;
        let mut engine = TestEngine::dummy_with_lists(&[anchored_height]);
        let bases = [97, 98, 99, 100].map(|cycle| cycle * interval);
        let hashes = bases.map(|base| BlockHash::from_byte_array([base as u8 + 1; 32]));
        {
            let list = engine.masternode_lists.get_mut(&anchored_height).expect("the list");
            let quorums = Arc::make_mut(&mut list.quorums).entry(chain_locks_type).or_default();
            for hash in hashes {
                let quorum_hash = QuorumHash::from_byte_array(hash.to_byte_array());
                quorums.insert(
                    quorum_hash,
                    Arc::new(quorum_entry(chain_locks_type, quorum_hash, None).into()),
                );
            }
        }
        for (base, hash) in bases.into_iter().zip(hashes) {
            engine.feed_block_height(base, hash);
        }
        anchor_at_newest_list(&mut engine);
        let anchor = engine.usable_anchor().await.expect("anchored");
        let signing_height = 101 * interval + window_end + 1;
        let [oldest, .., newest] =
            hashes.map(|hash| QuorumHash::from_byte_array(hash.to_byte_array()));

        assert!(engine
            .anchored_signer(chain_locks_type, oldest, signing_height, &anchor)
            .await
            .unwrap()
            .active()
            .is_none());
        assert!(engine
            .anchored_signer(chain_locks_type, newest, signing_height, &anchor)
            .await
            .unwrap()
            .active()
            .is_some());
        assert!(engine
            .anchored_signer(chain_locks_type, oldest, anchored_height + 1, &anchor)
            .await
            .unwrap()
            .active()
            .is_some());
    }

    /// Regtest and devnet have no checkpoints, so the first ChainLock a DIP-6
    /// verified quorum signs roots trust there. After that a quorum has to be
    /// anchored like anywhere else.
    #[tokio::test]
    async fn the_first_verified_chain_lock_roots_trust_where_there_are_no_checkpoints() {
        let mut engine = TestEngine::knowing(Network::Regtest, Default::default());
        let base = 1_000;
        engine.feed_block_height(base, BlockHash::dummy(base));
        engine.masternode_lists.insert(
            base,
            dashcore::sml::masternode_list::MasternodeList::empty(BlockHash::dummy(base), base),
        );
        let first = forge_chain_lock_above_the_newest_list(&mut engine);

        assert_eq!(engine.accept_chain_lock(&first).await, ChainLockVerdict::Accepted);
        let anchor = engine.usable_anchor().await.expect("rooted");
        assert_eq!(anchor.root, AnchorRoot::FirstChainLock);
        assert_eq!(anchor.height, first.block_height);

        let second = forge_chain_lock_above_the_newest_list(&mut engine);
        assert!(matches!(engine.accept_chain_lock(&second).await, ChainLockVerdict::Deferred(_)));
        assert_eq!(engine.usable_anchor().await, Some(anchor));
    }

    /// Headers can arrive in batches, so no list may sit at a ChainLock's
    /// signing height, and a ChainLock quorum mined between the lists around
    /// it leaves either one possibly exact. Selection is tried in both, and
    /// the anchored lists still decide which quorum may sign: the later one
    /// vouches for the new quorum once the anchor covers it.
    #[test_case(false; "selected in the earlier list")]
    #[test_case(true; "selected in the later, anchored list")]
    #[tokio::test]
    async fn a_chain_lock_signed_between_lists_a_quorum_was_mined_between_verifies(
        later_anchored: bool,
    ) {
        let chain_locks_type = Network::Regtest.chain_locks_type();
        let dkg = dkg(chain_locks_type);
        let cycle = 50 * dkg.interval;
        let anchored = cycle + dkg.mining_window_end + 1;
        let next_window = cycle + dkg.interval + dkg.mining_window_start;
        let later = next_window + 2;
        let signing_height = next_window + 1;
        let chain_lock_height = signing_height + 8;

        let mut engine = TestEngine::knowing(Network::Regtest, Default::default());
        for height in [anchored, later, chain_lock_height] {
            engine.feed_block_height(height, BlockHash::dummy(height));
        }
        let mut chain_lock = ChainLock {
            block_height: chain_lock_height,
            block_hash: BlockHash::dummy(chain_lock_height),
            signature: BLSSignature::from([0; 96]),
        };
        let request_id = chain_lock.request_id().expect("request id");
        let old = QuorumHash::from_byte_array([0x11; 32]);
        // Ground so that selection in the later list picks the new quorum.
        let order = |hash| {
            QuorumOrderingHash::create(&quorum_entry(chain_locks_type, hash, None), &request_id)
        };
        let new = (0x20..=u8::MAX)
            .map(|byte| QuorumHash::from_byte_array([byte; 32]))
            .find(|new| order(*new) < order(old))
            .expect("a hash the later list selects");
        let mut list = MasternodeList::empty(BlockHash::dummy(anchored), anchored);
        Arc::make_mut(&mut list.quorums)
            .entry(chain_locks_type)
            .or_default()
            .insert(old, Arc::new(forged_chain_lock_quorum(chain_locks_type, old)));
        let mut newer = list.clone();
        newer.known_height = later;
        newer.block_hash = BlockHash::dummy(later);
        Arc::make_mut(&mut newer.quorums)
            .entry(chain_locks_type)
            .or_default()
            .insert(new, Arc::new(forged_chain_lock_quorum(chain_locks_type, new)));
        let (signing_list, anchor_height) = if later_anchored {
            (&newer, later)
        } else {
            (&list, anchored)
        };
        let signer = signing_list
            .quorum_for_request(chain_locks_type, &request_id)
            .expect("selected")
            .quorum_entry
            .quorum_hash;
        assert_eq!(
            signer,
            if later_anchored {
                new
            } else {
                old
            }
        );
        chain_lock.signature = sign_as_forger(&chain_lock, chain_locks_type, signer);
        engine.masternode_lists.insert(anchored, list);
        engine.masternode_lists.insert(later, newer);
        engine.restore_chain_lock_anchor(ChainLockAnchor {
            height: anchor_height,
            block_hash: BlockHash::dummy(anchor_height),
            root: AnchorRoot::FirstChainLock,
        });

        assert_eq!(engine.accept_chain_lock(&chain_lock).await, ChainLockVerdict::Accepted);
        assert_eq!(
            engine.usable_anchor().await.map(|anchor| anchor.height),
            Some(chain_lock_height)
        );
    }

    /// A peer's list above the anchor can copy the ChainLock quorums of the
    /// anchored list below the signing height. Equal sets would make that
    /// list hold the quorums active at the signing height, with none of them
    /// aged, so they count only when both lists are anchored.
    #[tokio::test]
    async fn a_copied_quorum_set_above_the_anchor_does_not_unretire_a_quorum() {
        let chain_locks_type = Network::Mainnet.chain_locks_type();
        let dkg = dkg(chain_locks_type);
        let anchored = 100 * dkg.interval + dkg.mining_window_end + 1;
        let signing_height = 110 * dkg.interval + dkg.mining_window_end + 1;
        let mut engine = TestEngine::knowing(Network::Mainnet, Default::default());
        let mut list = MasternodeList::empty(BlockHash::dummy(anchored), anchored);
        for cycle in 97..=100 {
            let base = cycle * dkg.interval;
            engine.feed_block_height(base, BlockHash::dummy(base));
            let hash = QuorumHash::from_byte_array(BlockHash::dummy(base).to_byte_array());
            Arc::make_mut(&mut list.quorums)
                .entry(chain_locks_type)
                .or_default()
                .insert(hash, Arc::new(forged_chain_lock_quorum(chain_locks_type, hash)));
        }
        let mut copy = list.clone();
        copy.known_height = signing_height + 1;
        copy.block_hash = BlockHash::dummy(copy.known_height);
        for height in [anchored, copy.known_height, signing_height + 8] {
            engine.feed_block_height(height, BlockHash::dummy(height));
        }
        engine.masternode_lists.insert(anchored, list);
        engine.masternode_lists.insert(copy.known_height, copy.clone());
        anchor_at_newest_list_below(&mut engine, anchored);

        let mut chain_lock = ChainLock {
            block_height: signing_height + 8,
            block_hash: BlockHash::dummy(signing_height + 8),
            signature: BLSSignature::from([0; 96]),
        };
        let signer = copy
            .quorum_for_request(chain_locks_type, &chain_lock.request_id().expect("request id"))
            .expect("selected")
            .quorum_entry
            .quorum_hash;
        chain_lock.signature = sign_as_forger(&chain_lock, chain_locks_type, signer);

        assert!(matches!(
            engine.accept_chain_lock(&chain_lock).await,
            ChainLockVerdict::Deferred(_)
        ));
        assert_eq!(engine.usable_anchor().await.map(|anchor| anchor.height), Some(anchored));
    }

    /// A quorum whose base block is below the stored chain is older than any
    /// other but cannot be aged against its like: the anchored list vouches
    /// for it only while fewer than `active` mining windows passed above the
    /// stored chain's start, by when it is retired.
    #[tokio::test]
    async fn a_quorum_mined_below_the_stored_chain_signs_only_near_its_start() {
        let chain_locks_type = Network::Mainnet.chain_locks_type();
        let dkg = dkg(chain_locks_type);
        let anchored = dkg.mining_window_end + 1;
        let mut engine = TestEngine::knowing(Network::Mainnet, Default::default());
        engine.feed_block_height(anchored, BlockHash::dummy(anchored));
        let mut list = MasternodeList::empty(BlockHash::dummy(anchored), anchored);
        for byte in 1..=chain_locks_type.active_quorum_count() as u8 {
            let hash = QuorumHash::from_byte_array([byte; 32]);
            Arc::make_mut(&mut list.quorums)
                .entry(chain_locks_type)
                .or_default()
                .insert(hash, Arc::new(forged_chain_lock_quorum(chain_locks_type, hash)));
        }
        engine.masternode_lists.insert(anchored, list);
        anchor_at_newest_list(&mut engine);
        let anchor = engine.usable_anchor().await.expect("anchored");
        let unaged = QuorumHash::from_byte_array([1; 32]);

        let one_window_on = anchored + dkg.interval;
        let near = engine
            .anchored_signer(chain_locks_type, unaged, one_window_on, &anchor)
            .await
            .unwrap()
            .active();
        assert!(near.is_some(), "near the start of the stored chain");
        let lifetime_on = anchored + chain_locks_type.active_quorum_count() * dkg.interval;
        let far = engine
            .anchored_signer(chain_locks_type, unaged, lifetime_on, &anchor)
            .await
            .unwrap()
            .active();
        assert!(far.is_none(), "a quorum lifetime above the start of the stored chain");
    }

    /// Before trust has a root, a network without checkpoints takes the
    /// first ChainLock only from a DIP-6 verified quorum.
    #[tokio::test]
    async fn an_unverified_quorum_does_not_root_trust() {
        let mut engine = TestEngine::knowing(Network::Regtest, Default::default());
        let base = 1_000;
        engine.feed_block_height(base, BlockHash::dummy(base));
        engine.masternode_lists.insert(base, MasternodeList::empty(BlockHash::dummy(base), base));
        let first = forge_chain_lock_above_the_newest_list(&mut engine);
        let list = engine.masternode_lists.values_mut().next_back().expect("the forged list");
        for quorums in Arc::make_mut(&mut list.quorums).values_mut() {
            for quorum in quorums.values_mut() {
                Arc::make_mut(quorum).verified = LLMQEntryVerificationStatus::Unknown;
            }
        }

        assert!(matches!(engine.accept_chain_lock(&first).await, ChainLockVerdict::Deferred(_)));
        assert_eq!(engine.usable_anchor().await, None);
    }

    #[test]
    fn a_chain_lock_far_above_any_list_costs_no_time_and_no_overflow() {
        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let llmq_type = network.chain_locks_type();
            let started = std::time::Instant::now();
            let windows = mining_windows_between(llmq_type, 0, u32::MAX);
            // Counted in closed form: a walk over the windows would take seconds.
            assert!(started.elapsed() < std::time::Duration::from_secs(1));
            let interval = llmq_type.dkg_interval();
            assert!(windows.abs_diff(u32::MAX / interval) <= 1);
        }
    }

    /// The checkpoints trust may start at, with their block hashes as public
    /// block explorers report them. A checkpoint is the root of every quorum
    /// dash-spv trusts on its network, so one regenerated from another chain
    /// must not slip in unnoticed.
    const MAINNET_ROOTS: &[(u32, &str)] = &[
        (2000000, "0000000000000009bd68b5e00976c3f7482d4cc12b6596614fbba5678ef13a59"),
        (2050000, "000000000000000680f94c4df744eb264df5a94fc406de329fbb94d54c8dc5eb"),
        (2100000, "0000000000000019c3be91021a1e70544e29d71f8f8649c93e8c8a69bfd18389"),
        (2150000, "000000000000001139dcfcd14309c11b7c6abd7cb4164a68911d66127c97a726"),
        (2200000, "000000000000001aee1132b3c4631acc76b0c575d3e86cb1d2be9160f37428dc"),
        (2250000, "00000000000000062539a6cd3adece4a10598e729ef571bfded9d4b704af69f0"),
        (2300000, "00000000000000186f9f2fde843be3d66b8ae317cabb7d43dbde943d02a4b4d7"),
        (2350000, "00000000000000258216a62e8c7170be1207335474ddfa667092a71e3d4162d2"),
        (2400000, "000000000000002883c9151a37092287c1773c5a4d175a8f688373daa631f934"),
        (2450000, "00000000000000074832a3ff13968b2aa0c841fcdfced9c3619257242470f25f"),
        (2500000, "000000000000000ac721a208c5efba67e76cb08796324de3519fefa32a5b2f44"),
        (2550000, "000000000000000759db5eed70bf470171e7738b85765b395c1a75029c9683ce"),
    ];
    const TESTNET_ROOTS: &[(u32, &str)] = &[
        (950000, "0000010dc2164ab88e2302f7e01a0af25065871851b7598ae51eb92146bd514e"),
        (1000000, "000000fddf6f17f24b9f2c7e13daf1bff0307bdb0cf617b61917ef6bd1bddc6a"),
        (1050000, "000000accb2b32142fc1c6d90d68e45e392755fb3c79609c48d86b5a7c356bf6"),
        (1100000, "000000078cc3952c7f594de921ae82fcf430a5f3b86755cd72acd819d0001015"),
        (1150000, "000000e4454d0c168a4b52d85f10f1431d1bccc68c159be1f558f4e5b5c24e53"),
        (1200000, "000000595a1fc6b498adce4aa324a4b986d212c005ba1ff7a26d21950147d74f"),
        (1250000, "000002c1b93bb39dd9d4eb1f56a2f2e7443e8350178b9d35026fb5580bf441d8"),
        (1300000, "000001556cd2a74e8c80e4478f5d0865f5626ecddc5fa5f968340bafd7bd298e"),
        (1350000, "000000c62ce13fb0988e71f2b870d9d38dfd056f9ee175cc840a633a8f150215"),
        (1400000, "000000541a23f9db7411cddbe50f9f1ebd4aa7108ebdcad62214753f648c0239"),
        (1450000, "000000fa4225fa022d4216eabb176848d61d03027df12e0685f82d8b13c60f03"),
        (1500000, "000000b625f73fab6cb338c31cb656680ccfb3b574b9225022c8e90e293a0c12"),
        (1550000, "000000116cd3c11d44c88cbc0a26804bd277a5d790f684ec3a8aaa820690318c"),
    ];

    #[test_case(Network::Mainnet, MAINNET_ROOTS; "mainnet")]
    #[test_case(Network::Testnet, TESTNET_ROOTS; "testnet")]
    fn every_checkpoint_trust_may_start_at_is_the_known_block(
        network: Network,
        roots: &[(u32, &str)],
    ) {
        let eligible: Vec<(u32, String)> = crate::chain::CheckpointManager::for_network(network)
            .checkpoints()
            .filter(|checkpoint| may_root_at_checkpoint(network, checkpoint.height()))
            .map(|checkpoint| (checkpoint.height(), checkpoint.hash().to_string()))
            .collect();
        let pinned: Vec<(u32, String)> =
            roots.iter().map(|(height, hash)| (*height, hash.to_string())).collect();
        assert_eq!(eligible, pinned, "pin every checkpoint past V20");
    }

    #[test]
    fn a_chain_lock_roots_trust_only_while_its_quorums_can_sign_at_the_tip() {
        let chain_locks_type = Network::Regtest.chain_locks_type();
        let lifetime = chain_locks_type.active_window();

        assert!(may_root_trust(chain_locks_type, 1_000, None));
        assert!(may_root_trust(chain_locks_type, 1_000, Some(1_000 + lifetime)));
        assert!(!may_root_trust(chain_locks_type, 1_000, Some(1_000 + lifetime + 1)));
    }

    #[test_case(Network::Mainnet; "mainnet")]
    #[test_case(Network::Testnet; "testnet")]
    #[test_case(Network::Regtest; "regtest")]
    fn mining_windows_are_counted_where_they_have_a_block(network: Network) {
        let llmq_type = network.chain_locks_type();
        let dkg = dkg(llmq_type);
        let cycle = 1_000 * dkg.interval;
        let (start, end) = (cycle + dkg.mining_window_start, cycle + dkg.mining_window_end);

        assert_eq!(mining_windows_between(llmq_type, start - 1, start), 1);
        assert_eq!(mining_windows_between(llmq_type, end, start + dkg.interval - 1), 0);
        assert_eq!(mining_windows_between(llmq_type, cycle, cycle + 3 * dkg.interval), 3);
        assert_eq!(mining_windows_between(llmq_type, start, start), 0);
        assert_eq!(mining_windows_between(llmq_type, start + 1, start), 0);
    }

    fn mainnet_diff() -> MnListDiff {
        deserialize(include_bytes!(
            "../../../dash/tests/data/test_DML_diffs/mn_list_diff_2227096_2241332.bin"
        ))
        .expect("a mainnet diff")
    }

    fn with_payload(
        mut diff: MnListDiff,
        edit: impl FnOnce(&mut dashcore::transaction::special_transaction::coinbase::CoinbasePayload),
    ) -> MnListDiff {
        let Some(TransactionPayload::CoinbasePayloadType(payload)) =
            &mut diff.coinbase_tx.special_transaction_payload
        else {
            panic!("a coinbase payload");
        };
        edit(payload);
        diff
    }

    /// A coinbase carries the best ChainLock its miner knew, for the ancestor
    /// `bestCLHeightDiff + 1` blocks below it.
    #[test]
    fn a_coinbase_chain_lock_is_for_the_ancestor_its_height_difference_names() {
        let diff = mainnet_diff();
        let Some(TransactionPayload::CoinbasePayloadType(payload)) =
            &diff.coinbase_tx.special_transaction_payload
        else {
            panic!("a coinbase payload");
        };
        let height_diff = payload.best_cl_height.expect("a v3 payload");
        let signature = payload.best_cl_signature.expect("a v3 payload");
        let carrier = payload.height;

        assert_eq!(
            carried_chain_lock(&diff, carrier),
            Some((carrier - height_diff - 1, signature))
        );
        assert_eq!(carried_chain_lock(&diff, carrier + 1), None, "a payload of another height");
        let below_genesis =
            with_payload(diff.clone(), |payload| payload.best_cl_height = Some(carrier));
        assert_eq!(carried_chain_lock(&below_genesis, carrier), None, "below genesis");
        let older = with_payload(diff.clone(), |payload| payload.best_cl_height = Some(5));
        assert_eq!(carried_chain_lock(&older, carrier), Some((carrier - 6, signature)));
        let null = with_payload(diff.clone(), |payload| {
            payload.best_cl_signature = Some(BLSSignature::from([0; 96]))
        });
        assert_eq!(carried_chain_lock(&null, carrier), None, "no ChainLock yet");
        let v2 = with_payload(diff, |payload| payload.version = 2);
        assert_eq!(carried_chain_lock(&v2, carrier), None, "before CbTx v3");
    }

    /// A list above the anchor can carry another commitment, keyed by a
    /// secret a peer holds, under the hash of the anchored quorum selection
    /// picks. The anchored entry's key checks the signature, so a ChainLock the
    /// peer signs with its own key locks nothing.
    #[tokio::test]
    async fn a_chain_lock_signed_with_a_key_swapped_in_above_the_anchor_is_not_accepted() {
        let mut engine = TestEngine::mainnet_fixture();
        anchor_at_newest_list(&mut engine);
        let anchor = engine.usable_anchor().await;
        let chain_locks_type = engine.network().chain_locks_type();
        let newest = engine.latest_masternode_list().expect("the anchored list").clone();
        let list_height = newest.known_height + 1;
        let mut chain_lock = ChainLock {
            block_height: list_height + LLMQ_SIGN_HEIGHT_OFFSET,
            block_hash: BlockHash::from_byte_array([0xee; 32]),
            signature: BLSSignature::from([0; 96]),
        };
        let request_id = chain_lock.request_id().expect("request id");
        let selected = newest
            .quorum_for_request(chain_locks_type, &request_id)
            .expect("selected")
            .quorum_entry
            .quorum_hash;
        let mut list = newest.clone();
        list.known_height = list_height;
        list.block_hash = BlockHash::from_byte_array([0xef; 32]);
        Arc::make_mut(&mut list.quorums)
            .entry(chain_locks_type)
            .or_default()
            .insert(selected, Arc::new(forged_chain_lock_quorum(chain_locks_type, selected)));
        engine.feed_block_height(list_height, list.block_hash);
        engine.feed_block_height(chain_lock.block_height, chain_lock.block_hash);
        engine.masternode_lists.insert(list_height, list);
        chain_lock.signature = sign_as_forger(&chain_lock, chain_locks_type, selected);

        assert!(matches!(
            engine.accept_chain_lock(&chain_lock).await,
            ChainLockVerdict::Rejected(_)
        ));
        assert_eq!(engine.usable_anchor().await, anchor);
    }

    /// Headers can arrive in batches, so the anchor can cover a signing height
    /// no anchored list pins the active quorums at. A ChainLock whose signer
    /// was mined past the newest anchored list is then not decided, and waits
    /// for a list that holds the quorums active there, rather than being
    /// counted invalid.
    #[tokio::test]
    async fn a_signer_mined_past_the_newest_anchored_list_waits_below_the_anchor() {
        let chain_locks_type = Network::Regtest.chain_locks_type();
        let dkg = dkg(chain_locks_type);
        let cycle = 50 * dkg.interval;
        let anchored = cycle + dkg.mining_window_end + 1;
        let next_window = cycle + dkg.interval + dkg.mining_window_start;
        let signing_height = next_window + 1;
        let later = next_window + 2;
        let chain_lock_height = signing_height + 8;

        let mut engine = TestEngine::knowing(Network::Regtest, Default::default());
        for height in [anchored, signing_height, later, chain_lock_height] {
            engine.feed_block_height(height, BlockHash::dummy(height));
        }
        let mut chain_lock = ChainLock {
            block_height: chain_lock_height,
            block_hash: BlockHash::dummy(chain_lock_height),
            signature: BLSSignature::from([0; 96]),
        };
        let request_id = chain_lock.request_id().expect("request id");
        let old = QuorumHash::from_byte_array([0x11; 32]);
        let order = |hash| {
            QuorumOrderingHash::create(&quorum_entry(chain_locks_type, hash, None), &request_id)
        };
        let new = (0x20..=u8::MAX)
            .map(|byte| QuorumHash::from_byte_array([byte; 32]))
            .find(|new| order(*new) < order(old))
            .expect("a hash the later list selects");
        let mut list = MasternodeList::empty(BlockHash::dummy(anchored), anchored);
        Arc::make_mut(&mut list.quorums)
            .entry(chain_locks_type)
            .or_default()
            .insert(old, Arc::new(forged_chain_lock_quorum(chain_locks_type, old)));
        let mut newer = list.clone();
        newer.known_height = later;
        newer.block_hash = BlockHash::dummy(later);
        Arc::make_mut(&mut newer.quorums)
            .entry(chain_locks_type)
            .or_default()
            .insert(new, Arc::new(forged_chain_lock_quorum(chain_locks_type, new)));
        chain_lock.signature = sign_as_forger(&chain_lock, chain_locks_type, new);
        engine.masternode_lists.insert(anchored, list);
        engine.masternode_lists.insert(later, newer);
        engine.restore_chain_lock_anchor(ChainLockAnchor {
            height: signing_height,
            block_hash: BlockHash::dummy(signing_height),
            root: AnchorRoot::FirstChainLock,
        });

        assert!(matches!(
            engine.accept_chain_lock(&chain_lock).await,
            ChainLockVerdict::Deferred(_)
        ));
    }

    /// A list at or below the anchor counts only while the header chain holds
    /// its block at its height. One whose block the chain does not hold there
    /// may sit on a branch a peer made up, or one the chain left.
    #[test_case(None; "no block at its height")]
    #[test_case(Some(BlockHash::from_byte_array([0xcd; 32])); "another block at its height")]
    #[tokio::test]
    async fn a_list_below_the_anchor_off_the_header_chain_is_not_anchored(
        stored: Option<BlockHash>,
    ) {
        let mut engine = TestEngine::mainnet_fixture();
        anchor_at_newest_list(&mut engine);
        let newest = engine.latest_masternode_list().expect("the anchored list").known_height;
        let off_chain = (0..newest)
            .rev()
            .find(|height| engine.block_hash_at(*height).is_none())
            .expect("a height the fixture holds no block at");
        if let Some(stored) = stored {
            engine.feed_block_height(off_chain, stored);
        }
        let list = MasternodeList::empty(BlockHash::from_byte_array([0xab; 32]), off_chain);
        engine.masternode_lists.insert(off_chain, list);

        let anchored = engine.latest_anchored_list(off_chain).await.map(|list| list.known_height);
        assert!(anchored.is_some_and(|height| height < off_chain), "{anchored:?}");
    }

    /// Trust walks up from the newest anchored list, so pruning keeps it, and
    /// the lists the walk builds on up to a ChainLock quorum's lifetime above
    /// it, however far below the tip the anchor stays. Lists further up and
    /// below the retention window go, so a stuck anchor holds no more.
    #[tokio::test]
    async fn pruning_keeps_the_newest_anchored_list_and_the_walks_reach() {
        let mut engine = TestEngine::dummy_with_lists(&[100, 101]);
        anchor_at_newest_list_below(&mut engine, 100);
        let beyond = 100 + Network::Mainnet.chain_locks_type().active_window() + 1;
        let tip = beyond + engine.retention_window() + 10;
        let base = tip - 1;
        // The next QRInfo's base, which pruning keeps as well.
        let qr_info_base = beyond + 5;
        for height in [beyond, qr_info_base, base, tip] {
            engine.feed_block_height(height, BlockHash::dummy(height));
            let list = MasternodeList::empty(BlockHash::dummy(height), height);
            engine.masternode_lists.insert(height, list);
        }

        engine.prune_after_extending(base).await;

        let heights: Vec<_> = engine.masternode_lists.keys().copied().collect();
        assert_eq!(heights, vec![100, 101, qr_info_base, base, tip]);
        assert_eq!(
            engine.latest_anchored_list(u32::MAX).await.map(|list| list.known_height),
            Some(100)
        );
    }

    /// A persisted anchor counts only under a root this network starts trust
    /// from: a checkpoint past V20 that is compiled in.
    #[test_case(AnchorRoot::Checkpoint(42_000); "not a checkpoint")]
    #[test_case(AnchorRoot::FirstChainLock; "a first ChainLock")]
    #[tokio::test]
    async fn a_persisted_anchor_under_a_root_mainnet_does_not_trust_is_ignored(root: AnchorRoot) {
        let mut engine = TestEngine::mainnet_fixture();
        let newest = engine.latest_masternode_list().expect("a list").clone();
        engine.restore_chain_lock_anchor(ChainLockAnchor {
            height: newest.known_height,
            block_hash: newest.block_hash,
            root,
        });

        assert_eq!(engine.chain_lock_anchor(), None);
        assert_eq!(engine.usable_anchor().await, None);
    }

    /// A quorum that only a list off the header chain holds, below the anchor,
    /// does not resolve as anchored: that list may sit on a branch a peer made
    /// up, or one the chain left.
    #[tokio::test]
    async fn a_quorum_only_a_list_off_the_header_chain_holds_does_not_resolve() {
        let mut engine = TestEngine::mainnet_fixture();
        anchor_at_newest_list(&mut engine);
        let chain_locks_type = engine.network().chain_locks_type();
        let newest = engine.latest_masternode_list().expect("the anchored list").known_height;
        let off_chain = (0..newest)
            .rev()
            .find(|height| engine.block_hash_at(*height).is_none())
            .expect("a height the fixture holds no block at");
        let quorum_hash = QuorumHash::from_byte_array([0x99; 32]);
        let mut list = MasternodeList::empty(BlockHash::from_byte_array([0xab; 32]), off_chain);
        Arc::make_mut(&mut list.quorums)
            .entry(chain_locks_type)
            .or_default()
            .insert(quorum_hash, Arc::new(forged_chain_lock_quorum(chain_locks_type, quorum_hash)));
        engine.masternode_lists.insert(off_chain, list);

        assert!(engine
            .quorum_entry_for_hash_at_or_before_height(chain_locks_type, quorum_hash, newest)
            .is_some());
        assert!(engine.anchored_quorum(chain_locks_type, quorum_hash, u32::MAX).await.is_none());
    }
}
