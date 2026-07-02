//! Per-peer staged fork buffer.
//!
//! Buffers fork headers received from peers until either their cumulative
//! work exceeds the active chain (`branches` plus `take_branch`), they age out
//! (`expire_stale`), or the peer disconnects (`remove_peer`).
//!
//! All buffered branches are independently validated: each header must meet
//! its claimed PoW target, satisfy the median-time-past rule against the
//! ancestor history, and match DGW v3's expected `nBits` from the ancestor's
//! 24-block window.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashcore::consensus::Params;
use dashcore::{BlockHash, Header};

use crate::chain::difficulty::{min_difficulty_bits, next_work_required_dgw_v3};
use crate::chain::{ChainWork, ForkCandidate};
use crate::error::{SyncError, SyncResult};
use crate::types::HashedBlockHeader;

/// Number of blocks median-time-past is computed over (BIP113).
const MTP_WINDOW: usize = 11;

/// Cap on simultaneous fork branches buffered per peer to keep memory bounded.
pub(super) const MAX_FORK_HEADERS_PER_PEER: usize = 4096;

/// Maximum distinct fork branch tips a single peer may contribute.
const MAX_BRANCHES_PER_PEER: usize = 16;

/// Identifies a buffered branch by its source peer and tip hash.
pub(super) type BranchKey = (SocketAddr, BlockHash);

#[derive(Debug)]
pub(super) struct ForkBuffer {
    branches: HashMap<BranchKey, BufferedBranch>,
    params: Params,
}

#[derive(Debug)]
struct BufferedBranch {
    headers: Vec<HashedBlockHeader>,
    ancestor_height: u32,
    total_work: ChainWork,
    arrived_at: Instant,
}

impl ForkBuffer {
    pub(super) fn new(params: Params) -> Self {
        Self {
            branches: HashMap::new(),
            params,
        }
    }

    /// Validate and buffer a fork branch coming from `peer`.
    ///
    /// `headers` is the fork extension (oldest first, must connect to
    /// `ancestor_header`). `history` contains the active-chain headers
    /// preceding the ancestor in chain order, oldest first, with the ancestor
    /// itself at `history.last()`. Used for MTP and DGW retarget anchoring.
    pub(super) fn ingest(
        &mut self,
        peer: SocketAddr,
        headers: &[Header],
        ancestor_height: u32,
        ancestor_header: Header,
        history: &[Header],
    ) -> SyncResult<()> {
        if headers.is_empty() {
            return Ok(());
        }
        // dashd selects the retargeting algorithm by height: DGW v3 applies only
        // at or above `pow_dgw_height`, with KGW or the pre-KGW rule below it.
        // Only DGW is ported here, so a fork whose lowest validated header sits
        // below that activation cannot be checked correctly and is rejected.
        // Networks with retargeting disabled short-circuit DGW to `pow_limit`,
        // so they stay valid at any height.
        if !self.params.no_pow_retargeting && ancestor_height + 1 < self.params.pow_dgw_height {
            return Err(SyncError::Validation(format!(
                "fork ancestor at height {} is below the DGW activation height {}",
                ancestor_height, self.params.pow_dgw_height
            )));
        }
        if headers.len() > MAX_FORK_HEADERS_PER_PEER {
            return Err(SyncError::Validation(format!(
                "Fork branch too large: {} headers (max {})",
                headers.len(),
                MAX_FORK_HEADERS_PER_PEER
            )));
        }
        let peer_branch_count = self.branches.keys().filter(|(p, _)| *p == peer).count();
        if peer_branch_count >= MAX_BRANCHES_PER_PEER {
            return Err(SyncError::Validation(format!(
                "Too many concurrent fork branches from peer {} (max {})",
                peer, MAX_BRANCHES_PER_PEER
            )));
        }
        debug_assert_eq!(
            history.last().map(|h| h.block_hash()),
            Some(ancestor_header.block_hash()),
            "history.last() must be the ancestor header"
        );

        // Chain continuity: each header must extend the previous.
        let mut prev = ancestor_header;
        let mut hashed: Vec<HashedBlockHeader> = Vec::with_capacity(headers.len());
        let mut rolling_history: Vec<Header> = history.to_vec();
        for (offset, header) in headers.iter().enumerate() {
            let height = ancestor_height + offset as u32 + 1;
            if header.prev_blockhash != prev.block_hash() {
                return Err(SyncError::ForkChainBreak(format!(
                    "expected prev {}, got {}",
                    prev.block_hash(),
                    header.prev_blockhash
                )));
            }

            // PoW target met.
            let hashed_header = HashedBlockHeader::from(*header);
            if !header.target().is_met_by(*hashed_header.hash()) {
                return Err(SyncError::Validation(format!(
                    "Fork header at height {} failed PoW target",
                    height
                )));
            }

            // Median time past: candidate time must strictly exceed MTP of
            // last 11 ancestor headers.
            let mtp = median_time_past(&rolling_history);
            if (header.time as u64) <= mtp {
                return Err(SyncError::Validation(format!(
                    "Fork header at height {} fails MTP rule ({} <= {})",
                    height, header.time, mtp
                )));
            }

            // Mirror dashd's `GetNextWorkRequired`: exactly one value is
            // required. When the min-difficulty exception applies it replaces
            // the DGW output rather than joining it, otherwise DGW is required.
            let expected_bits =
                next_work_required_dgw_v3(&rolling_history, height - 1, &self.params);
            let required = min_difficulty_bits(&self.params, prev.time, prev.bits, header.time)
                .unwrap_or(expected_bits);
            if header.bits != required {
                return Err(SyncError::Validation(format!(
                    "Fork header at height {} bad bits: got {:?}, expected {:?}",
                    height, header.bits, required
                )));
            }

            hashed.push(hashed_header);
            rolling_history.push(*header);
            prev = *header;
        }

        let branch_work = ChainWork::accumulate(ChainWork::zero(), headers);

        let key = (peer, hashed.last().expect("non-empty fork branch").hash().to_owned());
        self.branches.insert(
            key,
            BufferedBranch {
                headers: hashed,
                ancestor_height,
                total_work: branch_work,
                arrived_at: Instant::now(),
            },
        );

        Ok(())
    }

    /// Drop branches older than `ttl`. Returns how many were evicted.
    pub(super) fn expire_stale(&mut self, ttl: Duration) -> usize {
        let now = Instant::now();
        let before = self.branches.len();
        self.branches.retain(|_, b| now.duration_since(b.arrived_at) <= ttl);
        before - self.branches.len()
    }

    /// Drop all buffered branches sourced from `peer`.
    pub(super) fn remove_peer(&mut self, peer: SocketAddr) {
        self.branches.retain(|(p, _), _| *p != peer);
    }

    /// Iterate over every buffered branch as its key, ancestor height, and
    /// cumulative extension work, without removing any.
    ///
    /// The caller must measure the active chain's extension work from each
    /// branch's own `ancestor_height` up to the active tip, because different
    /// branches fork at different ancestors and must be judged against their
    /// own baseline. Promote via `take_branch` only when the branch work is
    /// strictly heavier on that baseline.
    pub(super) fn branches(&self) -> impl Iterator<Item = (BranchKey, u32, ChainWork)> + '_ {
        self.branches.iter().map(|(key, b)| (*key, b.ancestor_height, b.total_work))
    }

    /// Remove the branch identified by `key` and return it as a promotable
    /// candidate.
    pub(super) fn take_branch(&mut self, key: BranchKey) -> Option<ForkCandidate> {
        let branch = self.branches.remove(&key)?;
        Some(ForkCandidate {
            ancestor_height: branch.ancestor_height,
            headers: branch.headers,
            total_work: branch.total_work,
        })
    }

    /// Return the set of branch tip hashes currently buffered.
    pub(super) fn branch_tip_hashes(&self) -> impl Iterator<Item = &BlockHash> {
        self.branches.keys().map(|(_, tip)| tip)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.branches.len()
    }
}

fn median_time_past(history: &[Header]) -> u64 {
    let window = if history.len() >= MTP_WINDOW {
        &history[history.len() - MTP_WINDOW..]
    } else {
        history
    };
    let mut times: Vec<u32> = window.iter().map(|h| h.time).collect();
    times.sort_unstable();
    times.get(times.len() / 2).copied().unwrap_or(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::block::Version;
    use dashcore::{BlockHash, CompactTarget, Header, Network, TxMerkleNode};
    use dashcore_hashes::Hash;

    /// Regtest `pow_limit` (≈2^255) expressed in compact form. Easy enough
    /// that most nonces satisfy PoW and matches DGW's expected next bits
    /// when retargeting is disabled on regtest.
    const EASY_BITS: u32 = 0x207fffff;

    fn easy_header(prev: BlockHash, time: u32, nonce_start: u32) -> Header {
        // Iterate nonces until PoW passes. With 2^255 target ~half pass.
        for nonce in nonce_start..nonce_start + 32 {
            let header = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::all_zeros(),
                time,
                bits: CompactTarget::from_consensus(EASY_BITS),
                nonce,
            };
            if header.target().is_met_by(header.block_hash()) {
                return header;
            }
        }
        panic!("could not find a valid nonce within 32 tries");
    }

    fn build_chain(start_time: u32, count: usize, start_prev: BlockHash) -> Vec<Header> {
        let mut prev = start_prev;
        let mut t = start_time;
        let mut headers = Vec::with_capacity(count);
        for n in 0..count {
            // each header at +600s satisfies MTP easily
            let header = easy_header(prev, t, (n as u32) * 32);
            prev = header.block_hash();
            t += 600;
            headers.push(header);
        }
        headers
    }

    fn regtest_params() -> Params {
        // Regtest has no_pow_retargeting = true, so DGW falls through to
        // pow_limit which matches our easy bits when run through DGW's clamp.
        // For these tests we use mainnet's params with allow_min skipped but
        // override no_pow_retargeting via regtest.
        Params::new(Network::Regtest)
    }

    #[test]
    fn ingest_accepts_pre_dgw_window_ancestor() {
        // Fork ancestor below the DGW window (24 blocks). DGW short-circuits to
        // pow_limit, and the fork header carries pow_limit bits, so ingest must
        // succeed without demanding a full 24-block history.
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let mut buf = ForkBuffer::new(regtest_params());

        let active = build_chain(1_700_000_000, 6, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();

        let fork = build_chain(1_700_000_000 + 7 * 600, 2, ancestor.block_hash());

        buf.ingest(peer, &fork, ancestor_height, ancestor, &active)
            .expect("pre-DGW-window fork must be accepted");
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn ingest_rejects_fork_below_dgw_activation_on_retargeting_network() {
        // On a retargeting network the fork's lowest validated header must sit
        // at or above the DGW activation height, since only DGW is ported. A
        // testnet fork anchored below `pow_dgw_height` (4002) is rejected before
        // any header validation. The dummy header never needs valid PoW because
        // the height gate fires first.
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let params = Params::new(Network::Testnet);
        assert!(!params.no_pow_retargeting);
        let mut buf = ForkBuffer::new(params);

        let ancestor_height = 100;
        let ancestor = easy_header(BlockHash::all_zeros(), 1_700_000_000, 0);
        let fork_header = easy_header(ancestor.block_hash(), 1_700_000_600, 0);

        let err = buf
            .ingest(peer, &[fork_header], ancestor_height, ancestor, &[ancestor])
            .expect_err("fork below DGW activation must be rejected");
        assert!(
            matches!(&err, SyncError::Validation(msg) if msg.contains("DGW activation height")),
            "expected DGW activation gate error, got: {:?}",
            err
        );
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn ingest_validates_and_buffers_single_branch() {
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let mut buf = ForkBuffer::new(regtest_params());

        // Active-chain history of 11 blocks so MTP works.
        let active = build_chain(1_700_000_000, 11, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();

        // Fork extension of 3 headers, must start after the ancestor.
        let fork = build_chain(1_700_000_000 + 12 * 600, 3, ancestor.block_hash());

        buf.ingest(peer, &fork, ancestor_height, ancestor, &active).expect("ingest");
        assert_eq!(buf.len(), 1);

        // The sole buffered branch, against a zero baseline, wins outright.
        let (key, winner_ancestor, work) = buf.branches().next().expect("a branch is buffered");
        assert_eq!(winner_ancestor, ancestor_height);
        assert!(work > ChainWork::zero());
        let candidate = buf.take_branch(key).expect("candidate should be removed");
        assert_eq!(candidate.ancestor_height, ancestor_height);
        assert_eq!(candidate.headers.len(), 3);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn ingest_rejects_branch_with_bad_pow() {
        // One fork header with bits set to the hardest possible compact target
        // so that no X11 hash can satisfy PoW. The DGW bits mismatch is also
        // present, but PoW fires first and we assert specifically on that error.
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let mut buf = ForkBuffer::new(regtest_params());

        let active = build_chain(1_700_000_000, 11, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();

        // 0x01000001 encodes target=1; no 32-byte X11 output can be ≤ 1.
        let impossible_bits = CompactTarget::from_consensus(0x01000001);
        let fork_header = Header {
            version: Version::ONE,
            prev_blockhash: ancestor.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000 + 12 * 600,
            bits: impossible_bits,
            nonce: 0,
        };

        let err = buf
            .ingest(peer, &[fork_header], ancestor_height, ancestor, &active)
            .expect_err("impossible PoW target must be rejected");
        assert!(
            matches!(&err, SyncError::Validation(msg) if msg.contains("failed PoW target")),
            "expected PoW failure, got: {:?}",
            err
        );
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn ingest_rejects_branch_with_wrong_bits() {
        // One fork header with correct PoW nonce but wrong bits field (DGW mismatch
        // only). Because the nonce was found for EASY_BITS and EASY_BITS is the
        // regtest pow_limit, any change to bits leaves the nonce intact — the hash
        // still meets the original target — so only the bits check fires.
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let mut buf = ForkBuffer::new(regtest_params());

        let active = build_chain(1_700_000_000, 11, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();

        let mut fork_header = easy_header(ancestor.block_hash(), 1_700_000_000 + 12 * 600, 0);
        // Switch bits to 0x2100ffff (easier than EASY_BITS) so the existing
        // nonce still satisfies PoW, but the bits value differs from the DGW
        // expected output (0x207fffff on regtest). This isolates the DGW check.
        let different_bits = CompactTarget::from_consensus(0x2100_ffff);
        fork_header.bits = different_bits;

        let err = buf
            .ingest(peer, &[fork_header], ancestor_height, ancestor, &active)
            .expect_err("wrong bits must be rejected");
        assert!(
            matches!(&err, SyncError::Validation(msg) if msg.contains("bad bits")),
            "expected DGW bits failure, got: {:?}",
            err
        );
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn ingest_rejects_branch_with_stale_timestamp() {
        // One fork header whose time equals the MTP of the ancestor window,
        // violating the strictly-greater rule (time must be > MTP, not >=).
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let mut buf = ForkBuffer::new(regtest_params());

        // Build 11 headers at regular 600s spacing.
        let start_time = 1_700_000_000u32;
        let active = build_chain(start_time, 11, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();

        // Compute the MTP of the 11-block window.
        let mut times: Vec<u32> = active.iter().map(|h| h.time).collect();
        times.sort_unstable();
        let mtp = times[times.len() / 2] as u64;

        // Build a fork header with time == mtp (must be strictly greater).
        // Search nonces for one whose hash meets the easy target at this time.
        let mut fork_header = None;
        for nonce in 0u32..64 {
            let h = Header {
                version: Version::ONE,
                prev_blockhash: ancestor.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: mtp as u32,
                bits: CompactTarget::from_consensus(EASY_BITS),
                nonce,
            };
            if h.target().is_met_by(h.block_hash()) {
                fork_header = Some(h);
                break;
            }
        }
        let fork_header = fork_header.expect("nonce search exhausted for MTP test");

        let err = buf
            .ingest(peer, &[fork_header], ancestor_height, ancestor, &active)
            .expect_err("MTP violation must be rejected");
        assert!(
            matches!(&err, SyncError::Validation(msg) if msg.contains("MTP rule")),
            "expected MTP failure, got: {:?}",
            err
        );
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn two_peers_serving_same_fork_dedup_per_peer() {
        let peer_a: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let peer_b: SocketAddr = "5.6.7.8:9999".parse().unwrap();
        let mut buf = ForkBuffer::new(regtest_params());

        let active = build_chain(1_700_000_000, 11, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();
        let fork = build_chain(1_700_000_000 + 12 * 600, 3, ancestor.block_hash());

        // Same fork (same hash chain) ingested twice from different peers.
        buf.ingest(peer_a, &fork, ancestor_height, ancestor, &active).unwrap();
        buf.ingest(peer_b, &fork, ancestor_height, ancestor, &active).unwrap();
        // Keys differ by peer so both entries exist.
        assert_eq!(buf.len(), 2);
        // But the same fork tip hash is keyed under (peer, hash). A repeated
        // ingest from the same peer with the same tip hash overwrites.
        buf.ingest(peer_a, &fork, ancestor_height, ancestor, &active).unwrap();
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn expire_stale_drops_old_branches() {
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let mut buf = ForkBuffer::new(regtest_params());
        let active = build_chain(1_700_000_000, 11, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();
        let fork = build_chain(1_700_000_000 + 12 * 600, 3, ancestor.block_hash());
        buf.ingest(peer, &fork, ancestor_height, ancestor, &active).unwrap();

        // TTL=0 expires immediately.
        let evicted = buf.expire_stale(Duration::from_secs(0));
        assert_eq!(evicted, 1);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn remove_peer_clears_its_branches() {
        let peer_a: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let peer_b: SocketAddr = "5.6.7.8:9999".parse().unwrap();
        let mut buf = ForkBuffer::new(regtest_params());
        let active = build_chain(1_700_000_000, 11, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();
        let fork = build_chain(1_700_000_000 + 12 * 600, 3, ancestor.block_hash());
        buf.ingest(peer_a, &fork, ancestor_height, ancestor, &active).unwrap();
        buf.ingest(peer_b, &fork, ancestor_height, ancestor, &active).unwrap();
        assert_eq!(buf.len(), 2);
        buf.remove_peer(peer_a);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn ingest_rejects_peer_exceeding_branch_cap() {
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let mut buf = ForkBuffer::new(regtest_params());
        let active = build_chain(1_700_000_000, 11, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();

        // Ingest MAX_BRANCHES_PER_PEER distinct branches (each with a unique tip).
        for i in 0..MAX_BRANCHES_PER_PEER {
            let fork_time = 1_700_000_000 + (12 + i as u32) * 600;
            let branch = build_chain(fork_time, 1, ancestor.block_hash());
            buf.ingest(peer, &branch, ancestor_height, ancestor, &active)
                .expect("ingest within cap should succeed");
        }
        assert_eq!(buf.len(), MAX_BRANCHES_PER_PEER);

        // One more branch from the same peer must be rejected.
        let extra_time = 1_700_000_000 + (12 + MAX_BRANCHES_PER_PEER as u32) * 600;
        let extra = build_chain(extra_time, 1, ancestor.block_hash());
        let err = buf
            .ingest(peer, &extra, ancestor_height, ancestor, &active)
            .expect_err("17th branch must be rejected");
        assert!(
            matches!(&err, SyncError::Validation(msg) if msg.contains("Too many concurrent")),
            "expected branch-cap error, got: {:?}",
            err
        );
        assert_eq!(buf.len(), MAX_BRANCHES_PER_PEER, "buffer unchanged after rejection");
    }

    #[test]
    fn ingest_rejects_chain_discontinuity_with_fork_chain_break() {
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let mut buf = ForkBuffer::new(regtest_params());

        let active = build_chain(1_700_000_000, 11, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();

        // Build a valid fork header but give it a wrong prev_blockhash so
        // the chain-continuity check fires and returns ForkChainBreak.
        let wrong_prev = BlockHash::from_slice(&[0xAB; 32]).unwrap();
        let disconnected_header = easy_header(wrong_prev, 1_700_000_000 + 12 * 600, 0);

        let err = buf
            .ingest(peer, &[disconnected_header], ancestor_height, ancestor, &active)
            .expect_err("disconnected chain must be rejected");
        assert!(
            matches!(&err, SyncError::ForkChainBreak(_)),
            "expected ForkChainBreak, got: {:?}",
            err
        );
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn ingest_accepts_valid_min_difficulty_fork_header() {
        // Regtest has `allow_min_difficulty_blocks = true` and a pow_limit that
        // matches `EASY_BITS`. A fork header whose time gap from its predecessor
        // exceeds 4×spacing triggers the min-difficulty exception, so the
        // required `bits` become `min_difficulty_bits(...)` in place of the DGW
        // output. This exercises the exception path that rejection tests do not
        // reach.
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let params = regtest_params();
        let mut buf = ForkBuffer::new(params.clone());

        let start_time = 1_700_000_000u32;
        let active = build_chain(start_time, 11, BlockHash::all_zeros());
        let ancestor_height = (active.len() as u32) - 1;
        let ancestor = *active.last().unwrap();

        // Gap well above 4×DASH_TARGET_SPACING (150s) so the min-difficulty
        // branch fires and returns the pow_limit bits, which equal `EASY_BITS`.
        let fork_time = ancestor.time + 750;
        let expected_min_bits =
            min_difficulty_bits(&params, ancestor.time, ancestor.bits, fork_time)
                .expect("gap > 4×spacing must produce min-difficulty bits");
        assert_eq!(expected_min_bits, CompactTarget::from_consensus(EASY_BITS));

        let fork_header = easy_header(ancestor.block_hash(), fork_time, 0);
        buf.ingest(peer, &[fork_header], ancestor_height, ancestor, &active)
            .expect("min-difficulty fork header must be accepted");
        assert_eq!(buf.len(), 1);
    }
}
