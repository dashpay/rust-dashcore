//! Difficulty retargeting for Dash.
//!
//! Ports the Dark Gravity Wave v3 algorithm from `dashd`'s `pow.cpp`. Only the
//! DGW v3 branch is implemented because the staged-fork pipeline only ingests
//! forks at heights well past `nPowDGWHeight` on every network (34140 on
//! mainnet, 4001/4002 on testnet/regtest/devnet).

use dashcore::consensus::Params;
use dashcore::pow::U256;
use dashcore::{CompactTarget, Header, Network, Target};

/// Number of blocks DGW v3 averages over.
const DGW_PAST_BLOCKS: u32 = 24;

/// Dash target block spacing in seconds.
///
/// `dashcore::consensus::Params` inherits Bitcoin's 600s default. Dash mainnet,
/// testnet, regtest, and devnet all run at 150s (2.5 minutes), so DGW retargets
/// against that value, not the Params field.
const DASH_TARGET_SPACING: u64 = 150;

/// Compute the next nBits target using DGW v3.
///
/// `previous_headers` must contain at least the most recent `DGW_PAST_BLOCKS`
/// headers in chain order (oldest first, `previous_headers.last()` being the
/// tip the new block will extend). The `tip_height` is the height of the last
/// entry. Returns `pow_limit` for heights below the DGW window per the dashd
/// pre-window short-circuit.
///
/// Networks with retargeting disabled (`no_pow_retargeting`, regtest) or
/// without enough history return `pow_limit` directly, matching dashd's
/// behavior on those branches.
pub(crate) fn next_work_required_dgw_v3(
    previous_headers: &[Header],
    tip_height: u32,
    params: &Params,
) -> CompactTarget {
    let pow_limit_target = pow_limit_target(params.network);
    let pow_limit_bits = pow_limit_target.to_compact_lossy();

    if tip_height < DGW_PAST_BLOCKS {
        return pow_limit_bits;
    }

    if params.no_pow_retargeting {
        return pow_limit_bits;
    }

    // dashd's `fPowAllowMinDifficultyBlocks` branch (testnet/devnet/regtest)
    // reverts to `pow_limit` when the candidate block is too far in the future
    // of the tip. The staged-fork pipeline does not yet have the candidate
    // block's own time at this call site, so it falls through to the standard
    // DGW average, which is strictly stricter, never looser, than dashd's
    // rule. Fork acceptance can therefore only be over-cautious on those
    // networks, not under-cautious.

    if (previous_headers.len() as u32) < DGW_PAST_BLOCKS {
        return pow_limit_bits;
    }

    let window = &previous_headers[previous_headers.len() - DGW_PAST_BLOCKS as usize..];

    let mut past_target_avg = U256::ZERO;
    for (i, header) in window.iter().rev().enumerate() {
        let count = (i + 1) as u64;
        let target = U256::from_be_bytes(Target::from_compact(header.bits).to_be_bytes());
        if count == 1 {
            past_target_avg = target;
        } else {
            // past_target_avg = (past_target_avg * count + target) / (count + 1)
            //
            // dashd's arith_uint256 wraps on overflow here, which happens once
            // targets approach 2^255 (devnet pow_limit). Wrap the multiply and
            // add to match rather than tripping their debug_asserts.
            past_target_avg = past_target_avg.wrapping_mul(U256::from(count)).wrapping_add(target)
                / U256::from(count + 1);
        }
    }

    let last = window.last().expect("window length checked above");
    let first = window.first().expect("window length checked above");
    let actual = (last.time as i64 - first.time as i64).max(0) as u64;
    let target_timespan = (DGW_PAST_BLOCKS as u64) * DASH_TARGET_SPACING;

    let actual_clamped = actual.max(target_timespan / 3).min(target_timespan.saturating_mul(3));

    let mut bn_new =
        past_target_avg.wrapping_mul(U256::from(actual_clamped)) / U256::from(target_timespan);

    let limit = U256::from_be_bytes(pow_limit_target.to_be_bytes());
    if bn_new > limit {
        bn_new = limit;
    }

    Target::from_be_bytes(bn_new.to_be_bytes()).to_compact_lossy()
}

/// Check whether `candidate_time` triggers a min-difficulty exception for
/// networks where `allow_min_difficulty_blocks` is set (testnet, devnet).
///
/// Mirrors dashd's `fPowAllowMinDifficultyBlocks` branch in `GetNextWorkRequired`:
/// - If candidate time > prev tip time + 2h: return `pow_limit` bits.
/// - If candidate time > prev tip time + 4×spacing: return prev tip bits * 10
///   (clamped to `pow_limit`).
/// - Otherwise: return `None` (normal DGW applies).
pub(crate) fn min_difficulty_bits(
    params: &Params,
    prev_tip_time: u32,
    prev_tip_bits: CompactTarget,
    candidate_time: u32,
) -> Option<CompactTarget> {
    if !params.allow_min_difficulty_blocks {
        return None;
    }
    let pow_limit = pow_limit_target(params.network);
    let pow_limit_bits = pow_limit.to_compact_lossy();
    let gap = (candidate_time as i64 - prev_tip_time as i64).max(0) as u64;
    if gap > 2 * 60 * 60 {
        return Some(pow_limit_bits);
    }
    if gap > DASH_TARGET_SPACING * 4 {
        let prev_target = U256::from_be_bytes(Target::from_compact(prev_tip_bits).to_be_bytes());
        let limit = U256::from_be_bytes(pow_limit.to_be_bytes());
        // Clamp before multiplying to avoid 256-bit overflow: if prev_target is
        // already at or above pow_limit / 10, the result caps to pow_limit.
        let threshold = limit / U256::from(10_u64);
        let result = if prev_target >= threshold {
            limit
        } else {
            prev_target * U256::from(10_u64)
        };
        return Some(Target::from_be_bytes(result.to_be_bytes()).to_compact_lossy());
    }
    None
}

fn pow_limit_target(network: Network) -> Target {
    // dashcore stores network `pow_limit` as a `Work` value whose `to_target`
    // inverse does not match dashd's `consensus.powLimit` for the network
    // constants. Use the dashd values directly here so the DGW clamp uses the
    // same upper bound the network enforces.
    let mut bytes = [0u8; 32];
    match network {
        // dashd mainnet/testnet: uint256S("00000fffffff...ff"), ~2^236.
        Network::Mainnet | Network::Testnet => {
            bytes[2] = 0x0f;
            for b in bytes.iter_mut().skip(3) {
                *b = 0xff;
            }
        }
        // dashd regtest/devnet: uint256S("7fffffff...ff"), ~2^255.
        Network::Regtest | Network::Devnet => {
            bytes[0] = 0x7f;
            for b in bytes.iter_mut().skip(1) {
                *b = 0xff;
            }
        }
    }
    Target::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use dashcore::block::Version;
    use dashcore::{BlockHash, CompactTarget, Header, TxMerkleNode};
    use dashcore_hashes::Hash;

    use super::*;

    fn synthetic_header(bits: u32, time: u32) -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        }
    }

    fn pow_limit_compact(params: &Params) -> CompactTarget {
        pow_limit_target(params.network).to_compact_lossy()
    }

    #[test]
    fn pow_limit_compact_matches_dashd_constants() {
        // dashd `consensus.powLimit`: mainnet/testnet is
        // uint256S("00000fffffff...ff") with compact 0x1e0fffff, regtest/devnet
        // is uint256S("7fffffff...ff") with compact 0x207fffff.
        assert_eq!(
            pow_limit_target(Network::Mainnet).to_compact_lossy(),
            CompactTarget::from_consensus(0x1e0fffff)
        );
        assert_eq!(
            pow_limit_target(Network::Testnet).to_compact_lossy(),
            CompactTarget::from_consensus(0x1e0fffff)
        );
        assert_eq!(
            pow_limit_target(Network::Regtest).to_compact_lossy(),
            CompactTarget::from_consensus(0x207fffff)
        );
        assert_eq!(
            pow_limit_target(Network::Devnet).to_compact_lossy(),
            CompactTarget::from_consensus(0x207fffff)
        );
    }

    #[test]
    fn pow_limit_returned_below_window() {
        let params = Params::new(Network::Mainnet);
        let bits = next_work_required_dgw_v3(&[], 10, &params);
        assert_eq!(bits, pow_limit_compact(&params));
    }

    #[test]
    fn pow_limit_returned_for_regtest_no_retargeting() {
        let params = Params::new(Network::Regtest);
        let window: Vec<Header> = (0..DGW_PAST_BLOCKS)
            .map(|i| synthetic_header(0x1d00ffff, 100 + i * DASH_TARGET_SPACING as u32))
            .collect();
        let bits = next_work_required_dgw_v3(&window, 100, &params);
        assert_eq!(bits, pow_limit_compact(&params));
    }

    #[test]
    fn constant_difficulty_window_tightens_slightly() {
        // 24 blocks at exactly target spacing. Because dashd's DGW only counts
        // 23 intervals over 24 blocks, the new target trends slightly stricter
        // (~23/24) even on a perfectly on-pace window. This is the documented
        // bias in `pow.cpp`. We assert the direction and magnitude rather than
        // strict equality.
        let params = Params::new(Network::Mainnet);
        let spacing = DASH_TARGET_SPACING as u32;
        let bits = 0x1b0404cb_u32;
        let window: Vec<Header> = (0..DGW_PAST_BLOCKS)
            .map(|i| synthetic_header(bits, 1_500_000_000 + i * spacing))
            .collect();

        let next = next_work_required_dgw_v3(&window, 100_000, &params);
        let next_target = Target::from_compact(next);
        let in_target = Target::from_compact(CompactTarget::from_consensus(bits));
        assert!(
            next_target < in_target,
            "DGW bias should yield a strictly tighter target on steady spacing"
        );
        // The expected factor is 23/24, so the new target should be at least 90% of the old.
        // We bound via a scaled comparison: in_target * 9 / 10 < next_target < in_target.
        let scaled_floor =
            U256::from_be_bytes(in_target.to_be_bytes()) * U256::from(9_u64) / U256::from(10_u64);
        let next_u = U256::from_be_bytes(next_target.to_be_bytes());
        assert!(
            next_u > scaled_floor,
            "DGW bias should be modest (< 10%), got {:?} vs input {:?}",
            next,
            bits
        );
    }

    #[test]
    fn devnet_pow_limit_window_does_not_overflow() {
        // Devnet retargets and its pow_limit sits near 2^255, so averaging a
        // full window multiplies values that overflow 256 bits. dashd's
        // arith_uint256 wraps silently there; this must return without tripping
        // the `Mul` debug_assert and stay clamped at or below pow_limit.
        let params = Params::new(Network::Devnet);
        let pow_limit_bits = pow_limit_compact(&params);
        let spacing = DASH_TARGET_SPACING as u32;
        let window: Vec<Header> = (0..DGW_PAST_BLOCKS)
            .map(|i| synthetic_header(pow_limit_bits.to_consensus(), 1_500_000_000 + i * spacing))
            .collect();

        let next = next_work_required_dgw_v3(&window, 100_000, &params);

        let next_u = U256::from_be_bytes(Target::from_compact(next).to_be_bytes());
        let limit_u = U256::from_be_bytes(pow_limit_target(params.network).to_be_bytes());
        assert!(next_u <= limit_u, "devnet DGW output must stay clamped at or below pow_limit");
    }

    #[test]
    fn fast_blocks_raise_difficulty() {
        // Blocks half the spacing apart should lower the target (raise difficulty).
        let params = Params::new(Network::Mainnet);
        let spacing = (DASH_TARGET_SPACING / 2) as u32;
        let bits = 0x1b0404cb_u32;
        let window: Vec<Header> = (0..DGW_PAST_BLOCKS)
            .map(|i| synthetic_header(bits, 1_500_000_000 + i * spacing))
            .collect();
        let next = next_work_required_dgw_v3(&window, 100_000, &params);

        let next_target = Target::from_compact(next);
        let prev_target = Target::from_compact(CompactTarget::from_consensus(bits));
        assert!(
            next_target < prev_target,
            "fast blocks should produce stricter target: next {:?} >= prev {:#x}",
            next,
            bits
        );
    }

    #[test]
    fn slow_blocks_lower_difficulty() {
        // Blocks 2x apart should raise the target (lower difficulty).
        let params = Params::new(Network::Mainnet);
        let spacing = (DASH_TARGET_SPACING * 2) as u32;
        let bits = 0x1b0404cb_u32;
        let window: Vec<Header> = (0..DGW_PAST_BLOCKS)
            .map(|i| synthetic_header(bits, 1_500_000_000 + i * spacing))
            .collect();
        let next = next_work_required_dgw_v3(&window, 100_000, &params);

        let next_target = Target::from_compact(next);
        let prev_target = Target::from_compact(CompactTarget::from_consensus(bits));
        assert!(
            next_target > prev_target,
            "slow blocks should produce looser target: next {:?} <= prev {:#x}",
            next,
            bits
        );
    }
}
