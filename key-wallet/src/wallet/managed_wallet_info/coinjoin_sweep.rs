//! CoinJoin sweep + one-time gap-limit recovery.
//!
//! Supports the DashSync → SwiftDashSDK migration: CoinJoin ("mixed coins") is
//! being dropped post-migration, so this lets a wallet **find** its scattered
//! mixed coins (recovery) and **sweep** them back into spendable balance.
//!
//! ## Sweep
//!
//! [`ManagedCoreFundsAccount::build_coinjoin_sweep_txs`] drains the *entire*
//! spendable balance of a CoinJoin account into a single destination address,
//! leaving no change. The UTXO set is split into balanced chunks of at most
//! [`MAX_INPUTS_PER_SWEEP`] inputs so no transaction exceeds the standard relay
//! size limit (a heavy mixer can hold thousands of small mixed-coin UTXOs); each
//! chunk spends a *disjoint* slice, so the transactions have no inter-dependency
//! and may broadcast in any order. Each chunk is built with
//! [`TransactionBuilder::sweep_to`], which consumes every input into one
//! no-change output (`total − fee`) — unlike normal coin selection, which would
//! re-select a covering subset and leave small UTXOs behind.
//!
//! DashSync CoinJoin puts mixing *change* on the internal chain (`.../1/i`), but
//! the SDK's CoinJoin account models only the external chain (`.../0/i`). Such
//! internal-chain coins are owned and spendable yet have no derivation path in
//! the account, so the sweep re-derives an address → path map across *both*
//! chains from the account xpub (see [`coinjoin_sweep_path_map`]) and signs every
//! input regardless of chain.
//!
//! ## Recovery
//!
//! [`ManagedCoreFundsAccount::set_coinjoin_gap_limit`] widens the CoinJoin pool's
//! gap limit and materializes the addresses so SPV watches the wider window —
//! DashSync used a gap of 400 versus the SDK default of 30, so a fresh scan would
//! otherwise miss deep mixed coins sitting past index 30.

use std::collections::{HashMap, HashSet};

use dashcore::{Address, Transaction};

use crate::account::account_type::AccountType;
use crate::gap_limit::MAX_GAP_LIMIT;
use crate::managed_account::address_pool::{AddressPool, AddressPoolType, KeySource};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::ManagedCoreFundsAccount;
use crate::signer::Signer;
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::wallet::managed_wallet_info::transaction_builder::{BuilderError, TransactionBuilder};
use crate::{ChildNumber, DerivationPath, ExtendedPubKey, Network, Utxo};

/// Max inputs per CoinJoin sweep transaction. A single Dash transaction must
/// stay under the standard relay/mempool size limit (`MAX_STANDARD_TX_SIZE` =
/// 100 000 B); at ~149 B/input that is ~670 inputs, so 500 leaves a comfortable
/// margin for the output + overhead. A heavy mixer's UTXOs are therefore swept
/// across `ceil(N / MAX_INPUTS_PER_SWEEP)` transactions rather than one
/// oversized, unrelayable transaction.
pub const MAX_INPUTS_PER_SWEEP: usize = 500;

/// Per-chain index ceiling for the sweep path resolver. A heavy mixer's CoinJoin
/// indices sit well under this; the cap only bounds the (never-hit-in-practice)
/// unresolved case so the search terminates.
pub const COINJOIN_SWEEP_MAX_INDEX: u32 = 20_000;

/// Errors from CoinJoin sweep / recovery.
#[derive(Debug)]
pub enum CoinJoinSweepError {
    /// Transaction building or signing failed.
    Build(BuilderError),
    /// An address-pool / derivation operation failed.
    AddressPool(String),
    /// The CoinJoin account has no spendable UTXOs to sweep.
    NoUtxos,
    /// The requested gap limit is zero (would underflow the pool).
    InvalidGapLimit,
    /// The destination address is not valid for the wallet's network.
    InvalidDestination(Network),
    /// One or more input addresses could not be resolved to a derivation path
    /// on either CoinJoin chain within `max_index`.
    UnresolvedInputs { count: usize, max_index: u32 },
    /// The signer did not consume every UTXO in a chunk (the no-change output
    /// amount would be wrong), so the chunk was aborted before broadcast.
    UnderConsumed { signed: usize, expected: usize },
}

impl std::fmt::Display for CoinJoinSweepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Build(e) => write!(f, "CoinJoin sweep build error: {e}"),
            Self::AddressPool(e) => write!(f, "CoinJoin address operation failed: {e}"),
            Self::NoUtxos => write!(f, "no spendable CoinJoin UTXOs to sweep"),
            Self::InvalidGapLimit => write!(f, "CoinJoin gap limit must be greater than zero"),
            Self::InvalidDestination(network) => {
                write!(f, "CoinJoin sweep destination is not valid for the wallet network {network:?}")
            }
            Self::UnresolvedInputs { count, max_index } => write!(
                f,
                "CoinJoin sweep: {count} input address(es) have no derivation path on either \
                 CoinJoin chain (within {max_index} indices)"
            ),
            Self::UnderConsumed { signed, expected } => write!(
                f,
                "CoinJoin sweep chunk must consume every UTXO in the chunk: \
                 signed {signed} inputs, expected {expected}"
            ),
        }
    }
}

impl std::error::Error for CoinJoinSweepError {}

impl From<BuilderError> for CoinJoinSweepError {
    fn from(e: BuilderError) -> Self {
        Self::Build(e)
    }
}

/// Balanced input count per sweep transaction for `total` spendable UTXOs, so
/// that `utxos.chunks(sweep_chunk_size(total))` yields `ceil(total /
/// MAX_INPUTS_PER_SWEEP)` near-equal chunks, each within `MAX_INPUTS_PER_SWEEP`.
///
/// Using a ceil-divided chunk size keeps chunks near-equal (e.g. 501 → 251 +
/// 250, not 500 + 1), so no chunk is a lone sub-fee dust input. `total` must be
/// greater than zero (the sweep early-returns on an empty UTXO set).
fn sweep_chunk_size(total: usize) -> usize {
    debug_assert!(total > 0, "sweep_chunk_size requires at least one UTXO");
    let num_chunks = total.div_ceil(MAX_INPUTS_PER_SWEEP);
    total.div_ceil(num_chunks)
}

/// Build an `address → absolute derivation path` map covering every address in
/// `needed_addrs` across BOTH CoinJoin chains — external (`/0/`) and internal
/// (`/1/`) — derived from the account's public xpub. `account_path` is the
/// hardened account path `m/9'/coin'/4'/account'`.
///
/// The SDK's CoinJoin account models only the external chain, but DashSync
/// CoinJoin puts mixing *change* on the internal chain. A migrated wallet's
/// internal-chain mixed coins are imported as spendable UTXOs yet have no
/// derivation path in the account, so signing a sweep that includes them fails
/// with "no derivation path for input address". This re-derives both chains
/// (non-hardened, public-key-only) and returns each input's absolute path so the
/// signer can sign every input regardless of chain.
///
/// Returns [`CoinJoinSweepError::UnresolvedInputs`] if any address can't be
/// resolved within `max_index` on either chain — defensive, so a sweep never
/// silently mis-signs or drops an input.
fn coinjoin_sweep_path_map(
    account_path: &DerivationPath,
    key_source: &KeySource,
    network: Network,
    needed_addrs: &[Address],
    max_index: u32,
) -> Result<HashMap<Address, DerivationPath>, CoinJoinSweepError> {
    const BATCH: u32 = 500;

    let mut needed: HashSet<Address> = needed_addrs.iter().cloned().collect();
    let mut path_map: HashMap<Address, DerivationPath> = HashMap::new();

    // chain 0 = external (receive / denominations), chain 1 = internal (change).
    for (chain, pool_type) in [
        (0u32, AddressPoolType::External),
        (1u32, AddressPoolType::Internal),
    ] {
        if needed.is_empty() {
            break;
        }
        let mut base = account_path.clone();
        base.push(
            ChildNumber::from_normal_idx(chain)
                .map_err(|e| CoinJoinSweepError::AddressPool(e.to_string()))?,
        );
        // Empty pool (NoKeySource skips generation); we generate below with the
        // real public key source so each `AddressInfo` carries its full path.
        let mut pool = AddressPool::new(base, pool_type, 0, network, &KeySource::NoKeySource)
            .map_err(|e| CoinJoinSweepError::AddressPool(e.to_string()))?;

        let mut generated = 0u32;
        while generated < max_index && !needed.is_empty() {
            let batch = pool
                .generate_addresses(BATCH, key_source, true)
                .map_err(|e| CoinJoinSweepError::AddressPool(e.to_string()))?;
            for addr in &batch {
                // Only drop from `needed` once the path is actually recorded, so
                // "removed from needed ⇒ inserted into path_map" holds by
                // construction. If `address_info` ever returned None for a
                // freshly generated address (an AddressPool invariant break), the
                // address stays in `needed` and the check below errors loudly
                // rather than silently dropping it into a mid-sign failure.
                if needed.contains(addr) {
                    if let Some(info) = pool.address_info(addr) {
                        path_map.insert(addr.clone(), info.path.clone());
                        needed.remove(addr);
                    }
                }
            }
            generated += BATCH;
        }
    }

    if !needed.is_empty() {
        return Err(CoinJoinSweepError::UnresolvedInputs {
            count: needed.len(),
            max_index,
        });
    }

    Ok(path_map)
}

impl ManagedCoreFundsAccount {
    /// Sweep the *entire* spendable balance of this CoinJoin account to `dest`,
    /// leaving no change behind, across one or more transactions.
    ///
    /// `account_xpub` is the account's watch-only public xpub (the account does
    /// not store it); it is used only to re-derive signing paths across both
    /// CoinJoin chains — no private key crosses any boundary. Returns the signed
    /// transactions in chunk order; the caller broadcasts them (they are
    /// disjoint, so order is irrelevant and a partial broadcast can be re-run).
    ///
    /// Fails if the destination is invalid for this account's network, there are
    /// no spendable UTXOs, an input address can't be resolved on either chain, or
    /// the signer fails to consume every UTXO in a chunk.
    pub async fn build_coinjoin_sweep_txs<S: Signer>(
        &self,
        account_xpub: ExtendedPubKey,
        current_height: u32,
        dest: Address,
        signer: &S,
    ) -> Result<Vec<Transaction>, CoinJoinSweepError> {
        let network = self.network();

        // Fund-safety invariant owned by the sweep itself: the drain is
        // irreversible, so refuse a destination that isn't valid on this network.
        if !dest.as_unchecked().is_valid_for_network(network) {
            return Err(CoinJoinSweepError::InvalidDestination(network));
        }

        // Snapshot every spendable UTXO — the sweep consumes all of them.
        let utxos: Vec<Utxo> = self
            .spendable_utxos(current_height)
            .into_iter()
            .cloned()
            .collect();
        if utxos.is_empty() {
            return Err(CoinJoinSweepError::NoUtxos);
        }

        // Resolve an absolute derivation path for every input address across BOTH
        // CoinJoin chains (external /0/ and internal /1/) so the signer can sign
        // internal-chain ("change") mixed coins too. Errors if any input can't be
        // resolved on either chain rather than failing mid-sign.
        let account_path = AccountType::CoinJoin {
            index: self.index_or_default(),
        }
        .derivation_path(network)
        .map_err(|e| CoinJoinSweepError::AddressPool(e.to_string()))?;
        let key_source = KeySource::Public(account_xpub);
        let input_addresses: Vec<Address> = utxos.iter().map(|u| u.address.clone()).collect();
        let path_map = coinjoin_sweep_path_map(
            &account_path,
            &key_source,
            network,
            &input_addresses,
            COINJOIN_SWEEP_MAX_INDEX,
        )?;

        // Balanced chunks of <= MAX_INPUTS_PER_SWEEP so no transaction exceeds the
        // relay size limit. `chunks()` over disjoint slices guarantees each UTXO
        // is consumed by exactly one transaction.
        let chunk_size = sweep_chunk_size(utxos.len());
        let mut signed_txs = Vec::with_capacity(utxos.len().div_ceil(chunk_size));

        for chunk in utxos.chunks(chunk_size) {
            let input_count = chunk.len();

            // `sweep_to` consumes every added input into one no-change output
            // (`total − fee`); the path resolver covers both chains.
            let (tx, _fee) = TransactionBuilder::new()
                .set_fee_rate(FeeRate::normal())
                .add_inputs(chunk.iter().cloned())
                .sweep_to(&dest)
                .build_signed(signer, |addr| path_map.get(&addr).cloned())
                .await?;

            // Fund-safety invariant: the single output is `total_input − fee`,
            // which is only correct if the signer consumed every UTXO in the
            // chunk. Abort the chunk rather than broadcast an under-consuming tx.
            if tx.input.len() != input_count {
                return Err(CoinJoinSweepError::UnderConsumed {
                    signed: tx.input.len(),
                    expected: input_count,
                });
            }
            signed_txs.push(tx);
        }

        Ok(signed_txs)
    }

    /// Widen this CoinJoin account's single-pool gap limit to `gap_limit` and
    /// generate addresses so indices up to `highest_used + gap_limit` exist and
    /// are watched by SPV. Returns the pool's highest generated index.
    ///
    /// `account_xpub` is the account's watch-only public xpub, used to derive the
    /// pool's addresses (non-hardened, public-key-only — no private key crosses
    /// any boundary).
    ///
    /// Setting the gap limit alone is not enough: SPV only watches addresses
    /// materialized into the pool's script index, so pre-generating the wide
    /// window (via [`AddressPool::maintain_gap_limit`]) is what lets a recovery
    /// scan find scattered mixed coins. The widened limit is in-memory only — a
    /// later wallet load reconstructs the pool at the default gap, which is the
    /// intended "revert after recovery" behavior.
    ///
    /// Rejects a zero gap limit: [`AddressPool::maintain_gap_limit`] computes
    /// `gap_limit - 1` when no address has been used yet, which underflows at 0
    /// (debug panic / release wrap to `u32::MAX` → unbounded address generation).
    pub fn set_coinjoin_gap_limit(
        &mut self,
        account_xpub: ExtendedPubKey,
        gap_limit: u32,
    ) -> Result<u32, CoinJoinSweepError> {
        let gap_limit = gap_limit.min(MAX_GAP_LIMIT);
        if gap_limit == 0 {
            return Err(CoinJoinSweepError::InvalidGapLimit);
        }
        let key_source = KeySource::Public(account_xpub);

        // CoinJoin uses a single address pool. Widen the gap limit, then
        // materialize addresses up to it. Scope the pool borrow so it ends before
        // `bump_monitor_revision` reborrows the account.
        let new_highest = {
            let mut pools = self.managed_account_type_mut().address_pools_mut();
            let pool = pools.first_mut().ok_or_else(|| {
                CoinJoinSweepError::AddressPool("CoinJoin account has no address pool".to_string())
            })?;
            pool.gap_limit = gap_limit;
            pool.maintain_gap_limit(&key_source)
                .map_err(|e| CoinJoinSweepError::AddressPool(e.to_string()))?;
            pool.highest_generated.unwrap_or(0)
        };

        // The watched-address set changed — bump the revision so the SPV
        // compact-filter / bloom filter is rebuilt to include the new scripts.
        self.bump_monitor_revision();

        Ok(new_highest)
    }
}

#[cfg(test)]
mod sweep_chunking_tests {
    use super::{sweep_chunk_size, MAX_INPUTS_PER_SWEEP};

    /// The chunk plan must, for any UTXO count: produce `ceil(total / MAX)`
    /// transactions, keep every chunk within `MAX` inputs, and consume every
    /// UTXO exactly once (disjoint slices that sum back to `total`).
    #[test]
    fn partitions_every_utxo_within_the_relay_cap() {
        for &total in &[
            1usize, 30, 499, 500, 501, 675, 999, 1000, 1001, 1499, 5000, 12_345,
        ] {
            let chunk_size = sweep_chunk_size(total);
            let sizes: Vec<usize> = (0..total)
                .collect::<Vec<_>>()
                .chunks(chunk_size)
                .map(|c| c.len())
                .collect();

            let expected_chunks = total.div_ceil(MAX_INPUTS_PER_SWEEP);
            assert_eq!(sizes.len(), expected_chunks, "tx count for {total} UTXOs");
            assert_eq!(
                sizes.iter().sum::<usize>(),
                total,
                "every UTXO consumed exactly once for {total}"
            );
            assert!(
                sizes
                    .iter()
                    .all(|&n| (1..=MAX_INPUTS_PER_SWEEP).contains(&n)),
                "every chunk within [1, {MAX_INPUTS_PER_SWEEP}] for {total}: {sizes:?}"
            );
        }
    }
}

#[cfg(test)]
mod coinjoin_sweep_path_map_tests {
    use super::coinjoin_sweep_path_map;
    use crate::account::account_type::AccountType;
    use crate::managed_account::address_pool::{AddressPool, AddressPoolType, KeySource};
    use crate::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Network};
    use secp256k1::Secp256k1;

    fn coinjoin_account(network: Network, seed_byte: u8) -> (ExtendedPubKey, DerivationPath) {
        let secp = Secp256k1::new();
        let master = ExtendedPrivKey::new_master(network, &[seed_byte; 32]).unwrap();
        let account_path = AccountType::CoinJoin { index: 0 }
            .derivation_path(network)
            .unwrap();
        let account_xpriv = master.derive_priv(&secp, &account_path).unwrap();
        (
            ExtendedPubKey::from_priv(&secp, &account_xpriv),
            account_path,
        )
    }

    /// Derive `<account_path>/<chain>/<index>` the way the resolver does, to get
    /// a known target address to look up.
    fn derive_addr(
        xpub: &ExtendedPubKey,
        account_path: &DerivationPath,
        network: Network,
        chain: u32,
        index: u32,
    ) -> dashcore::Address {
        let pool_type = if chain == 0 {
            AddressPoolType::External
        } else {
            AddressPoolType::Internal
        };
        let mut base = account_path.clone();
        base.push(ChildNumber::from_normal_idx(chain).unwrap());
        let mut pool =
            AddressPool::new(base, pool_type, 0, network, &KeySource::NoKeySource).unwrap();
        let addrs = pool
            .generate_addresses(index + 1, &KeySource::Public(*xpub), true)
            .unwrap();
        addrs[index as usize].clone()
    }

    fn abs_path(account_path: &DerivationPath, chain: u32, index: u32) -> DerivationPath {
        let mut p = account_path.clone();
        p.push(ChildNumber::from_normal_idx(chain).unwrap());
        p.push(ChildNumber::from_normal_idx(index).unwrap());
        p
    }

    /// Both an external (/0/) and an internal (/1/) CoinJoin address resolve to
    /// their correct absolute paths — the internal case is the bug this fixes.
    #[test]
    fn resolves_external_and_internal_chain_addresses() {
        let network = Network::Testnet;
        let (xpub, account_path) = coinjoin_account(network, 7);
        let key_source = KeySource::Public(xpub);

        let external = derive_addr(&xpub, &account_path, network, 0, 7);
        let internal = derive_addr(&xpub, &account_path, network, 1, 42);

        let map = coinjoin_sweep_path_map(
            &account_path,
            &key_source,
            network,
            &[external.clone(), internal.clone()],
            200,
        )
        .unwrap();

        assert_eq!(map.get(&external), Some(&abs_path(&account_path, 0, 7)));
        assert_eq!(map.get(&internal), Some(&abs_path(&account_path, 1, 42)));
    }

    /// An address not derivable from this account xpub on either chain yields the
    /// defensive error (here: a different wallet's CoinJoin address).
    #[test]
    fn errors_when_an_input_address_is_unresolvable() {
        let network = Network::Testnet;
        let (xpub, account_path) = coinjoin_account(network, 7);
        let key_source = KeySource::Public(xpub);

        let (other_xpub, other_path) = coinjoin_account(network, 9);
        let foreign = derive_addr(&other_xpub, &other_path, network, 0, 3);

        let result = coinjoin_sweep_path_map(&account_path, &key_source, network, &[foreign], 200);
        assert!(result.is_err(), "foreign address must not resolve");
    }
}
