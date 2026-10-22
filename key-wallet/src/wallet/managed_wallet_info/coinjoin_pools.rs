//! Pre-generating CoinJoin address pools past the gap limit.
//!
//! A wallet migrated from DashSync can hold mixed coins on CoinJoin addresses
//! far past the gap limit. Extending its CoinJoin pools to a fixed depth
//! before the first sync from birth lets the regular sync find them.

use super::ManagedWalletInfo;
use crate::account::AccountType;
use crate::error::{Error, Result};
use crate::managed_account::address_pool::AddressPool;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::wallet::Wallet;
use crate::KeySource;

/// Upper bound (exclusive) for the `last_index` passed to
/// [`ManagedWalletInfo::extend_coinjoin_pools`], so a bad argument cannot
/// derive for ever.
///
/// The only DashSync log at hand reported 10,530 CoinJoin addresses derived
/// (both chains together). Deep pools are not free: every extra script is
/// matched against every compact filter (about 3% of blocks match falsely at
/// 12,000 per chain), and past about 18,000 scripts in total dash-spv's
/// size-capped mempool bloom filter runs above its target false-positive rate.
pub const MAX_COINJOIN_POOL_DEPTH: u32 = 25_000;

impl ManagedWalletInfo {
    /// Derive both pools of every CoinJoin account up to and including `last_index`.
    ///
    /// Only for fresh wallet state, before the first sync from the wallet's
    /// birth height and before its addresses are persisted: addresses added
    /// after a block was processed do not bring that block back, and the new
    /// addresses are reported nowhere but in the returned count. The pools stay
    /// that deep for the life of the wallet state.
    ///
    /// Returns the number of addresses generated; indices already in a pool are
    /// skipped. The depth, the wallet, the fresh state and every CoinJoin
    /// account's key source are checked before anything changes. A derivation
    /// error past that point leaves the pools grown partway (the revisions are
    /// still bumped); discard the wallet state then.
    pub fn extend_coinjoin_pools(&mut self, wallet: &Wallet, last_index: u32) -> Result<usize> {
        if last_index >= MAX_COINJOIN_POOL_DEPTH {
            return Err(Error::InvalidParameter(format!(
                "CoinJoin pool depth {last_index} must be below {MAX_COINJOIN_POOL_DEPTH}"
            )));
        }
        if wallet.wallet_id != self.wallet_id || wallet.network != self.network {
            return Err(Error::InvalidParameter(
                "the wallet does not own this wallet info".to_string(),
            ));
        }
        // ChainLocks are applied to every wallet whether it scanned or not, so
        // only the heights and recorded transactions prove a scan.
        let floor = self.metadata.birth_height.saturating_sub(1);
        let synced_past_birth =
            self.metadata.last_processed_height > floor || self.metadata.synced_height > floor;
        if synced_past_birth
            // `tx_count` also counts finalized transactions whose records were pruned.
            || self.accounts.all_accounts().into_iter().any(|account| account.tx_count() > 0)
        {
            return Err(Error::InvalidParameter(
                "CoinJoin pools can only be extended before the first sync".to_string(),
            ));
        }
        if self.accounts.coinjoin_accounts.is_empty() {
            return Err(Error::InvalidParameter("the wallet has no CoinJoin account".to_string()));
        }
        let mut key_sources = Vec::with_capacity(self.accounts.coinjoin_accounts.len());
        for index in self.accounts.coinjoin_accounts.keys() {
            let key_source = wallet.key_source_for_account(AccountType::CoinJoin {
                index: *index,
            });
            if matches!(key_source, KeySource::NoKeySource) {
                return Err(Error::NoKeySource);
            }
            key_sources.push(key_source);
        }

        let mut generated = 0;
        let mut outcome = Ok(());
        for (account, key_source) in self.accounts.coinjoin_accounts.values_mut().zip(&key_sources)
        {
            let mut account_generated = 0;
            outcome =
                account.managed_account_type_mut().address_pools_mut().into_iter().try_for_each(
                    |pool| fill_pool(pool, key_source, last_index, &mut account_generated),
                );
            if account_generated > 0 {
                account.bump_monitor_revision();
            }
            generated += account_generated;
            if outcome.is_err() {
                break;
            }
        }
        if generated > 0 {
            // Like an account add: a filter scan snapshot taken before this
            // call must not commit (see `rewind_sync_checkpoint_for_new_account`).
            self.account_generation += 1;
        }
        outcome.map(|()| generated)
    }
}

/// Derive every index of `pool` up to and including `last_index` that it does
/// not hold yet, counting each one in `generated` as it lands.
fn fill_pool(
    pool: &mut AddressPool,
    key_source: &KeySource,
    last_index: u32,
    generated: &mut usize,
) -> Result<()> {
    for index in 0..=last_index {
        if pool.info_at_index(index).is_none() {
            pool.generate_address_at_index(index, key_source, true)?;
            *generated += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_account::address_pool::AddressPoolType;
    use crate::transaction_checking::{BlockInfo, TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
    use crate::Network;
    use dashcore::hashes::Hash;
    use dashcore::{Address, BlockHash, Transaction};

    const DENOM: u64 = 100_001;
    const GAP: u32 = crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT;
    /// Far past the gap limit, shallow enough for debug test runs.
    const DEPTH: u32 = 2 * GAP + 50;

    fn fresh_with(
        network: Network,
        options: WalletAccountCreationOptions,
    ) -> (Wallet, ManagedWalletInfo) {
        let wallet = Wallet::from_seed_bytes([0x01; 64], network, options).expect("wallet");
        let managed = ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);
        (wallet, managed)
    }

    fn fresh(network: Network) -> (Wallet, ManagedWalletInfo) {
        fresh_with(network, WalletAccountCreationOptions::Default)
    }

    fn highest_generated(managed: &ManagedWalletInfo) -> Vec<Option<u32>> {
        managed
            .accounts
            .coinjoin_accounts
            .values()
            .flat_map(|account| account.managed_account_type().address_pools())
            .map(|pool| pool.highest_generated)
            .collect()
    }

    fn assert_rejected(managed: &mut ManagedWalletInfo, wallet: &Wallet) {
        let before = highest_generated(managed);
        assert!(matches!(
            managed.extend_coinjoin_pools(wallet, DEPTH),
            Err(Error::InvalidParameter(_) | Error::NoKeySource)
        ));
        assert_eq!(highest_generated(managed), before, "nothing may change on a rejection");
    }

    fn coinjoin_address(wallet: &Wallet, network: Network, internal: bool, index: u32) -> Address {
        let key_source = wallet.key_source_for_account(AccountType::CoinJoin {
            index: 0,
        });
        let mut scratch = AddressPool::new_without_generation(
            Default::default(),
            if internal {
                AddressPoolType::Internal
            } else {
                AddressPoolType::External
            },
            GAP,
            network,
        );
        scratch.generate_address_at_index(index, &key_source, false).expect("derive")
    }

    /// 32008: a coin far past the gap limit, in an old ChainLocked block, is
    /// credited by the regular check when the pools were extended through its
    /// index (inclusive), and missed one index past the depth.
    #[tokio::test]
    async fn coins_up_to_the_extended_depth_are_found() {
        for network in [Network::Mainnet, Network::Testnet] {
            for internal in [false, true] {
                for (index, expected) in [(DEPTH, DENOM), (DEPTH + 1, 0)] {
                    let (mut wallet, mut managed) = fresh(network);
                    let revision = managed.accounts.coinjoin_accounts[&0].monitor_revision();
                    let generation = managed.account_generation();
                    let generated = managed.extend_coinjoin_pools(&wallet, DEPTH).expect("extend");
                    assert_eq!(generated, 2 * (DEPTH + 1 - GAP) as usize);
                    assert!(managed.account_generation() > generation);
                    assert!(managed.accounts.coinjoin_accounts[&0].monitor_revision() > revision);

                    let far = coinjoin_address(&wallet, network, internal, index);
                    let tx = Transaction::dummy(&far, 0..1, &[DENOM]);
                    let context = TransactionContext::InChainLockedBlock(BlockInfo::new(
                        1,
                        BlockHash::from_byte_array([1; 32]),
                        1_650_000_000,
                    ));
                    let result =
                        managed.check_core_transaction(&tx, context, &mut wallet, true, true).await;
                    let case = format!("{network:?} internal={internal} index={index}");
                    assert_eq!(result.total_received, expected, "{case}");
                    assert_eq!(managed.balance().total(), expected, "{case}");
                }
            }
        }
    }

    #[test]
    fn extend_rejects_bad_arguments_and_state_without_changing_anything() {
        let (wallet, mut managed) = fresh(Network::Testnet);
        for last_index in [MAX_COINJOIN_POOL_DEPTH, u32::MAX] {
            assert!(matches!(
                managed.extend_coinjoin_pools(&wallet, last_index),
                Err(Error::InvalidParameter(_))
            ));
        }

        let (other, _) = fresh_with(Network::Mainnet, WalletAccountCreationOptions::Default);
        assert_rejected(&mut managed, &other);

        let (no_coinjoin, mut no_coinjoin_info) =
            fresh_with(Network::Testnet, WalletAccountCreationOptions::None);
        assert!(no_coinjoin_info.accounts.coinjoin_accounts.is_empty());
        assert_rejected(&mut no_coinjoin_info, &no_coinjoin);

        let (wallet, mut missing_key) = fresh(Network::Testnet);
        let extra = missing_key.accounts.coinjoin_accounts[&0].clone();
        missing_key.accounts.coinjoin_accounts.insert(1, extra);
        assert_rejected(&mut missing_key, &wallet);

        let (wallet, mut synced) = fresh(Network::Testnet);
        synced.metadata.last_processed_height = 10;
        assert_rejected(&mut synced, &wallet);

        let (wallet, mut other_network) = fresh(Network::Testnet);
        other_network.network = Network::Mainnet;
        assert_rejected(&mut other_network, &wallet);

        let (wallet, mut certified) = fresh(Network::Testnet);
        certified.metadata.synced_height = 10;
        assert_rejected(&mut certified, &wallet);
    }

    #[tokio::test]
    async fn extend_rejects_a_wallet_that_already_saw_a_transaction() {
        let chain_locked = TransactionContext::InChainLockedBlock(BlockInfo::new(
            1,
            BlockHash::from_byte_array([1; 32]),
            1_650_000_000,
        ));
        for context in [TransactionContext::Mempool, chain_locked] {
            let (mut wallet, mut managed) = fresh(Network::Testnet);
            let near = coinjoin_address(&wallet, Network::Testnet, false, 0);
            let tx = Transaction::dummy(&near, 0..1, &[DENOM]);
            managed.check_core_transaction(&tx, context, &mut wallet, true, true).await;
            assert_eq!(managed.metadata.last_processed_height, 0);
            assert_rejected(&mut managed, &wallet);
        }
    }
}
