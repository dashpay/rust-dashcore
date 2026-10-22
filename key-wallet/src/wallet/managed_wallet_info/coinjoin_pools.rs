//! Pre-generating CoinJoin address pools past the gap limit.
//!
//! A wallet migrated from DashSync can hold mixed coins on CoinJoin addresses
//! far past the gap limit. Extending its CoinJoin pools to a fixed depth
//! before the first sync from birth lets the regular sync find them;
//! trimming afterwards drops the unused tail again.

use super::ManagedWalletInfo;
use crate::account::AccountType;
use crate::error::Result;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::wallet::Wallet;
use crate::KeySource;

impl ManagedWalletInfo {
    /// Derive both pools of every CoinJoin account up to and including `last_index`.
    ///
    /// Call it on fresh wallet state, before the first sync from the wallet's
    /// birth height: addresses added after a block was processed do not bring
    /// that block back. Returns the number of addresses generated.
    pub fn extend_coinjoin_pools(&mut self, wallet: &Wallet, last_index: u32) -> Result<usize> {
        let mut generated = 0;
        for (index, account) in self.accounts.coinjoin_accounts.iter_mut() {
            let key_source = wallet.key_source_for_account(AccountType::CoinJoin {
                index: *index,
            });
            if matches!(key_source, KeySource::NoKeySource) {
                continue;
            }
            let mut account_generated = 0;
            for pool in account.managed_account_type_mut().address_pools_mut() {
                let start = pool.stats().highest_generated.map_or(0, |h| h + 1);
                if start <= last_index {
                    account_generated +=
                        pool.generate_addresses(last_index - start + 1, &key_source, true)?.len();
                }
            }
            if account_generated > 0 {
                account.bump_monitor_revision();
            }
            generated += account_generated;
        }
        Ok(generated)
    }

    /// Drop the unused addresses past the highest used one plus the gap limit
    /// from every CoinJoin pool. Returns the number of addresses removed.
    pub fn trim_coinjoin_pools(&mut self) -> u32 {
        let mut pruned = 0;
        for account in self.accounts.coinjoin_accounts.values_mut() {
            let mut account_pruned = 0;
            for pool in account.managed_account_type_mut().address_pools_mut() {
                account_pruned += pool.prune_unused();
            }
            if account_pruned > 0 {
                account.bump_monitor_revision();
            }
            pruned += account_pruned;
        }
        pruned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_account::address_pool::{AddressPool, AddressPoolType};
    use crate::transaction_checking::{BlockInfo, TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
    use crate::Network;
    use dashcore::hashes::Hash;
    use dashcore::{Address, BlockHash, Transaction};

    const NETWORK: Network = Network::Testnet;
    const DENOM: u64 = 100_001;
    const GAP: u32 = crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT;
    /// Deep enough to sit far past the gap limit, shallow enough for debug test runs.
    const DEPTH: u32 = 2_999;

    fn fresh() -> (Wallet, ManagedWalletInfo) {
        let wallet =
            Wallet::new_random(NETWORK, WalletAccountCreationOptions::Default).expect("wallet");
        let managed = ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);
        (wallet, managed)
    }

    fn pool(managed: &ManagedWalletInfo, pool_type: AddressPoolType) -> &AddressPool {
        managed
            .accounts
            .coinjoin_accounts
            .get(&0)
            .expect("CoinJoin account")
            .managed_account_type()
            .address_pools()
            .into_iter()
            .find(|pool| pool.pool_type == pool_type)
            .expect("pool")
    }

    fn coinjoin_address(wallet: &Wallet, internal: bool, index: u32) -> Address {
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
            NETWORK,
        );
        scratch.generate_address_at_index(index, &key_source, false).expect("derive")
    }

    fn block(height: u32) -> TransactionContext {
        TransactionContext::InBlock(BlockInfo::new(
            height,
            BlockHash::from_byte_array([height as u8; 32]),
            1_650_000_000 + height,
        ))
    }

    #[test]
    fn extend_derives_both_chains_to_the_depth_and_is_idempotent() {
        let (wallet, mut managed) = fresh();
        let generated = managed.extend_coinjoin_pools(&wallet, 1_999).expect("extend");
        assert_eq!(generated, 2 * 2_000 - 2 * GAP as usize);
        for pool_type in [AddressPoolType::External, AddressPoolType::Internal] {
            assert_eq!(pool(&managed, pool_type).stats().highest_generated, Some(1_999));
            assert_eq!(pool(&managed, pool_type).stats().total_generated, 2_000);
        }
        assert_eq!(managed.extend_coinjoin_pools(&wallet, 1_999).expect("again"), 0);
        assert_eq!(managed.extend_coinjoin_pools(&wallet, 10).expect("shallower"), 0);
    }

    #[test]
    fn extend_leaves_other_accounts_alone() {
        let (wallet, mut managed) = fresh();
        let before: Vec<_> = managed
            .accounts
            .standard_bip44_accounts
            .values()
            .map(|a| a.managed_account_type().address_pools()[0].stats().total_generated)
            .collect();
        managed.extend_coinjoin_pools(&wallet, 999).expect("extend");
        let after: Vec<_> = managed
            .accounts
            .standard_bip44_accounts
            .values()
            .map(|a| a.managed_account_type().address_pools()[0].stats().total_generated)
            .collect();
        assert_eq!(before, after);
    }

    /// 32008: a coin far past the gap limit on either chain is credited by the
    /// regular check once the pools are extended past it, and missed without.
    #[tokio::test]
    async fn coins_past_the_gap_are_found_only_after_extending() {
        for internal in [false, true] {
            let far_index = DEPTH - 1;
            for extend in [false, true] {
                let (mut wallet, mut managed) = fresh();
                if extend {
                    managed.extend_coinjoin_pools(&wallet, DEPTH).expect("extend");
                }
                let far = coinjoin_address(&wallet, internal, far_index);
                let tx = Transaction::dummy(&far, 0..1, &[DENOM]);
                let result =
                    managed.check_core_transaction(&tx, block(1), &mut wallet, true, true).await;
                let expected = if extend {
                    DENOM
                } else {
                    0
                };
                assert_eq!(result.total_received, expected, "internal={internal} extend={extend}");
                assert_eq!(managed.balance().total(), expected);
            }
        }
    }

    #[tokio::test]
    async fn trim_keeps_used_addresses_and_the_gap() {
        let (mut wallet, mut managed) = fresh();
        managed.extend_coinjoin_pools(&wallet, DEPTH).expect("extend");
        let used = 2_500;
        let far = coinjoin_address(&wallet, false, used);
        let tx = Transaction::dummy(&far, 0..1, &[DENOM]);
        managed.check_core_transaction(&tx, block(1), &mut wallet, true, true).await;

        let pruned = managed.trim_coinjoin_pools();
        assert_eq!(pruned, (DEPTH - (used + GAP)) + (DEPTH - (GAP - 1)));
        let external = pool(&managed, AddressPoolType::External);
        assert_eq!(external.stats().highest_generated, Some(used + GAP));
        assert!(external.info_at_index(used).is_some_and(|info| info.is_used()));
        assert_eq!(
            pool(&managed, AddressPoolType::Internal).stats().highest_generated,
            Some(GAP - 1)
        );
        assert_eq!(managed.balance().total(), DENOM, "trimming must not touch the balance");
        assert_eq!(managed.trim_coinjoin_pools(), 0);
    }
}
