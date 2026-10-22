//! Pre-generating CoinJoin address pools past the gap limit.
//!
//! A wallet migrated from DashSync can hold mixed coins on CoinJoin addresses
//! far past the gap limit. Extending its CoinJoin pools to a fixed depth
//! before the first sync from birth lets the regular sync find them.

use super::ManagedWalletInfo;
use crate::account::AccountType;
use crate::error::{Error, Result};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::wallet::Wallet;
use crate::KeySource;

/// Upper bound (exclusive) for the `last_index` passed to
/// [`ManagedWalletInfo::extend_coinjoin_pools`]. DashSync derived about
/// 10,500 CoinJoin addresses per chain on the deepest wallets seen; much
/// deeper pools saturate dash-spv's size-capped mempool bloom filter.
pub const MAX_COINJOIN_POOL_DEPTH: u32 = 25_000;

impl ManagedWalletInfo {
    /// Derive both pools of every CoinJoin account up to and including `last_index`.
    ///
    /// Call it on fresh wallet state, before the first sync from the wallet's
    /// birth height and before the wallet's addresses are persisted: addresses
    /// added after a block was processed do not bring that block back, and the
    /// new addresses are not reported anywhere but in the returned count. The
    /// pools stay that deep for the life of the wallet state.
    ///
    /// Returns the number of addresses generated. The depth, the wallet and
    /// every CoinJoin account's key source are checked before anything changes.
    /// A derivation error past that point leaves the pools grown partway (the
    /// accounts that grew still get their monitor revision bumped); discard the
    /// wallet state then, as it is no longer fresh.
    pub fn extend_coinjoin_pools(&mut self, wallet: &Wallet, last_index: u32) -> Result<usize> {
        if last_index >= MAX_COINJOIN_POOL_DEPTH {
            return Err(Error::InvalidParameter(format!(
                "CoinJoin pool depth {last_index} must be below {MAX_COINJOIN_POOL_DEPTH}"
            )));
        }
        if wallet.wallet_id != self.wallet_id {
            return Err(Error::InvalidParameter(
                "the wallet does not own this wallet info".to_string(),
            ));
        }
        let mut key_sources = Vec::with_capacity(self.accounts.coinjoin_accounts.len());
        for index in self.accounts.coinjoin_accounts.keys() {
            let key_source = wallet.key_source_for_account(AccountType::CoinJoin {
                index: *index,
            });
            if matches!(key_source, KeySource::NoKeySource) {
                return Err(Error::InvalidParameter(format!(
                    "the wallet has no key source for CoinJoin account {index}"
                )));
            }
            key_sources.push(key_source);
        }

        let mut generated = 0;
        for (account, key_source) in self.accounts.coinjoin_accounts.values_mut().zip(&key_sources)
        {
            let mut account_generated = 0;
            let mut outcome = Ok(());
            'pools: for pool in account.managed_account_type_mut().address_pools_mut() {
                let start = pool.highest_generated.map_or(0, |h| h + 1);
                for index in start..=last_index {
                    if let Err(error) = pool.generate_address_at_index(index, key_source, true) {
                        outcome = Err(error);
                        break 'pools;
                    }
                    account_generated += 1;
                }
            }
            if account_generated > 0 {
                account.bump_monitor_revision();
            }
            generated += account_generated;
            outcome?;
        }
        Ok(generated)
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

    const DENOM: u64 = 100_001;
    const GAP: u32 = crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT;
    /// Deep enough to sit far past the gap limit, shallow enough for debug test runs.
    const DEPTH: u32 = 1_499;

    fn fresh(network: Network) -> (Wallet, ManagedWalletInfo) {
        let wallet =
            Wallet::from_seed_bytes([0x01; 64], network, WalletAccountCreationOptions::Default)
                .expect("wallet");
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

    fn monitor_revision(managed: &ManagedWalletInfo) -> u64 {
        managed.accounts.coinjoin_accounts.get(&0).expect("CoinJoin account").monitor_revision()
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

    fn block(height: u32) -> TransactionContext {
        TransactionContext::InBlock(BlockInfo::new(
            height,
            BlockHash::from_byte_array([height as u8; 32]),
            1_650_000_000 + height,
        ))
    }

    #[test]
    fn extend_derives_both_chains_to_the_depth_and_is_idempotent() {
        let (wallet, mut managed) = fresh(Network::Testnet);
        let generated = managed.extend_coinjoin_pools(&wallet, 1_999).expect("extend");
        assert_eq!(generated, 2 * 2_000 - 2 * GAP as usize);
        for pool_type in [AddressPoolType::External, AddressPoolType::Internal] {
            assert_eq!(pool(&managed, pool_type).highest_generated, Some(1_999));
            assert_eq!(pool(&managed, pool_type).stats().total_generated, 2_000);
        }
        assert_eq!(managed.extend_coinjoin_pools(&wallet, 1_999).expect("again"), 0);
        assert_eq!(managed.extend_coinjoin_pools(&wallet, 10).expect("shallower"), 0);
    }

    /// dash-spv rebuilds its filter only when the monitor revision moves.
    #[test]
    fn extend_bumps_the_monitor_revision_only_when_addresses_were_added() {
        let (wallet, mut managed) = fresh(Network::Testnet);
        let before = monitor_revision(&managed);
        managed.extend_coinjoin_pools(&wallet, 999).expect("extend");
        let after = monitor_revision(&managed);
        assert!(after > before);
        managed.extend_coinjoin_pools(&wallet, 999).expect("again");
        assert_eq!(monitor_revision(&managed), after);
    }

    #[test]
    fn extend_rejects_a_depth_at_or_above_the_maximum() {
        let (wallet, mut managed) = fresh(Network::Testnet);
        for last_index in [MAX_COINJOIN_POOL_DEPTH, u32::MAX] {
            assert!(matches!(
                managed.extend_coinjoin_pools(&wallet, last_index),
                Err(Error::InvalidParameter(_))
            ));
        }
        assert_eq!(pool(&managed, AddressPoolType::External).highest_generated, Some(GAP - 1));
    }

    #[test]
    fn extend_rejects_a_wallet_that_does_not_own_the_info() {
        let (_, mut managed) = fresh(Network::Testnet);
        let other = Wallet::from_seed_bytes(
            [0x02; 64],
            Network::Testnet,
            WalletAccountCreationOptions::Default,
        )
        .expect("wallet");
        assert!(matches!(
            managed.extend_coinjoin_pools(&other, 999),
            Err(Error::InvalidParameter(_))
        ));
        assert_eq!(pool(&managed, AddressPoolType::External).highest_generated, Some(GAP - 1));
    }

    #[test]
    fn extend_leaves_other_accounts_alone() {
        fn others(managed: &ManagedWalletInfo) -> Vec<(String, u64, Vec<u32>)> {
            managed
                .accounts
                .all_accounts()
                .into_iter()
                .filter(|account| {
                    !matches!(
                        account.managed_account_type().to_account_type(),
                        AccountType::CoinJoin { .. }
                    )
                })
                .map(|account| {
                    let pools = account
                        .managed_account_type()
                        .address_pools()
                        .iter()
                        .map(|pool| pool.stats().total_generated)
                        .collect();
                    (
                        format!("{:?}", account.managed_account_type().to_account_type()),
                        account.monitor_revision(),
                        pools,
                    )
                })
                .collect()
        }
        let (wallet, mut managed) = fresh(Network::Testnet);
        let before = others(&managed);
        assert!(!before.is_empty());
        managed.extend_coinjoin_pools(&wallet, 999).expect("extend");
        assert_eq!(others(&managed), before);
    }

    /// 32008: a coin far past the gap limit on either chain is credited by the
    /// regular check once the pools are extended through its index (inclusive),
    /// and missed without, or one index past the depth.
    #[tokio::test]
    async fn coins_past_the_gap_are_found_only_after_extending() {
        for network in [Network::Mainnet, Network::Testnet] {
            for internal in [false, true] {
                for (extend, index, expected) in
                    [(false, DEPTH, 0), (true, DEPTH, DENOM), (true, DEPTH + 1, 0)]
                {
                    let (mut wallet, mut managed) = fresh(network);
                    if extend {
                        managed.extend_coinjoin_pools(&wallet, DEPTH).expect("extend");
                    }
                    let far = coinjoin_address(&wallet, network, internal, index);
                    let tx = Transaction::dummy(&far, 0..1, &[DENOM]);
                    let result = managed
                        .check_core_transaction(&tx, block(1), &mut wallet, true, true)
                        .await;
                    let case =
                        format!("{network:?} internal={internal} extend={extend} index={index}");
                    assert_eq!(result.total_received, expected, "{case}");
                    assert_eq!(managed.balance().total(), expected, "{case}");
                }
            }
        }
    }
}
