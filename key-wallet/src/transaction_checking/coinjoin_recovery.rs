//! Recovery of CoinJoin outputs that landed past the address pool's gap limit.
//!
//! CoinJoin discovery walks each CoinJoin chain forward and stops after
//! `gap_limit` unused addresses. A wallet migrated from DashSync breaks that
//! assumption: DashSync marked a CoinJoin address used the moment it handed it
//! to a mixing session, so every failed session left an address that is used
//! locally and empty on chain. Enough failed sessions in a row leave a run of
//! empty addresses wider than any fixed gap, and every mixed coin past that run
//! stays invisible no matter how often the wallet rescans (ticket 32008).
//!
//! A wider gap only moves the wall. Instead, the wallet reacts to the evidence
//! that a coin went missing: a transaction that spends our CoinJoin coins of a
//! denomination but pays fewer outputs of that denomination back to our
//! CoinJoin pools. For such a transaction only, the chain is derived past the
//! generated end of the pool and compared against the transaction's unclaimed
//! outputs of that denomination. A match extends the pool up to it, which the
//! regular gap maintenance and the SPV rescan of newly derived scripts then
//! carry forward.

use std::collections::{BTreeMap, HashMap, HashSet};

use dashcore::blockdata::transaction::Transaction;
use dashcore::ScriptBuf;

use super::account_checker::DerivedAddressInfo;
use super::transaction_router::AccountTypeToCheck;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::KeySource;

/// How far past the generated end of each CoinJoin chain a missing output is
/// searched for. Derivation only; nothing in this window is watched unless an
/// output is found in it.
pub const COINJOIN_RECOVERY_PROBE_WINDOW: u32 = 2_000;

impl ManagedWalletInfo {
    /// Extend a CoinJoin pool to any output of `tx` that is ours but lies past
    /// the pool's generated end, when `tx` shows that one of our denominations
    /// was spent without coming back.
    ///
    /// Must run before the transaction is checked, so that the outputs found
    /// here are credited by the regular check. Returns the addresses added to
    /// the pools, for the caller to hand to SPV as newly derived scripts.
    pub(crate) fn recover_coinjoin_outputs(
        &mut self,
        tx: &Transaction,
        wallet: &Wallet,
    ) -> Vec<DerivedAddressInfo> {
        let mut derived = Vec::new();

        for (&index, account) in self.accounts.coinjoin_accounts.iter_mut() {
            // Our denominations spent by this transaction, and how many outputs
            // of each value it already pays to our pools.
            let mut spent: BTreeMap<u64, usize> = BTreeMap::new();
            for input in &tx.input {
                if let Some(utxo) = account.utxos.get(&input.previous_output) {
                    *spent.entry(utxo.txout.value).or_default() += 1;
                }
            }
            if spent.is_empty() {
                continue;
            }

            let pools = account.managed_account_type().address_pools();
            let is_ours =
                |script: &ScriptBuf| pools.iter().any(|pool| pool.contains_script_pubkey(script));
            let mut returned: HashMap<u64, usize> = HashMap::new();
            let mut unclaimed: HashSet<ScriptBuf> = HashSet::new();
            for output in &tx.output {
                if !spent.contains_key(&output.value) {
                    continue;
                }
                if is_ours(&output.script_pubkey) {
                    *returned.entry(output.value).or_default() += 1;
                } else {
                    unclaimed.insert(output.script_pubkey.clone());
                }
            }
            let missing = spent
                .iter()
                .any(|(value, count)| returned.get(value).copied().unwrap_or(0) < *count);
            if !missing || unclaimed.is_empty() {
                continue;
            }

            let key_source =
                wallet.key_source_for_account_type(&AccountTypeToCheck::CoinJoin, Some(index));
            if matches!(key_source, KeySource::NoKeySource) {
                continue;
            }

            let account_type = account.managed_account_type().to_account_type();
            let mut extended = false;
            for pool in account.managed_account_type_mut().address_pools_mut() {
                let start = pool.highest_generated.map(|h| h + 1).unwrap_or(0);
                let mut found: Vec<u32> = Vec::new();
                for probe in start..start.saturating_add(COINJOIN_RECOVERY_PROBE_WINDOW) {
                    let address = match pool.generate_address_at_index(probe, &key_source, false) {
                        Ok(address) => address,
                        Err(e) => {
                            tracing::warn!(error = %e, "CoinJoin recovery: derivation failed");
                            break;
                        }
                    };
                    if unclaimed.contains(&address.script_pubkey()) {
                        found.push(probe);
                    }
                }
                let Some(&highest) = found.last() else {
                    continue;
                };

                let pool_type = pool.pool_type;
                let mut new_infos = Vec::new();
                for next in start..=highest {
                    if pool.generate_address_at_index(next, &key_source, true).is_err() {
                        break;
                    }
                    if let Some(info) = pool.info_at_index(next) {
                        new_infos.push(info.clone());
                    }
                }
                for &probe in &found {
                    pool.mark_index_used(probe);
                }
                match pool.maintain_gap_limit(&key_source) {
                    Ok(infos) => new_infos.extend(infos),
                    Err(e) => tracing::error!(
                        error = %e,
                        "CoinJoin recovery: failed to maintain gap limit after extending pool"
                    ),
                }

                tracing::info!(
                    txid = %tx.txid(),
                    pool_type = ?pool_type,
                    previous_end = start.saturating_sub(1),
                    found = ?found,
                    added = new_infos.len(),
                    "CoinJoin recovery: extended pool to outputs past the gap limit"
                );
                derived.extend(new_infos.into_iter().map(|info| DerivedAddressInfo {
                    account_type,
                    pool_type,
                    info,
                }));
                extended = true;
            }
            if extended {
                account.bump_monitor_revision();
            }
        }

        derived
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountType;
    use crate::managed_account::address_pool::AddressPoolType;
    use crate::managed_account::managed_account_type::ManagedAccountType;
    use crate::transaction_checking::{BlockInfo, TransactionContext, WalletTransactionChecker};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::Network;
    use dashcore::hashes::Hash;
    use dashcore::{Address, BlockHash, OutPoint, TxIn, TxOut, Txid};

    const NETWORK: Network = Network::Testnet;
    /// 0.001 DASH CoinJoin denomination, fee included.
    const DENOM: u64 = 100_001;

    struct Fixture {
        wallet: Wallet,
        managed: ManagedWalletInfo,
        key_source: KeySource,
    }

    fn fixture() -> Fixture {
        let mut wallet =
            Wallet::new_random(NETWORK, WalletAccountCreationOptions::None).expect("wallet");
        wallet
            .add_account(
                AccountType::CoinJoin {
                    index: 0,
                },
                None,
            )
            .expect("CoinJoin account");
        let managed = ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);
        let xpub = wallet.accounts.coinjoin_accounts.get(&0).expect("account").account_xpub;
        Fixture {
            wallet,
            managed,
            key_source: KeySource::Public(xpub),
        }
    }

    fn coinjoin_address(fx: &mut Fixture, internal: bool, index: u32) -> Address {
        let account = fx.managed.first_coinjoin_managed_account_mut().expect("account");
        let ManagedAccountType::CoinJoin {
            external_addresses,
            internal_addresses,
            ..
        } = account.managed_account_type_mut()
        else {
            panic!("expected a CoinJoin account");
        };
        let pool = if internal {
            internal_addresses
        } else {
            external_addresses
        };
        pool.generate_address_at_index(index, &fx.key_source, false).expect("derive")
    }

    fn pool_end(fx: &Fixture, pool_type: AddressPoolType) -> Option<u32> {
        let account = fx.managed.first_coinjoin_managed_account().expect("account");
        account
            .managed_account_type()
            .address_pools()
            .into_iter()
            .find(|pool| pool.pool_type == pool_type)
            .and_then(|pool| pool.highest_generated)
    }

    fn block(height: u32) -> TransactionContext {
        TransactionContext::InChainLockedBlock(BlockInfo::new(
            height,
            BlockHash::from_slice(&[height as u8; 32]).expect("hash"),
            1_650_000_000 + height,
        ))
    }

    /// Funds our CoinJoin external index 0 with one denomination, then mixes it:
    /// our coin plus two foreign ones in, three denominations out, ours to `ours`.
    async fn fund_and_mix(
        fx: &mut Fixture,
        ours: Address,
    ) -> crate::transaction_checking::TransactionCheckResult {
        let first = coinjoin_address(fx, false, 0);
        let funding = dashcore::Transaction::dummy(&first, 0..1, &[DENOM]);
        let funded =
            fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;
        assert_eq!(funded.total_received, DENOM, "funding must be credited");

        let foreign_input = |n: u8| TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([n; 32]),
                vout: 0,
            },
            ..Default::default()
        };
        let mix = dashcore::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![
                foreign_input(0xa1),
                TxIn {
                    previous_output: OutPoint {
                        txid: funding.txid(),
                        vout: 0,
                    },
                    ..Default::default()
                },
                foreign_input(0xa2),
            ],
            output: vec![
                TxOut {
                    value: DENOM,
                    script_pubkey: Address::dummy(NETWORK, 1).script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: ours.script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: Address::dummy(NETWORK, 2).script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };
        fx.managed.check_core_transaction(&mix, block(2), &mut fx.wallet, true, true).await
    }

    /// 32008: the mixed coin comes back past the gap limit. Without recovery the
    /// wallet books the mix as a one-sided loss and never watches the address.
    #[tokio::test]
    async fn mixed_coin_returned_past_the_gap_limit_is_recovered() {
        let mut fx = fixture();
        let far = coinjoin_address(&mut fx, false, 350);
        let result = fund_and_mix(&mut fx, far.clone()).await;

        assert_eq!(result.total_sent, DENOM, "our input is debited");
        assert_eq!(result.total_received, DENOM, "the far output must be credited");
        let account = fx.managed.first_coinjoin_managed_account().expect("account");
        assert!(
            account.utxos.values().any(|utxo| utxo.address == far),
            "the far output must be a UTXO"
        );
        assert!(
            pool_end(&fx, AddressPoolType::External)
                >= Some(350 + crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT),
            "the pool must extend past the recovered index by the gap limit"
        );
        assert!(
            result.new_addresses.iter().any(|d| d.info.index == 350),
            "the recovered address must be reported as newly derived"
        );
        assert_eq!(fx.managed.balance.total(), DENOM, "nothing lost: balance equals the coin");
    }

    /// DashSync also mixed onto its internal CoinJoin chain.
    #[tokio::test]
    async fn mixed_coin_returned_past_the_gap_limit_on_the_internal_chain_is_recovered() {
        let mut fx = fixture();
        let far = coinjoin_address(&mut fx, true, 250);
        let result = fund_and_mix(&mut fx, far.clone()).await;

        assert_eq!(result.total_received, DENOM, "the far internal output must be credited");
        assert!(pool_end(&fx, AddressPoolType::Internal) >= Some(250));
        assert_eq!(fx.managed.balance.total(), DENOM);
    }

    /// A normal mix that returns the coin inside the pool derives nothing extra.
    #[tokio::test]
    async fn mix_returning_inside_the_pool_does_not_probe() {
        let mut fx = fixture();
        let near = coinjoin_address(&mut fx, false, 5);
        let result = fund_and_mix(&mut fx, near).await;

        assert_eq!(result.total_received, DENOM);
        assert_eq!(
            pool_end(&fx, AddressPoolType::External),
            Some(5 + crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT),
            "only the regular gap maintenance past the highest used index"
        );
    }

    /// A coin that really left (all outputs foreign) is not credited, and the
    /// pool is not extended by the probe.
    #[tokio::test]
    async fn coin_that_really_left_is_not_credited() {
        let mut fx = fixture();
        let foreign = Address::dummy(NETWORK, 3);
        let result = fund_and_mix(&mut fx, foreign).await;

        assert_eq!(result.total_received, 0);
        assert_eq!(
            pool_end(&fx, AddressPoolType::External),
            Some(crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT),
            "the probe found nothing, so the pool stays at the funding's gap"
        );
        assert_eq!(fx.managed.balance.total(), 0);
    }

    /// Past the probe window the output stays unknown — the window is a bound,
    /// not a guarantee.
    #[tokio::test]
    async fn output_past_the_probe_window_is_not_found() {
        let mut fx = fixture();
        let beyond = coinjoin_address(&mut fx, false, 100 + COINJOIN_RECOVERY_PROBE_WINDOW + 10);
        let result = fund_and_mix(&mut fx, beyond).await;
        assert_eq!(result.total_received, 0);
    }
}
