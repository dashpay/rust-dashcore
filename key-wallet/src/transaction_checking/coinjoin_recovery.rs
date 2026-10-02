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
//! A wider gap only moves the wall. Instead, the wallet looks past it whenever
//! a coin of ours may have gone there: a transaction that spends or pays any
//! coin of ours — a mix, or DashSync creating denominations and collaterals
//! from the main account — and pays a CoinJoin denomination or collateral
//! amount to a script no account of ours holds. Only
//! then is the chain derived past the generated end of the pool and compared
//! against those outputs. Counting what came back is not enough: a mix can
//! also spend a coin of ours the wallet has not found yet, whose return then
//! hides the one that is missing. A match extends the pool up to it; the regular
//! gap maintenance and SPV's matching of newly derived scripts carry it forward
//! from this block. Coins paid to the new addresses in blocks already scanned
//! are found only by a rescan from wallet creation, which is also what applies
//! this recovery to a wallet that synced before it existed.

use std::collections::{HashMap, HashSet};

use dashcore::blockdata::transaction::Transaction;
use dashcore::hashes::Hash;
use dashcore::{PubkeyHash, ScriptBuf};

use super::account_checker::DerivedAddressInfo;
use super::transaction_router::{
    COINJOIN_DENOMINATIONS, COINJOIN_MAX_COLLATERAL, COINJOIN_MIN_COLLATERAL,
};
use crate::bip32::{ChildNumber, ExtendedPubKey};
use crate::managed_account::address_pool::AddressPoolType;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::KeySource;

/// How far past the generated end of each CoinJoin chain a missing output is
/// searched for: the widest run of empty addresses that recovery can cross in
/// one step. Each recovered coin moves the pool end, so the window travels with
/// it; DashSync derived up to ~10,500 CoinJoin addresses on heavily mixed
/// wallets. Derivation only; nothing in this window is watched unless an
/// output is found in it.
pub const COINJOIN_RECOVERY_PROBE_WINDOW: u32 = 10_000;

/// Scripts derived for probing, per CoinJoin chain of one wallet, so that the
/// many one-sided mixes of a wallet derive the window once rather than once
/// each. The whole window is always compared — a mix can return more of our
/// coins than the inputs we know about — so the cache changes cost, never the
/// result.
#[derive(Default)]
pub struct CoinJoinProbeCache {
    chains: HashMap<(u32, AddressPoolType), ProbeRange>,
}

/// A contiguous run of derived indices `[from, until)` of one chain.
struct ProbeRange {
    /// The account key the run belongs to; another key starts afresh.
    account_xpub: ExtendedPubKey,
    /// The chain's branch key, derived once per run.
    branch: ExtendedPubKey,
    /// Every probed address is P2PKH, so its key hash identifies it.
    hashes: HashMap<PubkeyHash, u32>,
    from: u32,
    until: u32,
}

/// A clone starts empty: the cache is only an optimisation, and copying tens
/// of thousands of scripts with every wallet snapshot would cost more than it
/// saves.
impl Clone for CoinJoinProbeCache {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl std::fmt::Debug for CoinJoinProbeCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoinJoinProbeCache").field("chains", &self.chains.len()).finish()
    }
}

/// The branch index of a CoinJoin chain; `None` for pools a CoinJoin account
/// does not have.
fn branch_index(pool_type: AddressPoolType) -> Option<u32> {
    match pool_type {
        AddressPoolType::External => Some(0),
        AddressPoolType::Internal => Some(1),
        AddressPoolType::Absent | AddressPoolType::AbsentHardened => None,
    }
}

/// A CoinJoin denomination or collateral amount.
fn is_coinjoin_amount(value: u64) -> bool {
    COINJOIN_DENOMINATIONS.contains(&value)
        || (COINJOIN_MIN_COLLATERAL..=COINJOIN_MAX_COLLATERAL).contains(&value)
}

/// The key hash of `branch`'s child `index`, which the pool pays as P2PKH.
fn probe_hash(
    secp: &dashcore::secp256k1::Secp256k1<dashcore::secp256k1::VerifyOnly>,
    branch: &ExtendedPubKey,
    index: u32,
) -> crate::Result<PubkeyHash> {
    let child = ChildNumber::from_normal_idx(index).map_err(crate::Error::Bip32)?;
    let key = branch.ckd_pub(secp, child).map_err(crate::Error::Bip32)?;
    Ok(dashcore::PublicKey::new(key.public_key).pubkey_hash())
}

/// The key hash a P2PKH script pays; `None` for any other script.
fn p2pkh_hash(script: &ScriptBuf) -> Option<PubkeyHash> {
    if !script.is_p2pkh() {
        return None;
    }
    PubkeyHash::from_slice(&script.as_bytes()[3..23]).ok()
}

impl ManagedWalletInfo {
    /// Extend a CoinJoin pool to any output of `tx` that is ours but lies past
    /// the pool's generated end, when `tx` involves us and pays a CoinJoin
    /// denomination or collateral amount to a script no account of ours holds.
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

        // Cheap first: most transactions pay no CoinJoin-shaped amount at all.
        if !tx.output.iter().any(|output| is_coinjoin_amount(output.value)) {
            return derived;
        }
        let accounts = self.accounts.all_accounts();
        // Every output no account of ours holds is compared once probing; a
        // CoinJoin-shaped one among them is what starts it.
        let (claimed, unclaimed): (Vec<&dashcore::TxOut>, Vec<&dashcore::TxOut>) =
            tx.output.iter().partition(|output| {
                accounts
                    .iter()
                    .any(|account| account.contains_script_pub_key(&output.script_pubkey))
            });
        // The transaction must involve us: it pays one of our addresses (its
        // spend can arrive before the coin it spends), or spends a coin of ours.
        let involved = unclaimed.iter().any(|output| is_coinjoin_amount(output.value))
            && (!claimed.is_empty()
                || accounts.iter().filter_map(|account| account.as_funds()).any(|account| {
                    tx.input.iter().any(|input| account.utxos.contains_key(&input.previous_output))
                }));
        drop(accounts);
        if !involved {
            return derived;
        }
        let unclaimed: HashSet<PubkeyHash> =
            unclaimed.iter().filter_map(|output| p2pkh_hash(&output.script_pubkey)).collect();

        let secp = dashcore::secp256k1::Secp256k1::verification_only();
        for (&index, account) in self.accounts.coinjoin_accounts.iter_mut() {
            let account_type = account.managed_account_type().to_account_type();
            let key_source = wallet.key_source_for_account_type(
                &super::transaction_router::AccountTypeToCheck::CoinJoin,
                Some(index),
            );
            let KeySource::Public(account_xpub) = key_source else {
                continue;
            };

            let mut extended = false;
            for pool in account.managed_account_type_mut().address_pools_mut() {
                let Some(branch_index) = branch_index(pool.pool_type) else {
                    continue;
                };
                let start = pool.highest_generated.map(|h| h + 1).unwrap_or(0);
                let end = start.saturating_add(COINJOIN_RECOVERY_PROBE_WINDOW);
                let chains = &mut self.coinjoin_probe_cache.chains;
                let key = (index, pool.pool_type);
                // The cache covers `[start, end)` of this account key only:
                // indices below the pool end are watched already. A start
                // outside the cached run (the pool moved past it, or was
                // replaced) or another key starts afresh.
                let reusable = chains.get(&key).is_some_and(|range| {
                    range.account_xpub == account_xpub
                        && (range.from..=range.until).contains(&start)
                });
                if !reusable {
                    let branch = match ChildNumber::from_normal_idx(branch_index)
                        .and_then(|child| account_xpub.ckd_pub(&secp, child))
                    {
                        Ok(branch) => branch,
                        Err(e) => {
                            tracing::warn!(error = %e, "CoinJoin recovery: branch derivation failed");
                            continue;
                        }
                    };
                    chains.insert(
                        key,
                        ProbeRange {
                            account_xpub,
                            branch,
                            hashes: HashMap::new(),
                            from: start,
                            until: start,
                        },
                    );
                }
                let Some(range) = chains.get_mut(&key) else {
                    continue;
                };
                if start > range.from {
                    range.hashes.retain(|_, index| *index >= start);
                    range.from = start;
                }
                while range.until < end {
                    let probe = range.until;
                    match probe_hash(&secp, &range.branch, probe) {
                        Ok(hash) => {
                            range.hashes.insert(hash, probe);
                            range.until += 1;
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                index = probe,
                                "CoinJoin recovery: derivation failed, searching below it only"
                            );
                            break;
                        }
                    }
                }
                let mut found: Vec<u32> =
                    unclaimed.iter().filter_map(|hash| range.hashes.get(hash).copied()).collect();
                found.sort_unstable();
                let Some(&highest) = found.last() else {
                    continue;
                };

                let pool_type = pool.pool_type;
                let mut new_infos = Vec::new();
                for next in start..=highest {
                    if let Err(e) = pool.generate_address_at_index(next, &key_source, true) {
                        tracing::error!(
                            error = %e,
                            index = next,
                            "CoinJoin recovery: failed to extend pool, coins above it stay missing"
                        );
                        found.retain(|&index| index < next);
                        break;
                    }
                    if let Some(info) = pool.info_at_index(next) {
                        new_infos.push(info.clone());
                    }
                }
                if new_infos.is_empty() {
                    continue;
                }
                // The check that follows marks the found addresses used and
                // extends the gap past them, as for any other output of ours.
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
    /// An index past the generated end of a fresh CoinJoin pool.
    const PAST_GAP: u32 = crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT;

    struct Fixture {
        wallet: Wallet,
        managed: ManagedWalletInfo,
        key_source: KeySource,
    }

    fn fixture() -> Fixture {
        fixture_on(NETWORK)
    }

    fn fixture_on(network: Network) -> Fixture {
        let mut wallet =
            Wallet::new_random(network, WalletAccountCreationOptions::None).expect("wallet");
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
        let spend = OutPoint {
            txid: funding.txid(),
            vout: 0,
        };
        mix_spending(fx, spend, ours, 2).await.1
    }

    /// Mixes our coin at `spend` with two foreign ones at `height`; ours comes
    /// back to `ours` as output 1. Returns the mix's outpoint for ours too.
    async fn mix_spending(
        fx: &mut Fixture,
        spend: OutPoint,
        ours: Address,
        height: u32,
    ) -> (OutPoint, crate::transaction_checking::TransactionCheckResult) {
        let network = fx.wallet.network;
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
                    previous_output: spend,
                    ..Default::default()
                },
                foreign_input(0xa2),
            ],
            output: vec![
                TxOut {
                    value: DENOM,
                    script_pubkey: Address::dummy(network, 1).script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: ours.script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: Address::dummy(network, 2).script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };
        let result = fx
            .managed
            .check_core_transaction(&mix, block(height), &mut fx.wallet, true, true)
            .await;
        let returned = OutPoint {
            txid: mix.txid(),
            vout: 1,
        };
        (returned, result)
    }

    /// 32008: the mixed coin comes back past the gap limit. Without recovery the
    /// wallet books the mix as a one-sided loss and never watches the address.
    #[tokio::test]
    async fn mixed_coin_returned_past_the_gap_limit_is_recovered() {
        let mut fx = fixture();
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 250);
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
                >= Some(PAST_GAP + 250 + crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT),
            "the pool must extend past the recovered index by the gap limit"
        );
        assert!(
            result.new_addresses.iter().any(|d| d.info.index == PAST_GAP + 250),
            "the recovered address must be reported as newly derived"
        );
        assert_eq!(fx.managed.balance.total(), DENOM, "nothing lost: balance equals the coin");
    }

    /// DashSync also mixed onto its internal CoinJoin chain.
    #[tokio::test]
    async fn mixed_coin_returned_past_the_gap_limit_on_the_internal_chain_is_recovered() {
        let mut fx = fixture();
        let far = coinjoin_address(&mut fx, true, PAST_GAP + 150);
        let result = fund_and_mix(&mut fx, far.clone()).await;

        assert_eq!(result.total_received, DENOM, "the far internal output must be credited");
        assert!(pool_end(&fx, AddressPoolType::Internal) >= Some(PAST_GAP + 150));
        assert_eq!(fx.managed.balance.total(), DENOM);
    }

    /// A normal mix that returns the coin inside the pool extends nothing:
    /// the other participants' outputs are probed and found not ours.
    #[tokio::test]
    async fn mix_returning_inside_the_pool_extends_nothing() {
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
        let beyond = coinjoin_address(
            &mut fx,
            false,
            crate::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT + COINJOIN_RECOVERY_PROBE_WINDOW + 10,
        );
        let result = fund_and_mix(&mut fx, beyond).await;
        assert_eq!(result.total_received, 0);
    }

    /// A mix can return more of our coins than the inputs the wallet knows
    /// about (one of ours came from an address it has not discovered yet).
    /// Every one of them in the window must be found, not just as many as the
    /// known inputs.
    #[tokio::test]
    async fn every_returned_coin_is_found_not_just_the_known_inputs() {
        let mut fx = fixture();
        let far_a = coinjoin_address(&mut fx, false, PAST_GAP + 200);
        let far_b = coinjoin_address(&mut fx, false, PAST_GAP + 800);
        let first = coinjoin_address(&mut fx, false, 0);
        let funding = dashcore::Transaction::dummy(&first, 0..1, &[DENOM]);
        fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;

        let mix = dashcore::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: funding.txid(),
                        vout: 0,
                    },
                    ..Default::default()
                },
                // Ours as well, but on an address the wallet has not discovered.
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([0xb1; 32]),
                        vout: 0,
                    },
                    ..Default::default()
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([0xb2; 32]),
                        vout: 0,
                    },
                    ..Default::default()
                },
            ],
            output: vec![
                TxOut {
                    value: DENOM,
                    script_pubkey: far_a.script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: Address::dummy(NETWORK, 4).script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: far_b.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };
        let result =
            fx.managed.check_core_transaction(&mix, block(2), &mut fx.wallet, true, true).await;

        assert_eq!(result.total_received, 2 * DENOM, "both returned coins must be credited");
        assert_eq!(fx.managed.balance.total(), 2 * DENOM);
    }

    /// Two wallets probing the same indices never see each other's scripts.
    #[tokio::test]
    async fn probe_cache_is_per_wallet() {
        let mut first = fixture();
        let far = coinjoin_address(&mut first, false, PAST_GAP + 300);
        assert_eq!(fund_and_mix(&mut first, far).await.total_received, DENOM);

        let mut second = fixture();
        let foreign = coinjoin_address(&mut first, false, PAST_GAP + 300);
        let result = fund_and_mix(&mut second, foreign).await;
        assert_eq!(result.total_received, 0, "the first wallet's address is not ours");
    }

    /// A wallet on mainnet recovers the same way (32008 is a mainnet wallet).
    #[tokio::test]
    async fn mixed_coin_returned_past_the_gap_limit_is_recovered_on_mainnet() {
        let mut fx = fixture_on(Network::Mainnet);
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 250);
        let result = fund_and_mix(&mut fx, far).await;
        assert_eq!(result.total_received, DENOM, "the far output must be credited");
        assert_eq!(fx.managed.balance.total(), DENOM);
    }

    /// The recovered coin is mixed again and comes back past the new pool end:
    /// the second recovery reuses the cache, moved up to the new end.
    #[tokio::test]
    async fn a_recovered_coin_mixed_again_past_the_new_end_is_recovered() {
        let mut fx = fixture();
        let first_far = coinjoin_address(&mut fx, false, PAST_GAP + 200);
        let first = coinjoin_address(&mut fx, false, 0);
        let funding = dashcore::Transaction::dummy(&first, 0..1, &[DENOM]);
        fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;
        let spend = OutPoint {
            txid: funding.txid(),
            vout: 0,
        };
        let (recovered, result) = mix_spending(&mut fx, spend, first_far, 2).await;
        assert_eq!(result.total_received, DENOM, "the first far output must be credited");

        let new_start = pool_end(&fx, AddressPoolType::External).expect("pool end") + 1;
        let second_far = coinjoin_address(&mut fx, false, new_start + 500);
        let (_, result) = mix_spending(&mut fx, recovered, second_far.clone(), 3).await;
        assert_eq!(result.total_sent, DENOM, "the recovered coin is debited");
        assert_eq!(result.total_received, DENOM, "the second far output must be credited");
        assert_eq!(fx.managed.balance.total(), DENOM, "exactly one coin, at the second address");
        let account = fx.managed.first_coinjoin_managed_account().expect("account");
        assert!(account.utxos.values().any(|utxo| utxo.address == second_far));

        let range = fx
            .managed
            .coinjoin_probe_cache
            .chains
            .get(&(0, AddressPoolType::External))
            .expect("cached chain");
        assert_eq!(range.from, new_start, "the cache moves up with the pool");
        assert!(range.hashes.values().all(|&index| index >= new_start));
    }

    /// A mix spends a known coin of ours and one the wallet has not found yet;
    /// one coin comes back inside the pool, the other past the wall. As many
    /// came back as the wallet knew went in, yet one is still missing.
    #[tokio::test]
    async fn a_return_for_an_undiscovered_input_does_not_hide_a_far_coin() {
        let mut fx = fixture();
        let near = coinjoin_address(&mut fx, false, 5);
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 300);
        let first = coinjoin_address(&mut fx, false, 0);
        let funding = dashcore::Transaction::dummy(&first, 0..1, &[DENOM]);
        fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;

        let input = |txid: Txid| TxIn {
            previous_output: OutPoint {
                txid,
                vout: 0,
            },
            ..Default::default()
        };
        let mix = dashcore::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![
                input(funding.txid()),
                // Ours, on an address the wallet has not discovered.
                input(Txid::from_byte_array([0xc1; 32])),
                input(Txid::from_byte_array([0xc2; 32])),
            ],
            output: vec![
                TxOut {
                    value: DENOM,
                    script_pubkey: near.script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: Address::dummy(NETWORK, 5).script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: far.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };
        let result =
            fx.managed.check_core_transaction(&mix, block(2), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_received, 2 * DENOM, "both returned coins must be credited");
        assert_eq!(fx.managed.balance.total(), 2 * DENOM);
    }

    /// DashSync created denominations from the main account onto CoinJoin
    /// addresses past the wall; no CoinJoin coin is spent, yet they are ours.
    #[tokio::test]
    async fn denominations_created_past_the_gap_from_the_main_account_are_recovered() {
        let mut fx = fixture();
        fx.wallet
            .add_account(
                AccountType::Standard {
                    index: 0,
                    standard_account_type: crate::account::StandardAccountType::BIP44Account,
                },
                None,
            )
            .expect("BIP44 account");
        fx.managed = ManagedWalletInfo::from_wallet_with_name(&fx.wallet, "Test".to_string(), 0);
        let main_xpub =
            fx.wallet.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account").account_xpub;
        let main = {
            let account = fx.managed.first_bip44_managed_account_mut().expect("account");
            let pool = account
                .managed_account_type_mut()
                .address_pools_mut()
                .into_iter()
                .find(|pool| pool.pool_type == AddressPoolType::External)
                .expect("external pool");
            pool.generate_address_at_index(0, &KeySource::Public(main_xpub), false).expect("derive")
        };
        let funding = dashcore::Transaction::dummy(&main, 0..1, &[5 * DENOM]);
        let funded =
            fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;
        assert_eq!(funded.total_received, 5 * DENOM, "funding must be credited");

        let far_a = coinjoin_address(&mut fx, false, PAST_GAP + 400);
        let far_b = coinjoin_address(&mut fx, false, PAST_GAP + 401);
        let create = dashcore::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: funding.txid(),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![
                TxOut {
                    value: DENOM,
                    script_pubkey: far_a.script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: far_b.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };
        let result =
            fx.managed.check_core_transaction(&create, block(2), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_sent, 5 * DENOM);
        assert_eq!(result.total_received, 2 * DENOM, "both denominations must be credited");
        let coinjoin = fx.managed.first_coinjoin_managed_account().expect("account");
        assert_eq!(coinjoin.utxos.len(), 2);
    }

    /// The mix arrives before the coin it spends (rescan delivery order): no
    /// input is known yet, but an output to our pool shows the mix is ours.
    #[tokio::test]
    async fn a_mix_seen_before_its_funding_still_recovers_the_far_coin() {
        let mut fx = fixture();
        let near = coinjoin_address(&mut fx, false, 5);
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 300);
        let mix = dashcore::Transaction {
            version: 2,
            lock_time: 0,
            input: (0xd1..=0xd3)
                .map(|n| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([n; 32]),
                        vout: 0,
                    },
                    ..Default::default()
                })
                .collect(),
            output: vec![
                TxOut {
                    value: DENOM,
                    script_pubkey: near.script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: Address::dummy(NETWORK, 6).script_pubkey(),
                },
                TxOut {
                    value: DENOM,
                    script_pubkey: far.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };
        let result =
            fx.managed.check_core_transaction(&mix, block(3), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_received, 2 * DENOM, "both of our outputs must be credited");
    }

    /// A collateral output (0.0004 DASH) past the wall is ours as well.
    #[tokio::test]
    async fn a_collateral_output_past_the_gap_is_recovered() {
        const COLLATERAL: u64 = 40_000;
        let mut fx = fixture();
        let first = coinjoin_address(&mut fx, false, 0);
        let funding = dashcore::Transaction::dummy(&first, 0..1, &[DENOM]);
        fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 300);
        let make_collateral = dashcore::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: funding.txid(),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: COLLATERAL,
                script_pubkey: far.script_pubkey(),
            }],
            special_transaction_payload: None,
        };
        let result = fx
            .managed
            .check_core_transaction(&make_collateral, block(2), &mut fx.wallet, true, true)
            .await;
        assert_eq!(result.total_received, COLLATERAL, "the collateral must be credited");
        assert_eq!(fx.managed.balance.total(), COLLATERAL);
    }

    /// DashSync's denomination-creating transaction sent its odd change to the
    /// CoinJoin internal chain past the wall; it is found with the coins.
    #[tokio::test]
    async fn odd_change_past_the_gap_beside_a_far_denomination_is_recovered() {
        const CHANGE: u64 = 1_234_567;
        let mut fx = fixture();
        let first = coinjoin_address(&mut fx, false, 0);
        let funding = dashcore::Transaction::dummy(&first, 0..1, &[DENOM + CHANGE]);
        fx.managed.check_core_transaction(&funding, block(1), &mut fx.wallet, true, true).await;
        let far = coinjoin_address(&mut fx, false, PAST_GAP + 300);
        let change = coinjoin_address(&mut fx, true, PAST_GAP + 600);
        let create = dashcore::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: funding.txid(),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![
                TxOut {
                    value: DENOM,
                    script_pubkey: far.script_pubkey(),
                },
                TxOut {
                    value: CHANGE,
                    script_pubkey: change.script_pubkey(),
                },
            ],
            special_transaction_payload: None,
        };
        let result =
            fx.managed.check_core_transaction(&create, block(2), &mut fx.wallet, true, true).await;
        assert_eq!(result.total_received, DENOM + CHANGE, "the change must be credited too");
    }
}
