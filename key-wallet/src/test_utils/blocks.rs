//! Block-context and synthetic-transaction helpers shared across
//! transaction-checking tests.

use dashcore::blockdata::transaction::OutPoint;
use dashcore::{Address, Network, ScriptBuf, Transaction, TxIn, TxOut, Witness};

use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;

/// A block-confirmed context at `height` with a height-derived block hash.
pub fn block_ctx(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        dashcore::BlockHash::dummy(height),
        1_650_000_000 + height,
    ))
}

/// A chain-locked block context at `height` — the strongest finality signal,
/// which drops the transaction's full record under the default
/// `keep-finalized-transactions = OFF` feature. A full historical rescan
/// delivers old blocks already chainlocked, so this is the realistic "first
/// sighting" context for a coin funded and spent long ago.
pub fn chain_locked_block_ctx(height: u32) -> TransactionContext {
    TransactionContext::InChainLockedBlock(BlockInfo::new(
        height,
        dashcore::BlockHash::dummy(height),
        1_650_000_000 + height,
    ))
}

/// A transaction spending `inputs` and paying `value` to an unrelated external
/// address (`ext_id` selects a distinct dummy address). No change back to us.
pub fn spend_to_external(inputs: &[OutPoint], value: u64, ext_id: usize) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: inputs
            .iter()
            .map(|op| TxIn {
                previous_output: *op,
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value,
            script_pubkey: Address::dummy(Network::Testnet, ext_id).script_pubkey(),
        }],
        special_transaction_payload: None,
    }
}

/// Does any funding account currently hold a live UTXO at `outpoint`?
pub fn utxo_tracked(wallet: &ManagedWalletInfo, outpoint: &OutPoint) -> bool {
    wallet.accounts.all_funding_accounts().iter().any(|a| a.utxos.contains_key(outpoint))
}

/// Sum of `net_amount` across the wallet's live transaction history.
pub fn history_net(wallet: &ManagedWalletInfo) -> i64 {
    wallet.transaction_history().iter().map(|r| r.net_amount).sum()
}
