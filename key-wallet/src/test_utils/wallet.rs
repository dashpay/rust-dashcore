use dashcore::blockdata::script::Builder;
use dashcore::ecdsa::Signature;
use dashcore::sighash::{EcdsaSighashType, SighashCache};
use dashcore::{Address, Network, PublicKey, Transaction, TxIn, TxOut, Txid};

use crate::{
    account::{ManagedCoreFundsAccount, TransactionRecord},
    managed_account::managed_account_trait::ManagedAccountTrait,
    transaction_checking::{TransactionCheckResult, TransactionContext, WalletTransactionChecker},
    wallet::{
        initialization::WalletAccountCreationOptions,
        managed_wallet_info::transaction_builder::TransactionSigner, ManagedWalletInfo,
    },
    ExtendedPubKey, Utxo, Wallet,
};

/// Returns `tx` with every input signed as its coin's owner signs it, where the coin pays an
/// address of `info`'s funds accounts. A coin is looked up in `fundings`, then among the coins
/// `info` holds; other inputs are left as they are.
pub async fn sign_owned_inputs(
    wallet: &Wallet,
    info: &ManagedWalletInfo,
    mut tx: Transaction,
    fundings: &[&Transaction],
) -> Transaction {
    let funds: Vec<_> =
        info.accounts.all_accounts().into_iter().filter_map(|a| a.as_funds()).collect();
    let prevout = |input: &TxIn| -> Option<TxOut> {
        let outpoint = input.previous_output;
        fundings
            .iter()
            .find(|funding| funding.txid() == outpoint.txid)
            .and_then(|funding| funding.output.get(outpoint.vout as usize).cloned())
            .or_else(|| funds.iter().find_map(|a| a.utxos.get(&outpoint)).map(|u| u.txout.clone()))
    };
    let mut tasks = Vec::new();
    {
        let cache = SighashCache::new(&tx);
        for (index, input) in tx.input.iter().enumerate() {
            let Some(prevout) = prevout(input) else {
                continue;
            };
            let Ok(address) = Address::from_script(&prevout.script_pubkey, wallet.network) else {
                continue;
            };
            let Some(path) = funds.iter().find_map(|a| a.address_derivation_path(&address)) else {
                continue;
            };
            let sighash = cache
                .legacy_signature_hash(
                    index,
                    &prevout.script_pubkey,
                    EcdsaSighashType::All.to_u32(),
                )
                .expect("sighash");
            tasks.push((index, sighash, path));
        }
    }
    for (index, sighash, path) in tasks {
        let (signature, public_key) = wallet.sig_and_pubkey(sighash, path).await.expect("signs");
        tx.input[index].script_sig = Builder::new()
            .push_slice(Signature::sighash_all(signature.into()).serialize())
            .push_key(&PublicKey::new(public_key))
            .into_script();
    }
    tx
}

impl ManagedWalletInfo {
    pub fn dummy(id: u8) -> Self {
        ManagedWalletInfo::new(Network::Regtest, [id; 32])
    }
}

/// Pre-built wallet context for transaction checking tests.
///
/// Provides a testnet wallet with a default BIP44 account, a pre-derived
/// receive address, and the corresponding extended public key.
pub struct TestWalletContext {
    pub managed_wallet: ManagedWalletInfo,
    pub wallet: Wallet,
    pub receive_address: Address,
    pub xpub: ExtendedPubKey,
}

impl TestWalletContext {
    /// Creates a new random testnet wallet with a BIP44 account and one
    /// pre-derived receive address.
    pub fn new_random() -> Self {
        Self::new_random_with_options(WalletAccountCreationOptions::Default)
    }

    /// Like [`new_random`](Self::new_random) but with explicit account-creation
    /// options, so a test can build e.g. a funding-only wallet with no provider
    /// accounts.
    pub fn new_random_with_options(options: WalletAccountCreationOptions) -> Self {
        let wallet = Wallet::new_random(Network::Testnet, options).expect("Should create wallet");
        let mut managed_wallet =
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string(), 0);

        let xpub = wallet
            .accounts
            .standard_bip44_accounts
            .get(&0)
            .expect("Should have BIP44 account")
            .account_xpub;

        let receive_address = managed_wallet
            .first_bip44_managed_account_mut()
            .expect("Should have managed account")
            .next_receive_address(Some(&xpub))
            .expect("Should get address");

        Self {
            managed_wallet,
            wallet,
            receive_address,
            xpub,
        }
    }

    /// Returns the first BIP44 managed account (immutable).
    pub fn bip44_account(&self) -> &ManagedCoreFundsAccount {
        self.managed_wallet.first_bip44_managed_account().expect("Should have BIP44 account")
    }

    /// Returns a transaction record by txid from the first BIP44 account.
    pub fn transaction(&self, txid: &Txid) -> &TransactionRecord {
        self.bip44_account().transactions().get(txid).expect("Should have transaction")
    }

    /// Returns the first UTXO from the first BIP44 account.
    pub fn first_utxo(&self) -> &Utxo {
        self.bip44_account().utxos.values().next().expect("Should have UTXO")
    }

    /// Processes a transaction: runs `check_core_transaction` with `update_state = true`.
    pub async fn check_transaction(
        &mut self,
        tx: &Transaction,
        context: TransactionContext,
    ) -> TransactionCheckResult {
        self.managed_wallet.check_core_transaction(tx, context, &mut self.wallet, true, true).await
    }

    /// Returns `tx` signed by this wallet; see [`sign_owned_inputs`].
    pub async fn signed(&self, tx: Transaction, fundings: &[&Transaction]) -> Transaction {
        sign_owned_inputs(&self.wallet, &self.managed_wallet, tx, fundings).await
    }

    /// Funds the wallet's receive address via a mempool transaction and
    /// asserts it was accepted. Returns the context and the funding transaction.
    pub async fn with_mempool_funding(mut self, amount: u64) -> (Self, Transaction) {
        let tx = Transaction::dummy(&self.receive_address, 0..1, &[amount]);

        let result = self.check_transaction(&tx, TransactionContext::Mempool).await;
        assert!(result.is_relevant);
        assert!(result.is_new_transaction);

        (self, tx)
    }
}
