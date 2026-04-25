use dashcore::{Address, Network, Transaction, Txid};

use crate::{
    account::{ManagedCoreAccount, TransactionRecord},
    transaction_checking::{TransactionCheckResult, TransactionContext, WalletTransactionChecker},
    wallet::{initialization::WalletAccountCreationOptions, ManagedWalletInfo},
    ExtendedPubKey, Utxo, Wallet,
};

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
        let wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
            .expect("Should create wallet");
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
            .next_receive_address(Some(&xpub), true)
            .expect("Should get address");

        Self {
            managed_wallet,
            wallet,
            receive_address,
            xpub,
        }
    }

    /// Returns the first BIP44 managed account (immutable).
    pub fn bip44_account(&self) -> &ManagedCoreAccount {
        self.managed_wallet.first_bip44_managed_account().expect("Should have BIP44 account")
    }

    /// Returns a transaction record by txid from the first BIP44 account.
    pub fn transaction(&self, txid: &Txid) -> &TransactionRecord {
        self.bip44_account().transactions.get(txid).expect("Should have transaction")
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
