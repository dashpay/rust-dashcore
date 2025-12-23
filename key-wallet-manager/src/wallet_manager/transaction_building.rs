//! Transaction building functionality for the wallet manager

use super::{WalletError, WalletId, WalletManager};
use dashcore::Transaction;
use key_wallet::wallet::managed_wallet_info::fee::FeeLevel;
use key_wallet::wallet::managed_wallet_info::transaction_building::{
    AccountTypePreference, TransactionError,
};
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::Address;

impl<T: WalletInfoInterface> WalletManager<T> {
    /// Creates an unsigned transaction from a specific wallet and account
    ///
    /// This method delegates to the ManagedWalletInfo's create_payment_transaction method
    /// If account_type_pref is None, defaults to BIP44
    #[allow(clippy::too_many_arguments)]
    pub fn create_unsigned_payment_transaction(
        &mut self,
        wallet_id: &WalletId,
        account_index: u32,
        account_type_pref: Option<AccountTypePreference>,
        recipients: Vec<(Address, u64)>,
        fee_level: FeeLevel,
        current_block_height: u32,
    ) -> Result<Transaction, WalletError> {
        // Get the wallet
        let wallet = self.wallets.get(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        // Get the managed wallet info
        let managed_info =
            self.wallet_infos.get_mut(wallet_id).ok_or(WalletError::WalletNotFound(*wallet_id))?;

        // Delegate to the managed wallet info's method
        managed_info
            .create_unsigned_payment_transaction(
                wallet,
                account_index,
                account_type_pref,
                recipients,
                fee_level,
                current_block_height,
            )
            .map_err(|e| match e {
                TransactionError::NoAccount => WalletError::AccountNotFound(account_index),
                TransactionError::InsufficientFunds => WalletError::InsufficientFunds,
                TransactionError::ChangeAddressGeneration(msg) => {
                    WalletError::AddressGeneration(msg)
                }
                TransactionError::BuildFailed(msg) => WalletError::TransactionBuild(msg),
                TransactionError::CoinSelection(err) => {
                    WalletError::TransactionBuild(format!("Coin selection failed: {}", err))
                }
            })
    }
}
