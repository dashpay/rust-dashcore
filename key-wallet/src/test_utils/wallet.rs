use dashcore::{Address, Network};

use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::ExtendedPubKey;

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
            ManagedWalletInfo::from_wallet_with_name(&wallet, "Test".to_string());

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
}
