//! Example demonstrating how to create and manage wallets using WalletManager and SPVWalletManager
//!
//! This example shows:
//! - Creating wallets with WalletManager
//! - Creating wallets from mnemonics
//! - Using SPVWalletManager for SPV-specific functionality
//! - Managing wallet accounts and addresses

use hex;
use key_wallet::account::StandardAccountType;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::{AccountType, Network};
use key_wallet_manager::spv_wallet_manager::SPVWalletManager;
use key_wallet_manager::wallet_manager::WalletManager;

fn main() {
    println!("=== Wallet Creation Example ===\n");

    // Example 1: Basic wallet creation with WalletManager
    println!("1. Creating a basic wallet with WalletManager...");

    let mut manager = WalletManager::<ManagedWalletInfo>::new();

    let result = manager.create_wallet_with_random_mnemonic(
        WalletAccountCreationOptions::Default,
        Network::Testnet,
    );

    let wallet_id = match result {
        Ok(wallet_id) => {
            println!("✅ Wallet created successfully!");
            println!("   Wallet ID: {}", hex::encode(wallet_id));
            println!("   Total wallets: {}", manager.wallet_count());
            wallet_id
        }
        Err(e) => {
            println!("❌ Failed to create wallet: {:?}", e);
            return;
        }
    };

    // Example 2: Create wallet from mnemonic
    println!("\n2. Creating wallet from mnemonic...");

    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let result = manager.create_wallet_from_mnemonic(
        test_mnemonic,
        "", // No passphrase
        &[Network::Testnet],
        Some(100_000), // Birth height
        key_wallet::wallet::initialization::WalletAccountCreationOptions::Default,
    );

    let wallet_id2 = match result {
        Ok(wallet_id2) => {
            println!("✅ Wallet created from mnemonic!");
            println!("   Wallet ID: {}", hex::encode(wallet_id2));
            wallet_id2
        }
        Err(e) => {
            println!("❌ Failed to create wallet from mnemonic: {:?}", e);
            return;
        }
    };

    // Example 3: Managing accounts
    println!("\n3. Managing wallet accounts...");

    // Add a new account to the first wallet
    let account_result = manager.create_account(
        &wallet_id, // Account index 1 (0 is created by default)
        AccountType::Standard {
            index: 1,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        Network::Testnet,
        None,
    );

    match account_result {
        Ok(_) => {
            println!("✅ Account created successfully!");

            // Get all accounts
            if let Ok(accounts) = manager.get_accounts(&wallet_id) {
                println!("   Total accounts: {}", accounts.len());
            }
        }
        Err(e) => {
            println!("❌ Failed to create account: {:?}", e);
        }
    }

    // Example 4: Generate addresses
    println!("\n4. Generating addresses...");

    // Note: This might fail with InvalidNetwork error if the account collection
    // isn't properly initialized in the managed wallet info
    let address_result = manager.get_receive_address(
        &wallet_id,
        Network::Testnet,
        0, // Account index
        AccountTypePreference::BIP44,
        false, // Don't advance index
    );

    match address_result {
        Ok(result) => {
            if let Some(address) = result.address {
                println!("✅ Receive address: {}", address);
                if let Some(account_type) = result.account_type_used {
                    println!("   Account type used: {:?}", account_type);
                }
            } else {
                println!("⚠️  No address generated");
            }
        }
        Err(e) => {
            println!("⚠️  Could not get address: {:?}", e);
            println!("   (This is expected with the current implementation)");
        }
    }

    // Example 5: Using SPVWalletManager
    println!("\n5. Using SPVWalletManager for SPV functionality...");

    let mut spv_manager = SPVWalletManager::with_base(WalletManager::<ManagedWalletInfo>::new());

    // Create a wallet through SPVWalletManager
    let spv_result = spv_manager.base.create_wallet_with_random_mnemonic(
        WalletAccountCreationOptions::Default,
        Network::Testnet,
    );

    match spv_result {
        Ok(wallet_id3) => {
            println!("✅ SPV wallet created!");
            println!("   Wallet ID: {}", hex::encode(wallet_id3));
            println!("   Sync status: {:?}", spv_manager.sync_status(Network::Testnet));
            println!("   Sync height: {}", spv_manager.sync_height(Network::Testnet));

            // Set target height for sync
            spv_manager.set_target_height(Network::Testnet, 1_000_000);
            println!("   Target height set to: 1,000,000");

            // Update sync status after setting target
            println!("   Updated sync status: {:?}", spv_manager.sync_status(Network::Testnet));
        }
        Err(e) => {
            println!("❌ Failed to create SPV wallet: {:?}", e);
        }
    }

    // Example 6: Getting wallet balance
    println!("\n6. Checking wallet balances...");

    for (i, wallet_id) in [wallet_id, wallet_id2].iter().enumerate() {
        match manager.get_wallet_balance(wallet_id) {
            Ok(balance) => {
                println!("   Wallet {}: {} satoshis", i + 1, balance.total);
            }
            Err(e) => {
                println!("   Wallet {}: Error - {:?}", i + 1, e);
            }
        }
    }

    let total_balance = manager.get_total_balance();
    println!("   Total balance across all wallets: {} satoshis", total_balance);

    // Example 7: Block height tracking
    println!("\n7. Block height tracking...");

    println!("   Current height (Testnet): {}", manager.current_height(Network::Testnet));

    // Update height
    manager.update_height(Network::Testnet, 850_000);
    println!("   Updated height to: {}", manager.current_height(Network::Testnet));

    println!("\n=== Summary ===");
    println!("Total wallets created: {}", manager.wallet_count());
    println!("✅ Example completed successfully!");
}
