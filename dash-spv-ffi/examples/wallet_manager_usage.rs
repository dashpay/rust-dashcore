/// Example demonstrating the simplified FFIWalletManager usage
///
/// The refactored design removes unnecessary indirection by:
/// 1. FFIWalletManager directly contains Arc<RwLock<WalletManager>>
/// 2. No longer requires going through the client for each operation
/// 3. Cleaner and more efficient access to wallet functionality
use dash_spv_ffi::*;
use key_wallet_ffi::{wallet_manager_free, wallet_manager_wallet_count, FFIError};

fn main() {
    unsafe {
        // Create a config for testnet
        let config = dash_spv_ffi_config_testnet();
        if config.is_null() {
            panic!("Failed to create config");
        }

        // Create an SPV client
        let client = dash_spv_ffi_client_new(config);
        if client.is_null() {
            panic!("Failed to create client");
        }

        // Get the wallet manager - now returns void* for Swift compatibility
        // This contains a cloned Arc to the wallet manager, allowing
        // direct interaction without going through the client
        let wallet_manager_ptr = dash_spv_ffi_client_get_wallet_manager(client);
        if wallet_manager_ptr.is_null() {
            panic!("Failed to get wallet manager");
        }
        // Cast back to FFIWalletManager for use
        let wallet_manager = wallet_manager_ptr as *mut key_wallet_ffi::FFIWalletManager;

        // Now we can use the wallet manager directly
        // No need to go through client -> inner -> spv_client -> wallet()

        // Get the number of wallets (should be 0 initially)
        let mut error = std::mem::zeroed::<FFIError>();
        let wallet_count = wallet_manager_wallet_count(wallet_manager, &mut error);
        println!("Number of wallets: {}", wallet_count);

        // Note: To get total balance, you would need to iterate through wallets
        // For now, just show the wallet count
        println!("Currently managing {} wallets", wallet_count);

        // Example of processing a transaction (with mock data)
        // In real usage, you would have actual transaction hex
        /*
        let tx_hex = "01000000..."; // Transaction hex string
        let mut error = std::mem::zeroed();
        let affected = wallet_manager_process_transaction(
            wallet_manager,
            tx_hex.as_ptr() as *const i8,
            FFINetworks::Testnet,
            100000, // block height
            &mut error
        );

        if affected >= 0 {
            println!("Transaction affected {} wallets", affected);
        } else {
            println!("Failed to process transaction");
        }
        */

        // Clean up
        // The wallet manager can now be independently destroyed
        // It maintains its own Arc reference to the underlying wallet
        wallet_manager_free(wallet_manager);
        dash_spv_ffi_client_destroy(client);
        dash_spv_ffi_config_destroy(config);

        println!("Example completed successfully!");
    }
}
