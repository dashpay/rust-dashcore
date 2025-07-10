//! Example showing how to use the non-blocking sync methods to avoid lock contention.
//! This demonstrates how DET can process network messages without holding a write lock
//! for extended periods, allowing concurrent read operations like get_quorum_public_key_sync().

use dash_spv::{DashSpvClient, ClientConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    // Create SPV client configuration
    let config = ClientConfig {
        network: dashcore::Network::Mainnet,
        data_dir: "./spv_data".to_string(),
        peer: Some("seed.dash.org:9999".to_string()),
        ..Default::default()
    };
    
    // Create client wrapped in Arc<RwLock> for shared access
    let client = Arc::new(RwLock::new(DashSpvClient::new(config).await?));
    
    // Check for sync state issues before starting
    {
        let mut client_guard = client.write().await;
        
        // Get diagnostics to check for corrupted state
        let diagnostics = client_guard.get_sync_diagnostics().await;
        tracing::info!("SPV Diagnostics:\n{}", diagnostics);
        
        // Fix corrupted sync state if detected
        if diagnostics.contains("Chain state height: 0") && diagnostics.contains("Storage header height: 2") {
            tracing::warn!("Detected corrupted sync state, resetting to checkpoint");
            client_guard.reset_to_checkpoint(2_300_000).await?;
        }
        
        // Now start the client
        client_guard.start().await?;
    }
    
    // Spawn a task to process network messages without blocking
    let network_client = client.clone();
    let network_task = tokio::spawn(async move {
        let mut sync_initialized = false;
        let mut interval = interval(Duration::from_millis(100));
        
        loop {
            interval.tick().await;
            
            // Acquire write lock only for short duration
            let mut client_guard = network_client.write().await;
            
            // Initialize sync if not done yet
            if !sync_initialized {
                match client_guard.initialize_sync().await {
                    Ok(true) => {
                        tracing::info!("Sync initialized successfully");
                        sync_initialized = true;
                    }
                    Ok(false) => {
                        // Not ready yet or already initialized
                    }
                    Err(e) => {
                        tracing::error!("Failed to initialize sync: {}", e);
                    }
                }
            }
            
            // Process messages for a short duration (50ms)
            match client_guard.process_network_messages(Duration::from_millis(50)).await {
                Ok(true) => {
                    // More messages may be available
                }
                Ok(false) => {
                    // Client stopped
                    break;
                }
                Err(e) => {
                    tracing::error!("Network processing error: {}", e);
                }
            }
            
            // Release lock before next iteration
            drop(client_guard);
        }
        
        tracing::info!("Network processing task completed");
    });
    
    // Spawn a task for periodic maintenance
    let maintenance_client = client.clone();
    let maintenance_task = tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(5));
        
        loop {
            interval.tick().await;
            
            // Acquire write lock briefly for maintenance
            let mut client_guard = maintenance_client.write().await;
            if let Err(e) = client_guard.perform_maintenance().await {
                tracing::error!("Maintenance error: {}", e);
            }
            drop(client_guard);
        }
    });
    
    // Now the main thread can perform read operations without being blocked
    let query_client = client.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            
            // Read operations only need a read lock
            let client_guard = query_client.read().await;
            
            // Example: Query sync progress
            match client_guard.sync_progress().await {
                Ok(progress) => {
                    tracing::info!("Sync progress: headers={}, filters={}", 
                        progress.header_height, 
                        progress.filter_header_height
                    );
                }
                Err(e) => {
                    tracing::error!("Failed to get sync progress: {}", e);
                }
            }
            
            // Example: Query quorum (this won't block because we only hold a read lock)
            let quorum_type = 4;
            let quorum_hash = [0u8; 32]; // Example hash
            if let Some(key) = client_guard.get_quorum_public_key_sync(quorum_type, quorum_hash) {
                tracing::info!("Found quorum key: {:?}", &key[..8]);
            }
            
            drop(client_guard);
        }
    });
    
    // Wait for user to press Enter
    println!("SPV client running. Press Enter to stop...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    // Stop the client
    {
        let mut client_guard = client.write().await;
        client_guard.stop().await?;
    }
    
    // Wait for tasks to complete
    let _ = network_task.await;
    
    Ok(())
}