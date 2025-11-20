//! Example demonstrating QuorumLookup usage for shared quorum queries.
//!
//! This example shows how to use the QuorumLookup component to perform
//! quorum queries without requiring exclusive access to the DashSpvClient.
//!
//! # Key Points
//!
//! 1. Get QuorumLookup from the client via `client.quorum_lookup()`
//! 2. Clone the Arc<QuorumLookup> to use in different threads/tasks
//! 3. Perform concurrent quorum queries without blocking
//! 4. No need for Arc<RwLock<DashSpvClient>> wrapping

use dash_spv::client::QuorumLookup;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 QuorumLookup Usage Example\n");

    // In a real application, you would get this from your DashSpvClient:
    // let quorum_lookup = client.quorum_lookup();
    //
    // For this example, we'll create one directly:
    let quorum_lookup = Arc::new(QuorumLookup::new());

    println!("✅ Created QuorumLookup component\n");
    println!("📋 Initial state:");
    println!("   - Is available: {}", quorum_lookup.is_available());
    println!("   - Masternode lists: {}\n", quorum_lookup.masternode_list_count());

    // Clone it for use in another async task
    let lookup_clone1 = quorum_lookup.clone();
    let lookup_clone2 = quorum_lookup.clone();

    // Spawn multiple tasks that use the cloned lookups concurrently
    let task1 = tokio::spawn(async move {
        println!("🔍 Task 1: Attempting quorum query at height 100000...");
        let quorum_hash = [0u8; 32];
        match lookup_clone1.get_quorum_at_height(100000, 1, &quorum_hash).await {
            Some(quorum) => {
                println!(
                    "   ✅ Task 1: Found quorum (public key length: {})",
                    quorum.quorum_entry.quorum_public_key.len()
                );
            }
            None => {
                println!("   ⚠️  Task 1: Quorum not found (expected before masternode sync)");
            }
        }
    });

    let task2 = tokio::spawn(async move {
        println!("🔍 Task 2: Checking masternode list range...");
        match lookup_clone2.masternode_list_height_range() {
            Some((min, max)) => {
                println!("   📊 Task 2: Masternode lists from height {} to {}", min, max);
            }
            None => {
                println!("   ⚠️  Task 2: No masternode lists available yet");
            }
        }
    });

    // Use the original lookup in the main thread
    println!("🔍 Main: Checking availability...");
    if quorum_lookup.is_available() {
        println!("   ✅ Main: QuorumLookup is ready for queries");
    } else {
        println!("   ⚠️  Main: QuorumLookup waiting for masternode sync");
    }

    // Wait for all tasks
    task1.await?;
    task2.await?;

    println!("\n✨ Example complete!");
    println!("\n📚 Integration with DashSpvClient:");
    println!("   ```rust");
    println!("   // In your app, after creating the SPV client:");
    println!("   let client = DashSpvClient::new(...).await?;");
    println!("   ");
    println!("   // Get the shared QuorumLookup component:");
    println!("   let quorum_lookup = client.quorum_lookup();");
    println!("   ");
    println!("   // Clone and use across your application:");
    println!("   let lookup_for_thread = quorum_lookup.clone();");
    println!("   ");
    println!("   // Query quorums from anywhere:");
    println!("   if let Some(quorum) = quorum_lookup");
    println!("       .get_quorum_at_height(height, quorum_type, &hash)");
    println!("       .await");
    println!("   {{");
    println!("       // Use the quorum data");
    println!("   }}");
    println!("   ```");
    println!("\n🎯 Benefits:");
    println!("   1. No need to wrap DashSpvClient in Arc<RwLock<_>>");
    println!("   2. Multiple concurrent queries without blocking");
    println!("   3. Cheap cloning via Arc");
    println!("   4. Thread-safe by design");

    Ok(())
}
