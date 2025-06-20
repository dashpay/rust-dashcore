import Foundation
import SwiftData
import SwiftDashCoreSDK

/// Helper for creating and managing SwiftData ModelContainer with migration support
struct ModelContainerHelper {
    
    /// Create a ModelContainer with automatic migration recovery
    static func createContainer() throws -> ModelContainer {
        let schema = Schema([
            HDWallet.self,
            HDAccount.self,
            HDWatchedAddress.self,
            Transaction.self,
            UTXO.self,
            Balance.self,
            SyncState.self
        ])
        
        do {
            // First attempt: try to create normally
            return try createContainer(with: schema, inMemory: false)
        } catch {
            print("Initial ModelContainer creation failed: \(error)")
            print("Detailed error: \(error.localizedDescription)")
            
            // Second attempt: clean up and retry
            cleanupCorruptStore()
            
            do {
                return try createContainer(with: schema, inMemory: false)
            } catch {
                print("Failed to create persistent store after cleanup: \(error)")
                
                // Final attempt: in-memory store
                print("Falling back to in-memory store")
                return try createContainer(with: schema, inMemory: true)
            }
        }
    }
    
    private static func createContainer(with schema: Schema, inMemory: Bool) throws -> ModelContainer {
        let modelConfiguration = ModelConfiguration(
            schema: schema,
            isStoredInMemoryOnly: inMemory,
            groupContainer: .automatic,
            cloudKitDatabase: .none
        )
        
        return try ModelContainer(
            for: schema,
            configurations: [modelConfiguration]
        )
    }
    
    static func cleanupCorruptStore() {
        print("Starting cleanup of corrupt store...")
        
        guard let appSupportURL = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else { return }
        
        let documentsURL = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first
        
        // Clean up all files in Application Support that could be related to the store
        if let contents = try? FileManager.default.contentsOfDirectory(at: appSupportURL, includingPropertiesForKeys: nil) {
            for fileURL in contents {
                if fileURL.lastPathComponent.contains("store") || 
                   fileURL.lastPathComponent.hasPrefix("default") ||
                   fileURL.lastPathComponent == "SwiftData" {
                    do {
                        try FileManager.default.removeItem(at: fileURL)
                        print("Removed: \(fileURL.lastPathComponent)")
                    } catch {
                        print("Failed to remove \(fileURL.lastPathComponent): \(error)")
                    }
                }
            }
        }
        
        // Also clean up Documents directory
        if let documentsURL = documentsURL,
           let contents = try? FileManager.default.contentsOfDirectory(at: documentsURL, includingPropertiesForKeys: nil) {
            for fileURL in contents {
                if fileURL.lastPathComponent.contains("store") || 
                   fileURL.lastPathComponent.hasPrefix("default") {
                    do {
                        try FileManager.default.removeItem(at: fileURL)
                        print("Removed from Documents: \(fileURL.lastPathComponent)")
                    } catch {
                        print("Failed to remove from Documents \(fileURL.lastPathComponent): \(error)")
                    }
                }
            }
        }
        
        print("Store cleanup completed")
    }
    
    /// Check if the current store needs migration
    static func needsMigration(for container: ModelContainer) -> Bool {
        // This would check the model version or schema changes
        // For now, return false as we handle migration errors automatically
        return false
    }
    
    /// Export wallet data before migration
    static func exportDataForMigration(from context: ModelContext) throws -> Data? {
        do {
            let wallets = try context.fetch(FetchDescriptor<HDWallet>())
            
            // Create export structure
            let exportData = MigrationExportData(
                wallets: wallets.map { wallet in
                    MigrationWallet(
                        id: wallet.id,
                        name: wallet.name,
                        network: wallet.network,
                        encryptedSeed: wallet.encryptedSeed,
                        seedHash: wallet.seedHash,
                        createdAt: wallet.createdAt
                    )
                }
            )
            
            return try JSONEncoder().encode(exportData)
        } catch {
            print("Failed to export data for migration: \(error)")
            return nil
        }
    }
}

// MARK: - Migration Data Structures

private struct MigrationExportData: Codable {
    let wallets: [MigrationWallet]
}

private struct MigrationWallet: Codable {
    let id: UUID
    let name: String
    let network: DashNetwork
    let encryptedSeed: Data
    let seedHash: String
    let createdAt: Date
}