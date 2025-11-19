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
            SwiftDashCoreSDK.Transaction.self,
            SwiftDashCoreSDK.UTXO.self,
            SwiftDashCoreSDK.Balance.self,
            SwiftDashCoreSDK.WatchedAddress.self,
            SyncState.self
        ])

        // Check if we have migration issues by looking for specific error patterns
        let shouldCleanup = UserDefaults.standard.bool(forKey: "ForceModelCleanup")
        if shouldCleanup {
            print("Force cleanup requested, removing all data...")
            cleanupCorruptStore()
            UserDefaults.standard.set(false, forKey: "ForceModelCleanup")
        }

        do {
            // First attempt: try to create normally
            return try createContainer(with: schema, inMemory: false)
        } catch {
            print("Initial ModelContainer creation failed: \(error)")
            print("Detailed error: \(error.localizedDescription)")

            // Check if it's a migration error or model error
            if error.localizedDescription.contains("migration") ||
               error.localizedDescription.contains("relationship") ||
               error.localizedDescription.contains("to-one") ||
               error.localizedDescription.contains("to-many") ||
               error.localizedDescription.contains("materialize") ||
               error.localizedDescription.contains("Array") {
                print("Model/Migration error detected, performing complete cleanup...")
                UserDefaults.standard.set(true, forKey: "ForceModelCleanup")
            }

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

        // Clean up all SQLite and SwiftData related files
        let patternsToRemove = [
            "default.store",
            "default.store-shm",
            "default.store-wal",
            "SwiftData",
            ".sqlite",
            ".sqlite-shm",
            ".sqlite-wal",
            "ModelContainer",
            ".db"
        ]

        // Clean up all files in Application Support that could be related to the store
        if let contents = try? FileManager.default.contentsOfDirectory(at: appSupportURL, includingPropertiesForKeys: nil) {
            for fileURL in contents {
                let filename = fileURL.lastPathComponent

                // Check if file matches any of our patterns
                let shouldRemove = patternsToRemove.contains { pattern in
                    filename.contains(pattern) || filename.hasPrefix("default")
                }

                if shouldRemove {
                    do {
                        try FileManager.default.removeItem(at: fileURL)
                        print("Removed: \(filename)")
                    } catch {
                        print("Failed to remove \(filename): \(error)")
                    }
                }
            }
        }

        // Also clean up Documents directory
        if let documentsURL = documentsURL,
           let contents = try? FileManager.default.contentsOfDirectory(at: documentsURL, includingPropertiesForKeys: nil) {
            for fileURL in contents {
                let filename = fileURL.lastPathComponent

                // Check if file matches any of our patterns
                let shouldRemove = patternsToRemove.contains { pattern in
                    filename.contains(pattern) || filename.hasPrefix("default")
                }

                if shouldRemove {
                    do {
                        try FileManager.default.removeItem(at: fileURL)
                        print("Removed from Documents: \(filename)")
                    } catch {
                        print("Failed to remove from Documents \(filename): \(error)")
                    }
                }
            }
        }

        // Clear any cached SwiftData files
        let cacheURL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
        if let cacheURL = cacheURL {
            let swiftDataCache = cacheURL.appendingPathComponent("SwiftData")
            if FileManager.default.fileExists(atPath: swiftDataCache.path) {
                do {
                    try FileManager.default.removeItem(at: swiftDataCache)
                    print("Removed SwiftData cache")
                } catch {
                    print("Failed to remove SwiftData cache: \(error)")
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