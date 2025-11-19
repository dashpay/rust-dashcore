import Foundation
import SwiftData

@Observable
public final class StorageManager {
    private let modelContainer: ModelContainer
    private let modelContext: ModelContext
    private let backgroundContext: ModelContext

    @MainActor
    public init() throws {
        let schema = Schema([
            WatchedAddress.self,
            Transaction.self,
            UTXO.self,
            Balance.self
        ])

        let configuration = ModelConfiguration(
            schema: schema,
            isStoredInMemoryOnly: false,
            groupContainer: .automatic,
            cloudKitDatabase: .none
        )

        self.modelContainer = try ModelContainer(
            for: schema,
            configurations: [configuration]
        )

        self.modelContext = modelContainer.mainContext
        self.backgroundContext = ModelContext(modelContainer)

        // Configure contexts
        modelContext.autosaveEnabled = true
        backgroundContext.autosaveEnabled = false
    }

    // MARK: - Watched Addresses

    public func saveWatchedAddress(_ address: WatchedAddress) throws {
        modelContext.insert(address)
        try modelContext.save()
    }

    public func fetchWatchedAddresses() throws -> [WatchedAddress] {
        let descriptor = FetchDescriptor<WatchedAddress>(
            sortBy: [SortDescriptor(\.createdAt, order: .reverse)]
        )
        return try modelContext.fetch(descriptor)
    }

    public func fetchWatchedAddress(by address: String) throws -> WatchedAddress? {
        let predicate = #Predicate<WatchedAddress> { watchedAddress in
            watchedAddress.address == address
        }

        let descriptor = FetchDescriptor<WatchedAddress>(predicate: predicate)
        return try modelContext.fetch(descriptor).first
    }

    public func deleteWatchedAddress(_ address: WatchedAddress) throws {
        modelContext.delete(address)
        try modelContext.save()
    }

    // MARK: - Transactions

    public func saveTransaction(_ transaction: Transaction) throws {
        modelContext.insert(transaction)
        try modelContext.save()
    }

    public func saveTransactions(_ transactions: [Transaction]) async throws {
        for transaction in transactions {
            backgroundContext.insert(transaction)
        }
        try backgroundContext.save()
    }

    public func fetchTransactions(
        for address: String? = nil,
        limit: Int = 100,
        offset: Int = 0
    ) throws -> [Transaction] {
        var descriptor = FetchDescriptor<Transaction>(
            sortBy: [SortDescriptor(\.timestamp, order: .reverse)]
        )

        if let address = address {
            // This would need a relationship or additional field to filter by address
            // For now, fetch all transactions
        }

        descriptor.fetchLimit = limit
        descriptor.fetchOffset = offset

        return try modelContext.fetch(descriptor)
    }

    public func fetchTransaction(by txid: String) throws -> Transaction? {
        let predicate = #Predicate<Transaction> { transaction in
            transaction.txid == txid
        }

        let descriptor = FetchDescriptor<Transaction>(predicate: predicate)
        return try modelContext.fetch(descriptor).first
    }

    public func updateTransaction(_ transaction: Transaction) throws {
        try modelContext.save()
    }

    // MARK: - UTXOs

    public func saveUTXO(_ utxo: UTXO) throws {
        modelContext.insert(utxo)
        try modelContext.save()
    }

    public func saveUTXOs(_ utxos: [UTXO]) async throws {
        for utxo in utxos {
            backgroundContext.insert(utxo)
        }
        try backgroundContext.save()
    }

    public func fetchUTXOs(
        for address: String? = nil,
        includeSpent: Bool = false
    ) throws -> [UTXO] {
        var predicate: Predicate<UTXO>?

        if let address = address {
            if includeSpent {
                predicate = #Predicate<UTXO> { utxo in
                    utxo.address == address
                }
            } else {
                predicate = #Predicate<UTXO> { utxo in
                    utxo.address == address && !utxo.isSpent
                }
            }
        } else if !includeSpent {
            predicate = #Predicate<UTXO> { utxo in
                !utxo.isSpent
            }
        }

        let descriptor = FetchDescriptor<UTXO>(
            predicate: predicate,
            sortBy: [SortDescriptor(\.value, order: .reverse)]
        )

        return try modelContext.fetch(descriptor)
    }

    public func markUTXOAsSpent(outpoint: String) throws {
        let predicate = #Predicate<UTXO> { utxo in
            utxo.outpoint == outpoint
        }

        let descriptor = FetchDescriptor<UTXO>(predicate: predicate)
        if let utxo = try modelContext.fetch(descriptor).first {
            utxo.isSpent = true
            try modelContext.save()
        }
    }

    // MARK: - Balance

    public func saveBalance(_ balance: Balance, for address: String) throws {
        if let watchedAddress = try fetchWatchedAddress(by: address) {
            watchedAddress.balance = balance
            try modelContext.save()
        }
    }

    public func fetchBalance(for address: String) throws -> Balance? {
        let watchedAddress = try fetchWatchedAddress(by: address)
        return watchedAddress?.balance
    }

    // MARK: - Batch Operations

    public func performBatchUpdate<T>(
        _ updates: @escaping () throws -> T
    ) async throws -> T {
        let result = try updates()
        try backgroundContext.save()
        return result
    }

    // MARK: - Cleanup

    public func deleteAllData() throws {
        try modelContext.delete(model: WatchedAddress.self)
        try modelContext.delete(model: Transaction.self)
        try modelContext.delete(model: UTXO.self)
        try modelContext.delete(model: Balance.self)
        try modelContext.save()
    }

    public func pruneOldTransactions(olderThan date: Date) throws {
        let predicate = #Predicate<Transaction> { transaction in
            transaction.timestamp < date
        }

        try modelContext.delete(model: Transaction.self, where: predicate)
        try modelContext.save()
    }

    // MARK: - Statistics

    public func getStorageStatistics() throws -> StorageStatistics {
        let addressCount = try modelContext.fetchCount(FetchDescriptor<WatchedAddress>())
        let transactionCount = try modelContext.fetchCount(FetchDescriptor<Transaction>())
        let utxoCount = try modelContext.fetchCount(FetchDescriptor<UTXO>())

        let spentUTXOPredicate = #Predicate<UTXO> { $0.isSpent }
        let spentUTXOCount = try modelContext.fetchCount(
            FetchDescriptor<UTXO>(predicate: spentUTXOPredicate)
        )

        return StorageStatistics(
            watchedAddressCount: addressCount,
            transactionCount: transactionCount,
            totalUTXOCount: utxoCount,
            spentUTXOCount: spentUTXOCount,
            unspentUTXOCount: utxoCount - spentUTXOCount
        )
    }
}

// MARK: - Storage Statistics

public struct StorageStatistics {
    public let watchedAddressCount: Int
    public let transactionCount: Int
    public let totalUTXOCount: Int
    public let spentUTXOCount: Int
    public let unspentUTXOCount: Int

    public var description: String {
        """
        Storage Statistics:
        - Watched Addresses: \(watchedAddressCount)
        - Transactions: \(transactionCount)
        - Total UTXOs: \(totalUTXOCount)
        - Spent UTXOs: \(spentUTXOCount)
        - Unspent UTXOs: \(unspentUTXOCount)
        """
    }
}
