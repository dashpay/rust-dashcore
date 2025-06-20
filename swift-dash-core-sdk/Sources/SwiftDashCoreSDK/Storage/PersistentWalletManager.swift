import Foundation
import Combine
import SwiftData

@Observable
public final class PersistentWalletManager: WalletManager {
    private let storage: StorageManager
    private var syncTask: Task<Void, Never>?
    
    public init(client: SPVClient, storage: StorageManager) {
        self.storage = storage
        super.init(client: client)
        
        Task {
            await loadPersistedData()
        }
    }
    
    deinit {
        syncTask?.cancel()
    }
    
    // MARK: - Overrides
    
    public override func watchAddress(_ address: String, label: String? = nil) async throws {
        try await super.watchAddress(address, label: label)
        
        // Persist to storage
        let watchedAddress = WatchedAddress(address: address, label: label)
        try storage.saveWatchedAddress(watchedAddress)
        
        // Start syncing data for this address
        await syncAddressData(address)
    }
    
    public override func unwatchAddress(_ address: String) async throws {
        try await super.unwatchAddress(address)
        
        // Remove from storage
        if let watchedAddress = try storage.fetchWatchedAddress(by: address) {
            try storage.deleteWatchedAddress(watchedAddress)
        }
    }
    
    public override func getBalance(for address: String) async throws -> Balance {
        // Try to get from storage first
        if let cachedBalance = try storage.fetchBalance(for: address) {
            // Check if balance is recent (within last minute)
            if Date.now.timeIntervalSince(cachedBalance.lastUpdated) < 60 {
                return cachedBalance
            }
        }
        
        // Fetch fresh balance
        let balance = try await super.getBalance(for: address)
        
        // Save to storage
        try storage.saveBalance(balance, for: address)
        
        return balance
    }
    
    public override func getUTXOs(for address: String? = nil) async throws -> [UTXO] {
        // Get from storage
        let cachedUTXOs = try storage.fetchUTXOs(for: address)
        
        // If we have recent data, return it
        if !cachedUTXOs.isEmpty {
            return cachedUTXOs
        }
        
        // Otherwise fetch fresh data
        let utxos = try await super.getUTXOs(for: address)
        
        // Save to storage
        try await storage.saveUTXOs(utxos)
        
        return utxos
    }
    
    public override func getTransactions(for address: String? = nil, limit: Int = 100) async throws -> [Transaction] {
        // Get from storage
        let cachedTransactions = try storage.fetchTransactions(for: address, limit: limit)
        
        // If we have data, return it (we'll sync in background)
        if !cachedTransactions.isEmpty {
            Task {
                await syncTransactions(for: address)
            }
            return cachedTransactions
        }
        
        // Otherwise fetch fresh data
        let transactions = try await super.getTransactions(for: address, limit: limit)
        
        // Save to storage
        try await storage.saveTransactions(transactions)
        
        return transactions
    }
    
    // MARK: - Persistence Methods
    
    private func loadPersistedData() async {
        do {
            // Load watched addresses
            let addresses = try storage.fetchWatchedAddresses()
            watchedAddresses = Set(addresses.map { $0.address })
            
            // Load total balance
            var totalConfirmed: UInt64 = 0
            var totalPending: UInt64 = 0
            var totalInstantLocked: UInt64 = 0
            
            for address in addresses {
                if let balance = address.balance {
                    totalConfirmed += balance.confirmed
                    totalPending += balance.pending
                    totalInstantLocked += balance.instantLocked
                }
            }
            
            totalBalance = Balance(
                confirmed: totalConfirmed,
                pending: totalPending,
                instantLocked: totalInstantLocked,
                total: totalConfirmed + totalPending
            )
        } catch {
            print("Failed to load persisted data: \(error)")
        }
    }
    
    private func syncAddressData(_ address: String) async {
        do {
            // Sync balance
            let balance = try await getBalance(for: address)
            try storage.saveBalance(balance, for: address)
            
            // Sync UTXOs
            let utxos = try await getUTXOs(for: address)
            try await storage.saveUTXOs(utxos)
            
            // Sync transactions
            let transactions = try await getTransactions(for: address)
            try await storage.saveTransactions(transactions)
            
            // Update activity timestamp
            if let watchedAddress = try storage.fetchWatchedAddress(by: address) {
                watchedAddress.updateActivity()
                try storage.saveWatchedAddress(watchedAddress)
            }
        } catch {
            print("Failed to sync address data: \(error)")
        }
    }
    
    private func syncTransactions(for address: String?) async {
        do {
            let transactions = try await super.getTransactions(for: address)
            
            // Update or insert transactions
            for transaction in transactions {
                if let existing = try storage.fetchTransaction(by: transaction.txid) {
                    // Update existing transaction
                    existing.confirmations = transaction.confirmations
                    existing.isInstantLocked = transaction.isInstantLocked
                    try storage.updateTransaction(existing)
                } else {
                    // Save new transaction
                    try storage.saveTransaction(transaction)
                }
            }
        } catch {
            print("Failed to sync transactions: \(error)")
        }
    }
    
    // MARK: - Public Persistence Methods
    
    public func startPeriodicSync(interval: TimeInterval = 30) {
        syncTask?.cancel()
        
        syncTask = Task {
            while !Task.isCancelled {
                await syncAllData()
                
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            }
        }
    }
    
    public func stopPeriodicSync() {
        syncTask?.cancel()
        syncTask = nil
    }
    
    public func syncAllData() async {
        for address in watchedAddresses {
            await syncAddressData(address)
        }
        
        await updateTotalBalance()
    }
    
    public func getStorageStatistics() throws -> StorageStatistics {
        return try storage.getStorageStatistics()
    }
    
    public func clearAllData() throws {
        try storage.deleteAllData()
        watchedAddresses.removeAll()
        totalBalance = Balance()
    }
    
    public func exportWalletData() throws -> WalletExportData {
        let addresses = try storage.fetchWatchedAddresses()
        let transactions = try storage.fetchTransactions()
        let utxos = try storage.fetchUTXOs()
        
        // Convert SwiftData models to Codable types
        let exportedAddresses = addresses.map { address in
            WalletExportData.ExportedAddress(
                address: address.address,
                label: address.label,
                createdAt: address.createdAt,
                isActive: address.isActive,
                balance: address.balance.map { balance in
                    WalletExportData.ExportedBalance(
                        confirmed: balance.confirmed,
                        pending: balance.pending,
                        instantLocked: balance.instantLocked,
                        total: balance.total
                    )
                }
            )
        }
        
        let exportedTransactions = transactions.map { tx in
            WalletExportData.ExportedTransaction(
                txid: tx.txid,
                height: tx.height,
                timestamp: tx.timestamp,
                amount: tx.amount,
                fee: tx.fee,
                confirmations: tx.confirmations,
                isInstantLocked: tx.isInstantLocked,
                size: tx.size,
                version: tx.version
            )
        }
        
        let exportedUTXOs = utxos.map { utxo in
            WalletExportData.ExportedUTXO(
                txid: utxo.txid,
                vout: utxo.vout,
                address: utxo.address,
                value: utxo.value,
                height: utxo.height,
                confirmations: utxo.confirmations,
                isInstantLocked: utxo.isInstantLocked
            )
        }
        
        return WalletExportData(
            addresses: exportedAddresses,
            transactions: exportedTransactions,
            utxos: exportedUTXOs,
            exportDate: .now
        )
    }
    
    public func importWalletData(_ data: WalletExportData) async throws {
        // Clear existing data
        try clearAllData()
        
        // Import addresses
        for exportedAddress in data.addresses {
            let address = WatchedAddress(
                address: exportedAddress.address,
                label: exportedAddress.label,
                createdAt: exportedAddress.createdAt,
                isActive: exportedAddress.isActive
            )
            
            // Create balance if present
            if let exportedBalance = exportedAddress.balance {
                let balance = Balance(
                    confirmed: exportedBalance.confirmed,
                    pending: exportedBalance.pending,
                    instantLocked: exportedBalance.instantLocked
                )
                address.balance = balance
            }
            
            try storage.saveWatchedAddress(address)
            watchedAddresses.insert(address.address)
        }
        
        // Import transactions
        let transactions = data.transactions.map { exportedTx in
            Transaction(
                txid: exportedTx.txid,
                height: exportedTx.height,
                timestamp: exportedTx.timestamp,
                amount: exportedTx.amount,
                fee: exportedTx.fee,
                confirmations: exportedTx.confirmations,
                isInstantLocked: exportedTx.isInstantLocked,
                size: exportedTx.size,
                version: exportedTx.version
            )
        }
        try await storage.saveTransactions(transactions)
        
        // Import UTXOs
        let utxos = data.utxos.map { exportedUTXO in
            let outpoint = "\(exportedUTXO.txid):\(exportedUTXO.vout)"
            return UTXO(
                outpoint: outpoint,
                txid: exportedUTXO.txid,
                vout: exportedUTXO.vout,
                address: exportedUTXO.address,
                script: Data(), // Empty script for imported UTXOs
                value: exportedUTXO.value,
                height: exportedUTXO.height ?? 0,
                confirmations: exportedUTXO.confirmations,
                isInstantLocked: exportedUTXO.isInstantLocked
            )
        }
        try await storage.saveUTXOs(utxos)
        
        // Update balances
        await updateTotalBalance()
    }
}

// MARK: - Wallet Export Data

public struct WalletExportData: Codable {
    public struct ExportedAddress: Codable {
        public let address: String
        public let label: String?
        public let createdAt: Date
        public let isActive: Bool
        public let balance: ExportedBalance?
    }
    
    public struct ExportedBalance: Codable {
        public let confirmed: UInt64
        public let pending: UInt64
        public let instantLocked: UInt64
        public let total: UInt64
    }
    
    public struct ExportedTransaction: Codable {
        public let txid: String
        public let height: UInt32?
        public let timestamp: Date
        public let amount: Int64
        public let fee: UInt64
        public let confirmations: UInt32
        public let isInstantLocked: Bool
        public let size: UInt32
        public let version: UInt32
    }
    
    public struct ExportedUTXO: Codable {
        public let txid: String
        public let vout: UInt32
        public let address: String
        public let value: UInt64
        public let height: UInt32?
        public let confirmations: UInt32
        public let isInstantLocked: Bool
    }
    
    public let addresses: [ExportedAddress]
    public let transactions: [ExportedTransaction]
    public let utxos: [ExportedUTXO]
    public let exportDate: Date
    
    public var formattedSize: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        
        if let data = try? encoder.encode(self) {
            return ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .binary)
        }
        
        return "Unknown"
    }
}