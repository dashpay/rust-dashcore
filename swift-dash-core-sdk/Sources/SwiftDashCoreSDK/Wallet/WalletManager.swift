import Foundation
import Combine
import DashSPVFFI

@Observable
public class WalletManager {
    internal let client: SPVClient
    
    public internal(set) var watchedAddresses: Set<String> = []
    public internal(set) var totalBalance: Balance = Balance()
    public internal(set) var totalMempoolBalance: MempoolBalance = MempoolBalance(pending: 0, pendingInstant: 0)
    public internal(set) var transactions: [String: Transaction] = [:] // txid -> Transaction
    public internal(set) var addressTransactions: [String: Set<String>] = [:] // address -> Set of txids
    public internal(set) var mempoolTransactions: Set<String> = [] // txids of mempool transactions
    
    private var cancellables = Set<AnyCancellable>()
    
    public init(client: SPVClient) {
        self.client = client
        setupEventHandlers()
    }
    
    // MARK: - Address Management
    
    public func watchAddress(_ address: String, label: String? = nil) async throws {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        try validateAddress(address)
        
        // Add address to SPV client watch list
        try await client.addWatchItem(type: .address, data: address)
        
        watchedAddresses.insert(address)
        
        // Update balance for new address
        try await updateBalance(for: address)
    }
    
    public func unwatchAddress(_ address: String) async throws {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        // Remove address from SPV client watch list
        try await client.removeWatchItem(type: .address, data: address)
        
        watchedAddresses.remove(address)
        await updateTotalBalance()
    }
    
    public func watchScript(_ script: Data) async throws {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        // Convert script data to hex string
        let scriptHex = script.map { String(format: "%02x", $0) }.joined()
        
        // Add script to SPV client watch list
        try await client.addWatchItem(type: .script, data: scriptHex)
    }
    
    // MARK: - Balance Queries
    
    public func getBalance(for address: String) async throws -> Balance {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        return try await client.getAddressBalance(address)
    }
    
    public func getTotalBalance() async throws -> Balance {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        return try await client.getTotalBalance()
    }
    
    public func getBalanceWithMempool() async throws -> Balance {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        return try await client.getBalanceWithMempool()
    }
    
    public func getMempoolBalance(for address: String) async throws -> MempoolBalance {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        return try await client.getMempoolBalance(for: address)
    }
    
    public func getTotalMempoolBalance() async throws -> MempoolBalance {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        var totalPending: UInt64 = 0
        var totalPendingInstant: UInt64 = 0
        
        for address in watchedAddresses {
            let mempoolBalance = try await getMempoolBalance(for: address)
            totalPending += mempoolBalance.pending
            totalPendingInstant += mempoolBalance.pendingInstant
        }
        
        return MempoolBalance(pending: totalPending, pendingInstant: totalPendingInstant)
    }
    
    /// Combined balance including confirmed and mempool
    public func getCombinedBalance() async throws -> (confirmed: Balance, mempool: MempoolBalance, total: UInt64) {
        let confirmedBalance = try await getTotalBalance()
        let mempoolBalance = try await getTotalMempoolBalance()
        let total = confirmedBalance.total + mempoolBalance.total
        
        return (confirmed: confirmedBalance, mempool: mempoolBalance, total: total)
    }
    
    // MARK: - UTXO Management
    
    public func getUTXOs(for address: String? = nil) async throws -> [UTXO] {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        // This would call the FFI function to get UTXOs
        return []
    }
    
    public func getSpendableUTXOs(minConfirmations: UInt32 = 1) async throws -> [UTXO] {
        let allUTXOs = try await getUTXOs()
        return allUTXOs.filter { utxo in
            utxo.confirmations >= minConfirmations || utxo.isInstantLocked
        }
    }
    
    // MARK: - Transaction History
    
    public func getTransactions(for address: String? = nil, limit: Int = 100) async throws -> [Transaction] {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        var result: [Transaction]
        
        // Filter by address if provided
        if let address = address {
            // Get transaction IDs for this address
            let txids = addressTransactions[address] ?? Set<String>()
            
            // Get the actual transaction objects
            result = txids.compactMap { transactions[$0] }
        } else {
            // Return all transactions
            result = Array(transactions.values)
        }
        
        // Sort by timestamp, newest first
        result.sort { $0.timestamp > $1.timestamp }
        
        // Apply limit
        if result.count > limit {
            result = Array(result.prefix(limit))
        }
        
        return result
    }
    
    public func getTransaction(txid: String) async throws -> Transaction? {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        // Return from local storage
        return transactions[txid]
    }
    
    // MARK: - Transaction Building
    
    public func createTransaction(
        to address: String,
        amount: UInt64,
        feeRate: UInt64 = 1000,
        changeAddress: String? = nil
    ) async throws -> Data {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        try validateAddress(address)
        
        let utxos = try await getSpendableUTXOs()
        let totalAvailable = utxos.reduce(0) { $0 + $1.value }
        
        guard totalAvailable >= amount else {
            throw DashSDKError.insufficientFunds(required: amount, available: totalAvailable)
        }
        
        // Select UTXOs for the transaction
        let selectedUTXOs = selectUTXOs(from: utxos, targetAmount: amount, feeRate: feeRate)
        
        // Build transaction
        let builder = TransactionBuilder()
        return try builder.buildTransaction(
            inputs: selectedUTXOs,
            outputs: [(address: address, amount: amount)],
            changeAddress: changeAddress ?? watchedAddresses.first ?? "",
            feeRate: feeRate
        )
    }
    
    // MARK: - Private
    
    private func setupEventHandlers() {
        client.eventPublisher
            .sink { [weak self] event in
                Task { [weak self] in
                    await self?.handleEvent(event)
                }
            }
            .store(in: &cancellables)
    }
    
    private func handleEvent(_ event: SPVEvent) async {
        switch event {
        case .balanceUpdated(let balance):
            self.totalBalance = balance
        case .transactionReceived(let txid, let confirmed, let amount, let addresses, let blockHeight):
            // Handle transaction with full details
            await handleTransactionDetected(txid: txid, confirmed: confirmed, amount: amount, addresses: addresses, blockHeight: blockHeight)
        case .mempoolTransactionAdded(let txid, let amount, let addresses):
            // Handle new mempool transaction
            await handleMempoolTransactionAdded(txid: txid, amount: amount, addresses: addresses)
        case .mempoolTransactionConfirmed(let txid, let blockHeight, let confirmations):
            // Handle confirmed mempool transaction
            await handleMempoolTransactionConfirmed(txid: txid, blockHeight: blockHeight, confirmations: confirmations)
        case .mempoolTransactionRemoved(let txid, let reason):
            // Handle removed mempool transaction
            await handleMempoolTransactionRemoved(txid: txid, reason: reason)
        default:
            break
        }
    }
    
    private func updateBalance(for address: String) async throws {
        _ = try await getBalance(for: address)
        // Update total balance after adding new address
        await updateTotalBalance()
    }
    
    internal func updateTotalBalance() async {
        do {
            totalBalance = try await getTotalBalance()
        } catch {
            print("Failed to update total balance: \(error)")
        }
    }
    
    private func handleTransactionDetected(txid: String, confirmed: Bool, amount: Int64, addresses: [String], blockHeight: UInt32?) async {
        // Check if we already have this transaction
        if var existingTx = transactions[txid] {
            // Update confirmation status if needed
            if confirmed && existingTx.confirmations == 0 {
                existingTx.confirmations = 1
                existingTx.height = blockHeight
                transactions[txid] = existingTx
            }
            return
        }
        
        // Create transaction with real data
        let transaction = Transaction(
            txid: txid,
            height: blockHeight,
            timestamp: Date(),
            amount: amount,
            fee: 0, // Fee is not provided in the event
            confirmations: confirmed ? 1 : 0,
            isInstantLocked: false // Could be determined from confirmation speed
        )
        
        // Store the transaction
        transactions[txid] = transaction
        
        // Associate transaction with addresses
        for address in addresses {
            // Add to address-transaction mapping
            if addressTransactions[address] == nil {
                addressTransactions[address] = Set<String>()
            }
            addressTransactions[address]?.insert(txid)
        }
        
        // Update balance
        await updateTotalBalance()
        
        // Log for debugging
        print("💸 New transaction detected: \(txid)")
        print("   Amount: \(amount) satoshis (\(Double(amount) / 100_000_000) DASH)")
        print("   Addresses: \(addresses.joined(separator: ", "))")
        print("   Confirmed: \(confirmed), Height: \(blockHeight ?? 0)")
        print("📊 Total transactions stored: \(transactions.count)")
    }
    
    private func handleMempoolTransactionAdded(txid: String, amount: Int64, addresses: [String]) async {
        // Add to mempool transactions set
        mempoolTransactions.insert(txid)
        
        // Create unconfirmed transaction
        let transaction = Transaction(
            txid: txid,
            height: nil,
            timestamp: Date(),
            amount: amount,
            fee: 0, // Fee not provided in event
            confirmations: 0,
            isInstantLocked: false
        )
        
        // Store the transaction
        transactions[txid] = transaction
        
        // Associate with addresses
        for address in addresses {
            if addressTransactions[address] == nil {
                addressTransactions[address] = Set<String>()
            }
            addressTransactions[address]?.insert(txid)
        }
        
        // Update mempool balance
        await updateMempoolBalance()
        
        print("🔄 New mempool transaction: \(txid)")
        print("   Amount: \(amount) satoshis")
        print("   Addresses: \(addresses.joined(separator: ", "))")
    }
    
    private func handleMempoolTransactionConfirmed(txid: String, blockHeight: UInt32, confirmations: UInt32) async {
        // Remove from mempool set
        mempoolTransactions.remove(txid)
        
        // Update transaction status
        if var transaction = transactions[txid] {
            transaction.height = blockHeight
            transaction.confirmations = confirmations
            transactions[txid] = transaction
            
            print("✅ Mempool transaction confirmed: \(txid) at height \(blockHeight)")
        }
        
        // Update balances
        await updateTotalBalance()
        await updateMempoolBalance()
    }
    
    private func handleMempoolTransactionRemoved(txid: String, reason: MempoolRemovalReason) async {
        // Remove from mempool set
        mempoolTransactions.remove(txid)
        
        // Remove transaction if it wasn't confirmed
        if reason != MempoolRemovalReason.confirmed {
            transactions.removeValue(forKey: txid)
            
            // Remove from address mappings
            for (address, var txids) in addressTransactions {
                if txids.remove(txid) != nil {
                    addressTransactions[address] = txids.isEmpty ? nil : txids
                }
            }
        }
        
        // Update mempool balance
        await updateMempoolBalance()
        
        print("❌ Mempool transaction removed: \(txid), reason: \(reason)")
    }
    
    private func updateMempoolBalance() async {
        do {
            totalMempoolBalance = try await getTotalMempoolBalance()
        } catch {
            print("Failed to update mempool balance: \(error)")
        }
    }
    
    private func validateAddress(_ address: String) throws {
        // This would call the FFI validation function
        guard address.starts(with: "X") || address.starts(with: "y") else {
            throw DashSDKError.invalidAddress(address)
        }
    }
    
    private func selectUTXOs(from utxos: [UTXO], targetAmount: UInt64, feeRate: UInt64) -> [UTXO] {
        // Simple UTXO selection algorithm
        var selected: [UTXO] = []
        var totalSelected: UInt64 = 0
        
        // Sort by value descending
        let sorted = utxos.sorted { $0.value > $1.value }
        
        for utxo in sorted {
            selected.append(utxo)
            totalSelected += utxo.value
            
            // Estimate fee based on transaction size
            let estimatedFee = UInt64(selected.count * 148 + 2 * 34 + 10) * feeRate / 1000
            
            if totalSelected >= targetAmount + estimatedFee {
                break
            }
        }
        
        return selected
    }
}

// MARK: - Transaction Builder

public struct TransactionBuilder {
    public init() {}
    
    public func buildTransaction(
        inputs: [UTXO],
        outputs: [(address: String, amount: UInt64)],
        changeAddress: String,
        feeRate: UInt64
    ) throws -> Data {
        // This would build a proper Dash transaction
        // For now, return empty data as placeholder
        return Data()
    }
    
    public func estimateFee(
        inputs: Int,
        outputs: Int,
        feeRate: UInt64
    ) -> UInt64 {
        // Estimate transaction size: inputs * 148 + outputs * 34 + 10
        let estimatedSize = UInt64(inputs * 148 + outputs * 34 + 10)
        return estimatedSize * feeRate / 1000
    }
}