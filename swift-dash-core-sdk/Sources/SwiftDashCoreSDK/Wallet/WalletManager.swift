import Foundation
import Combine
import DashSPVFFI

@Observable
public class WalletManager {
    private let client: SPVClient
    private var ffiClient: FFIClient? {
        // This would need to be exposed by SPVClient or passed in
        return nil
    }
    
    public internal(set) var watchedAddresses: Set<String> = []
    public internal(set) var totalBalance: Balance = Balance()
    
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
        
        // Note: We need access to the FFI client pointer from SPVClient
        // This is a design consideration - SPVClient might need to expose
        // a method to perform FFI operations or pass the client pointer
        
        watchedAddresses.insert(address)
        
        // Update balance for new address
        try await updateBalance(for: address)
    }
    
    public func unwatchAddress(_ address: String) async throws {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        watchedAddresses.remove(address)
        await updateTotalBalance()
    }
    
    public func watchScript(_ script: Data) async throws {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        // Implementation would call FFI watch script function
    }
    
    // MARK: - Balance Queries
    
    public func getBalance(for address: String) async throws -> Balance {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        // This would call the FFI function to get balance
        // For now, return a mock balance
        return Balance()
    }
    
    public func getTotalBalance() async throws -> Balance {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        // This would call the FFI function to get total balance
        return totalBalance
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
        
        // This would call the FFI function to get transactions
        return []
    }
    
    public func getTransaction(txid: String) async throws -> Transaction? {
        guard client.isConnected else {
            throw DashSDKError.notConnected
        }
        
        // This would call the FFI function to get a specific transaction
        return nil
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
        case .transactionReceived(let txid, let confirmed):
            // Refresh transactions for affected addresses
            await updateTotalBalance()
        default:
            break
        }
    }
    
    private func updateBalance(for address: String) async throws {
        let balance = try await getBalance(for: address)
        // Update stored balance
    }
    
    internal func updateTotalBalance() async {
        do {
            totalBalance = try await getTotalBalance()
        } catch {
            // Handle error
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