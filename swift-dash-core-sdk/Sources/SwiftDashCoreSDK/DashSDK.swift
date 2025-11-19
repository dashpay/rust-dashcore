import Foundation
import Combine

@Observable
public final class DashSDK {
    private let client: SPVClient
    private let wallet: PersistentWalletManager
    private let storage: StorageManager

    public var isConnected: Bool {
        client.isConnected
    }

    public var syncProgress: SyncProgress? {
        client.syncProgress
    }

    public var stats: SPVStats? {
        client.stats
    }

    public var watchedAddresses: Set<String> {
        wallet.watchedAddresses
    }

    public var totalBalance: Balance {
        wallet.totalBalance
    }

    public var eventPublisher: AnyPublisher<SPVEvent, Never> {
        client.eventPublisher
    }

    @MainActor
    public init(configuration: SPVClientConfiguration = .default) throws {
        self.storage = try StorageManager()
        self.client = SPVClient(configuration: configuration)
        self.wallet = PersistentWalletManager(client: client, storage: storage)
    }

    // MARK: - Connection Management

    public func connect() async throws {
        try await client.start()

        // Re-sync persisted addresses with SPV client
        await syncPersistedAddresses()

        wallet.startPeriodicSync()
    }

    public func disconnect() async throws {
        wallet.stopPeriodicSync()
        try await client.stop()
    }

    // MARK: - Synchronization

    public func syncToTip() async throws -> AsyncThrowingStream<SyncProgress, Error> {
        return try await client.syncToTip()
    }

    public func rescanBlockchain(from height: UInt32 = 0) async throws {
        try await client.rescanBlockchain(from: height)
    }

    // MARK: - Enhanced Sync Operations

    public func syncToTipWithProgress(
        progressCallback: (@Sendable (DetailedSyncProgress) -> Void)? = nil,
        completionCallback: (@Sendable (Bool, String?) -> Void)? = nil
    ) async throws {
        try await client.syncToTipWithProgress(
            progressCallback: progressCallback,
            completionCallback: completionCallback
        )
    }

    public func syncProgressStream() -> SyncProgressStream {
        return client.syncProgressStream()
    }

    // MARK: - Wallet Operations

    public func watchAddress(_ address: String, label: String? = nil) async throws {
        try await wallet.watchAddress(address, label: label)
    }

    public func watchAddresses(_ addresses: [String]) async throws {
        for address in addresses {
            try await wallet.watchAddress(address)
        }
    }

    public func unwatchAddress(_ address: String) async throws {
        try await wallet.unwatchAddress(address)
    }

    public func getBalance() async throws -> Balance {
        return try await wallet.getTotalBalance()
    }

    public func getBalance(for address: String) async throws -> Balance {
        return try await wallet.getBalance(for: address)
    }

    public func getBalanceWithMempool() async throws -> Balance {
        return try await client.getBalanceWithMempool()
    }

    public func getBalanceWithMempool(for address: String) async throws -> Balance {
        // For now, get regular balance as mempool tracking may not be enabled
        // TODO: Implement address-specific mempool balance
        return try await wallet.getBalance(for: address)
    }

    public func getTransactions(limit: Int = 100) async throws -> [Transaction] {
        return try await wallet.getTransactions(limit: limit)
    }

    public func getTransactions(for address: String, limit: Int = 100) async throws -> [Transaction] {
        return try await wallet.getTransactions(for: address, limit: limit)
    }

    public func getUTXOs() async throws -> [UTXO] {
        return try await wallet.getUTXOs()
    }

    // MARK: - Mempool Operations

    public func enableMempoolTracking(strategy: MempoolStrategy) async throws {
        try await client.enableMempoolTracking(strategy: strategy)
    }

    public func getMempoolBalance(for address: String) async throws -> MempoolBalance {
        return try await client.getMempoolBalance(for: address)
    }

    public func getMempoolTransactionCount() async throws -> Int {
        return try await client.getMempoolTransactionCount()
    }

    // MARK: - Transaction Management

    public func sendTransaction(
        to address: String,
        amount: UInt64,
        feeRate: UInt64 = 1000
    ) async throws -> String {
        // Create transaction
        let txData = try await wallet.createTransaction(
            to: address,
            amount: amount,
            feeRate: feeRate
        )

        // Broadcast transaction
        let txHex = txData.map { String(format: "%02x", $0) }.joined()
        try await client.broadcastTransaction(txHex)

        // For now, return a placeholder - the actual txid should come from parsing the transaction
        return "transaction_sent"
    }

    public func estimateFee(
        to address: String,
        amount: UInt64,
        feeRate: UInt64 = 1000
    ) async throws -> UInt64 {
        let utxos = try await wallet.getSpendableUTXOs()
        let builder = TransactionBuilder()

        // Estimate inputs needed
        var inputCount = 0
        var totalInput: UInt64 = 0

        for utxo in utxos.sorted(by: { $0.value > $1.value }) {
            inputCount += 1
            totalInput += utxo.value

            if totalInput >= amount {
                break
            }
        }

        // 1 output for recipient, 1 for change
        let outputCount = 2

        return builder.estimateFee(
            inputs: inputCount,
            outputs: outputCount,
            feeRate: feeRate
        )
    }

    // MARK: - Data Management

    public func refreshData() async {
        await wallet.syncAllData()
    }

    public func getStorageStatistics() throws -> StorageStatistics {
        return try wallet.getStorageStatistics()
    }

    public func clearAllData() throws {
        try wallet.clearAllData()
    }

    public func exportWalletData() throws -> WalletExportData {
        return try wallet.exportWalletData()
    }

    public func importWalletData(_ data: WalletExportData) async throws {
        try await wallet.importWalletData(data)
    }

    // MARK: - Network Information

    public func isFilterSyncAvailable() async -> Bool {
        return await client.isFilterSyncAvailable()
    }

    public func validateAddress(_ address: String) -> Bool {
        // Basic validation - would call FFI function
        return address.starts(with: "X") || address.starts(with: "y")
    }

    public func getNetworkInfo() -> NetworkInfo {
        return NetworkInfo(
            network: client.configuration.network,
            isConnected: client.isConnected,
            connectedPeers: client.stats?.connectedPeers ?? 0,
            blockHeight: client.stats?.headerHeight ?? 0
        )
    }

    // MARK: - Private Helpers

    private func syncPersistedAddresses() async {
        // This triggers the PersistentWalletManager to reload addresses
        // and re-watch them in the SPV client
        await wallet.syncAllData()
    }
}

// MARK: - Network Info

public struct NetworkInfo {
    public let network: DashNetwork
    public let isConnected: Bool
    public let connectedPeers: UInt32
    public let blockHeight: UInt32

    public var description: String {
        """
        Network: \(network.name)
        Connected: \(isConnected)
        Peers: \(connectedPeers)
        Block Height: \(blockHeight)
        """
    }
}

// MARK: - Convenience Extensions

extension DashSDK {
    @MainActor
    public static func mainnet() throws -> DashSDK {
        return try DashSDK(configuration: .mainnet())
    }

    @MainActor
    public static func testnet() throws -> DashSDK {
        return try DashSDK(configuration: .testnet())
    }

    @MainActor
    public static func regtest() throws -> DashSDK {
        return try DashSDK(configuration: .regtest())
    }

    @MainActor
    public static func devnet() throws -> DashSDK {
        return try DashSDK(configuration: .devnet())
    }
}
