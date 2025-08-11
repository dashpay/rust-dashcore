import Foundation
import SwiftData
import Combine
import SwiftDashCoreSDK
import os.log

public enum WatchVerificationStatus {
    case unknown
    case verifying
    case verified(total: Int, watching: Int)
    case failed(error: String)
}

// Local definition since it's not being exported from the SDK
public enum WatchAddressError: Error, LocalizedError {
    case clientNotConnected
    case invalidAddress(String)
    case storageFailure(String)
    case networkError(String)
    case alreadyWatching(String)
    case unknownError(String)
    
    public var errorDescription: String? {
        switch self {
        case .clientNotConnected:
            return "SPV client is not connected"
        case .invalidAddress(let address):
            return "Invalid address format: \(address)"
        case .storageFailure(let reason):
            return "Failed to persist watch item: \(reason)"
        case .networkError(let reason):
            return "Network error: \(reason)"
        case .alreadyWatching(let address):
            return "Already watching address: \(address)"
        case .unknownError(let reason):
            return "Unknown error: \(reason)"
        }
    }
    
    public var isRecoverable: Bool {
        switch self {
        case .clientNotConnected, .networkError, .storageFailure:
            return true
        case .invalidAddress, .alreadyWatching, .unknownError:
            return false
        }
    }
}

@MainActor
class WalletService: ObservableObject {
    static let shared = WalletService()
    
    @Published var activeWallet: HDWallet?
    @Published var activeAccount: HDAccount?
    @Published var syncProgress: SyncProgress?
    @Published var detailedSyncProgress: DetailedSyncProgress?
    @Published var isConnected: Bool = false
    @Published var isSyncing: Bool = false
    @Published var watchAddressErrors: [WatchAddressError] = []
    @Published var pendingWatchCount: Int = 0
    @Published var watchVerificationStatus: WatchVerificationStatus = .unknown
    @Published var mempoolTransactionCount: Int = 0
    
    var sdk: DashSDK?
    private var cancellables = Set<AnyCancellable>()
    private var syncTask: Task<Void, Never>?
    var modelContext: ModelContext?
    
    // Watch address error tracking
    private var pendingWatchAddresses: [String: [(address: String, error: Error)]] = [:]
    private var watchVerificationTimer: Timer?
    private let logger = Logger(subsystem: "com.dash.wallet", category: "WalletService")
    
    // Computed property for sync statistics
    var syncStatistics: [String: String] {
        guard let progress = detailedSyncProgress else {
            return [:]
        }
        return progress.statistics
    }
    
    private init() {}
    
    func configure(modelContext: ModelContext) {
        self.modelContext = modelContext
    }
    
    // MARK: - Wallet Management
    
    func createWallet(
        name: String,
        mnemonic: [String],
        password: String,
        network: DashNetwork
    ) throws -> HDWallet {
        guard let context = modelContext else {
            throw WalletError.noContext
        }
        
        // Generate seed from mnemonic
        let seed = HDWalletService.mnemonicToSeed(mnemonic)
        let seedHash = HDWalletService.seedHash(seed)
        
        // Check for duplicate wallet
        let descriptor = FetchDescriptor<HDWallet>()
        let allWallets = try context.fetch(descriptor)
        if allWallets.first(where: { $0.seedHash == seedHash && $0.network == network }) != nil {
            throw WalletError.duplicateWallet
        }
        
        // Encrypt seed
        let encryptedSeed = try HDWalletService.encryptSeed(seed, password: password)
        
        // Create wallet
        let wallet = HDWallet(
            name: name,
            network: network,
            encryptedSeed: encryptedSeed,
            seedHash: seedHash
        )
        
        context.insert(wallet)
        
        // Create default account
        let account = try createAccount(
            for: wallet,
            index: 0,
            label: "Primary Account",
            password: password
        )
        wallet.accounts.append(account)
        
        try context.save()
        
        return wallet
    }
    
    func createAccount(
        for wallet: HDWallet,
        index: UInt32,
        label: String,
        password: String
    ) throws -> HDAccount {
        // Decrypt seed
        let seed = try HDWalletService.decryptSeed(wallet.encryptedSeed, password: password)
        
        // Derive account xpub
        let xpub = HDWalletService.deriveExtendedPublicKey(
            seed: seed,
            network: wallet.network,
            account: index
        )
        
        // Create account
        let account = HDAccount(
            accountIndex: index,
            label: label,
            extendedPublicKey: xpub
        )
        
        account.wallet = wallet
        
        // Generate initial addresses (5 receive, 1 change)
        let initialReceiveCount = 5
        let initialChangeCount = 1
        
        // Generate receive addresses
        for i in 0..<initialReceiveCount {
            let address = HDWalletService.deriveAddress(
                xpub: xpub,
                network: wallet.network,
                change: false,
                index: UInt32(i)
            )
            
            let path = BIP44.derivationPath(
                network: wallet.network,
                account: index,
                change: false,
                index: UInt32(i)
            )
            
            let watchedAddress = HDWatchedAddress(
                address: address,
                index: UInt32(i),
                isChange: false,
                derivationPath: path,
                label: "Receive"
            )
            watchedAddress.account = account
            account.addresses.append(watchedAddress)
        }
        
        // Generate change address
        for i in 0..<initialChangeCount {
            let address = HDWalletService.deriveAddress(
                xpub: xpub,
                network: wallet.network,
                change: true,
                index: UInt32(i)
            )
            
            let path = BIP44.derivationPath(
                network: wallet.network,
                account: index,
                change: true,
                index: UInt32(i)
            )
            
            let watchedAddress = HDWatchedAddress(
                address: address,
                index: UInt32(i),
                isChange: true,
                derivationPath: path,
                label: "Change"
            )
            watchedAddress.account = account
            account.addresses.append(watchedAddress)
        }
        
        return account
    }
    
    func deleteWallet(_ wallet: HDWallet) throws {
        guard let context = modelContext else {
            throw WalletError.noContext
        }
        
        if wallet == activeWallet {
            Task {
                await disconnect()
            }
            activeWallet = nil
            activeAccount = nil
        }
        
        context.delete(wallet)
        try context.save()
    }
    
    // MARK: - Connection & Sync
    
    func connect(wallet: HDWallet, account: HDAccount) async throws {
        print("🔗 Connecting wallet: \(wallet.name) - Account: \(account.displayName)")
        print("   Network: \(wallet.network)")
        
        // Disconnect if needed
        if isConnected {
            print("⚠️ Disconnecting existing connection...")
            await disconnect()
        }
        
        // Create SDK configuration
        let config = SPVClientConfiguration()
        config.network = wallet.network
        config.validationMode = ValidationMode.full
        
        // Enable trace logging for detailed debugging
        config.logLevel = "trace"
        
        // Enable mempool tracking with FetchAll strategy for testing
        // This allows the wallet to see all network transactions
        config.mempoolConfig = .fetchAll(maxTransactions: 5000)
        
        // Using active masternode peers
        if wallet.network == .mainnet {
            config.additionalPeers = [
                "142.93.154.186:9999",
                "8.219.251.8:9999",
                "165.22.30.195:9999",
                "65.109.114.212:9999",
                "188.40.21.248:9999",
                "66.42.58.154:9999"
            ]
        } else if wallet.network == .testnet {
            config.additionalPeers = [
                "192.168.1.137:19999",
                "54.149.33.167:19999",
                "35.90.252.3:19999",
                "18.237.170.32:19999",
                "34.220.243.24:19999",
                "34.214.48.68:19999"
            ]
        }
        
        print("📡 Initializing DashSDK...")
        // Initialize SDK on MainActor since DashSDK init is marked @MainActor
        sdk = try await MainActor.run {
            try DashSDK(configuration: config)
        }
        
        // Connect
        print("🌐 Connecting to Dash network...")
        try await sdk?.connect()
        isConnected = true
        print("✅ Connected successfully!")
        
        // Enable mempool tracking after connection
        print("🔄 Enabling mempool tracking...")
        try await sdk?.enableMempoolTracking(strategy: .fetchAll)
        print("✅ Mempool tracking enabled with FetchAll strategy")
        
        activeWallet = wallet
        activeAccount = account
        
        // Setup event handling
        setupEventHandling()
        
        // Start watching addresses
        print("👀 Watching account addresses...")
        await watchAccountAddresses(account)
        
        // Start watch address verification
        startWatchVerification()
        
        // Update account balance after adding watch addresses
        print("💰 Fetching initial balance...")
        try? await updateAccountBalance(account)
        
        print("🎯 Ready for sync!")
    }
    
    func disconnect() async {
        syncTask?.cancel()
        
        // Stop watch verification
        stopWatchVerification()
        
        if let sdk = sdk, isConnected {
            try? await sdk.disconnect()
        }
        
        isConnected = false
        isSyncing = false
        syncProgress = nil
        detailedSyncProgress = nil
        sdk = nil
        watchVerificationStatus = .unknown
    }
    
    func startSync() async throws {
        guard let sdk = sdk, isConnected else {
            throw WalletError.notConnected
        }
        
        print("🔄 Starting sync for wallet: \(activeWallet?.name ?? "Unknown")")
        isSyncing = true
        
        syncTask = Task {
            do {
                print("📡 Starting enhanced sync with detailed progress...")
                var lastLogTime = Date()
                
                // Use the new sync progress stream
                for await progress in sdk.syncProgressStream() {
                    if Task.isCancelled { break }
                    
                    self.detailedSyncProgress = progress
                    
                    // Convert to legacy SyncProgress for compatibility
                    self.syncProgress = SyncProgress(
                        currentHeight: progress.currentHeight,
                        totalHeight: progress.totalHeight,
                        progress: progress.percentage / 100.0,
                        status: mapSyncStageToStatus(progress.stage),
                        estimatedTimeRemaining: progress.estimatedSecondsRemaining > 0 ? TimeInterval(progress.estimatedSecondsRemaining) : nil,
                        message: progress.stageMessage
                    )
                    
                    // Log progress every second to avoid spam
                    if Date().timeIntervalSince(lastLogTime) > 1.0 {
                        print("\(progress.stage.icon) \(progress.statusMessage)")
                        print("   Speed: \(progress.formattedSpeed) | ETA: \(progress.formattedTimeRemaining)")
                        print("   Peers: \(progress.connectedPeers) | Headers: \(progress.totalHeadersProcessed)")
                        lastLogTime = Date()
                    }
                    
                    // Update sync state in storage
                    if let wallet = activeWallet {
                        await self.updateSyncState(walletId: wallet.id, progress: self.syncProgress!)
                    }
                    
                    // Check if sync is complete
                    if progress.isComplete {
                        break
                    }
                }
                
                // Sync completed
                print("✅ Sync completed!")
                self.isSyncing = false
                if let wallet = activeWallet {
                    wallet.lastSynced = Date()
                    try? modelContext?.save()
                    
                    // Update balance after sync
                    if let account = activeAccount {
                        print("💰 Updating balance after sync...")
                        try? await updateAccountBalance(account)
                    }
                }
                
            } catch {
                self.isSyncing = false
                self.detailedSyncProgress = nil
                print("❌ Sync error: \(error)")
            }
        }
    }
    
    // Helper to map sync stage to legacy status
    private func mapSyncStageToStatus(_ stage: SyncStage) -> SyncStatus {
        switch stage {
        case .connecting:
            return .connecting
        case .queryingHeight:
            return .connecting
        case .downloading, .validating, .storing:
            return .downloadingHeaders
        case .complete:
            return .synced
        case .failed:
            return .error
        }
    }
    
    func stopSync() {
        syncTask?.cancel()
        isSyncing = false
        
        // Note: cancelSync would need to be exposed on DashSDK if we want to cancel at the SPVClient level
    }
    
    // Alternative sync method using callbacks for real-time updates
    func startSyncWithCallbacks() async throws {
        guard let sdk = sdk, isConnected else {
            throw WalletError.notConnected
        }
        
        print("🔄 Starting callback-based sync for wallet: \(activeWallet?.name ?? "Unknown")")
        isSyncing = true
        
        try await sdk.syncToTipWithProgress(
            progressCallback: { [weak self] progress in
                Task { @MainActor in
                    self?.detailedSyncProgress = progress
                    
                    // Convert to legacy SyncProgress
                    self?.syncProgress = SyncProgress(
                        currentHeight: progress.currentHeight,
                        totalHeight: progress.totalHeight,
                        progress: progress.percentage / 100.0,
                        status: self?.mapSyncStageToStatus(progress.stage) ?? .connecting,
                        estimatedTimeRemaining: progress.estimatedSecondsRemaining > 0 ? TimeInterval(progress.estimatedSecondsRemaining) : nil,
                        message: progress.stageMessage
                    )
                    
                    print("\(progress.stage.icon) \(progress.statusMessage)")
                }
            },
            completionCallback: { [weak self] success, error in
                Task { @MainActor in
                    self?.isSyncing = false
                    
                    if success {
                        print("✅ Sync completed successfully!")
                        if let wallet = self?.activeWallet {
                            wallet.lastSynced = Date()
                            try? self?.modelContext?.save()
                            
                            // Update balance after sync
                            if let account = self?.activeAccount {
                                print("💰 Updating balance after sync...")
                                try? await self?.updateAccountBalance(account)
                            }
                        }
                    } else {
                        print("❌ Sync failed: \(error ?? "Unknown error")")
                        self?.detailedSyncProgress = nil
                    }
                }
            }
        )
    }
    
    // MARK: - Address Management
    
    func discoverAddresses(for account: HDAccount) async throws {
        guard let sdk = sdk, let wallet = account.wallet else {
            throw WalletError.invalidState
        }
        
        let discoveryService = AddressDiscoveryService(sdk: sdk)
        let (externalAddresses, internalAddresses) = try await discoveryService.discoverAddresses(
            for: account,
            network: wallet.network,
            gapLimit: account.gapLimit
        )
        
        // Save discovered addresses
        try await saveDiscoveredAddresses(
            account: account,
            external: externalAddresses,
            internalAddresses: internalAddresses
        )
    }
    
    func generateNewAddress(for account: HDAccount, isChange: Bool = false) throws -> HDWatchedAddress {
        guard let wallet = account.wallet, let context = modelContext else {
            throw WalletError.noContext
        }
        
        let index = isChange ? account.lastUsedInternalIndex + 1 : account.lastUsedExternalIndex + 1
        
        let address = HDWalletService.deriveAddress(
            xpub: account.extendedPublicKey,
            network: wallet.network,
            change: isChange,
            index: index
        )
        
        let path = BIP44.derivationPath(
            network: wallet.network,
            account: account.accountIndex,
            change: isChange,
            index: index
        )
        
        let watchedAddress = HDWatchedAddress(
            address: address,
            index: index,
            isChange: isChange,
            derivationPath: path,
            label: isChange ? "Change" : "Receive"
        )
        watchedAddress.account = account
        
        account.addresses.append(watchedAddress)
        
        if isChange {
            account.lastUsedInternalIndex = index
        } else {
            account.lastUsedExternalIndex = index
        }
        
        try context.save()
        
        // Watch in SDK with proper error handling
        Task {
            do {
                if let sdk = sdk {
                    try await sdk.watchAddress(address)
                    logger.info("Successfully watching new address: \(address)")
                } else {
                    logger.error("Cannot watch address: SDK not initialized")
                }
            } catch {
                logger.error("Failed to watch new address \(address): \(error)")
                // Schedule retry
                if let sdk = sdk, sdk.isConnected {
                    scheduleWatchAddressRetry(addresses: [address], account: account)
                }
            }
        }
        
        return watchedAddress
    }
    
    // MARK: - Balance & Transactions
    
    func updateAccountBalance(_ account: HDAccount) async throws {
        guard let sdk = sdk else {
            throw WalletError.notConnected
        }
        
        var confirmedTotal: UInt64 = 0
        var pendingTotal: UInt64 = 0
        var instantLockedTotal: UInt64 = 0
        var mempoolTotal: UInt64 = 0
        
        for address in account.addresses {
            // Use getBalanceWithMempool to include mempool transactions
            let balance = try await sdk.getBalanceWithMempool(for: address.address)
            confirmedTotal += balance.confirmed
            pendingTotal += balance.pending
            instantLockedTotal += balance.instantLocked
            mempoolTotal += balance.mempool
        }
        
        account.balance = Balance(
            confirmed: confirmedTotal,
            pending: pendingTotal,
            instantLocked: instantLockedTotal,
            total: confirmedTotal + pendingTotal + mempoolTotal
        )
        try? modelContext?.save()
    }
    
    func updateTransactions(for account: HDAccount) async throws {
        guard let sdk = sdk, let context = modelContext else {
            throw WalletError.notConnected
        }
        
        for address in account.addresses {
            let sdkTransactions = try await sdk.getTransactions(for: address.address)
            
            for sdkTx in sdkTransactions {
                // Check if transaction already exists
                let txidToCheck = sdkTx.txid
                let descriptor = FetchDescriptor<SwiftDashCoreSDK.Transaction>(
                    predicate: #Predicate { transaction in
                        transaction.txid == txidToCheck
                    }
                )
                let existingTransactions = try? context.fetch(descriptor)
                
                if existingTransactions?.isEmpty == false {
                    // Transaction already exists, skip
                    continue
                } else {
                    // Create a new transaction instance for this context
                    let newTransaction = SwiftDashCoreSDK.Transaction(
                        txid: sdkTx.txid,
                        height: sdkTx.height,
                        timestamp: sdkTx.timestamp,
                        amount: sdkTx.amount,
                        fee: sdkTx.fee,
                        confirmations: sdkTx.confirmations,
                        isInstantLocked: sdkTx.isInstantLocked,
                        raw: sdkTx.raw,
                        size: sdkTx.size,
                        version: sdkTx.version
                    )
                    context.insert(newTransaction)
                    
                    // Add transaction ID to account and address
                    if !account.transactionIds.contains(sdkTx.txid) {
                        account.transactionIds.append(sdkTx.txid)
                    }
                    if !address.transactionIds.contains(sdkTx.txid) {
                        address.transactionIds.append(sdkTx.txid)
                    }
                }
            }
        }
        
        try context.save()
    }
    
    // MARK: - Private Helpers
    
    private func setupEventHandling() {
        sdk?.eventPublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] event in
                self?.handleSDKEvent(event)
            }
            .store(in: &cancellables)
    }
    
    private func handleSDKEvent(_ event: SPVEvent) {
        switch event {
        case .balanceUpdated:
            Task {
                if let account = activeAccount {
                    try? await updateAccountBalance(account)
                }
            }
            
        case .transactionReceived(let txid, let confirmed, let amount, let addresses, let blockHeight):
            Task {
                if let account = activeAccount {
                    print("📱 iOS App received transaction: \(txid)")
                    print("   Amount: \(amount) satoshis")
                    print("   Addresses: \(addresses)")
                    print("   Confirmed: \(confirmed), Block: \(blockHeight ?? 0)")
                    
                    // Create and save the transaction
                    await saveTransaction(
                        txid: txid,
                        amount: amount,
                        addresses: addresses,
                        confirmed: confirmed,
                        blockHeight: blockHeight,
                        account: account
                    )
                }
            }
            
        case .mempoolTransactionAdded(let txid, let amount, let addresses):
            Task {
                if let account = activeAccount {
                    print("🔄 Mempool transaction added: \(txid)")
                    print("   Amount: \(amount) satoshis")
                    print("   Addresses: \(addresses)")
                    
                    // Save as unconfirmed transaction
                    await saveTransaction(
                        txid: txid,
                        amount: amount,
                        addresses: addresses,
                        confirmed: false,
                        blockHeight: nil,
                        account: account
                    )
                    
                    // Update mempool count
                    await updateMempoolTransactionCount()
                }
            }
            
        case .mempoolTransactionConfirmed(let txid, let blockHeight, let confirmations):
            Task {
                if let account = activeAccount {
                    print("✅ Mempool transaction confirmed: \(txid) at height \(blockHeight) with \(confirmations) confirmations")
                    
                    // Update transaction confirmation status
                    await confirmTransaction(txid: txid, blockHeight: blockHeight)
                    
                    // Update mempool count
                    await updateMempoolTransactionCount()
                }
            }
            
        case .mempoolTransactionRemoved(let txid, let reason):
            Task {
                if let account = activeAccount {
                    print("❌ Mempool transaction removed: \(txid), reason: \(reason)")
                    
                    // Remove or mark transaction as dropped
                    await removeTransaction(txid: txid)
                    
                    // Update mempool count
                    await updateMempoolTransactionCount()
                }
            }
            
        case .syncProgressUpdated(let progress):
            self.syncProgress = progress
            
        default:
            break
        }
    }
    
    private func watchAccountAddresses(_ account: HDAccount) async {
        guard let sdk = sdk else {
            logger.error("Cannot watch addresses: SDK not initialized")
            return
        }
        
        var failedAddresses: [(address: String, error: Error)] = []
        
        for address in account.addresses {
            do {
                try await sdk.watchAddress(address.address)
                logger.info("Successfully watching address: \(address.address)")
            } catch {
                logger.error("Failed to watch address \(address.address): \(error)")
                failedAddresses.append((address.address, error))
            }
        }
        
        // Handle failed addresses
        if !failedAddresses.isEmpty {
            await handleFailedWatchAddresses(failedAddresses, account: account)
        }
    }
    
    private func handleFailedWatchAddresses(_ failures: [(address: String, error: Error)], account: HDAccount) async {
        // Store failed addresses for retry
        pendingWatchAddresses[account.id.uuidString] = failures
        
        // Update pending watch count
        pendingWatchCount = pendingWatchAddresses.values.reduce(0) { $0 + $1.count }
        
        // Notify UI of partial failure
        watchAddressErrors = failures.map { _, error in
            if let watchError = error as? WatchAddressError {
                return watchError
            } else {
                return WatchAddressError.unknownError(error.localizedDescription)
            }
        }
        
        // Schedule retry for recoverable errors
        let recoverableFailures = failures.filter { _, error in
            if let watchError = error as? WatchAddressError {
                return watchError.isRecoverable
            }
            return true // Assume unknown errors might be recoverable
        }
        
        if !recoverableFailures.isEmpty {
            scheduleWatchAddressRetry(addresses: recoverableFailures.map { $0.address }, account: account)
        }
    }
    
    private func saveDiscoveredAddresses(
        account: HDAccount,
        external: [String],
        internalAddresses: [String]
    ) async throws {
        guard let wallet = account.wallet, let context = modelContext else {
            throw WalletError.noContext
        }
        
        // Save external addresses
        for (index, address) in external.enumerated() {
            let path = BIP44.derivationPath(
                network: wallet.network,
                account: account.accountIndex,
                change: false,
                index: UInt32(index)
            )
            
            let watchedAddress = HDWatchedAddress(
                address: address,
                index: UInt32(index),
                isChange: false,
                derivationPath: path,
                label: "Receive"
            )
            watchedAddress.account = account
            
            account.addresses.append(watchedAddress)
        }
        
        // Save internal addresses
        for (index, address) in internalAddresses.enumerated() {
            let path = BIP44.derivationPath(
                network: wallet.network,
                account: account.accountIndex,
                change: true,
                index: UInt32(index)
            )
            
            let watchedAddress = HDWatchedAddress(
                address: address,
                index: UInt32(index),
                isChange: true,
                derivationPath: path,
                label: "Change"
            )
            watchedAddress.account = account
            
            account.addresses.append(watchedAddress)
        }
        
        try context.save()
    }
    
    private func updateSyncState(walletId: UUID, progress: SyncProgress) async {
        guard let context = modelContext else { return }
        
        let descriptor = FetchDescriptor<SyncState>()
        let allStates = try? context.fetch(descriptor)
        
        if let syncState = allStates?.first(where: { $0.walletId == walletId }) {
            syncState.update(from: progress)
        } else {
            let syncState = SyncState(walletId: walletId)
            syncState.update(from: progress)
            context.insert(syncState)
        }
        
        try? context.save()
    }
    
    private func saveTransaction(
        txid: String,
        amount: Int64,
        addresses: [String],
        confirmed: Bool,
        blockHeight: UInt32?,
        account: HDAccount
    ) async {
        guard let context = modelContext else { return }
        
        // Check if transaction already exists
        let descriptor = FetchDescriptor<Transaction>()
        
        let existingTransactions = try? context.fetch(descriptor)
        if let existingTx = existingTransactions?.first(where: { $0.txid == txid }) {
            // Update existing transaction
            existingTx.confirmations = confirmed ? max(1, existingTx.confirmations) : 0
            existingTx.height = blockHeight ?? existingTx.height
            print("📝 Updated existing transaction: \(txid)")
        } else {
            // Create new transaction
            let transaction = Transaction(
                txid: txid,
                height: blockHeight,
                timestamp: Date(),
                amount: amount,
                confirmations: confirmed ? 1 : 0,
                isInstantLocked: false
            )
            
            // Associate transaction ID with account
            if !account.transactionIds.contains(txid) {
                account.transactionIds.append(txid)
            }
            
            // Associate transaction ID with addresses
            for addressString in addresses {
                if let watchedAddress = account.addresses.first(where: { $0.address == addressString }) {
                    if !watchedAddress.transactionIds.contains(txid) {
                        watchedAddress.transactionIds.append(txid)
                    }
                    print("🔗 Linked transaction to address: \(addressString)")
                }
            }
            
            context.insert(transaction)
            print("💾 Saved new transaction: \(txid) with amount: \(amount) satoshis")
        }
        
        // Save context
        do {
            try context.save()
            print("✅ Transaction saved to database")
            
            // Update account balance
            try? await updateAccountBalance(account)
        } catch {
            print("❌ Error saving transaction: \(error)")
        }
    }
    
    // MARK: - Mempool Transaction Helpers
    
    private func confirmTransaction(txid: String, blockHeight: UInt32) async {
        guard let context = modelContext else { return }
        
        let descriptor = FetchDescriptor<Transaction>()
        let existingTransactions = try? context.fetch(descriptor)
        
        if let transaction = existingTransactions?.first(where: { $0.txid == txid }) {
            transaction.confirmations = 1
            transaction.height = blockHeight
            print("✅ Updated transaction \(txid) as confirmed at height \(blockHeight)")
            
            do {
                try context.save()
                // Update balance after confirmation
                if let account = activeAccount {
                    try? await updateAccountBalance(account)
                }
            } catch {
                print("❌ Error updating confirmed transaction: \(error)")
            }
        }
    }
    
    private func removeTransaction(txid: String) async {
        guard let context = modelContext else { return }
        
        let descriptor = FetchDescriptor<Transaction>()
        let existingTransactions = try? context.fetch(descriptor)
        
        if let transaction = existingTransactions?.first(where: { $0.txid == txid }) {
            // Remove transaction from account and address references
            if let account = activeAccount {
                account.transactionIds.removeAll { $0 == txid }
                
                for address in account.addresses {
                    address.transactionIds.removeAll { $0 == txid }
                }
            }
            
            // Delete the transaction
            context.delete(transaction)
            print("🗑️ Removed transaction \(txid) from database")
            
            do {
                try context.save()
                // Update balance after removal
                if let account = activeAccount {
                    try? await updateAccountBalance(account)
                }
            } catch {
                print("❌ Error removing transaction: \(error)")
            }
        }
    }
    
    private func updateMempoolTransactionCount() async {
        guard let context = modelContext, let account = activeAccount else { return }
        
        let descriptor = FetchDescriptor<Transaction>()
        let allTransactions = try? context.fetch(descriptor)
        
        // Count unconfirmed transactions (confirmations == 0)
        let accountTxIds = Set(account.transactionIds)
        let mempoolCount = allTransactions?.filter { transaction in
            accountTxIds.contains(transaction.txid) && transaction.confirmations == 0
        }.count ?? 0
        
        await MainActor.run {
            self.mempoolTransactionCount = mempoolCount
        }
    }
    
    // MARK: - Watch Address Retry
    
    private func scheduleWatchAddressRetry(addresses: [String], account: HDAccount) {
        Task {
            // Simple retry after 5 seconds
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            
            guard let sdk = sdk else { return }
            
            var stillFailedAddresses: [(address: String, error: Error)] = []
            
            for address in addresses {
                do {
                    try await sdk.watchAddress(address)
                    logger.info("Successfully watched address on retry: \(address)")
                } catch {
                    logger.warning("Retry failed for address: \(address)")
                    stillFailedAddresses.append((address, error))
                }
            }
            
            // Update pending addresses
            if stillFailedAddresses.isEmpty {
                pendingWatchAddresses.removeValue(forKey: account.id.uuidString)
            } else {
                pendingWatchAddresses[account.id.uuidString] = stillFailedAddresses
            }
            
            // Update pending count
            await MainActor.run {
                self.pendingWatchCount = self.pendingWatchAddresses.values.reduce(0) { $0 + $1.count }
            }
        }
    }
    
    // MARK: - Watch Address Verification
    
    private func startWatchVerification() {
        watchVerificationTimer = Timer.scheduledTimer(withTimeInterval: 60.0, repeats: true) { _ in
            Task {
                await self.verifyAllWatchedAddresses()
            }
        }
    }
    
    private func stopWatchVerification() {
        watchVerificationTimer?.invalidate()
        watchVerificationTimer = nil
    }
    
    private func verifyAllWatchedAddresses() async {
        guard let sdk = sdk, let account = activeAccount else { return }
        
        watchVerificationStatus = .verifying
        
        let addresses = account.addresses.map { $0.address }
        let totalAddresses = addresses.count
        var watchedAddresses = 0
        
        do {
            // TODO: verifyWatchedAddresses method needs to be implemented in SPVClient
            // For now, assume all addresses are watched
            watchedAddresses = totalAddresses
            /*
            let verificationResults = try await sdk.client.verifyWatchedAddresses(addresses)
            let missingAddresses = verificationResults.compactMap { address, isWatched in
                isWatched ? nil : address
            }
            
            watchedAddresses = addresses.count - missingAddresses.count
            
            if !missingAddresses.isEmpty {
                logger.warning("Found \(missingAddresses.count) addresses not being watched for account \(account.label)")
                
                // Re-watch missing addresses
                for address in missingAddresses {
                    do {
                        try await sdk.watchAddress(address)
                        logger.info("Re-watched missing address: \(address)")
                        watchedAddresses += 1
                    } catch {
                        logger.error("Failed to re-watch address \(address): \(error)")
                        scheduleWatchAddressRetry(addresses: [address], account: account)
                    }
                }
            }
            */
            
            watchVerificationStatus = .verified(total: totalAddresses, watching: watchedAddresses)
        } catch {
            logger.error("Failed to verify watched addresses for account \(account.label): \(error)")
            watchVerificationStatus = .failed(error: error.localizedDescription)
        }
    }
}

// MARK: - Wallet Errors

enum WalletError: LocalizedError {
    case noContext
    case duplicateWallet
    case notConnected
    case invalidState
    case invalidMnemonic
    case decryptionFailed
    
    var errorDescription: String? {
        switch self {
        case .noContext:
            return "Storage context not available"
        case .duplicateWallet:
            return "A wallet with this seed already exists"
        case .notConnected:
            return "Wallet is not connected"
        case .invalidState:
            return "Invalid wallet state"
        case .invalidMnemonic:
            return "Invalid mnemonic phrase"
        case .decryptionFailed:
            return "Failed to decrypt wallet"
        }
    }
}