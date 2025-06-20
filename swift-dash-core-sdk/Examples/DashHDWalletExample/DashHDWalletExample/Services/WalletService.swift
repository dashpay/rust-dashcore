import Foundation
import SwiftData
import Combine
import SwiftDashCoreSDK

@MainActor
class WalletService: ObservableObject {
    static let shared = WalletService()
    
    @Published var activeWallet: HDWallet?
    @Published var activeAccount: HDAccount?
    @Published var syncProgress: SyncProgress?
    @Published var detailedSyncProgress: DetailedSyncProgress?
    @Published var isConnected: Bool = false
    @Published var isSyncing: Bool = false
    
    var sdk: DashSDK?
    private var cancellables = Set<AnyCancellable>()
    private var syncTask: Task<Void, Never>?
    var modelContext: ModelContext?
    
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
        
        // Using local network for testing - comment out to use public peers
        if wallet.network == .mainnet {
            config.additionalPeers = [
                "192.168.1.163:9999"  // Local mainnet node
            ]
        } else if wallet.network == .testnet {
            config.additionalPeers = [
                "192.168.1.163:19999"  // Local testnet node
            ]
        }
        
        // Original public peers (commented out for testing)
        /*
        if wallet.network == .mainnet {
            config.additionalPeers = [
                "65.109.114.212:9999",
                "8.222.135.69:9999",
                "188.40.180.135:9999"
            ]
        } else if wallet.network == .testnet {
            config.additionalPeers = [
                "43.229.77.46:19999",
                "45.77.167.247:19999",
                "178.62.203.249:19999"
            ]
        }
        */
        
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
        
        activeWallet = wallet
        activeAccount = account
        
        // Setup event handling
        setupEventHandling()
        
        // Start watching addresses
        print("👀 Watching account addresses...")
        await watchAccountAddresses(account)
        print("🎯 Ready for sync!")
    }
    
    func disconnect() async {
        syncTask?.cancel()
        
        if let sdk = sdk, isConnected {
            try? await sdk.disconnect()
        }
        
        isConnected = false
        isSyncing = false
        syncProgress = nil
        detailedSyncProgress = nil
        sdk = nil
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
        
        // Watch in SDK
        Task {
            try? await sdk?.watchAddress(address)
        }
        
        return watchedAddress
    }
    
    // MARK: - Balance & Transactions
    
    func updateAccountBalance(_ account: HDAccount) async throws {
        guard let sdk = sdk else {
            throw WalletError.notConnected
        }
        
        var totalBalance = Balance()
        
        for address in account.addresses {
            let balance = try await sdk.getBalance(for: address.address)
            totalBalance.confirmed += balance.confirmed
            totalBalance.pending += balance.pending
            totalBalance.instantLocked += balance.instantLocked
            totalBalance.total += balance.total
        }
        
        account.balance = totalBalance
        try? modelContext?.save()
    }
    
    func updateTransactions(for account: HDAccount) async throws {
        guard let sdk = sdk, let context = modelContext else {
            throw WalletError.notConnected
        }
        
        var allTransactions: [Transaction] = []
        
        for address in account.addresses {
            let transactions = try await sdk.getTransactions(for: address.address)
            
            for tx in transactions {
                // Check if transaction already exists
                let descriptor = FetchDescriptor<Transaction>()
                let existingTransactions = try context.fetch(descriptor)
                
                if existingTransactions.contains(where: { $0.txid == tx.txid }) {
                    // Transaction already exists, skip
                    continue
                } else {
                    // Add new transaction
                    context.insert(tx)
                    allTransactions.append(tx)
                }
            }
        }
        
        account.transactions.append(contentsOf: allTransactions)
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
            
        case .transactionReceived:
            Task {
                if let account = activeAccount {
                    try? await updateTransactions(for: account)
                }
            }
            
        case .syncProgressUpdated(let progress):
            self.syncProgress = progress
            
        default:
            break
        }
    }
    
    private func watchAccountAddresses(_ account: HDAccount) async {
        guard let sdk = sdk else { return }
        
        for address in account.addresses {
            try? await sdk.watchAddress(address.address)
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