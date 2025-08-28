import Foundation
import Combine
import DashSPVFFI
import Network

// MARK: - Sync Progress Types
// These types are defined here to ensure they're available for SPVClient

/// Detailed sync progress information with real-time statistics
public struct DetailedSyncProgress: Sendable, Equatable {
    public let currentHeight: UInt32
    public let totalHeight: UInt32
    public let percentage: Double
    public let headersPerSecond: Double
    public let estimatedSecondsRemaining: Int64
    public let stage: SyncStage
    public let stageMessage: String
    public let connectedPeers: UInt32
    public let totalHeadersProcessed: UInt64
    public let syncStartTimestamp: Date
    
    /// Calculated properties
    public var blocksRemaining: UInt32 {
        guard totalHeight > currentHeight else { return 0 }
        return totalHeight - currentHeight
    }
    
    public var isComplete: Bool {
        return percentage >= 100.0 || stage == .complete
    }
    
    public var formattedPercentage: String {
        return String(format: "%.1f%%", percentage)
    }
    
    public var formattedSpeed: String {
        if headersPerSecond > 0 {
            return String(format: "%.0f headers/sec", headersPerSecond)
        }
        return "Calculating..."
    }
    
    public var formattedTimeRemaining: String {
        guard estimatedSecondsRemaining > 0 else {
            return stage == .complete ? "Complete" : "Calculating..."
        }
        
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.hour, .minute, .second]
        formatter.unitsStyle = .abbreviated
        return formatter.string(from: TimeInterval(estimatedSecondsRemaining)) ?? "Unknown"
    }
    
    public var syncDuration: TimeInterval {
        return Date().timeIntervalSince(syncStartTimestamp)
    }
    
    public var formattedSyncDuration: String {
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.hour, .minute, .second]
        formatter.unitsStyle = .positional
        formatter.zeroFormattingBehavior = .pad
        return formatter.string(from: syncDuration) ?? "00:00:00"
    }
    
    /// Public initializer for creating DetailedSyncProgress
    public init(
        currentHeight: UInt32,
        totalHeight: UInt32,
        percentage: Double,
        headersPerSecond: Double,
        estimatedSecondsRemaining: Int64,
        stage: SyncStage,
        stageMessage: String,
        connectedPeers: UInt32,
        totalHeadersProcessed: UInt64,
        syncStartTimestamp: Date
    ) {
        self.currentHeight = currentHeight
        self.totalHeight = totalHeight
        self.percentage = percentage
        self.headersPerSecond = headersPerSecond
        self.estimatedSecondsRemaining = estimatedSecondsRemaining
        self.stage = stage
        self.stageMessage = stageMessage
        self.connectedPeers = connectedPeers
        self.totalHeadersProcessed = totalHeadersProcessed
        self.syncStartTimestamp = syncStartTimestamp
    }
    
    /// Initialize from FFI type
    internal init(ffiProgress: FFIDetailedSyncProgress) {
        self.currentHeight = ffiProgress.current_height
        self.totalHeight = ffiProgress.total_height
        self.percentage = ffiProgress.percentage
        self.headersPerSecond = ffiProgress.headers_per_second
        self.estimatedSecondsRemaining = ffiProgress.estimated_seconds_remaining
        self.stage = SyncStage(ffiStage: ffiProgress.stage)
        self.stageMessage = String(cString: ffiProgress.stage_message.ptr)
        self.connectedPeers = ffiProgress.connected_peers
        self.totalHeadersProcessed = ffiProgress.total_headers
        self.syncStartTimestamp = Date(timeIntervalSince1970: TimeInterval(ffiProgress.sync_start_timestamp))
    }
}

/// Sync stage enumeration with detailed states
public enum SyncStage: Equatable, Sendable {
    case connecting
    case queryingHeight
    case downloading
    case validating
    case storing
    case complete
    case failed
    
    /// Initialize from FFI enum value
    internal init(ffiStage: FFISyncStage) {
        switch ffiStage.rawValue {
        case 0:  // Connecting
            self = .connecting
        case 1:  // QueryingHeight
            self = .queryingHeight
        case 2:  // Downloading
            self = .downloading
        case 3:  // Validating
            self = .validating
        case 4:  // Storing
            self = .storing
        case 5:  // Complete
            self = .complete
        case 6:  // Failed
            self = .failed
        default:
            self = .failed
        }
    }
    
    public var description: String {
        switch self {
        case .connecting:
            return "Connecting to peers"
        case .queryingHeight:
            return "Querying blockchain height"
        case .downloading:
            return "Downloading headers"
        case .validating:
            return "Validating headers"
        case .storing:
            return "Storing headers"
        case .complete:
            return "Synchronization complete"
        case .failed:
            return "Synchronization failed"
        }
    }
    
    public var isActive: Bool {
        switch self {
        case .complete, .failed:
            return false
        default:
            return true
        }
    }
    
    public var icon: String {
        switch self {
        case .connecting:
            return "📡"
        case .queryingHeight:
            return "🔍"
        case .downloading:
            return "⬇️"
        case .validating:
            return "✅"
        case .storing:
            return "💾"
        case .complete:
            return "✨"
        case .failed:
            return "❌"
        }
    }
}

/// Sync progress stream for async iteration
public struct SyncProgressStream: AsyncSequence {
    public typealias Element = DetailedSyncProgress
    
    private let client: SPVClient
    private let progressCallback: (@Sendable (DetailedSyncProgress) -> Void)?
    private let completionCallback: (@Sendable (Bool, String?) -> Void)?
    
    internal init(
        client: SPVClient,
        progressCallback: (@Sendable (DetailedSyncProgress) -> Void)? = nil,
        completionCallback: (@Sendable (Bool, String?) -> Void)? = nil
    ) {
        self.client = client
        self.progressCallback = progressCallback
        self.completionCallback = completionCallback
    }
    
    public func makeAsyncIterator() -> AsyncIterator {
        return AsyncIterator(
            client: client,
            progressCallback: progressCallback,
            completionCallback: completionCallback
        )
    }
    
    public final class AsyncIterator: AsyncIteratorProtocol, @unchecked Sendable {
        private let client: SPVClient
        private let progressCallback: (@Sendable (DetailedSyncProgress) -> Void)?
        private let completionCallback: (@Sendable (Bool, String?) -> Void)?
        private var isComplete = false
        private let progressContinuation: AsyncStream<DetailedSyncProgress>.Continuation
        private var progressStream: AsyncStream<DetailedSyncProgress>
        private var progressIterator: AsyncStream<DetailedSyncProgress>.AsyncIterator
        
        init(
            client: SPVClient,
            progressCallback: (@Sendable (DetailedSyncProgress) -> Void)?,
            completionCallback: (@Sendable (Bool, String?) -> Void)?
        ) {
            self.client = client
            self.progressCallback = progressCallback
            self.completionCallback = completionCallback
            
            var continuation: AsyncStream<DetailedSyncProgress>.Continuation!
            self.progressStream = AsyncStream<DetailedSyncProgress> { cont in
                continuation = cont
            }
            self.progressContinuation = continuation
            self.progressIterator = progressStream.makeAsyncIterator()
            
            // Start sync operation
            Task {
                await self.startSync()
            }
        }
        
        private func startSync() async {
            // Start sync with progress tracking using client callbacks
            do {
                try await client.syncToTipWithProgress(
                    progressCallback: { progress in
                        // Send to stream
                        self.progressContinuation.yield(progress)
                        
                        // Call user callback if provided
                        self.progressCallback?(progress)
                    },
                    completionCallback: { success, error in
                        // Call user callback if provided
                        self.completionCallback?(success, error)
                        
                        // Complete the stream
                        self.progressContinuation.finish()
                    }
                )
            } catch {
                // Handle sync start error
                completionCallback?(false, error.localizedDescription)
                progressContinuation.finish()
            }
        }
        
        public func next() async -> DetailedSyncProgress? {
            guard !isComplete else { return nil }
            
            if let progress = await progressIterator.next() {
                return progress
            } else {
                isComplete = true
                return nil
            }
        }
    }
}

// MARK: - Convenience Extensions

extension DetailedSyncProgress {
    /// Check if sync is in an error state
    public var hasError: Bool {
        return stage == .failed
    }
    
    /// Get a user-friendly status message
    public var statusMessage: String {
        if isComplete {
            return "Sync complete! \(currentHeight)/\(totalHeight) blocks"
        } else if hasError {
            return stageMessage.isEmpty ? "Sync failed" : stageMessage
        } else {
            return "\(stage.icon) \(stageMessage) - \(formattedPercentage)"
        }
    }
    
    /// Get detailed statistics as a dictionary
    public var statistics: [String: String] {
        return [
            "Current Height": "\(currentHeight)",
            "Total Height": "\(totalHeight)",
            "Progress": formattedPercentage,
            "Speed": formattedSpeed,
            "Time Remaining": formattedTimeRemaining,
            "Connected Peers": "\(connectedPeers)",
            "Headers Processed": "\(totalHeadersProcessed)",
            "Duration": formattedSyncDuration
        ]
    }
}

// MARK: - Callback Holders

// Callback holder to wrap Swift callbacks for C interop
private class CallbackHolder {
    let progressCallback: ((Double, String?) -> Void)?
    let completionCallback: ((Bool, String?) -> Void)?
    
    init(progressCallback: ((Double, String?) -> Void)? = nil,
         completionCallback: ((Bool, String?) -> Void)? = nil) {
        self.progressCallback = progressCallback
        self.completionCallback = completionCallback
    }
}

// Detailed callback holder for the new sync progress API
private class DetailedCallbackHolder {
    let progressCallback: (@Sendable (Any) -> Void)?
    let completionCallback: (@Sendable (Bool, String?) -> Void)?
    
    init(progressCallback: (@Sendable (Any) -> Void)? = nil,
         completionCallback: (@Sendable (Bool, String?) -> Void)? = nil) {
        self.progressCallback = progressCallback
        self.completionCallback = completionCallback
    }
}

// Event callback holder for persistent event callbacks
private class EventCallbackHolder {
    weak var client: SPVClient?
    
    init(client: SPVClient) {
        self.client = client
    }
}

// C callback functions that extract Swift callbacks from userData
private let syncProgressCallback: @convention(c) (Double, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = { progress, message, userData in
    guard let userData = userData else { return }
    let holder = Unmanaged<CallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    let msg = message.map { String(cString: $0) }
    holder.progressCallback?(progress, msg)
}

private let syncCompletionCallback: @convention(c) (Bool, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = { success, error, userData in
    guard let userData = userData else { return }
    let holder = Unmanaged<CallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    let err = error.map { String(cString: $0) }
    holder.completionCallback?(success, err)
    // Release the holder after completion
    Unmanaged<CallbackHolder>.fromOpaque(userData).release()
}

// Detailed sync callbacks
private let detailedSyncProgressCallback: @convention(c) (UnsafePointer<FFIDetailedSyncProgress>?, UnsafeMutableRawPointer?) -> Void = { ffiProgress, userData in
    print("🟢 detailedSyncProgressCallback called from FFI")
    guard let userData = userData,
          let ffiProgress = ffiProgress else { 
        print("🟢 userData or ffiProgress is nil")
        return 
    }
    
    print("🟢 Getting holder from userData")
    let holder = Unmanaged<DetailedCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    print("🟢 Calling holder.progressCallback")
    // Pass the FFI progress directly, conversion will happen in the holder's callback
    holder.progressCallback?(ffiProgress.pointee)
}

private let detailedSyncCompletionCallback: @convention(c) (Bool, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = { success, error, userData in
    guard let userData = userData else { return }
    let holder = Unmanaged<DetailedCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    let err = error.map { String(cString: $0) }
    holder.completionCallback?(success, err)
    // Release the holder after completion
    Unmanaged<DetailedCallbackHolder>.fromOpaque(userData).release()
}

// Event callbacks
private let eventBlockCallback: BlockCallback = { height, hashBytes, userData in
    guard let userData = userData,
          let hashBytes = hashBytes else { return }
    
    let holder = Unmanaged<EventCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    guard let client = holder.client else { return }
    
    // Convert byte array to hex string
    let hashArray = withUnsafeBytes(of: hashBytes.pointee) { bytes in
        Array(bytes)
    }
    let hashHex = hashArray.map { String(format: "%02x", $0) }.joined()
    
    let event = SPVEvent.blockReceived(
        height: height,
        hash: hashHex
    )
    client.eventSubject.send(event)
}

private let eventTransactionCallback: TransactionCallback = { txidBytes, confirmed, amount, addresses, blockHeight, userData in
    guard let userData = userData,
          let txidBytes = txidBytes else { return }
    
    let holder = Unmanaged<EventCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    guard let client = holder.client else { return }
    
    // Convert byte array to hex string
    let txidArray = withUnsafeBytes(of: txidBytes.pointee) { bytes in
        Array(bytes)
    }
    let txidString = txidArray.map { String(format: "%02x", $0) }.joined()
    
    let addressArray: [String] = {
        if let addresses = addresses {
            let addressesString = String(cString: addresses)
            return addressesString.split(separator: ",").map(String.init)
        }
        return []
    }()
    
    let event = SPVEvent.transactionReceived(
        txid: txidString,
        confirmed: confirmed,
        amount: amount,
        addresses: addressArray,
        blockHeight: blockHeight > 0 ? blockHeight : nil
    )
    client.eventSubject.send(event)
}

private let eventBalanceCallback: BalanceCallback = { confirmed, unconfirmed, userData in
    guard let userData = userData else { return }
    
    let holder = Unmanaged<EventCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    guard let client = holder.client else { return }
    
    let balance = Balance(
        confirmed: confirmed,
        pending: unconfirmed,
        instantLocked: 0,  // InstantLocked amount not provided in callback
        total: confirmed + unconfirmed
    )
    let event = SPVEvent.balanceUpdated(balance)
    client.eventSubject.send(event)
}

// Mempool event callbacks
private let eventMempoolTransactionAddedCallback: MempoolTransactionCallback = { txidBytes, amount, addresses, isInstantSend, userData in
    guard let userData = userData,
          let txidBytes = txidBytes else { return }
    
    let holder = Unmanaged<EventCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    guard let client = holder.client else { return }
    
    // Convert byte array to hex string
    let txidArray = withUnsafeBytes(of: txidBytes.pointee) { bytes in
        Array(bytes)
    }
    let txidString = txidArray.map { String(format: "%02x", $0) }.joined()
    
    let addressArray: [String] = {
        if let addresses = addresses {
            let addressesString = String(cString: addresses)
            return addressesString.split(separator: ",").map(String.init)
        }
        return []
    }()
    
    let event = SPVEvent.mempoolTransactionAdded(
        txid: txidString,
        amount: amount,
        addresses: addressArray
    )
    client.eventSubject.send(event)
}

private let eventMempoolTransactionConfirmedCallback: MempoolConfirmedCallback = { txidBytes, blockHeight, blockHashBytes, userData in
    guard let userData = userData,
          let txidBytes = txidBytes else { return }
    
    let holder = Unmanaged<EventCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    guard let client = holder.client else { return }
    
    // Convert byte array to hex string
    let txidArray = withUnsafeBytes(of: txidBytes.pointee) { bytes in
        Array(bytes)
    }
    let txidString = txidArray.map { String(format: "%02x", $0) }.joined()
    
    // For now, we're using blockHeight as confirmations (1 confirmation when just confirmed)
    let confirmations: UInt32 = 1
    
    let event = SPVEvent.mempoolTransactionConfirmed(
        txid: txidString,
        blockHeight: blockHeight,
        confirmations: confirmations
    )
    client.eventSubject.send(event)
}

private let eventMempoolTransactionRemovedCallback: MempoolRemovedCallback = { txidBytes, reason, userData in
    guard let userData = userData,
          let txidBytes = txidBytes else { return }
    
    let holder = Unmanaged<EventCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    guard let client = holder.client else { return }
    
    // Convert byte array to hex string
    let txidArray = withUnsafeBytes(of: txidBytes.pointee) { bytes in
        Array(bytes)
    }
    let txidString = txidArray.map { String(format: "%02x", $0) }.joined()
    
    let removalReason: MempoolRemovalReason = {
        switch reason {
        case 0: return .expired
        case 1: return .replaced
        case 2: return .doubleSpent
        case 3: return .confirmed
        case 4: return .manual
        default: return .unknown
        }
    }()
    
    let event = SPVEvent.mempoolTransactionRemoved(
        txid: txidString,
        reason: removalReason
    )
    client.eventSubject.send(event)
}

@Observable
public final class SPVClient {
    @ObservationIgnored
    private var client: UnsafeMutablePointer<FFIDashSpvClient>?
    public let configuration: SPVClientConfiguration
    private let asyncBridge = AsyncBridge()
    private var eventCallbacksSet = false
    private var eventCallbackHolder: EventCallbackHolder?
    
    public private(set) var isConnected: Bool = false
    public private(set) var syncProgress: SyncProgress?
    public private(set) var stats: SPVStats?
    
    internal let eventSubject = PassthroughSubject<SPVEvent, Never>()
    public var eventPublisher: AnyPublisher<SPVEvent, Never> {
        eventSubject.eraseToAnyPublisher()
    }
    
    public init(configuration: SPVClientConfiguration = .default) {
        self.configuration = configuration
        
        print("\n🚧 Initializing SPV Client...")
        print("   - Network: \(configuration.network.rawValue)")
        print("   - Log level: \(configuration.logLevel)")
        
        // Initialize Rust logging with configured level
        print("🔧 Initializing Rust FFI logging...")
        let logResult = FFIBridge.withCString(configuration.logLevel) { logLevel in
            dash_spv_ffi_init_logging(logLevel)
        }
        
        if logResult != 0 {
            print("⚠️ Failed to initialize logging with level '\(configuration.logLevel)', defaulting to 'info'")
            let _ = dash_spv_ffi_init_logging("info")
        } else {
            print("✅ Rust logging initialized with level: \(configuration.logLevel)")
        }
    }
    
    /// Expose FFI client handle for Platform SDK integration
    /// This is needed for Platform SDK to access Core chain data for proof verification
    /// Note: This will be nil until start() has been called
    public var ffiClientHandle: UnsafeMutablePointer<FFIDashSpvClient>? {
        return client
    }
    
    deinit {
        Task { [asyncBridge] in
            await asyncBridge.cancelAll()
        }
        
        // Clean up event callback holder if needed
        if eventCallbackHolder != nil {
            // The userData was retained, so we need to release it
            // Note: This is only needed if client is destroyed before callbacks complete
        }
        
        if let client = client {
            dash_spv_ffi_client_destroy(client)
        }
    }
    
    // MARK: - Network Information
    
    public func isFilterSyncAvailable() async -> Bool {
        guard let client = client else { return false }
        return dash_spv_ffi_client_is_filter_sync_available(client)
    }
    
    
    // MARK: - Lifecycle
    
    public func start() async throws {
        guard !isConnected else {
            throw DashSDKError.alreadyConnected
        }
        
        print("🚀 Starting SPV client...")
        print("📡 Network: \(configuration.network.rawValue)")
        print("👥 Configured peers: \(configuration.additionalPeers.count)")
        for (index, peer) in configuration.additionalPeers.enumerated() {
            print("   \(index + 1). \(peer)")
        }
        
        // Log network reachability status if available
        logNetworkReachability()
        
        print("\n📋 Creating FFI configuration...")
        print("   - Max peers: \(configuration.maxPeers)")
        print("   - Validation mode: \(configuration.validationMode)")
        print("   - Filter load enabled: \(configuration.enableFilterLoad)")
        print("   - User agent: \(configuration.userAgent)")
        print("   - Log level: \(configuration.logLevel)")
        
        let ffiConfig = try configuration.createFFIConfig()
        defer {
            print("🧹 Cleaning up FFI config")
            dash_spv_ffi_config_destroy(OpaquePointer(ffiConfig))
        }
        
        print("\n🏗️ Creating SPV client with FFI...")
        guard let newClient = dash_spv_ffi_client_new(OpaquePointer(ffiConfig)) else {
            let error = FFIBridge.getLastError() ?? "Unknown error"
            print("❌ Failed to create SPV client: \(error)")
            throw DashSDKError.invalidConfiguration("Failed to create SPV client: \(error)")
        }
        print("✅ SPV client created successfully")
        
        self.client = newClient
        
        // Always set up event callbacks before starting the client
        // This is required by the FFI layer to avoid InvalidArgument error
        print("🎯 Setting up event callbacks...")
        setupEventCallbacks()
        
        print("\n🔌 Starting SPV client (calling dash_spv_ffi_client_start)...")
        let startTime = Date()
        let result = dash_spv_ffi_client_start(client)
        let startDuration = Date().timeIntervalSince(startTime)
        print("⏱️ FFI start call completed in \(String(format: "%.3f", startDuration)) seconds")
        
        if result != 0 {
            let error = FFIBridge.getLastError() ?? "Unknown error"
            print("❌ Failed to start SPV client: \(error) (code: \(result))")
            throw DashSDKError.ffiError(code: result, message: error)
        }
        
        try FFIBridge.checkError(result)
        
        isConnected = true
        print("✅ SPV client started successfully")
        
        // Monitor peer connections with multiple checks
        print("\n🔍 Monitoring peer connections...")
        var totalWaitTime = 0
        let maxWaitTime = 30 // 30 seconds max
        var lastPeerCount: UInt32 = 0
        
        while totalWaitTime < maxWaitTime {
            await updateStats()
            
            if let stats = self.stats {
                if stats.connectedPeers != lastPeerCount {
                    print("   [\(totalWaitTime)s] Connected peers: \(stats.connectedPeers) (change: +\(Int(stats.connectedPeers) - Int(lastPeerCount)))")
                    lastPeerCount = stats.connectedPeers
                }
                
                if stats.connectedPeers > 0 {
                    print("\n🎉 Successfully connected to \(stats.connectedPeers) peer(s)!")
                    break
                }
            }
            
            // Wait 1 second before next check
            try await Task.sleep(nanoseconds: 1_000_000_000)
            totalWaitTime += 1
            
            // Log every 5 seconds if still no peers
            if totalWaitTime % 5 == 0 && (stats?.connectedPeers ?? 0) == 0 {
                print("   [\(totalWaitTime)s] Still waiting for peer connections...")
                
                // Try to get more detailed error info
                if let error = FFIBridge.getLastError() {
                    print("   ⚠️ Last FFI error: \(error)")
                }
            }
        }
        
        await updateStats()
        
        if let stats = self.stats {
            print("\n📊 Final connection stats:")
            print("   - Connected peers: \(stats.connectedPeers)")
            print("   - Header height: \(stats.headerHeight)")
            print("   - Filter height: \(stats.filterHeight)")
            print("   - Total headers: \(stats.totalHeaders)")
            print("   - Network: \(configuration.network.rawValue)")
            
            if stats.connectedPeers == 0 {
                print("\n⚠️ WARNING: No peers connected after \(totalWaitTime) seconds!")
                print("Possible issues:")
                print("  1. Network connectivity problems")
                print("  2. Firewall blocking connections")
                print("  3. Invalid peer addresses")
                print("  4. Peers are offline or unreachable")
            }
        } else {
            print("\n❌ Failed to retrieve stats after starting")
        }
    }
    
    public func stop() async throws {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        let result = dash_spv_ffi_client_stop(client)
        try FFIBridge.checkError(result)
        
        isConnected = false
        syncProgress = nil
        stats = nil
    }
    
    // MARK: - Sync Operations
    
    public func syncToTip() async throws -> AsyncThrowingStream<SyncProgress, Error> {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        let (_, stream) = await asyncBridge.syncProgressStream { id, progressCallback, completionCallback in
            // Create a callback holder that wraps the Swift callbacks
            let callbackHolder = CallbackHolder(
                progressCallback: progressCallback,
                completionCallback: completionCallback
            )
            
            let userData = Unmanaged.passRetained(callbackHolder).toOpaque()
            
            let result = dash_spv_ffi_client_sync_to_tip(
                client,
                syncCompletionCallback,
                userData
            )
            
            if result != 0 {
                completionCallback(false, "Failed to start sync")
                Unmanaged<CallbackHolder>.fromOpaque(userData).release()
            }
        }
        
        return stream
    }
    
    public func rescanBlockchain(from height: UInt32) async throws {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        let result = dash_spv_ffi_client_rescan_blockchain(client, height)
        try FFIBridge.checkError(result)
    }
    
    public func getCurrentSyncProgress() -> SyncProgress? {
        guard isConnected, let client = client else {
            return nil
        }
        
        guard let ffiProgress = dash_spv_ffi_client_get_sync_progress(client) else {
            return nil
        }
        defer {
            dash_spv_ffi_sync_progress_destroy(ffiProgress)
        }
        
        let progress = SyncProgress(ffiProgress: ffiProgress.pointee)
        self.syncProgress = progress
        return progress
    }
    
    // MARK: - Enhanced Sync Operations with Detailed Progress
    
    
    /// Cancel ongoing sync operation
    public func cancelSync() async throws {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        let result = dash_spv_ffi_client_cancel_sync(client)
        try FFIBridge.checkError(result)
    }
    
    // MARK: - Balance Operations
    
    public func getAddressBalance(_ address: String) async throws -> Balance {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        let balancePtr = FFIBridge.withCString(address) { addressCStr in
            dash_spv_ffi_client_get_address_balance(client, addressCStr)
        }
        
        guard let balancePtr = balancePtr else {
            throw DashSDKError.ffiError(code: -1, message: FFIBridge.getLastError() ?? "Failed to get address balance")
        }
        
        defer {
            dash_spv_ffi_balance_destroy(balancePtr)
        }
        
        let ffiBalance = balancePtr.pointee
        return Balance(
            confirmed: ffiBalance.confirmed,
            pending: ffiBalance.pending,
            instantLocked: ffiBalance.instantlocked,
            total: ffiBalance.total
        )
    }
    
    public func getTotalBalance() async throws -> Balance {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        guard let balancePtr = dash_spv_ffi_client_get_total_balance(client) else {
            throw DashSDKError.ffiError(code: -1, message: FFIBridge.getLastError() ?? "Failed to get total balance")
        }
        
        defer {
            dash_spv_ffi_balance_destroy(balancePtr)
        }
        
        let ffiBalance = balancePtr.pointee
        return Balance(
            confirmed: ffiBalance.confirmed,
            pending: ffiBalance.pending,
            instantLocked: ffiBalance.instantlocked,
            total: ffiBalance.total
        )
    }
    
    // MARK: - Mempool Operations
    
    public func enableMempoolTracking(strategy: MempoolStrategy) async throws {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        let result = dash_spv_ffi_client_enable_mempool_tracking(client, strategy.ffiValue)
        try FFIBridge.checkError(result)
    }
    
    public func getBalanceWithMempool() async throws -> Balance {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        guard let balancePtr = dash_spv_ffi_client_get_balance_with_mempool(client) else {
            throw DashSDKError.ffiError(code: -1, message: FFIBridge.getLastError() ?? "Failed to get balance with mempool")
        }
        
        defer {
            dash_spv_ffi_balance_destroy(balancePtr)
        }
        
        let ffiBalance = balancePtr.pointee
        return Balance(
            confirmed: ffiBalance.confirmed,
            pending: ffiBalance.pending,
            instantLocked: ffiBalance.instantlocked,
            total: ffiBalance.total
        )
    }
    
    public func getMempoolBalance(for address: String) async throws -> MempoolBalance {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        let balancePtr = FFIBridge.withCString(address) { addressCStr in
            dash_spv_ffi_client_get_mempool_balance(client, addressCStr)
        }
        
        guard let balancePtr = balancePtr else {
            throw DashSDKError.ffiError(code: -1, message: FFIBridge.getLastError() ?? "Failed to get mempool balance")
        }
        
        defer {
            dash_spv_ffi_balance_destroy(balancePtr)
        }
        
        let ffiBalance = balancePtr.pointee
        return MempoolBalance(
            pending: ffiBalance.mempool,
            pendingInstant: ffiBalance.mempool_instant
        )
    }
    
    public func getMempoolTransactionCount() async throws -> Int {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        let count = dash_spv_ffi_client_get_mempool_transaction_count(client)
        if count < 0 {
            throw DashSDKError.ffiError(code: -1, message: FFIBridge.getLastError() ?? "Failed to get mempool transaction count")
        }
        
        return Int(count)
    }
    
    public func recordSend(txid: String) async throws {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        let result = FFIBridge.withCString(txid) { txidCStr in
            dash_spv_ffi_client_record_send(client, txidCStr)
        }
        
        try FFIBridge.checkError(result)
    }
    
    // MARK: - Network Operations
    
    public func broadcastTransaction(_ transactionHex: String) async throws {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        let result = FFIBridge.withCString(transactionHex) { txHex in
            dash_spv_ffi_client_broadcast_transaction(client, txHex)
        }
        
        try FFIBridge.checkError(result)
    }
    
    // MARK: - Stats
    
    /// Debug method to print detailed connection information
    public func debugConnectionState() async {
        print("\n🔍 SPV Client Debug Information:")
        print("================================")
        
        print("\n📋 Configuration:")
        print("   - Network: \(configuration.network.rawValue)")
        print("   - Max peers: \(configuration.maxPeers)")
        print("   - Additional peers: \(configuration.additionalPeers.count)")
        for (index, peer) in configuration.additionalPeers.enumerated() {
            print("     \(index + 1). \(peer)")
        }
        print("   - Data directory: \(configuration.dataDirectory?.path ?? "None")")
        print("   - Validation mode: \(configuration.validationMode)")
        print("   - Filter load enabled: \(configuration.enableFilterLoad)")
        
        print("\n🔌 Connection State:")
        print("   - Is connected: \(isConnected)")
        print("   - Client pointer: \(client != nil ? "Valid" : "Nil")")
        print("   - Event callbacks set: \(eventCallbacksSet)")
        
        if isConnected {
            await updateStats()
            
            if let stats = self.stats {
                print("\n📊 Current Stats:")
                print("   - Connected peers: \(stats.connectedPeers)")
                print("   - Header height: \(stats.headerHeight)")
                print("   - Filter height: \(stats.filterHeight)")
                print("   - Total headers: \(stats.totalHeaders)")
                print("   - Network: \(configuration.network.rawValue)")
            } else {
                print("\n⚠️ Unable to retrieve stats")
            }
            
            // Check FFI error state
            if let error = FFIBridge.getLastError() {
                print("\n❌ Last FFI Error: \(error)")
            }
        }
        
        // Network reachability check
        logNetworkReachability()
        
        print("\n================================")
    }
    
    public func updateStats() async {
        guard isConnected, let client = client else {
            return
        }
        
        guard let ffiStats = dash_spv_ffi_client_get_stats(client) else {
            let error = FFIBridge.getLastError()
            if let error = error {
                print("⚠️ Failed to get SPV stats: \(error)")
            }
            return
        }
        defer {
            dash_spv_ffi_spv_stats_destroy(ffiStats)
        }
        
        let previousPeerCount = self.stats?.connectedPeers ?? 0
        let ffiStatsValue = ffiStats.pointee
        
        // Debug log the raw FFI values
        print("🔍 FFI Stats Debug:")
        print("   - connected_peers: \(ffiStatsValue.connected_peers)")
        print("   - total_peers: \(ffiStatsValue.total_peers)")
        print("   - header_height: \(ffiStatsValue.header_height)")
        print("   - filter_height: \(ffiStatsValue.filter_height)")
        
        self.stats = SPVStats(ffiStats: ffiStatsValue)
        
        // Log significant changes
        if let stats = self.stats {
            if stats.connectedPeers != previousPeerCount {
                print("👥 Peer count changed: \(previousPeerCount) → \(stats.connectedPeers)")
            }
        }
    }
    
    // MARK: - Private
    
    private func logNetworkReachability() {
        let monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "NetworkMonitor")
        
        monitor.pathUpdateHandler = { path in
            print("\n🌐 Network Status:")
            print("   - Status: \(path.status == .satisfied ? "✅ Connected" : "❌ Disconnected")")
            
            if path.status == .satisfied {
                print("   - Is expensive: \(path.isExpensive ? "Yes" : "No")")
                print("   - Is constrained: \(path.isConstrained ? "Yes" : "No")")
                
                print("   - Available interfaces:")
                for interface in path.availableInterfaces {
                    print("     • \(interface.name) (\(interface.type))")
                }
                
                if path.usesInterfaceType(.wifi) {
                    print("   - Using: WiFi")
                } else if path.usesInterfaceType(.cellular) {
                    print("   - Using: Cellular")
                } else if path.usesInterfaceType(.wiredEthernet) {
                    print("   - Using: Ethernet")
                } else {
                    print("   - Using: Other/Unknown")
                }
            } else {
                print("   ⚠️ No network connection available!")
            }
            
            // Stop monitoring after first check
            monitor.cancel()
        }
        
        monitor.start(queue: queue)
        
        // Give it a moment to report
        Thread.sleep(forTimeInterval: 0.1)
    }
    
    private func setupEventCallbacks() {
        guard let client = client else { 
            print("❌ Cannot setup event callbacks - client is nil")
            return 
        }
        
        print("📢 Setting up event callbacks...")
        
        // Create event callback holder with weak reference to self
        let eventHolder = EventCallbackHolder(client: self)
        self.eventCallbackHolder = eventHolder
        let userData = Unmanaged.passRetained(eventHolder).toOpaque()
        
        let callbacks = FFIEventCallbacks(
            on_block: eventBlockCallback,
            on_transaction: eventTransactionCallback,
            on_balance_update: eventBalanceCallback,
            on_mempool_transaction_added: eventMempoolTransactionAddedCallback,
            on_mempool_transaction_confirmed: eventMempoolTransactionConfirmedCallback,
            on_mempool_transaction_removed: eventMempoolTransactionRemovedCallback,
            user_data: userData
        )
        
        print("   - Block callback: ✅")
        print("   - Transaction callback: ✅")
        print("   - Balance callback: ✅")
        print("   - Mempool callbacks: ✅")
        
        let result = dash_spv_ffi_client_set_event_callbacks(client, callbacks)
        if result != 0 {
            let error = FFIBridge.getLastError() ?? "Unknown error"
            print("❌ Failed to set event callbacks: \(error) (code: \(result))")
            // Don't mark as set if it failed
            eventCallbacksSet = false
            // Note: We don't throw here as the client might still work without event callbacks
            // The FFI layer will handle the error appropriately
        } else {
            print("✅ Event callbacks set successfully")
            eventCallbacksSet = true
        }
    }
}

// MARK: - SPV Events

public enum SPVEvent {
    case blockReceived(height: UInt32, hash: String)
    case transactionReceived(txid: String, confirmed: Bool, amount: Int64, addresses: [String], blockHeight: UInt32?)
    case balanceUpdated(Balance)
    case syncProgressUpdated(SyncProgress)
    case connectionStatusChanged(Bool)
    case error(DashSDKError)
    case mempoolTransactionAdded(txid: String, amount: Int64, addresses: [String])
    case mempoolTransactionConfirmed(txid: String, blockHeight: UInt32, confirmations: UInt32)
    case mempoolTransactionRemoved(txid: String, reason: MempoolRemovalReason)
}

// MARK: - Enhanced Sync Methods Extension
// These methods depend on DetailedSyncProgress which is defined in the Models folder

extension SPVClient {
    /// Sync to blockchain tip with detailed progress tracking
    public func syncToTipWithProgress(
        progressCallback: (@Sendable (DetailedSyncProgress) -> Void)? = nil,
        completionCallback: (@Sendable (Bool, String?) -> Void)? = nil
    ) async throws {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        // Check if we have peers before starting sync
        await updateStats()
        if let stats = self.stats, stats.connectedPeers == 0 {
            print("⚠️ Warning: No peers connected. Waiting for peer connections...")
            print("   Current network: \(configuration.network.rawValue)")
            print("   Total headers: \(stats.totalHeaders)")
            
            // Wait up to 10 seconds for peers to connect
            var waitTime = 0
            while waitTime < 10 {
                try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
                waitTime += 1
                
                await updateStats()
                if let updatedStats = self.stats {
                    print("   [\(waitTime)s] Peers: \(updatedStats.connectedPeers), Headers: \(updatedStats.headerHeight)")
                    if updatedStats.connectedPeers > 0 {
                        print("🎉 Connected to \(updatedStats.connectedPeers) peer(s)")
                        break
                    }
                }
            }
            
            // Final check
            if let finalStats = self.stats, finalStats.connectedPeers == 0 {
                let error = "No peers connected after 10 seconds. Check network connectivity and peer configuration."
                print("❌ \(error)")
                print("   Configured peers: \(configuration.additionalPeers)")
                completionCallback?(false, error)
                throw DashSDKError.networkError(error)
            }
        }
        
        print("\n📡 Starting blockchain sync...")
        print("   - Connected peers: \(stats?.connectedPeers ?? 0)")
        print("   - Current height: \(stats?.headerHeight ?? 0)")
        print("   - Filter height: \(stats?.filterHeight ?? 0)")
        
        // Create a callback holder with type-erased callbacks
        let wrappedProgressCallback: (@Sendable (Any) -> Void)? = progressCallback.map { callback in
            { progress in
                print("🟣 FFI progress callback wrapper called")
                if let detailedProgress = progress as? FFIDetailedSyncProgress {
                    print("🟣 Converting FFI progress to Swift DetailedSyncProgress")
                    callback(DetailedSyncProgress(ffiProgress: detailedProgress))
                } else {
                    print("🟣 Failed to cast progress to FFIDetailedSyncProgress")
                }
            }
        }
        
        let callbackHolder = DetailedCallbackHolder(
            progressCallback: wrappedProgressCallback,
            completionCallback: completionCallback
        )
        
        let userData = Unmanaged.passRetained(callbackHolder).toOpaque()
        
        let result = dash_spv_ffi_client_sync_to_tip_with_progress(
            client,
            detailedSyncProgressCallback,
            detailedSyncCompletionCallback,
            userData
        )
        
        if result != 0 {
            let error = FFIBridge.getLastError() ?? "Failed to start sync"
            print("❌ Sync failed: \(error)")
            completionCallback?(false, error)
            Unmanaged<DetailedCallbackHolder>.fromOpaque(userData).release()
            try FFIBridge.checkError(result)
        } else {
            print("✅ Sync started successfully")
        }
    }
    
    /// Create a sync progress stream with detailed progress information
    public func syncProgressStream() -> SyncProgressStream {
        return SyncProgressStream(client: self)
    }
}