import Foundation
import Combine
import DashSPVFFI

// MARK: - Sync Progress Types
// These types are defined here to ensure they're available for SPVClient

/// Detailed sync progress information with real-time statistics
public struct DetailedSyncProgress: Sendable {
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
    guard let userData = userData,
          let ffiProgress = ffiProgress else { return }
    
    let holder = Unmanaged<DetailedCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
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
private let eventBlockCallback: @convention(c) (UInt32, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = { height, hash, userData in
    guard let userData = userData,
          let hash = hash else { return }
    
    let holder = Unmanaged<EventCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    guard let client = holder.client else { return }
    
    let event = SPVEvent.blockReceived(
        height: height,
        hash: String(cString: hash)
    )
    client.eventSubject.send(event)
}

private let eventTransactionCallback: @convention(c) (UnsafePointer<CChar>?, Bool, UnsafeMutableRawPointer?) -> Void = { txid, confirmed, userData in
    guard let userData = userData,
          let txid = txid else { return }
    
    let holder = Unmanaged<EventCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    guard let client = holder.client else { return }
    
    let event = SPVEvent.transactionReceived(
        txid: String(cString: txid),
        confirmed: confirmed
    )
    client.eventSubject.send(event)
}

private let eventBalanceCallback: @convention(c) (UInt64, UInt64, UnsafeMutableRawPointer?) -> Void = { confirmed, unconfirmed, userData in
    guard let userData = userData else { return }
    
    let holder = Unmanaged<EventCallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    guard let client = holder.client else { return }
    
    let balance = Balance(
        confirmed: confirmed,
        pending: unconfirmed
    )
    let event = SPVEvent.balanceUpdated(balance)
    client.eventSubject.send(event)
}

@Observable
public final class SPVClient {
    private var client: OpaquePointer?
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
        
        // Initialize Rust logging to enable trace output
        let _ = dash_spv_ffi_init_logging("trace")
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
    
    // MARK: - Watch Items
    
    public func addWatchItem(type: WatchItemType, data: String) async throws {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        // Create FFI watch item based on type
        let watchItem: UnsafeMutablePointer<FFIWatchItem>?
        
        switch type {
        case .address:
            watchItem = dash_spv_ffi_watch_item_address(data)
        case .script:
            watchItem = dash_spv_ffi_watch_item_script(data)
        case .outpoint:
            // For outpoint, we need to parse txid and vout from data
            // Expected format: "txid:vout"
            let components = data.split(separator: ":")
            guard components.count == 2,
                  let vout = UInt32(components[1]) else {
                throw DashSDKError.invalidArgument("Invalid outpoint format. Expected: txid:vout")
            }
            let txid = String(components[0])
            watchItem = dash_spv_ffi_watch_item_outpoint(txid, vout)
        }
        
        guard let item = watchItem else {
            throw DashSDKError.invalidArgument("Failed to create watch item")
        }
        defer {
            dash_spv_ffi_watch_item_destroy(item)
        }
        
        let result = dash_spv_ffi_client_add_watch_item(client, item)
        try FFIBridge.checkError(result)
    }
    
    public func removeWatchItem(type: WatchItemType, data: String) async throws {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        // Create FFI watch item based on type
        let watchItem: UnsafeMutablePointer<FFIWatchItem>?
        
        switch type {
        case .address:
            watchItem = dash_spv_ffi_watch_item_address(data)
        case .script:
            watchItem = dash_spv_ffi_watch_item_script(data)
        case .outpoint:
            // For outpoint, we need to parse txid and vout from data
            let components = data.split(separator: ":")
            guard components.count == 2,
                  let vout = UInt32(components[1]) else {
                throw DashSDKError.invalidArgument("Invalid outpoint format. Expected: txid:vout")
            }
            let txid = String(components[0])
            watchItem = dash_spv_ffi_watch_item_outpoint(txid, vout)
        }
        
        guard let item = watchItem else {
            throw DashSDKError.invalidArgument("Failed to create watch item")
        }
        defer {
            dash_spv_ffi_watch_item_destroy(item)
        }
        
        let result = dash_spv_ffi_client_remove_watch_item(client, item)
        try FFIBridge.checkError(result)
    }
    
    // MARK: - Lifecycle
    
    public func start() async throws {
        guard !isConnected else {
            throw DashSDKError.alreadyConnected
        }
        
        let ffiConfig = try configuration.createFFIConfig()
        defer {
            dash_spv_ffi_config_destroy(OpaquePointer(ffiConfig))
        }
        
        guard let newClient = dash_spv_ffi_client_new(OpaquePointer(ffiConfig)) else {
            throw DashSDKError.invalidConfiguration("Failed to create SPV client")
        }
        
        self.client = newClient
        
        if !eventCallbacksSet {
            setupEventCallbacks()
        }
        
        let result = dash_spv_ffi_client_start(client)
        try FFIBridge.checkError(result)
        
        isConnected = true
        await updateStats()
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
                syncProgressCallback,
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
    
    public func updateStats() async {
        guard isConnected, let client = client else {
            return
        }
        
        guard let ffiStats = dash_spv_ffi_client_get_stats(client) else {
            return
        }
        defer {
            dash_spv_ffi_spv_stats_destroy(ffiStats)
        }
        
        self.stats = SPVStats(ffiStats: ffiStats.pointee)
    }
    
    // MARK: - Private
    
    private func setupEventCallbacks() {
        guard let client = client else { return }
        
        // Create event callback holder with weak reference to self
        let eventHolder = EventCallbackHolder(client: self)
        self.eventCallbackHolder = eventHolder
        let userData = Unmanaged.passRetained(eventHolder).toOpaque()
        
        let callbacks = FFIEventCallbacks(
            on_block: eventBlockCallback,
            on_transaction: eventTransactionCallback,
            on_balance_update: eventBalanceCallback,
            user_data: userData
        )
        
        let result = dash_spv_ffi_client_set_event_callbacks(client, callbacks)
        if result != 0 {
            print("Warning: Failed to set event callbacks")
        }
        
        eventCallbacksSet = true
    }
}

// MARK: - SPV Events

public enum SPVEvent {
    case blockReceived(height: UInt32, hash: String)
    case transactionReceived(txid: String, confirmed: Bool)
    case balanceUpdated(Balance)
    case syncProgressUpdated(SyncProgress)
    case connectionStatusChanged(Bool)
    case error(DashSDKError)
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
        
        // Create a callback holder with type-erased callbacks
        let wrappedProgressCallback: (@Sendable (Any) -> Void)? = progressCallback.map { callback in
            { progress in
                if let detailedProgress = progress as? FFIDetailedSyncProgress {
                    callback(DetailedSyncProgress(ffiProgress: detailedProgress))
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
            completionCallback?(false, "Failed to start sync")
            Unmanaged<DetailedCallbackHolder>.fromOpaque(userData).release()
            try FFIBridge.checkError(result)
        }
    }
    
    /// Create a sync progress stream with detailed progress information
    public func syncProgressStream() -> SyncProgressStream {
        return SyncProgressStream(client: self)
    }
}