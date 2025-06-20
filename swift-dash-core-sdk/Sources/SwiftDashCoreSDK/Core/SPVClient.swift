import Foundation
import Combine
import DashSPVFFI

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

// Event callback holder for persistent event callbacks
private class EventCallbackHolder {
    weak var client: SPVClient?
    
    init(client: SPVClient) {
        self.client = client
    }
}

// C callback functions that extract Swift callbacks from userData
private let syncProgressCallback: dash_spv_ffi_progress_callback = { progress, message, userData in
    guard let userData = userData else { return }
    let holder = Unmanaged<CallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    let msg = message.map { String(cString: $0) }
    holder.progressCallback?(progress, msg)
}

private let syncCompletionCallback: dash_spv_ffi_completion_callback = { success, error, userData in
    guard let userData = userData else { return }
    let holder = Unmanaged<CallbackHolder>.fromOpaque(userData).takeUnretainedValue()
    let err = error.map { String(cString: $0) }
    holder.completionCallback?(success, err)
    // Release the holder after completion
    Unmanaged<CallbackHolder>.fromOpaque(userData).release()
}

// Event callbacks
private let eventBlockCallback: dash_spv_ffi_block_callback = { height, hash, userData in
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

private let eventTransactionCallback: dash_spv_ffi_transaction_callback = { txid, confirmed, userData in
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

private let eventBalanceCallback: dash_spv_ffi_balance_callback = { confirmed, unconfirmed, userData in
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
    private var client: FFIClient?
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
    }
    
    deinit {
        Task { [asyncBridge] in
            await asyncBridge.cancelAll()
        }
        
        // Clean up event callback holder if needed
        if let holder = eventCallbackHolder {
            // The userData was retained, so we need to release it
            // Note: This is only needed if client is destroyed before callbacks complete
        }
        
        if let client = client {
            dash_spv_ffi_client_destroy(client)
        }
    }
    
    // MARK: - Lifecycle
    
    public func start() async throws {
        guard !isConnected else {
            throw DashSDKError.alreadyConnected
        }
        
        let ffiConfig = try configuration.createFFIConfig()
        defer {
            dash_spv_ffi_config_destroy(ffiConfig)
        }
        
        guard let newClient = dash_spv_ffi_client_new(ffiConfig) else {
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
        
        try await asyncBridge.withAsyncCallback { completionCallback in
            let callbackHolder = CallbackHolder(completionCallback: completionCallback)
            let userData = Unmanaged.passRetained(callbackHolder).toOpaque()
            
            let result = dash_spv_ffi_client_rescan_blockchain(
                client,
                height,
                syncCompletionCallback,
                userData
            )
            
            if result != 0 {
                completionCallback(false, "Failed to start rescan")
                Unmanaged<CallbackHolder>.fromOpaque(userData).release()
            }
        }
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
    
    // MARK: - Network Operations
    
    public func broadcastTransaction(_ transaction: Data) async throws -> String {
        guard isConnected, let client = client else {
            throw DashSDKError.notConnected
        }
        
        return try await FFIBridge.withData(transaction) { ptr, len in
            guard let result = dash_spv_ffi_client_broadcast_transaction(client, ptr, len) else {
                throw DashSDKError.networkError("Failed to broadcast transaction")
            }
            defer {
                dash_spv_ffi_string_destroy(result)
            }
            
            guard let txid = FFIBridge.toString(result.pointee) else {
                throw DashSDKError.networkError("Invalid transaction ID returned")
            }
            
            return txid
        }
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
        
        let callbacks = dash_spv_ffi_event_callbacks(
            on_block: eventBlockCallback,
            on_transaction: eventTransactionCallback,
            on_balance: eventBalanceCallback,
            user_data: userData
        )
        
        withUnsafePointer(to: callbacks) { ptr in
            dash_spv_ffi_client_set_event_callbacks(client, ptr)
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