import Foundation
import DashSPVFFI

@Observable
public final class SPVClientConfiguration {
    public var network: DashNetwork = .mainnet
    public var dataDirectory: URL?
    public var validationMode: ValidationMode = .basic
    public var maxPeers: UInt32 = 12
    public var additionalPeers: [String] = []
    public var userAgent: String = "SwiftDashCoreSDK/1.0"
    public var enableFilterLoad: Bool = true
    public var initialBlockFilter: Bool = true
    public var dustRelayFee: UInt64 = 3000
    public var mempoolConfig: MempoolConfig = .disabled
    public var logLevel: String = "info"  // Options: "error", "warn", "info", "debug", "trace"
    public var startFromHeight: UInt32? = nil  // Start syncing from a specific block height (uses nearest checkpoint)
    public var walletCreationTime: UInt32? = nil  // Wallet creation time as Unix timestamp (for checkpoint selection)
    
    public init() {
        setupDefaultDataDirectory()
    }
    
    public static var `default`: SPVClientConfiguration {
        return SPVClientConfiguration()
    }
    
    private func setupDefaultDataDirectory() {
        if let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            self.dataDirectory = documentsPath.appendingPathComponent("DashSPV").appendingPathComponent(network.rawValue)
            print("📁 SPV data directory set to: \(self.dataDirectory?.path ?? "nil")")
        }
    }
    
    public func validate() throws {
        if let dataDir = dataDirectory {
            if !FileManager.default.fileExists(atPath: dataDir.path) {
                try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)
            }
        }
        
        for peer in additionalPeers {
            guard peer.contains(":") else {
                throw DashSDKError.invalidConfiguration("Invalid peer address format: \(peer)")
            }
        }
    }
    
    internal func createFFIConfig() throws -> FFIClientConfig {
        try validate()
        
        print("Creating FFI config for network: \(network.name) (value: \(network.ffiValue))")
        
        guard let config = dash_spv_ffi_config_new(network.ffiValue) else {
            // Check for error
            if let errorMsg = dash_spv_ffi_get_last_error() {
                let error = String(cString: errorMsg)
                print("FFI Error: \(error)")
                dash_spv_ffi_clear_error()
                throw DashSDKError.invalidConfiguration("Failed to create FFI config: \(error)")
            }
            throw DashSDKError.invalidConfiguration("Failed to create FFI config")
        }
        
        if let dataDir = dataDirectory {
            print("📂 Setting SPV data directory for persistence: \(dataDir.path)")
            let result = FFIBridge.withCString(dataDir.path) { path in
                dash_spv_ffi_config_set_data_dir(config, path)
            }
            try FFIBridge.checkError(result)
            
            // Check if sync state already exists
            let syncStateFile = dataDir.appendingPathComponent("sync_state.json")
            if FileManager.default.fileExists(atPath: syncStateFile.path) {
                print("✅ Found existing sync state at: \(syncStateFile.path)")
            } else {
                print("📝 No existing sync state found, will start fresh sync")
            }
        }
        
        var result = dash_spv_ffi_config_set_validation_mode(config, validationMode.ffiValue)
        try FFIBridge.checkError(result)
        
        result = dash_spv_ffi_config_set_max_peers(config, maxPeers)
        try FFIBridge.checkError(result)
        
        // User agent setting is not supported in current implementation
        // result = FFIBridge.withCString(userAgent) { agent in
        //     dash_spv_ffi_config_set_user_agent(config, agent)
        // }
        // try FFIBridge.checkError(result)
        
        result = dash_spv_ffi_config_set_filter_load(config, enableFilterLoad)
        try FFIBridge.checkError(result)
        
        for peer in additionalPeers {
            result = FFIBridge.withCString(peer) { peerStr in
                dash_spv_ffi_config_add_peer(config, peerStr)
            }
            try FFIBridge.checkError(result)
        }
        
        // Configure mempool settings
        result = dash_spv_ffi_config_set_mempool_tracking(config, mempoolConfig.enabled)
        try FFIBridge.checkError(result)
        
        if mempoolConfig.enabled {
            result = dash_spv_ffi_config_set_mempool_strategy(config, FFIMempoolStrategy(rawValue: mempoolConfig.strategy.rawValue))
            try FFIBridge.checkError(result)
            
            result = dash_spv_ffi_config_set_max_mempool_transactions(config, mempoolConfig.maxTransactions)
            try FFIBridge.checkError(result)
            
            result = dash_spv_ffi_config_set_mempool_timeout(config, mempoolConfig.timeoutSeconds)
            try FFIBridge.checkError(result)
            
            result = dash_spv_ffi_config_set_fetch_mempool_transactions(config, mempoolConfig.fetchTransactions)
            try FFIBridge.checkError(result)
            
            result = dash_spv_ffi_config_set_persist_mempool(config, mempoolConfig.persistMempool)
            try FFIBridge.checkError(result)
        }
        
        // Configure checkpoint sync if specified
        if let height = startFromHeight {
            result = dash_spv_ffi_config_set_start_from_height(config, height)
            try FFIBridge.checkError(result)
        }
        
        if let timestamp = walletCreationTime {
            result = dash_spv_ffi_config_set_wallet_creation_time(config, timestamp)
            try FFIBridge.checkError(result)
        }
        
        return UnsafeMutableRawPointer(config)
    }
}

extension SPVClientConfiguration {
    public static func mainnet() -> SPVClientConfiguration {
        let config = SPVClientConfiguration()
        config.network = .mainnet
        return config
    }
    
    public static func testnet() -> SPVClientConfiguration {
        let config = SPVClientConfiguration()
        config.network = .testnet
        return config
    }
    
    public static func regtest() -> SPVClientConfiguration {
        let config = SPVClientConfiguration()
        config.network = .regtest
        config.validationMode = .none
        return config
    }
    
    public static func devnet() -> SPVClientConfiguration {
        let config = SPVClientConfiguration()
        config.network = .devnet
        return config
    }
    
    /// Configure the SPV client to use checkpoint sync for faster initial synchronization.
    /// For testnet, this will sync from the latest checkpoint at height 1088640 instead of genesis.
    /// For mainnet, this will sync from the latest checkpoint at height 1100000 instead of genesis.
    public func enableCheckpointSync() {
        switch network {
        case .testnet:
            startFromHeight = 1088640  // Testnet checkpoint
        case .mainnet:
            startFromHeight = 1100000  // Mainnet checkpoint
        case .devnet, .regtest:
            // No checkpoints for devnet/regtest
            break
        }
    }
    
    /// Configure checkpoint sync for a specific wallet creation time.
    /// The client will automatically select the appropriate checkpoint.
    public func setWalletCreationTime(_ timestamp: UInt32) {
        walletCreationTime = timestamp
    }
    
    /// Configure checkpoint sync to start from a specific height.
    /// The client will use the nearest checkpoint at or before this height.
    public func setStartFromHeight(_ height: UInt32) {
        startFromHeight = height
    }
}
