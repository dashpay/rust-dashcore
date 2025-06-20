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
    
    public init() {
        setupDefaultDataDirectory()
    }
    
    public static var `default`: SPVClientConfiguration {
        return SPVClientConfiguration()
    }
    
    private func setupDefaultDataDirectory() {
        if let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            self.dataDirectory = documentsPath.appendingPathComponent("DashSPV").appendingPathComponent(network.rawValue)
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
            let result = FFIBridge.withCString(dataDir.path) { path in
                dash_spv_ffi_config_set_data_dir(config, path)
            }
            try FFIBridge.checkError(result)
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
}