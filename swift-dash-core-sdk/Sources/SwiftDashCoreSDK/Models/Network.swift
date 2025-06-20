import Foundation

public enum DashNetwork: String, Codable, CaseIterable, Sendable {
    case mainnet = "mainnet"
    case testnet = "testnet"
    case regtest = "regtest"
    case devnet = "devnet"
    
    public var defaultPort: UInt16 {
        switch self {
        case .mainnet:
            return 9999
        case .testnet:
            return 19999
        case .regtest:
            return 19899
        case .devnet:
            return 19799
        }
    }
    
    public var protocolVersion: UInt32 {
        return 70230
    }
    
    public var name: String {
        return self.rawValue
    }
    
    internal var ffiValue: FFINetwork {
        switch self {
        case .mainnet:
            return FFINetwork(0)
        case .testnet:
            return FFINetwork(1)
        case .regtest:
            return FFINetwork(2)
        case .devnet:
            return FFINetwork(3)
        }
    }
    
    internal init?(ffiNetwork: FFINetwork) {
        switch ffiNetwork {
        case FFINetwork(0):
            self = .mainnet
        case FFINetwork(1):
            self = .testnet
        case FFINetwork(2):
            self = .regtest
        case FFINetwork(3):
            self = .devnet
        default:
            return nil
        }
    }
}