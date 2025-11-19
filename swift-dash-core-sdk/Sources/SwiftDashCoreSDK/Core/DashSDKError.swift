import Foundation

public enum DashSDKError: LocalizedError {
    case invalidConfiguration(String)
    case networkError(String)
    case syncError(String)
    case walletError(String)
    case storageError(String)
    case validationError(String)
    case ffiError(code: Int32, message: String)
    case notConnected
    case alreadyConnected
    case invalidAddress(String)
    case invalidTransaction(String)
    case insufficientFunds(required: UInt64, available: UInt64)
    case transactionBuildError(String)
    case persistenceError(String)
    case invalidArgument(String)
    case unknownError(String)
    case notImplemented(String)

    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration(let message):
            return "Invalid configuration: \(message)"
        case .networkError(let message):
            return "Network error: \(message)"
        case .syncError(let message):
            return "Synchronization error: \(message)"
        case .walletError(let message):
            return "Wallet error: \(message)"
        case .storageError(let message):
            return "Storage error: \(message)"
        case .validationError(let message):
            return "Validation error: \(message)"
        case .ffiError(let code, let message):
            return "FFI error (\(code)): \(message)"
        case .notConnected:
            return "SPV client is not connected"
        case .alreadyConnected:
            return "SPV client is already connected"
        case .invalidAddress(let address):
            return "Invalid address: \(address)"
        case .invalidTransaction(let message):
            return "Invalid transaction: \(message)"
        case .insufficientFunds(let required, let available):
            let reqDash = Double(required) / 100_000_000
            let availDash = Double(available) / 100_000_000
            return "Insufficient funds: required \(reqDash) DASH, available \(availDash) DASH"
        case .transactionBuildError(let message):
            return "Failed to build transaction: \(message)"
        case .persistenceError(let message):
            return "Persistence error: \(message)"
        case .invalidArgument(let message):
            return "Invalid argument: \(message)"
        case .unknownError(let message):
            return "Unknown error: \(message)"
        case .notImplemented(let message):
            return "Not implemented: \(message)"
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .invalidConfiguration:
            return "Check your configuration settings and try again"
        case .networkError:
            return "Check your internet connection and try again"
        case .syncError:
            return "Try restarting the sync process"
        case .walletError:
            return "Check your wallet settings"
        case .storageError:
            return "Check available disk space and permissions"
        case .validationError:
            return "The data received is invalid"
        case .ffiError:
            return "Internal error occurred"
        case .notConnected:
            return "Connect to the network first"
        case .alreadyConnected:
            return "Disconnect before connecting again"
        case .invalidAddress:
            return "Provide a valid Dash address"
        case .invalidTransaction:
            return "Check transaction parameters"
        case .insufficientFunds:
            return "Add more funds to your wallet"
        case .transactionBuildError:
            return "Check transaction inputs and outputs"
        case .persistenceError:
            return "Try clearing app data and resyncing"
        case .invalidArgument:
            return "Check the provided arguments"
        case .unknownError:
            return "Try again or contact support"
        case .notImplemented:
            return "This feature is temporarily unavailable"
        }
    }
}