import Foundation

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