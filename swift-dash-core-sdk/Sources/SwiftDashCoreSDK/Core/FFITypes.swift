import Foundation
import DashSPVFFI

typealias FFIErrorCode = Int32
typealias FFIClientConfig = UnsafeMutableRawPointer
typealias FFIClient = UnsafeMutableRawPointer
// These types come directly from the C header via DashSPVFFI module
// No need for redundant typealias - use directly as FFIString, FFIDetailedSyncProgress, etc.

enum FFIError: Error {
    case success
    case nullPointer
    case invalidArgument
    case networkError
    case storageError
    case validationError
    case syncError
    case walletError
    case configError
    case runtimeError
    case unknown
    
    init(code: FFIErrorCode) {
        switch code {
        case 0:
            self = .success
        case 1:
            self = .nullPointer
        case 2:
            self = .invalidArgument
        case 3:
            self = .networkError
        case 4:
            self = .storageError
        case 5:
            self = .validationError
        case 6:
            self = .syncError
        case 7:
            self = .walletError
        case 8:
            self = .configError
        case 9:
            self = .runtimeError
        default:
            self = .unknown
        }
    }
}