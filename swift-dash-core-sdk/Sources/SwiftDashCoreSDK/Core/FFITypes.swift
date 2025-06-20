import Foundation
import DashSPVFFI

typealias FFINetwork = UInt32
typealias FFIValidationMode = UInt32
typealias FFIErrorCode = Int32
typealias FFIClientConfig = UnsafeMutableRawPointer
typealias FFIClient = UnsafeMutableRawPointer
typealias FFIString = dash_spv_ffi_string
typealias FFIArray = dash_spv_ffi_array
typealias FFIBalance = dash_spv_ffi_balance
typealias FFIUtxo = dash_spv_ffi_utxo
typealias FFITransaction = dash_spv_ffi_transaction
typealias FFITransactionResult = dash_spv_ffi_transaction_result
typealias FFISyncProgress = dash_spv_ffi_sync_progress
typealias FFISpvStats = dash_spv_ffi_spv_stats
typealias FFIWatchItem = dash_spv_ffi_watch_item
typealias FFIWatchItemType = UInt32
typealias FFIAddressStats = dash_spv_ffi_address_stats

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