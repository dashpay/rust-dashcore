import Foundation
import DashSPVFFI

// FFI types are imported directly from the C header

public enum ValidationMode: String, Codable, CaseIterable, Sendable {
    case none = "none"
    case basic = "basic"
    case full = "full"

    public var description: String {
        switch self {
        case .none:
            return "No validation - trust all data"
        case .basic:
            return "Basic validation - verify headers and PoW"
        case .full:
            return "Full validation - verify everything including ChainLocks"
        }
    }

    internal var ffiValue: FFIValidationMode {
        switch self {
        case .none:
            return FFIValidationMode(rawValue: 0)
        case .basic:
            return FFIValidationMode(rawValue: 1)
        case .full:
            return FFIValidationMode(rawValue: 2)
        }
    }

    internal init?(ffiMode: FFIValidationMode) {
        switch ffiMode.rawValue {
        case 0:
            self = .none
        case 1:
            self = .basic
        case 2:
            self = .full
        default:
            return nil
        }
    }
}