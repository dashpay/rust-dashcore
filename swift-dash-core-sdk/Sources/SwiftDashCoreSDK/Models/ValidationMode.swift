import Foundation

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
            return FFIValidationMode(0)
        case .basic:
            return FFIValidationMode(1)
        case .full:
            return FFIValidationMode(2)
        }
    }
    
    internal init?(ffiMode: FFIValidationMode) {
        switch ffiMode {
        case FFIValidationMode(0):
            self = .none
        case FFIValidationMode(1):
            self = .basic
        case FFIValidationMode(2):
            self = .full
        default:
            return nil
        }
    }
}