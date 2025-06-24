import Foundation
import DashSPVFFI

/// Strategy for handling mempool (unconfirmed) transactions
public enum MempoolStrategy: CaseIterable, Sendable {
    /// Fetch all announced transactions (poor privacy, high bandwidth)
    case fetchAll
    /// Use BIP37 bloom filters (moderate privacy, good efficiency)
    case bloomFilter
    /// Only fetch when recently sent or from known addresses (good privacy, default)
    case selective
    
    internal var ffiValue: FFIMempoolStrategy {
        switch self {
        case .fetchAll:
            return FFIMempoolStrategy(rawValue: 0)
        case .bloomFilter:
            return FFIMempoolStrategy(rawValue: 1)
        case .selective:
            return FFIMempoolStrategy(rawValue: 2)
        }
    }
    
    internal init?(ffiStrategy: FFIMempoolStrategy) {
        switch ffiStrategy.rawValue {
        case 0:
            self = .fetchAll
        case 1:
            self = .bloomFilter
        case 2:
            self = .selective
        default:
            return nil
        }
    }
    
    public var description: String {
        switch self {
        case .fetchAll:
            return "Fetch All (Poor Privacy)"
        case .bloomFilter:
            return "Bloom Filter (Moderate Privacy)"
        case .selective:
            return "Selective (Good Privacy)"
        }
    }
}

/// Reason for removing a transaction from mempool
public enum MempoolRemovalReason: Sendable {
    /// Transaction expired (exceeded timeout)
    case expired
    /// Transaction was replaced by another transaction
    case replaced(byTxid: String?)
    /// Transaction was double-spent
    case doubleSpent(conflictingTxid: String?)
    /// Transaction was included in a block
    case confirmed
    /// Manual removal (e.g., user action)
    case manual
    
    internal init(ffiReason: FFIMempoolRemovalReason) {
        switch ffiReason.rawValue {
        case 0:
            self = .expired
        case 1:
            self = .replaced(byTxid: nil)
        case 2:
            self = .doubleSpent(conflictingTxid: nil)
        case 3:
            self = .confirmed
        case 4:
            self = .manual
        default:
            self = .manual
        }
    }
    
    public var description: String {
        switch self {
        case .expired:
            return "Expired"
        case .replaced(let byTxid):
            if let txid = byTxid {
                return "Replaced by \(txid)"
            }
            return "Replaced"
        case .doubleSpent(let conflictingTxid):
            if let txid = conflictingTxid {
                return "Double-spent by \(txid)"
            }
            return "Double-spent"
        case .confirmed:
            return "Confirmed in block"
        case .manual:
            return "Manually removed"
        }
    }
}

/// Unconfirmed transaction in mempool
public struct UnconfirmedTransaction: Identifiable, Sendable {
    public let id: String // txid
    public let amount: Int64
    public let fee: UInt64
    public let isInstantSend: Bool
    public let isOutgoing: Bool
    public let addresses: [String]
    public let firstSeen: Date
    
    public var formattedAmount: String {
        let dash = Double(abs(amount)) / 100_000_000.0
        let sign = amount < 0 ? "-" : "+"
        return "\(sign)\(String(format: "%.8f", dash)) DASH"
    }
    
    public var formattedFee: String {
        let dash = Double(fee) / 100_000_000.0
        return String(format: "%.8f DASH", dash)
    }
}