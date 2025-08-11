import Foundation
import DashSPVFFI

/// Strategy for handling mempool transactions
public enum MempoolStrategy: UInt32, CaseIterable, Sendable {
    /// Fetch all announced transactions (poor privacy, high bandwidth)
    case fetchAll = 0
    /// Use BIP37 bloom filters (moderate privacy, good efficiency)
    case bloomFilter = 1
    /// Only fetch when recently sent or from known addresses (good privacy)
    case selective = 2
    
    internal var ffiValue: FFIMempoolStrategy {
        return FFIMempoolStrategy(rawValue: self.rawValue)
    }
}

/// Configuration for mempool tracking
public struct MempoolConfig {
    /// Whether mempool tracking is enabled
    public let enabled: Bool
    
    /// Strategy for handling mempool transactions
    public let strategy: MempoolStrategy
    
    /// Maximum number of transactions to track
    public let maxTransactions: UInt32
    
    /// Time after which unconfirmed transactions are pruned (in seconds)
    public let timeoutSeconds: UInt64
    
    /// Whether to fetch transaction data from INV messages
    public let fetchTransactions: Bool
    
    /// Whether to persist mempool transactions across restarts
    public let persistMempool: Bool
    
    /// Initialize with custom configuration
    public init(
        enabled: Bool,
        strategy: MempoolStrategy = .selective,
        maxTransactions: UInt32 = 1000,
        timeoutSeconds: UInt64 = 3600,
        fetchTransactions: Bool = true,
        persistMempool: Bool = false
    ) {
        self.enabled = enabled
        self.strategy = strategy
        self.maxTransactions = maxTransactions
        self.timeoutSeconds = timeoutSeconds
        self.fetchTransactions = fetchTransactions
        self.persistMempool = persistMempool
    }
    
    /// Create a FetchAll configuration
    public static func fetchAll(maxTransactions: UInt32 = 5000) -> MempoolConfig {
        return MempoolConfig(
            enabled: true,
            strategy: .fetchAll,
            maxTransactions: maxTransactions,
            timeoutSeconds: 3600,
            fetchTransactions: true,
            persistMempool: false
        )
    }
    
    /// Create a Selective configuration (recommended)
    public static func selective(maxTransactions: UInt32 = 1000) -> MempoolConfig {
        return MempoolConfig(
            enabled: true,
            strategy: .selective,
            maxTransactions: maxTransactions,
            timeoutSeconds: 3600,
            fetchTransactions: true,
            persistMempool: false
        )
    }
    
    /// Create a disabled configuration
    public static var disabled: MempoolConfig {
        return MempoolConfig(enabled: false)
    }
}

/// Represents an unconfirmed transaction in the mempool
public struct MempoolTransaction {
    /// Transaction ID
    public let txid: String
    
    /// Raw transaction data
    public let rawTransaction: Data
    
    /// Time when first seen
    public let firstSeen: Date
    
    /// Transaction fee in satoshis
    public let fee: UInt64
    
    /// Whether this is an InstantSend transaction
    public let isInstantSend: Bool
    
    /// Whether this is an outgoing transaction
    public let isOutgoing: Bool
    
    /// Addresses affected by this transaction
    public let affectedAddresses: [String]
    
    /// Net amount change (positive for incoming, negative for outgoing)
    public let netAmount: Int64
    
    /// Size of the transaction in bytes
    public let size: UInt32
    
    /// Fee rate in satoshis per byte
    public var feeRate: Double {
        guard size > 0 else { return 0 }
        return Double(fee) / Double(size)
    }
}

/// Mempool balance information
public struct MempoolBalance {
    /// Pending balance from regular mempool transactions
    public let pending: UInt64
    
    /// Pending balance from InstantSend transactions
    public let pendingInstant: UInt64
    
    /// Total pending balance
    public var total: UInt64 {
        return pending + pendingInstant
    }
}

/// Reason why a transaction was removed from mempool
public enum MempoolRemovalReason: UInt8, Equatable, Sendable {
    /// Transaction expired after timeout
    case expired = 0
    /// Transaction was replaced by another
    case replaced = 1
    /// Transaction was double-spent
    case doubleSpent = 2
    /// Transaction was included in a block
    case confirmed = 3
    /// Transaction was manually removed
    case manual = 4
    /// Unknown reason
    case unknown = 255
}

/// Mempool event types
public enum MempoolEvent {
    /// New transaction added to mempool
    case transactionAdded(MempoolTransaction)
    
    /// Transaction confirmed in a block
    case transactionConfirmed(txid: String, blockHeight: UInt32, blockHash: String)
    
    /// Transaction removed from mempool
    case transactionRemoved(txid: String, reason: MempoolRemovalReason)
}

/// Protocol for mempool event observers
public protocol MempoolObserver: AnyObject {
    /// Called when a mempool event occurs
    func mempoolEvent(_ event: MempoolEvent)
}