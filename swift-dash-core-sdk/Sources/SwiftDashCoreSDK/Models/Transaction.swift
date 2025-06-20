import Foundation
import SwiftData

@Model
public final class Transaction {
    @Attribute(.unique) public var txid: String
    public var height: UInt32?
    public var timestamp: Date
    public var amount: Int64
    public var fee: UInt64
    public var confirmations: UInt32
    public var isInstantLocked: Bool
    public var raw: Data
    public var size: UInt32
    public var version: UInt32
    
    public init(
        txid: String,
        height: UInt32? = nil,
        timestamp: Date = .now,
        amount: Int64 = 0,
        fee: UInt64 = 0,
        confirmations: UInt32 = 0,
        isInstantLocked: Bool = false,
        raw: Data = Data(),
        size: UInt32 = 0,
        version: UInt32 = 1
    ) {
        self.txid = txid
        self.height = height
        self.timestamp = timestamp
        self.amount = amount
        self.fee = fee
        self.confirmations = confirmations
        self.isInstantLocked = isInstantLocked
        self.raw = raw
        self.size = size
        self.version = version
    }
    
    internal convenience init(ffiTransaction: FFITransaction) {
        let timestamp = Date(timeIntervalSince1970: TimeInterval(ffiTransaction.timestamp))
        
        self.init(
            txid: String(cString: ffiTransaction.txid),
            height: ffiTransaction.height == UInt32.max ? nil : ffiTransaction.height,
            timestamp: timestamp,
            amount: Int64(bitPattern: ffiTransaction.amount),
            fee: ffiTransaction.fee,
            confirmations: ffiTransaction.confirmations,
            isInstantLocked: ffiTransaction.is_instant_locked,
            raw: Data(bytes: ffiTransaction.raw_tx, count: Int(ffiTransaction.raw_tx_len)),
            size: ffiTransaction.size,
            version: ffiTransaction.version
        )
    }
    
    public var isConfirmed: Bool {
        return confirmations > 0
    }
    
    public var isPending: Bool {
        return confirmations == 0 && !isInstantLocked
    }
    
    public var status: TransactionStatus {
        if isInstantLocked {
            return .instantLocked
        } else if confirmations >= 6 {
            return .confirmed
        } else if confirmations > 0 {
            return .confirming(confirmations)
        } else {
            return .pending
        }
    }
}

public enum TransactionStatus: Equatable {
    case pending
    case confirming(UInt32)
    case confirmed
    case instantLocked
    
    public var description: String {
        switch self {
        case .pending:
            return "Pending"
        case .confirming(let confirmations):
            return "\(confirmations)/6 confirmations"
        case .confirmed:
            return "Confirmed"
        case .instantLocked:
            return "InstantSend"
        }
    }
    
    public var isSettled: Bool {
        switch self {
        case .confirmed, .instantLocked:
            return true
        case .pending, .confirming:
            return false
        }
    }
}