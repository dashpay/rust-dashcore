import Foundation
import SwiftData
import DashSPVFFI

// FFI types are imported directly from the C header

@Model
public final class Balance {
    public var confirmed: UInt64
    public var pending: UInt64
    public var instantLocked: UInt64
    public var total: UInt64
    public var lastUpdated: Date
    
    public init(
        confirmed: UInt64 = 0,
        pending: UInt64 = 0,
        instantLocked: UInt64 = 0,
        total: UInt64 = 0,
        lastUpdated: Date = .now
    ) {
        self.confirmed = confirmed
        self.pending = pending
        self.instantLocked = instantLocked
        self.total = total
        self.lastUpdated = lastUpdated
    }
    
    internal convenience init(ffiBalance: FFIBalance) {
        self.init(
            confirmed: ffiBalance.confirmed,
            pending: ffiBalance.pending,
            instantLocked: ffiBalance.instantlocked,
            total: ffiBalance.total,
            lastUpdated: .now
        )
    }
    
    public var available: UInt64 {
        return confirmed + instantLocked
    }
    
    public var unconfirmed: UInt64 {
        return pending
    }
    
    public func update(from other: Balance) {
        self.confirmed = other.confirmed
        self.pending = other.pending
        self.instantLocked = other.instantLocked
        self.total = other.total
        self.lastUpdated = other.lastUpdated
    }
}

extension Balance {
    public var formattedConfirmed: String {
        return formatDash(confirmed)
    }
    
    public var formattedPending: String {
        return formatDash(pending)
    }
    
    public var formattedInstantLocked: String {
        return formatDash(instantLocked)
    }
    
    public var formattedTotal: String {
        return formatDash(total)
    }
    
    private func formatDash(_ satoshis: UInt64) -> String {
        let dash = Double(satoshis) / 100_000_000.0
        return String(format: "%.8f DASH", dash)
    }
}