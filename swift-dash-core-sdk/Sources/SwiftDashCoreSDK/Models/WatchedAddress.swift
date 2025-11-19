import Foundation
import SwiftData

@Model
public final class WatchedAddress {
    @Attribute(.unique) public var address: String
    public var label: String?
    public var createdAt: Date
    public var lastActivity: Date?
    public var isActive: Bool

    @Relationship(deleteRule: .cascade) public var balance: Balance?
    @Relationship(deleteRule: .cascade) public var transactions: [Transaction]
    @Relationship(deleteRule: .cascade) public var utxos: [UTXO]

    public init(
        address: String,
        label: String? = nil,
        createdAt: Date = .now,
        isActive: Bool = true
    ) {
        self.address = address
        self.label = label
        self.createdAt = createdAt
        self.isActive = isActive
        self.transactions = []
        self.utxos = []
    }

    public var displayName: String {
        return label ?? address
    }

    public var shortAddress: String {
        guard address.count > 12 else { return address }
        let prefix = address.prefix(6)
        let suffix = address.suffix(4)
        return "\(prefix)...\(suffix)"
    }

    public var totalReceived: UInt64 {
        return transactions
            .filter { $0.amount > 0 }
            .reduce(0) { $0 + UInt64($1.amount) }
    }

    public var totalSent: UInt64 {
        return transactions
            .filter { $0.amount < 0 }
            .reduce(0) { $0 + UInt64(abs($1.amount)) }
    }

    public var spendableUTXOs: [UTXO] {
        return utxos.filter { $0.isSpendable }
    }

    public var pendingTransactions: [Transaction] {
        return transactions.filter { $0.isPending }
    }

    public func updateActivity() {
        self.lastActivity = .now
    }
}

extension WatchedAddress {
    public enum SortOption: String, CaseIterable {
        case label = "label"
        case address = "address"
        case balance = "balance"
        case activity = "activity"
        case created = "created"

        public var description: String {
            switch self {
            case .label:
                return "Label"
            case .address:
                return "Address"
            case .balance:
                return "Balance"
            case .activity:
                return "Last Activity"
            case .created:
                return "Date Added"
            }
        }
    }
}
