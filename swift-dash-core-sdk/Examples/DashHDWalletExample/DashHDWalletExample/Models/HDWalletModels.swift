import Foundation
import SwiftData
import SwiftDashCoreSDK

// MARK: - HD Wallet

@Model
final class HDWallet {
    @Attribute(.unique) var id: UUID
    var name: String
    var network: DashNetwork
    var createdAt: Date
    var lastSynced: Date?
    var encryptedSeed: Data // Encrypted mnemonic seed
    var seedHash: String // For duplicate detection
    
    @Relationship(deleteRule: .cascade) var accounts: [HDAccount]
    
    init(name: String, network: DashNetwork, encryptedSeed: Data, seedHash: String) {
        self.id = UUID()
        self.name = name
        self.network = network
        self.createdAt = Date()
        self.encryptedSeed = encryptedSeed
        self.seedHash = seedHash
        self.accounts = []
    }
    
    var displayNetwork: String {
        switch network {
        case .mainnet:
            return "Mainnet"
        case .testnet:
            return "Testnet"
        case .regtest:
            return "Regtest"
        case .devnet:
            return "Devnet"
        }
    }
    
    var totalBalance: Balance {
        let balance = Balance()
        for account in accounts {
            balance.confirmed += account.balance?.confirmed ?? 0
            balance.pending += account.balance?.pending ?? 0
            balance.instantLocked += account.balance?.instantLocked ?? 0
            balance.total += account.balance?.total ?? 0
        }
        balance.lastUpdated = Date()
        return balance
    }
}

// MARK: - HD Account (BIP44)

@Model
final class HDAccount {
    @Attribute(.unique) var id: UUID
    var accountIndex: UInt32
    var label: String
    var extendedPublicKey: String // xpub for this account
    var createdAt: Date
    var lastUsedExternalIndex: UInt32
    var lastUsedInternalIndex: UInt32
    var gapLimit: UInt32
    
    @Relationship var wallet: HDWallet?
    @Relationship(deleteRule: .cascade) var balance: Balance?
    @Relationship(deleteRule: .cascade) var addresses: [HDWatchedAddress]
    @Relationship(deleteRule: .cascade) var transactions: [Transaction]
    
    init(
        accountIndex: UInt32,
        label: String,
        extendedPublicKey: String,
        gapLimit: UInt32 = 20
    ) {
        self.id = UUID()
        self.accountIndex = accountIndex
        self.label = label
        self.extendedPublicKey = extendedPublicKey
        self.createdAt = Date()
        self.lastUsedExternalIndex = 0
        self.lastUsedInternalIndex = 0
        self.gapLimit = gapLimit
        self.addresses = []
        self.transactions = []
    }
    
    var displayName: String {
        return label.isEmpty ? "Account #\(accountIndex)" : label
    }
    
    var derivationPath: String {
        guard let wallet = wallet else { return "" }
        let coinType: UInt32 = wallet.network == .mainnet ? 5 : 1
        return "m/44'/\(coinType)'/\(accountIndex)'"
    }
    
    var externalAddresses: [HDWatchedAddress] {
        addresses.filter { !$0.isChange }.sorted { $0.index < $1.index }
    }
    
    var internalAddresses: [HDWatchedAddress] {
        addresses.filter { $0.isChange }.sorted { $0.index < $1.index }
    }
    
    var receiveAddress: HDWatchedAddress? {
        // Find the first unused address or the next one to generate
        return externalAddresses.first { $0.transactions.isEmpty }
    }
}

// MARK: - HD Watched Address

@Model
final class HDWatchedAddress {
    @Attribute(.unique) var address: String
    var label: String?
    var createdAt: Date
    var lastActive: Date?
    @Relationship var balance: Balance?
    @Relationship(deleteRule: .cascade) var transactions: [Transaction]
    @Relationship(deleteRule: .cascade) var utxos: [UTXO]
    
    // HD specific properties
    var index: UInt32
    var isChange: Bool
    var derivationPath: String
    @Relationship var account: HDAccount?
    
    init(address: String, index: UInt32, isChange: Bool, derivationPath: String, label: String? = nil) {
        self.address = address
        self.index = index
        self.isChange = isChange
        self.derivationPath = derivationPath
        self.label = label
        self.createdAt = Date()
        self.balance = nil
        self.transactions = []
        self.utxos = []
    }
    
    var formattedBalance: String {
        guard let balance = balance else { return "0.00000000 DASH" }
        return balance.formattedTotal
    }
}

// MARK: - Sync State

@Model
final class SyncState {
    @Attribute(.unique) var walletId: UUID
    var currentHeight: UInt32
    var totalHeight: UInt32
    var progress: Double
    var status: String
    var lastError: String?
    var startTime: Date
    var estimatedCompletion: Date?
    
    init(walletId: UUID) {
        self.walletId = walletId
        self.currentHeight = 0
        self.totalHeight = 0
        self.progress = 0
        self.status = "idle"
        self.startTime = Date()
    }
    
    func update(from syncProgress: SyncProgress) {
        self.currentHeight = syncProgress.currentHeight
        self.totalHeight = syncProgress.totalHeight
        self.progress = syncProgress.progress
        self.status = syncProgress.status.rawValue
        
        if let eta = syncProgress.estimatedTimeRemaining {
            self.estimatedCompletion = Date().addingTimeInterval(eta)
        }
    }
}