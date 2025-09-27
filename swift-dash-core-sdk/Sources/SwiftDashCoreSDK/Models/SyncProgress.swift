import Foundation
import DashSPVFFI

// FFI types are imported directly from the C header

public struct SyncProgress: Sendable, Equatable {
    public let currentHeight: UInt32
    public let totalHeight: UInt32
    public let progress: Double
    public let status: SyncStatus
    public let estimatedTimeRemaining: TimeInterval?
    public let message: String?
    public let filterSyncAvailable: Bool
    public let filterHeaderHeight: UInt32
    public let masternodeHeight: UInt32
    public let peerCount: UInt32
    public let filtersDownloaded: UInt32
    public let lastSyncedFilterHeight: UInt32
    
    public init(
        currentHeight: UInt32,
        totalHeight: UInt32,
        progress: Double,
        status: SyncStatus,
        estimatedTimeRemaining: TimeInterval? = nil,
        message: String? = nil,
        filterSyncAvailable: Bool = false,
        filterHeaderHeight: UInt32 = 0,
        masternodeHeight: UInt32 = 0,
        peerCount: UInt32 = 0,
        headersSynced: Bool = false,
        filterHeadersSynced: Bool = false,
        masternodesSynced: Bool = false,
        filtersDownloaded: UInt32 = 0,
        lastSyncedFilterHeight: UInt32 = 0
    ) {
        self.currentHeight = currentHeight
        self.totalHeight = totalHeight
        self.progress = progress
        self.status = status
        self.estimatedTimeRemaining = estimatedTimeRemaining
        self.message = message
        self.filterSyncAvailable = filterSyncAvailable
        self.filterHeaderHeight = filterHeaderHeight
        self.masternodeHeight = masternodeHeight
        self.peerCount = peerCount
        self.filtersDownloaded = filtersDownloaded
        self.lastSyncedFilterHeight = lastSyncedFilterHeight
    }
    
    internal init(ffiProgress: FFISyncProgress) {
        self.currentHeight = ffiProgress.header_height
        self.totalHeight = 0 // FFISyncProgress doesn't provide total height
        self.progress = 0.0
        self.status = .downloadingHeaders
        self.estimatedTimeRemaining = nil
        self.message = nil
        self.filterSyncAvailable = ffiProgress.filter_sync_available
        self.filterHeaderHeight = ffiProgress.filter_header_height
        self.masternodeHeight = ffiProgress.masternode_height
        self.peerCount = ffiProgress.peer_count
        self.filtersDownloaded = ffiProgress.filters_downloaded
        self.lastSyncedFilterHeight = ffiProgress.last_synced_filter_height
    }
    
    public var blocksRemaining: UInt32 {
        guard totalHeight > currentHeight else { return 0 }
        return totalHeight - currentHeight
    }
    
    public var isComplete: Bool {
        return currentHeight >= totalHeight || progress >= 1.0
    }
    
    public var percentageComplete: Int {
        return Int(progress * 100)
    }
    
    public var formattedTimeRemaining: String? {
        guard let eta = estimatedTimeRemaining else { return nil }
        
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.hour, .minute, .second]
        formatter.unitsStyle = .abbreviated
        return formatter.string(from: eta)
    }
}

public enum SyncStatus: String, Codable, Sendable {
    case idle = "idle"
    case connecting = "connecting"
    case downloadingHeaders = "downloading_headers"
    case downloadingFilters = "downloading_filters"
    case scanning = "scanning"
    case synced = "synced"
    case error = "error"
    
    internal init?(ffiStatus: UInt32) {
        switch ffiStatus {
        case 0:
            self = .idle
        case 1:
            self = .connecting
        case 2:
            self = .downloadingHeaders
        case 3:
            self = .downloadingFilters
        case 4:
            self = .scanning
        case 5:
            self = .synced
        case 6:
            self = .error
        default:
            return nil
        }
    }
    
    public var description: String {
        switch self {
        case .idle:
            return "Idle"
        case .connecting:
            return "Connecting to peers"
        case .downloadingHeaders:
            return "Downloading headers"
        case .downloadingFilters:
            return "Downloading filters"
        case .scanning:
            return "Scanning blockchain"
        case .synced:
            return "Fully synced"
        case .error:
            return "Sync error"
        }
    }
    
    public var isActive: Bool {
        switch self {
        case .idle, .synced, .error:
            return false
        case .connecting, .downloadingHeaders, .downloadingFilters, .scanning:
            return true
        }
    }
}
