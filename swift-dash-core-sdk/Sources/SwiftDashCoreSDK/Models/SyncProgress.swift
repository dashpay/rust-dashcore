import Foundation

public struct SyncProgress: Sendable {
    public let currentHeight: UInt32
    public let totalHeight: UInt32
    public let progress: Double
    public let status: SyncStatus
    public let estimatedTimeRemaining: TimeInterval?
    public let message: String?
    
    public init(
        currentHeight: UInt32,
        totalHeight: UInt32,
        progress: Double,
        status: SyncStatus,
        estimatedTimeRemaining: TimeInterval? = nil,
        message: String? = nil
    ) {
        self.currentHeight = currentHeight
        self.totalHeight = totalHeight
        self.progress = progress
        self.status = status
        self.estimatedTimeRemaining = estimatedTimeRemaining
        self.message = message
    }
    
    internal init(ffiProgress: FFISyncProgress) {
        self.currentHeight = ffiProgress.current_height
        self.totalHeight = ffiProgress.total_height
        self.progress = ffiProgress.progress
        self.status = SyncStatus(ffiStatus: ffiProgress.status) ?? .idle
        self.estimatedTimeRemaining = ffiProgress.eta > 0 ? TimeInterval(ffiProgress.eta) : nil
        self.message = ffiProgress.message.flatMap { FFIBridge.toString($0.pointee) }
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