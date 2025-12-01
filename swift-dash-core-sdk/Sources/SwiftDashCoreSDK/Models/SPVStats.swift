import Foundation
import DashSPVFFI

// FFI types are imported directly from the C header

public struct SPVStats: Sendable {
    public let connectedPeers: UInt32
    public let totalPeers: UInt32
    public let headerHeight: UInt32
    public let filterHeight: UInt32
    public let scannedHeight: UInt32
    public let totalHeaders: UInt64
    public let totalFilters: UInt64
    public let totalTransactions: UInt64
    public let startTime: Date
    public let bytesReceived: UInt64
    public let bytesSent: UInt64

    public init(
        connectedPeers: UInt32 = 0,
        totalPeers: UInt32 = 0,
        headerHeight: UInt32 = 0,
        filterHeight: UInt32 = 0,
        scannedHeight: UInt32 = 0,
        totalHeaders: UInt64 = 0,
        totalFilters: UInt64 = 0,
        totalTransactions: UInt64 = 0,
        startTime: Date = .now,
        bytesReceived: UInt64 = 0,
        bytesSent: UInt64 = 0
    ) {
        self.connectedPeers = connectedPeers
        self.totalPeers = totalPeers
        self.headerHeight = headerHeight
        self.filterHeight = filterHeight
        self.scannedHeight = scannedHeight
        self.totalHeaders = totalHeaders
        self.totalFilters = totalFilters
        self.totalTransactions = totalTransactions
        self.startTime = startTime
        self.bytesReceived = bytesReceived
        self.bytesSent = bytesSent
    }

    internal init(ffiStats: FFISpvStats) {
        self.connectedPeers = ffiStats.connected_peers
        self.totalPeers = ffiStats.total_peers
        self.headerHeight = ffiStats.header_height
        self.filterHeight = ffiStats.filter_height
        self.scannedHeight = 0 // Not provided by FFISpvStats
        self.totalHeaders = ffiStats.headers_downloaded
        self.totalFilters = ffiStats.filters_downloaded
        self.totalTransactions = ffiStats.blocks_processed // Use blocks_processed
        self.startTime = Date.now.addingTimeInterval(-TimeInterval(ffiStats.uptime))
        self.bytesReceived = ffiStats.bytes_received
        self.bytesSent = ffiStats.bytes_sent
    }

    public var uptime: TimeInterval {
        return Date.now.timeIntervalSince(startTime)
    }

    public var formattedUptime: String {
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.day, .hour, .minute, .second]
        formatter.unitsStyle = .abbreviated
        return formatter.string(from: uptime) ?? "0s"
    }

    public var totalBytesTransferred: UInt64 {
        return bytesReceived + bytesSent
    }

    public var formattedBytesReceived: String {
        return ByteCountFormatter.string(fromByteCount: Int64(bytesReceived), countStyle: .binary)
    }

    public var formattedBytesSent: String {
        return ByteCountFormatter.string(fromByteCount: Int64(bytesSent), countStyle: .binary)
    }

    public var formattedTotalBytes: String {
        return ByteCountFormatter.string(fromByteCount: Int64(totalBytesTransferred), countStyle: .binary)
    }

    public var isConnected: Bool {
        return connectedPeers > 0
    }

    public var connectionStatus: String {
        if connectedPeers == 0 {
            return "Disconnected"
        } else if connectedPeers == 1 {
            return "1 peer connected"
        } else {
            return "\(connectedPeers) peers connected"
        }
    }
}
