import Foundation
import DashSPVFFI

// MARK: - Watch Item Verification

extension SPVClient {
    // For now, we'll track watched addresses locally since the FFI doesn't expose a way to query them
    private static var watchedAddresses = Set<String>()
    private static let watchedAddressesLock = NSLock()
    
    /// Override addWatchItem to track addresses locally
    public func addWatchItemWithTracking(type: WatchItemType, data: String) async throws {
        try await addWatchItem(type: type, data: data)
        
        // Track addresses locally
        if type == .address {
            Self.watchedAddressesLock.lock()
            Self.watchedAddresses.insert(data)
            Self.watchedAddressesLock.unlock()
        }
    }
    
    /// Override removeWatchItem to update local tracking
    public func removeWatchItemWithTracking(type: WatchItemType, data: String) async throws {
        try await removeWatchItem(type: type, data: data)
        
        // Update local tracking
        if type == .address {
            Self.watchedAddressesLock.lock()
            Self.watchedAddresses.remove(data)
            Self.watchedAddressesLock.unlock()
        }
    }
    
    /// Verifies that an address is being watched (using local tracking)
    public func isWatchingAddress(_ address: String) async throws -> Bool {
        Self.watchedAddressesLock.lock()
        defer { Self.watchedAddressesLock.unlock() }
        return Self.watchedAddresses.contains(address)
    }
    
    /// Verifies all addresses in a list are being watched
    public func verifyWatchedAddresses(_ addresses: [String]) async throws -> [String: Bool] {
        Self.watchedAddressesLock.lock()
        defer { Self.watchedAddressesLock.unlock() }
        
        var results: [String: Bool] = [:]
        for address in addresses {
            results[address] = Self.watchedAddresses.contains(address)
        }
        return results
    }
    
    /// Gets all watched addresses
    public func getWatchedAddresses() async throws -> Set<String> {
        Self.watchedAddressesLock.lock()
        defer { Self.watchedAddressesLock.unlock() }
        return Self.watchedAddresses
    }
    
    /// Clears the local watch tracking (does not affect actual watch items in SPV)
    public func clearLocalWatchTracking() {
        Self.watchedAddressesLock.lock()
        defer { Self.watchedAddressesLock.unlock() }
        Self.watchedAddresses.removeAll()
    }
}