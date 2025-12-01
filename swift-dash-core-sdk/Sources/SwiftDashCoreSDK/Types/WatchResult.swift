import Foundation

public struct WatchAddressResult {
    public let address: String
    public let success: Bool
    public let error: WatchAddressError?
    public let timestamp: Date
    public let retryCount: Int

    public init(address: String, success: Bool, error: WatchAddressError? = nil, timestamp: Date = Date(), retryCount: Int = 0) {
        self.address = address
        self.success = success
        self.error = error
        self.timestamp = timestamp
        self.retryCount = retryCount
    }
}
