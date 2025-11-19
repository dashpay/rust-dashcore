import Foundation
import os.log

public class WatchAddressRetryManager {
    private var retryQueue: [WatchRetryItem] = []
    private var retryTimer: Timer?
    private let maxRetries = 3
    private let retryDelay: TimeInterval = 5.0
    private let logger = Logger(subsystem: "com.dash.sdk", category: "WatchAddressRetryManager")
    private weak var client: SPVClient?

    struct WatchRetryItem {
        let address: String
        let accountId: String
        var retryCount: Int
        let firstAttempt: Date
    }

    public init(client: SPVClient) {
        self.client = client
    }

    deinit {
        retryTimer?.invalidate()
    }

    public func scheduleRetry(address: String, accountId: String) {
        let item = WatchRetryItem(
            address: address,
            accountId: accountId,
            retryCount: 0,
            firstAttempt: Date()
        )

        retryQueue.append(item)
        startRetryTimer()
    }

    private func startRetryTimer() {
        guard retryTimer == nil else { return }

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }

            self.retryTimer = Timer.scheduledTimer(withTimeInterval: self.retryDelay, repeats: true) { _ in
                Task {
                    await self.processRetryQueue()
                }
            }
        }
    }

    private func processRetryQueue() async {
        guard let client = client else {
            logger.error("Client is nil, cannot process retry queue")
            return
        }

        var remainingItems: [WatchRetryItem] = []

        for var item in retryQueue {
            if item.retryCount >= maxRetries {
                logger.error("Max retries exceeded for address: \(item.address)")
                continue
            }

            do {
                try await client.addWatchItem(type: .address, data: item.address)
                logger.info("Successfully watched address on retry: \(item.address)")
            } catch {
                item.retryCount += 1
                remainingItems.append(item)
                logger.warning("Retry \(item.retryCount) failed for address: \(item.address)")
            }
        }

        retryQueue = remainingItems

        if retryQueue.isEmpty {
            DispatchQueue.main.async { [weak self] in
                self?.retryTimer?.invalidate()
                self?.retryTimer = nil
            }
        }
    }

    public func getPendingRetries() -> [String] {
        return retryQueue.map { $0.address }
    }

    public func clearRetryQueue() {
        retryQueue.removeAll()
        retryTimer?.invalidate()
        retryTimer = nil
    }

    public func removeAddress(_ address: String) {
        retryQueue.removeAll { $0.address == address }

        if retryQueue.isEmpty {
            retryTimer?.invalidate()
            retryTimer = nil
        }
    }
}