import Foundation
import Combine
import SwiftDashCoreSDK

@MainActor
class WalletViewModel: ObservableObject {
    @Published var isConnected = false
    @Published var syncProgress: SyncProgress?
    @Published var stats: SPVStats?
    @Published var watchedAddresses: Set<String> = []
    @Published var totalBalance = Balance()
    @Published var recentTransactions: [Transaction] = []
    @Published var showError = false
    @Published var errorMessage = ""

    private var sdk: DashSDK?
    private var cancellables = Set<AnyCancellable>()
    private var syncTask: Task<Void, Never>?

    init() {
        setupSDK()
    }

    deinit {
        syncTask?.cancel()
    }

    // MARK: - Setup

    private func setupSDK() {
        do {
            // Use testnet for example
            let config = SPVClientConfiguration.testnet()
            sdk = try DashSDK(configuration: config)

            // Setup event handling
            sdk?.eventPublisher
                .receive(on: DispatchQueue.main)
                .sink { [weak self] event in
                    self?.handleEvent(event)
                }
                .store(in: &cancellables)

        } catch {
            showError(error)
        }
    }

    // MARK: - Connection

    func connect() async {
        do {
            guard let sdk = sdk else { return }

            try await sdk.connect()
            isConnected = true

            // Start monitoring
            startMonitoring()

            // Load initial data
            await refreshData()

        } catch {
            showError(error)
        }
    }

    func disconnect() async {
        do {
            guard let sdk = sdk else { return }

            stopMonitoring()
            try await sdk.disconnect()
            isConnected = false

            // Clear data
            syncProgress = nil
            stats = nil

        } catch {
            showError(error)
        }
    }

    // MARK: - Wallet Operations

    func watchAddress(_ address: String, label: String?) async {
        do {
            guard let sdk = sdk else { return }

            try await sdk.watchAddress(address, label: label)
            watchedAddresses.insert(address)

            // Refresh balance
            await updateBalance()

        } catch {
            showError(error)
        }
    }

    func unwatchAddress(_ address: String) async {
        do {
            guard let sdk = sdk else { return }

            try await sdk.unwatchAddress(address)
            watchedAddresses.remove(address)

            // Refresh balance
            await updateBalance()

        } catch {
            showError(error)
        }
    }

    func sendTransaction(to address: String, amount: UInt64) async {
        do {
            guard let sdk = sdk else { return }

            let txid = try await sdk.sendTransaction(
                to: address,
                amount: amount
            )

            // Show success
            errorMessage = "Transaction sent! TXID: \(txid)"
            showError = true

            // Refresh data
            await refreshData()

        } catch {
            showError(error)
        }
    }

    func estimateFee(to address: String, amount: UInt64) async -> UInt64 {
        do {
            guard let sdk = sdk else { return 0 }

            return try await sdk.estimateFee(
                to: address,
                amount: amount
            )

        } catch {
            return 0
        }
    }

    // MARK: - Data Management

    func refreshData() async {
        await updateBalance()
        await updateTransactions()
        await updateStats()
    }

    private func updateBalance() async {
        do {
            guard let sdk = sdk else { return }

            totalBalance = try await sdk.getBalance()

        } catch {
            print("Failed to update balance: \(error)")
        }
    }

    private func updateTransactions() async {
        do {
            guard let sdk = sdk else { return }

            recentTransactions = try await sdk.getTransactions(limit: 20)

        } catch {
            print("Failed to update transactions: \(error)")
        }
    }

    private func updateStats() async {
        guard let sdk = sdk else { return }

        stats = sdk.stats
        syncProgress = sdk.syncProgress
    }

    func exportWallet() async {
        do {
            guard let sdk = sdk else { return }

            let exportData = try sdk.exportWalletData()

            // In a real app, you would save this to a file
            errorMessage = "Wallet data exported (\(exportData.formattedSize))"
            showError = true

        } catch {
            showError(error)
        }
    }

    // MARK: - Monitoring

    private func startMonitoring() {
        syncTask = Task {
            while !Task.isCancelled {
                await updateStats()

                try? await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
            }
        }
    }

    private func stopMonitoring() {
        syncTask?.cancel()
        syncTask = nil
    }

    // MARK: - Event Handling

    private func handleEvent(_ event: SPVEvent) {
        switch event {
        case .blockReceived(let height, let hash):
            print("New block: \(height) - \(hash)")

        case .transactionReceived(let txid, let confirmed):
            print("Transaction: \(txid) - Confirmed: \(confirmed)")
            Task {
                await updateTransactions()
            }

        case .balanceUpdated(let balance):
            self.totalBalance = balance

        case .syncProgressUpdated(let progress):
            self.syncProgress = progress

        case .connectionStatusChanged(let connected):
            self.isConnected = connected

        case .error(let error):
            showError(error)
        }
    }

    // MARK: - Error Handling

    private func showError(_ error: Error) {
        if let dashError = error as? DashSDKError {
            errorMessage = dashError.localizedDescription
        } else {
            errorMessage = error.localizedDescription
        }
        showError = true
    }
}
