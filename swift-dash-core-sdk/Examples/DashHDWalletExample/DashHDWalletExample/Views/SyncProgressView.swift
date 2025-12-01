import SwiftUI
import SwiftDashCoreSDK

struct SyncProgressView: View {
    @EnvironmentObject private var walletService: WalletService
    @Environment(\.dismiss) private var dismiss

    @State private var hasStarted = false

    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                if let progress = walletService.syncProgress {
                    // Progress Info
                    VStack(spacing: 16) {
                        // Status Icon
                        Image(systemName: statusIcon(for: progress.status))
                            .font(.system(size: 60))
                            .foregroundColor(statusColor(for: progress.status))
                            .symbolEffect(.pulse, isActive: progress.status.isActive)

                        // Status Text
                        Text(progress.status.description)
                            .font(.title2)
                            .fontWeight(.medium)

                        // Progress Bar
                        VStack(alignment: .leading, spacing: 8) {
                            ProgressView(value: progress.progress)
                                .progressViewStyle(.linear)

                            HStack {
                                Text("\(progress.percentageComplete)%")
                                    .monospacedDigit()

                                Spacer()

                                if let eta = progress.formattedTimeRemaining {
                                    Text("ETA: \(eta)")
                                }
                            }
                            .font(.caption)
                            .foregroundColor(.secondary)
                        }
                        .frame(maxWidth: 400)

                        // Block Progress
                        BlockProgressView(
                            current: progress.currentHeight,
                            total: progress.totalHeight,
                            remaining: progress.blocksRemaining
                        )

                        // Message
                        if let message = progress.message {
                            Text(message)
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                        }
                    }
                } else if !hasStarted {
                    // Start Sync
                    VStack(spacing: 20) {
                        Image(systemName: "arrow.triangle.2.circlepath.circle")
                            .font(.system(size: 80))
                            .foregroundColor(.blue)

                        Text("Ready to Sync")
                            .font(.title2)
                            .fontWeight(.medium)

                        Text("This will synchronize your wallet with the Dash blockchain")
                            .font(.body)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: 300)

                        Button("Start Sync") {
                            Task {
                                do {
                                    // First test if we can get stats
                                    print("🧪 Testing SDK stats before sync...")
                                    if let stats = walletService.sdk?.stats {
                                        print("📊 Stats: connected peers: \(stats.connectedPeers), headers: \(stats.headerHeight)")
                                    } else {
                                        print("⚠️ No stats available")
                                    }

                                    startSync()
                                } catch {
                                    print("Failed to test SDK: \(error)")
                                }
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                    }
                } else {
                    // Loading
                    ProgressView("Starting sync...")
                        .progressViewStyle(.circular)
                }

                // Network Stats
                if let stats = walletService.sdk?.stats {
                    NetworkStatsView(stats: stats)
                        .padding(.top)
                }
            }
            .padding()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .navigationTitle("Blockchain Sync")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(walletService.isSyncing ? "Stop" : "Close") {
                        if walletService.isSyncing {
                            walletService.stopSync()
                        }
                        dismiss()
                    }
                }
            }
        }
        #if os(macOS)
        .frame(width: 600, height: 500)
        #endif
    }

    private func startSync() {
        hasStarted = true
        Task {
            try? await walletService.startSync()
        }
    }

    private func statusIcon(for status: SyncStatus) -> String {
        switch status {
        case .idle:
            return "circle"
        case .connecting:
            return "network"
        case .downloadingHeaders:
            return "arrow.down.circle"
        case .downloadingFilters:
            return "line.3.horizontal.decrease.circle"
        case .scanning:
            return "magnifyingglass.circle"
        case .synced:
            return "checkmark.circle.fill"
        case .error:
            return "exclamationmark.triangle.fill"
        }
    }

    private func statusColor(for status: SyncStatus) -> Color {
        switch status {
        case .idle:
            return .gray
        case .connecting, .downloadingHeaders, .downloadingFilters, .scanning:
            return .blue
        case .synced:
            return .green
        case .error:
            return .red
        }
    }
}

// MARK: - Block Progress View

struct BlockProgressView: View {
    let current: UInt32
    let total: UInt32
    let remaining: UInt32

    var body: some View {
        VStack(spacing: 12) {
            HStack(spacing: 20) {
                BlockStatView(
                    label: "Current Block",
                    value: "\(current)",
                    icon: "cube"
                )

                BlockStatView(
                    label: "Total Blocks",
                    value: "\(total)",
                    icon: "cube.fill"
                )

                BlockStatView(
                    label: "Remaining",
                    value: "\(remaining)",
                    icon: "clock"
                )
            }
        }
        .padding()
        .background(Color.secondary.opacity(0.1))
        .cornerRadius(8)
    }
}

struct BlockStatView: View {
    let label: String
    let value: String
    let icon: String

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(.blue)

            Text(value)
                .font(.headline)
                .monospacedDigit()

            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Network Stats View

struct NetworkStatsView: View {
    let stats: SPVStats

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Network Statistics")
                .font(.caption)
                .foregroundColor(.secondary)

            HStack(spacing: 20) {
                StatItemView(
                    label: "Peers",
                    value: "\(stats.connectedPeers)/\(stats.totalPeers)"
                )

                StatItemView(
                    label: "Downloaded",
                    value: stats.formattedBytesReceived
                )

                StatItemView(
                    label: "Uploaded",
                    value: stats.formattedBytesSent
                )

                StatItemView(
                    label: "Uptime",
                    value: stats.formattedUptime
                )
            }
        }
        .padding()
        .background(Color.secondary.opacity(0.05))
        .cornerRadius(8)
    }
}

struct StatItemView: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption2)
                .foregroundColor(.secondary)

            Text(value)
                .font(.caption)
                .fontWeight(.medium)
        }
    }
}
