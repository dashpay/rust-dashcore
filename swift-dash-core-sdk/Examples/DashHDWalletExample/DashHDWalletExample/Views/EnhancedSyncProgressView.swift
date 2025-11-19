import SwiftUI
import SwiftDashCoreSDK

struct EnhancedSyncProgressView: View {
    @EnvironmentObject private var walletService: WalletService
    @Environment(\.dismiss) private var dismiss

    @State private var hasStarted = false
    @State private var showStatistics = false
    @State private var useCallbackSync = true

    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                if let detailedProgress = walletService.detailedSyncProgress {
                    // Enhanced Progress Display
                    DetailedProgressContent(progress: detailedProgress)
                        .transition(.opacity.combined(with: .scale))
                } else if let legacyProgress = walletService.syncProgress {
                    // Fallback to legacy progress
                    LegacyProgressContent(progress: legacyProgress)
                        .transition(.opacity)
                } else if !hasStarted {
                    // Start Sync Options
                    StartSyncContent(
                        useCallbackSync: $useCallbackSync,
                        onStart: startSync
                    )
                } else {
                    // Loading
                    ProgressView("Initializing sync...")
                        .progressViewStyle(.circular)
                        .scaleEffect(1.5)
                }

                // Filter Sync Status Warning (if not available)
                if let syncProgress = walletService.syncProgress,
                   !syncProgress.filterSyncAvailable {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.orange)
                        Text("Compact filters not available - connected peers don't support BIP 157/158")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(.horizontal)
                    .padding(.vertical, 8)
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(8)
                }

                // Statistics Toggle
                if walletService.detailedSyncProgress != nil {
                    Button(showStatistics ? "Hide Statistics" : "Show Statistics") {
                        withAnimation {
                            showStatistics.toggle()
                        }
                    }
                    .buttonStyle(.bordered)
                }

                // Detailed Statistics
                if showStatistics, !walletService.syncStatistics.isEmpty {
                    DetailedStatisticsView(statistics: walletService.syncStatistics)
                        .transition(.asymmetric(
                            insertion: .move(edge: .bottom).combined(with: .opacity),
                            removal: .move(edge: .bottom).combined(with: .opacity)
                        ))
                }
            }
            .padding()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .navigationTitle("Blockchain Sync")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(walletService.isSyncing ? "Cancel" : "Close") {
                        if walletService.isSyncing {
                            walletService.stopSync()
                        }
                        dismiss()
                    }
                }

                if walletService.isSyncing {
                    ToolbarItem(placement: .primaryAction) {
                        Menu {
                            Button("Pause Sync", systemImage: "pause.circle") {
                                // Future: Implement pause functionality
                            }
                            .disabled(true)

                            Button("Cancel Sync", systemImage: "xmark.circle") {
                                walletService.stopSync()
                            }
                        } label: {
                            Image(systemName: "ellipsis.circle")
                        }
                    }
                }
            }
            .animation(.easeInOut, value: walletService.detailedSyncProgress?.percentage ?? 0)
            .animation(.easeInOut, value: showStatistics)
        }
        #if os(macOS)
        .frame(width: 700, height: showStatistics ? 700 : 600)
        #endif
    }

    private func startSync() {
        hasStarted = true
        Task {
            do {
                if useCallbackSync {
                    try await walletService.startSyncWithCallbacks()
                } else {
                    try await walletService.startSync()
                }
            } catch {
                print("Sync error: \(error)")
            }
        }
    }
}

// MARK: - Detailed Progress Content

struct DetailedProgressContent: View {
    let progress: DetailedSyncProgress

    var body: some View {
        VStack(spacing: 24) {
            // Stage Icon and Status
            VStack(spacing: 12) {
                Text(progress.stage.icon)
                    .font(.system(size: 80))
                    .symbolEffect(.pulse, isActive: progress.stage.isActive)

                Text(progress.stage.description)
                    .font(.title2)
                    .fontWeight(.semibold)

                Text(progress.stageMessage)
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }

            // Progress Circle
            CircularProgressView(
                progress: progress.percentage / 100.0,
                formattedPercentage: progress.formattedPercentage,
                speed: progress.formattedSpeed
            )
            .frame(width: 200, height: 200)

            // Block Progress
            VStack(spacing: 16) {
                HStack(spacing: 30) {
                    ProgressStatView(
                        title: "Current Height",
                        value: "\(progress.currentHeight)",
                        icon: "arrow.up.square"
                    )

                    ProgressStatView(
                        title: "Target Height",
                        value: "\(progress.totalHeight)",
                        icon: "flag.checkered"
                    )

                    ProgressStatView(
                        title: "Connected Peers",
                        value: "\(progress.connectedPeers)",
                        icon: "network"
                    )
                }

                // ETA and Duration
                HStack(spacing: 30) {
                    VStack(spacing: 4) {
                        Label("Time Remaining", systemImage: "clock")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(progress.formattedTimeRemaining)
                            .font(.headline)
                            .monospacedDigit()
                    }

                    VStack(spacing: 4) {
                        Label("Sync Duration", systemImage: "timer")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(progress.formattedSyncDuration)
                            .font(.headline)
                            .monospacedDigit()
                    }
                }
            }
            .padding()
            .background(Color(PlatformColor.secondarySystemBackground))
            .cornerRadius(12)
        }
    }
}

// MARK: - Circular Progress View

struct CircularProgressView: View {
    let progress: Double
    let formattedPercentage: String
    let speed: String

    var body: some View {
        ZStack {
            // Background circle
            Circle()
                .stroke(Color.gray.opacity(0.2), lineWidth: 20)

            // Progress circle
            Circle()
                .trim(from: 0, to: progress)
                .stroke(
                    LinearGradient(
                        colors: [.blue, .cyan],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    style: StrokeStyle(lineWidth: 20, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
                .animation(.easeInOut(duration: 0.5), value: progress)

            // Center content
            VStack(spacing: 8) {
                Text(formattedPercentage)
                    .font(.largeTitle)
                    .fontWeight(.bold)
                    .monospacedDigit()

                Text(speed)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}

// MARK: - Progress Stat View

struct ProgressStatView: View {
    let title: String
    let value: String
    let icon: String

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(.accentColor)

            Text(value)
                .font(.headline)
                .monospacedDigit()

            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Start Sync Content

struct StartSyncContent: View {
    @Binding var useCallbackSync: Bool
    let onStart: () -> Void

    var body: some View {
        VStack(spacing: 30) {
            Image(systemName: "arrow.triangle.2.circlepath.circle")
                .font(.system(size: 100))
                .foregroundColor(.accentColor)
                .symbolEffect(.pulse)

            VStack(spacing: 12) {
                Text("Ready to Sync")
                    .font(.largeTitle)
                    .fontWeight(.bold)

                Text("Synchronize your wallet with the Dash blockchain to see your latest balance and transactions")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 400)
            }

            // Sync Method Toggle
            VStack(spacing: 12) {
                Toggle("Use Callback-based Sync", isOn: $useCallbackSync)
                    .toggleStyle(.switch)
                    .frame(width: 250)

                Text(useCallbackSync ? "Real-time updates via callbacks" : "Stream-based async iteration")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding()
            .background(Color(PlatformColor.secondarySystemBackground))
            .cornerRadius(8)

            Button(action: onStart) {
                Label("Start Sync", systemImage: "play.circle.fill")
                    .font(.headline)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }
}

// MARK: - Legacy Progress Content

struct LegacyProgressContent: View {
    let progress: SyncProgress

    var body: some View {
        VStack(spacing: 20) {
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

            // Message
            if let message = progress.message {
                Text(message)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
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

// MARK: - Detailed Statistics View

struct DetailedStatisticsView: View {
    let statistics: [String: String]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Detailed Statistics", systemImage: "chart.line.uptrend.xyaxis")
                .font(.headline)
                .padding(.bottom, 8)

            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible()),
                GridItem(.flexible())
            ], spacing: 16) {
                ForEach(statistics.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(key)
                            .font(.caption)
                            .foregroundColor(.secondary)

                        Text(value)
                            .font(.body)
                            .fontWeight(.medium)
                            .monospacedDigit()
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(PlatformColor.tertiarySystemBackground))
                    .cornerRadius(8)
                }
            }
        }
        .padding()
        .background(Color(PlatformColor.secondarySystemBackground))
        .cornerRadius(12)
    }
}

// MARK: - Preview

struct EnhancedSyncProgressView_Previews: PreviewProvider {
    static var previews: some View {
        EnhancedSyncProgressView()
            .environmentObject(WalletService.shared)
    }
}