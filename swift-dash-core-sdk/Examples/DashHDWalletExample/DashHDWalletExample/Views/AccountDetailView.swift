import SwiftUI
import SwiftData
import SwiftDashCoreSDK

struct AccountDetailView: View {
    @EnvironmentObject private var walletService: WalletService
    @Environment(\.modelContext) private var modelContext

    let account: HDAccount
    @State private var selectedTab = 0
    @State private var showReceiveAddress = false
    @State private var showSendTransaction = false

    var body: some View {
        VStack(spacing: 0) {
            // Account Header
            AccountHeaderView(
                account: account,
                onReceive: { showReceiveAddress = true },
                onSend: { showSendTransaction = true }
            )

            Divider()

            // Tab View
            TabView(selection: $selectedTab) {
                // Transactions Tab
                TransactionsTabView(account: account)
                    .tabItem {
                        Label("Transactions", systemImage: "list.bullet")
                    }
                    .tag(0)

                // Addresses Tab
                AddressesTabView(account: account)
                    .tabItem {
                        Label("Addresses", systemImage: "qrcode")
                    }
                    .tag(1)

                // UTXOs Tab
                UTXOsTabView(account: account)
                    .tabItem {
                        Label("UTXOs", systemImage: "bitcoinsign.circle")
                    }
                    .tag(2)
            }
        }
        .sheet(isPresented: $showReceiveAddress) {
            ReceiveAddressView(account: account)
        }
        .sheet(isPresented: $showSendTransaction) {
            SendTransactionView(account: account)
        }
    }
}

// MARK: - Account Header View

struct AccountHeaderView: View {
    @EnvironmentObject private var walletService: WalletService
    let account: HDAccount
    let onReceive: () -> Void
    let onSend: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            // Account Info
            VStack(spacing: 8) {
                Text(account.displayName)
                    .font(.title2)
                    .fontWeight(.semibold)

                Text(account.derivationPath)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .fontDesign(.monospaced)
            }

            // Balance
            if let balance = account.balance {
                BalanceView(balance: balance)
            }

            // Mempool Status
            if walletService.mempoolTransactionCount > 0 {
                MempoolStatusView(count: walletService.mempoolTransactionCount)
            }

            // Watch Status
            WatchStatusView(status: walletService.watchVerificationStatus)

            // Watch Errors
            if !walletService.watchAddressErrors.isEmpty || walletService.pendingWatchCount > 0 {
                WatchErrorsView(
                    errors: walletService.watchAddressErrors,
                    pendingCount: walletService.pendingWatchCount
                )
            }

            // Action Buttons
            HStack(spacing: 16) {
                Button(action: onReceive) {
                    Label("Receive", systemImage: "arrow.down.circle.fill")
                }
                .buttonStyle(.borderedProminent)

                Button(action: onSend) {
                    Label("Send", systemImage: "arrow.up.circle.fill")
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(PlatformColor.controlBackground)
    }
}

// MARK: - Balance View

struct BalanceView: View {
    let balance: Balance

    var body: some View {
        VStack(spacing: 8) {
            Text(balance.formattedTotal)
                .font(.system(size: 32, weight: .medium, design: .monospaced))

            HStack(spacing: 20) {
                BalanceComponent(
                    label: "Available",
                    amount: formatDash(balance.available),
                    color: .green
                )

                if balance.pending > 0 {
                    BalanceComponent(
                        label: "Pending",
                        amount: formatDash(balance.pending),
                        color: .orange
                    )
                }

                if balance.instantLocked > 0 {
                    BalanceComponent(
                        label: "InstantSend",
                        amount: formatDash(balance.instantLocked),
                        color: .blue
                    )
                }

                if balance.mempool > 0 {
                    BalanceComponent(
                        label: "Mempool",
                        amount: formatDash(balance.mempool),
                        color: .purple
                    )
                }
            }
        }
    }

    private func formatDash(_ satoshis: UInt64) -> String {
        let dash = Double(satoshis) / 100_000_000.0
        return String(format: "%.8f", dash)
    }
}

struct BalanceComponent: View {
    let label: String
    let amount: String
    let color: Color

    var body: some View {
        VStack(spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)

            Text(amount)
                .font(.system(.body, design: .monospaced))
                .foregroundColor(color)
        }
    }
}

// MARK: - Transactions Tab

struct TransactionsTabView: View {
    let account: HDAccount
    @State private var searchText = ""
    @Environment(\.modelContext) private var modelContext

    var filteredTransactions: [SwiftDashCoreSDK.Transaction] {
        // Fetch transactions by IDs
        let txIds = account.transactionIds
        let descriptor = FetchDescriptor<SwiftDashCoreSDK.Transaction>(
            predicate: #Predicate { transaction in
                txIds.contains(transaction.txid)
            },
            sortBy: [SortDescriptor(\.timestamp, order: .reverse)]
        )

        let allTransactions = (try? modelContext.fetch(descriptor)) ?? []

        if searchText.isEmpty {
            return allTransactions
        } else {
            return allTransactions.filter { tx in
                tx.txid.localizedCaseInsensitiveContains(searchText)
            }
        }
    }

    var body: some View {
        VStack {
            if account.transactionIds.isEmpty {
                EmptyStateView(
                    icon: "list.bullet.rectangle",
                    title: "No Transactions",
                    message: "Transactions will appear here once you receive or send funds"
                )
            } else {
                List {
                    ForEach(filteredTransactions) { transaction in
                        TransactionRowView(transaction: transaction)
                    }
                }
                .searchable(text: $searchText, prompt: "Search transactions")
            }
        }
    }
}

// MARK: - Addresses Tab

struct AddressesTabView: View {
    @EnvironmentObject private var walletService: WalletService
    let account: HDAccount
    @State private var showingExternal = true

    var addresses: [HDWatchedAddress] {
        showingExternal ? account.externalAddresses : account.internalAddresses
    }

    var body: some View {
        VStack {
            // Address Type Picker
            Picker("Address Type", selection: $showingExternal) {
                Text("Receive").tag(true)
                Text("Change").tag(false)
            }
            .pickerStyle(SegmentedPickerStyle())
            .padding()

            if addresses.isEmpty {
                EmptyStateView(
                    icon: "qrcode",
                    title: "No Addresses",
                    message: "Generate addresses to receive funds"
                )
            } else {
                List {
                    ForEach(addresses) { address in
                        AddressRowView(address: address)
                    }
                }
            }

            // Generate New Address Button
            HStack {
                Spacer()
                Button("Generate New Address") {
                    generateNewAddress()
                }
                .padding()
            }
        }
    }

    private func generateNewAddress() {
        Task {
            do {
                _ = try walletService.generateNewAddress(
                    for: account,
                    isChange: !showingExternal
                )
            } catch {
                print("Error generating address: \(error)")
            }
        }
    }
}

// MARK: - UTXOs Tab

struct UTXOsTabView: View {
    let account: HDAccount
    @Environment(\.modelContext) private var modelContext

    var utxos: [UTXO] {
        // Collect all UTXO outpoints from addresses
        let allOutpoints = account.addresses.flatMap { $0.utxoOutpoints }

        // Fetch UTXOs by outpoints
        let descriptor = FetchDescriptor<SwiftDashCoreSDK.UTXO>(
            predicate: #Predicate { utxo in
                allOutpoints.contains(utxo.outpoint) && !utxo.isSpent
            }
        )

        return (try? modelContext.fetch(descriptor)) ?? []
    }

    var totalValue: UInt64 {
        utxos.reduce(0) { $0 + $1.value }
    }

    var body: some View {
        VStack {
            if utxos.isEmpty {
                EmptyStateView(
                    icon: "bitcoinsign.circle",
                    title: "No UTXOs",
                    message: "Unspent outputs will appear here"
                )
            } else {
                VStack {
                    // Summary
                    HStack {
                        Text("\(utxos.count) UTXOs")
                            .font(.headline)
                        Spacer()
                        Text("Total: \(formatDash(totalValue))")
                            .font(.headline)
                            .monospacedDigit()
                    }
                    .padding()

                    // UTXO List
                    List {
                        ForEach(utxos.sorted { $0.value > $1.value }) { utxo in
                            UTXORowView(utxo: utxo)
                        }
                    }
                }
            }
        }
    }

    private func formatDash(_ satoshis: UInt64) -> String {
        let dash = Double(satoshis) / 100_000_000.0
        return String(format: "%.8f DASH", dash)
    }
}

// MARK: - Empty State View

struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: icon)
                .font(.system(size: 60))
                .foregroundColor(.secondary)

            Text(title)
                .font(.title3)
                .fontWeight(.medium)

            Text(message)
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Row Views

struct TransactionRowView: View {
    let transaction: SwiftDashCoreSDK.Transaction

    var body: some View {
        HStack {
            // Direction Icon
            Image(systemName: transaction.amount >= 0 ? "arrow.down.circle.fill" : "arrow.up.circle.fill")
                .foregroundColor(transaction.amount >= 0 ? .green : .red)
                .font(.title2)

            // Transaction Info
            VStack(alignment: .leading, spacing: 4) {
                Text(transaction.txid)
                    .font(.caption)
                    .fontDesign(.monospaced)
                    .lineLimit(1)
                    .truncationMode(.middle)

                Text(transaction.timestamp, style: .relative)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            // Amount and Status
            VStack(alignment: .trailing, spacing: 4) {
                Text(formatAmount(transaction.amount))
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(transaction.amount >= 0 ? .green : .red)

                if transaction.isInstantLocked {
                    Label("InstantSend", systemImage: "bolt.fill")
                        .font(.caption2)
                        .foregroundColor(.blue)
                } else if transaction.confirmations > 0 {
                    Text("\(transaction.confirmations) conf")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                } else {
                    Text("Pending")
                        .font(.caption2)
                        .foregroundColor(.orange)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private func formatAmount(_ satoshis: Int64) -> String {
        let dash = Double(abs(satoshis)) / 100_000_000.0
        let sign = satoshis >= 0 ? "+" : "-"
        return "\(sign)\(String(format: "%.8f", dash))"
    }
}

struct AddressRowView: View {
    let address: HDWatchedAddress
    @State private var isCopied = false

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(address.address)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)

                    if address.transactionIds.count > 0 {
                        Text("(\(address.transactionIds.count) tx)")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }

                Text("Index: \(address.index)")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            Spacer()

            if let balance = address.balance {
                Text(balance.formattedTotal)
                    .font(.caption)
                    .monospacedDigit()
                    .foregroundColor(.secondary)
            }

            Button(action: copyAddress) {
                Image(systemName: isCopied ? "checkmark" : "doc.on.doc")
                    .font(.caption)
            }
            .buttonStyle(.plain)
        }
        .padding(.vertical, 4)
    }

    private func copyAddress() {
        Clipboard.copy(address.address)

        withAnimation {
            isCopied = true
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            withAnimation {
                isCopied = false
            }
        }
    }
}

struct UTXORowView: View {
    let utxo: UTXO

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(utxo.outpoint)
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)

                HStack {
                    Text("Height: \(utxo.height)")
                    Text("•")
                    Text("\(utxo.confirmations) conf")
                }
                .font(.caption2)
                .foregroundColor(.secondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 4) {
                Text(utxo.formattedValue)
                    .font(.system(.body, design: .monospaced))

                if utxo.isInstantLocked {
                    Text("InstantSend")
                        .font(.caption2)
                        .foregroundColor(.blue)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Mempool Status View

struct MempoolStatusView: View {
    let count: Int

    var body: some View {
        HStack {
            Image(systemName: "clock.arrow.circlepath")
                .foregroundColor(.purple)

            Text("\(count) unconfirmed transaction\(count == 1 ? "" : "s") in mempool")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(Color.purple.opacity(0.1))
        .cornerRadius(8)
    }
}