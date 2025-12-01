import SwiftUI
import SwiftDashCoreSDK

struct ContentView: View {
    @StateObject private var viewModel = WalletViewModel()
    @State private var showAddAddress = false
    @State private var showSendTransaction = false

    var body: some View {
        NavigationView {
            List {
                // Connection Status
                ConnectionSection(viewModel: viewModel)

                // Balance Section
                if viewModel.isConnected {
                    BalanceSection(balance: viewModel.totalBalance)

                    // Sync Progress
                    if let progress = viewModel.syncProgress {
                        SyncProgressSection(progress: progress)
                    }

                    // Watched Addresses
                    WatchedAddressesSection(
                        addresses: Array(viewModel.watchedAddresses),
                        onAdd: { showAddAddress = true },
                        onRemove: viewModel.unwatchAddress
                    )

                    // Recent Transactions
                    TransactionsSection(transactions: viewModel.recentTransactions)
                }
            }
            .navigationTitle("Dash Wallet")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button("Add Address") {
                            showAddAddress = true
                        }

                        Button("Send Transaction") {
                            showSendTransaction = true
                        }

                        Button("Refresh") {
                            Task {
                                await viewModel.refreshData()
                            }
                        }

                        Divider()

                        Button("Export Wallet Data") {
                            Task {
                                await viewModel.exportWallet()
                            }
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .disabled(!viewModel.isConnected)
                }
            }
        }
        .sheet(isPresented: $showAddAddress) {
            AddAddressView(viewModel: viewModel)
        }
        .sheet(isPresented: $showSendTransaction) {
            SendTransactionView(viewModel: viewModel)
        }
        .alert("Error", isPresented: $viewModel.showError) {
            Button("OK") { }
        } message: {
            Text(viewModel.errorMessage)
        }
    }
}

// MARK: - Connection Section

struct ConnectionSection: View {
    @ObservedObject var viewModel: WalletViewModel

    var body: some View {
        Section("Connection") {
            HStack {
                Text("Status")
                Spacer()
                if viewModel.isConnected {
                    Label("Connected", systemImage: "circle.fill")
                        .foregroundColor(.green)
                } else {
                    Label("Disconnected", systemImage: "circle")
                        .foregroundColor(.red)
                }
            }

            if viewModel.isConnected {
                if let stats = viewModel.stats {
                    HStack {
                        Text("Peers")
                        Spacer()
                        Text("\(stats.connectedPeers)")
                    }

                    HStack {
                        Text("Block Height")
                        Spacer()
                        Text("\(stats.headerHeight)")
                    }
                }
            } else {
                Button("Connect") {
                    Task {
                        await viewModel.connect()
                    }
                }
            }
        }
    }
}

// MARK: - Balance Section

struct BalanceSection: View {
    let balance: Balance

    var body: some View {
        Section("Balance") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Total")
                        .font(.headline)
                    Spacer()
                    Text(balance.formattedTotal)
                        .font(.headline)
                        .monospacedDigit()
                }

                HStack {
                    Text("Available")
                        .foregroundColor(.secondary)
                    Spacer()
                    Text(formatDash(balance.available))
                        .foregroundColor(.secondary)
                        .monospacedDigit()
                }

                if balance.pending > 0 {
                    HStack {
                        Text("Pending")
                            .foregroundColor(.orange)
                        Spacer()
                        Text(balance.formattedPending)
                            .foregroundColor(.orange)
                            .monospacedDigit()
                    }
                }

                if balance.instantLocked > 0 {
                    HStack {
                        Text("InstantSend")
                            .foregroundColor(.blue)
                        Spacer()
                        Text(balance.formattedInstantLocked)
                            .foregroundColor(.blue)
                            .monospacedDigit()
                    }
                }
            }
            .padding(.vertical, 4)
        }
    }

    private func formatDash(_ satoshis: UInt64) -> String {
        let dash = Double(satoshis) / 100_000_000.0
        return String(format: "%.8f DASH", dash)
    }
}

// MARK: - Sync Progress Section

struct SyncProgressSection: View {
    let progress: SyncProgress

    var body: some View {
        Section("Sync Progress") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(progress.status.description)
                    Spacer()
                    Text("\(progress.percentageComplete)%")
                }

                ProgressView(value: progress.progress)

                HStack {
                    Text("Block \(progress.currentHeight) of \(progress.totalHeight)")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Spacer()

                    if let eta = progress.formattedTimeRemaining {
                        Text("ETA: \(eta)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .padding(.vertical, 4)
        }
    }
}

// MARK: - Watched Addresses Section

struct WatchedAddressesSection: View {
    let addresses: [String]
    let onAdd: () -> Void
    let onRemove: (String) async -> Void

    var body: some View {
        Section("Watched Addresses") {
            if addresses.isEmpty {
                Text("No addresses watched")
                    .foregroundColor(.secondary)
            } else {
                ForEach(addresses, id: \.self) { address in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(shortenAddress(address))
                                .font(.system(.body, design: .monospaced))
                        }
                        Spacer()
                    }
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) {
                            Task {
                                await onRemove(address)
                            }
                        } label: {
                            Label("Remove", systemImage: "trash")
                        }
                    }
                }
            }

            Button(action: onAdd) {
                Label("Add Address", systemImage: "plus.circle")
            }
        }
    }

    private func shortenAddress(_ address: String) -> String {
        guard address.count > 12 else { return address }
        let prefix = address.prefix(8)
        let suffix = address.suffix(6)
        return "\(prefix)...\(suffix)"
    }
}

// MARK: - Transactions Section

struct TransactionsSection: View {
    let transactions: [Transaction]

    var body: some View {
        Section("Recent Transactions") {
            if transactions.isEmpty {
                Text("No transactions")
                    .foregroundColor(.secondary)
            } else {
                ForEach(transactions, id: \.txid) { transaction in
                    TransactionRow(transaction: transaction)
                }
            }
        }
    }
}

struct TransactionRow: View {
    let transaction: Transaction

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(shortenTxid(transaction.txid))
                    .font(.system(.caption, design: .monospaced))

                Text(transaction.timestamp, style: .relative)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 4) {
                Text(formatAmount(transaction.amount))
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(transaction.amount >= 0 ? .green : .red)

                StatusBadge(status: transaction.status)
            }
        }
        .padding(.vertical, 2)
    }

    private func shortenTxid(_ txid: String) -> String {
        guard txid.count > 12 else { return txid }
        let prefix = txid.prefix(6)
        let suffix = txid.suffix(4)
        return "\(prefix)...\(suffix)"
    }

    private func formatAmount(_ satoshis: Int64) -> String {
        let dash = Double(abs(satoshis)) / 100_000_000.0
        let sign = satoshis >= 0 ? "+" : "-"
        return "\(sign)\(String(format: "%.8f", dash))"
    }
}

struct StatusBadge: View {
    let status: TransactionStatus

    var body: some View {
        Text(status.description)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(backgroundColor)
            .foregroundColor(.white)
            .cornerRadius(4)
    }

    private var backgroundColor: Color {
        switch status {
        case .pending:
            return .orange
        case .confirming:
            return .yellow
        case .confirmed:
            return .green
        case .instantLocked:
            return .blue
        }
    }
}

// MARK: - Add Address View

struct AddAddressView: View {
    @ObservedObject var viewModel: WalletViewModel
    @Environment(\.dismiss) var dismiss

    @State private var address = ""
    @State private var label = ""

    var body: some View {
        NavigationView {
            Form {
                Section("Address Details") {
                    TextField("Dash Address", text: $address)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)

                    TextField("Label (Optional)", text: $label)
                }

                Section {
                    Button("Add Address") {
                        Task {
                            await viewModel.watchAddress(address, label: label.isEmpty ? nil : label)
                            dismiss()
                        }
                    }
                    .disabled(address.isEmpty)
                }
            }
            .navigationTitle("Add Address")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
    }
}

// MARK: - Send Transaction View

struct SendTransactionView: View {
    @ObservedObject var viewModel: WalletViewModel
    @Environment(\.dismiss) var dismiss

    @State private var recipientAddress = ""
    @State private var amount = ""
    @State private var estimatedFee: UInt64 = 0

    var body: some View {
        NavigationView {
            Form {
                Section("Transaction Details") {
                    TextField("Recipient Address", text: $recipientAddress)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)

                    TextField("Amount (DASH)", text: $amount)
                        .keyboardType(.decimalPad)
                        .onChange(of: amount) { _ in
                            updateEstimatedFee()
                        }
                }

                Section("Fee") {
                    HStack {
                        Text("Estimated Fee")
                        Spacer()
                        Text(formatDash(estimatedFee))
                    }
                }

                Section {
                    Button("Send Transaction") {
                        Task {
                            await sendTransaction()
                        }
                    }
                    .disabled(recipientAddress.isEmpty || amount.isEmpty)
                }
            }
            .navigationTitle("Send Transaction")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
    }

    private func updateEstimatedFee() {
        guard let dashAmount = Double(amount) else { return }
        let satoshis = UInt64(dashAmount * 100_000_000)

        Task {
            estimatedFee = await viewModel.estimateFee(
                to: recipientAddress,
                amount: satoshis
            )
        }
    }

    private func sendTransaction() async {
        guard let dashAmount = Double(amount) else { return }
        let satoshis = UInt64(dashAmount * 100_000_000)

        await viewModel.sendTransaction(
            to: recipientAddress,
            amount: satoshis
        )

        dismiss()
    }

    private func formatDash(_ satoshis: UInt64) -> String {
        let dash = Double(satoshis) / 100_000_000.0
        return String(format: "%.8f DASH", dash)
    }
}
