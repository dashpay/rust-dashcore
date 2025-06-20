import SwiftUI
import SwiftData

struct WalletDetailView: View {
    @EnvironmentObject private var walletService: WalletService
    @Environment(\.modelContext) private var modelContext
    
    let wallet: HDWallet
    @State private var selectedAccount: HDAccount?
    @State private var showCreateAccount = false
    @State private var showSyncProgress = false
    @State private var isConnecting = false
    
    var body: some View {
        #if os(iOS)
        Group {
            if wallet.name.isEmpty {
                ContentUnavailableView {
                    Label("Wallet Error", systemImage: "exclamationmark.triangle")
                } description: {
                    Text("Unable to load wallet data")
                }
            } else {
                AccountListView(
                    wallet: wallet,
                    selectedAccount: $selectedAccount,
                    onCreateAccount: { showCreateAccount = true }
                )
            }
        }
        .navigationTitle(wallet.name.isEmpty ? "Error" : wallet.name)
        .navigationBarTitleDisplayMode(.large)
        .toolbar {
            ToolbarItemGroup {
                // Connection Status
                ConnectionStatusView(
                    isConnected: walletService.isConnected && walletService.activeWallet == wallet,
                    isSyncing: walletService.isSyncing
                )
                
                // Sync Button
                if walletService.isConnected && walletService.activeWallet == wallet {
                    Button(action: { showSyncProgress = true }) {
                        Label("Sync", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(walletService.isSyncing)
                } else {
                    Button(action: connectWallet) {
                        Label("Connect", systemImage: "link")
                    }
                    .disabled(isConnecting)
                }
            }
        }
        .sheet(isPresented: $showCreateAccount) {
            CreateAccountView(wallet: wallet) { account in
                selectedAccount = account
            }
        }
        .sheet(isPresented: $showSyncProgress) {
            SyncProgressView()
        }
        .onAppear {
            if selectedAccount == nil {
                selectedAccount = wallet.accounts.first
            }
        }
        #else
        HSplitView {
            // Account List
            AccountListView(
                wallet: wallet,
                selectedAccount: $selectedAccount,
                onCreateAccount: { showCreateAccount = true }
            )
            .frame(minWidth: 200, idealWidth: 250)
            
            // Account Detail
            if let account = selectedAccount {
                AccountDetailView(account: account)
            } else {
                EmptyAccountView()
            }
        }
        .navigationTitle(wallet.name)
        .navigationSubtitle(wallet.displayNetwork)
        .toolbar {
            ToolbarItemGroup {
                // Connection Status
                ConnectionStatusView(
                    isConnected: walletService.isConnected && walletService.activeWallet == wallet,
                    isSyncing: walletService.isSyncing
                )
                
                // Sync Button
                if walletService.isConnected && walletService.activeWallet == wallet {
                    Button(action: { showSyncProgress = true }) {
                        Label("Sync", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(walletService.isSyncing)
                } else {
                    Button(action: connectWallet) {
                        Label("Connect", systemImage: "link")
                    }
                    .disabled(isConnecting)
                }
            }
        }
        .sheet(isPresented: $showCreateAccount) {
            CreateAccountView(wallet: wallet) { account in
                selectedAccount = account
            }
        }
        .sheet(isPresented: $showSyncProgress) {
            SyncProgressView()
        }
        .onAppear {
            if selectedAccount == nil {
                selectedAccount = wallet.accounts.first
            }
        }
        #endif
    }
    
    private func connectWallet() {
        guard let firstAccount = wallet.accounts.first else { return }
        
        isConnecting = true
        Task {
            do {
                try await walletService.connect(wallet: wallet, account: firstAccount)
                selectedAccount = firstAccount
            } catch {
                print("Connection error: \(error)")
            }
            isConnecting = false
        }
    }
}

// MARK: - Account List View

struct AccountListView: View {
    let wallet: HDWallet
    @Binding var selectedAccount: HDAccount?
    let onCreateAccount: () -> Void
    
    var body: some View {
        #if os(iOS)
        List {
            Section("Accounts") {
                ForEach(wallet.accounts.sorted { $0.accountIndex < $1.accountIndex }) { account in
                    NavigationLink(destination: AccountDetailView(account: account)) {
                        AccountRowView(account: account)
                    }
                }
            }
            
            Section {
                Button(action: onCreateAccount) {
                    Label("Add Account", systemImage: "plus.circle")
                }
            }
        }
        .listStyle(.insetGrouped)
        #else
        List(selection: $selectedAccount) {
            Section("Accounts") {
                ForEach(wallet.accounts.sorted { $0.accountIndex < $1.accountIndex }) { account in
                    AccountRowView(account: account)
                        .tag(account)
                }
            }
            
            Section {
                Button(action: onCreateAccount) {
                    Label("Add Account", systemImage: "plus.circle")
                }
            }
        }
        .listStyle(SidebarListStyle())
        #endif
    }
}

// MARK: - Account Row View

struct AccountRowView: View {
    let account: HDAccount
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(account.displayName)
                .font(.headline)
            
            Text(account.derivationPath)
                .font(.caption)
                .foregroundColor(.secondary)
                .fontDesign(.monospaced)
            
            if let balance = account.balance {
                Text(balance.formattedTotal)
                    .font(.caption)
                    .monospacedDigit()
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Empty Account View

struct EmptyAccountView: View {
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "person.crop.circle.dashed")
                .font(.system(size: 80))
                .foregroundColor(.secondary)
            
            Text("No Account Selected")
                .font(.title2)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Connection Status View

struct ConnectionStatusView: View {
    let isConnected: Bool
    let isSyncing: Bool
    
    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
            
            Text(statusText)
                .font(.caption)
                .foregroundColor(.secondary)
            
            if isSyncing {
                ProgressView()
                    .scaleEffect(0.7)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Color.secondary.opacity(0.1))
        .cornerRadius(6)
    }
    
    private var statusColor: Color {
        if isSyncing {
            return .orange
        } else if isConnected {
            return .green
        } else {
            return .red
        }
    }
    
    private var statusText: String {
        if isSyncing {
            return "Syncing"
        } else if isConnected {
            return "Connected"
        } else {
            return "Disconnected"
        }
    }
}