import SwiftUI
import SwiftData
import SwiftDashCoreSDK

struct ContentView: View {
    @Environment(\.modelContext) private var modelContext
    @EnvironmentObject private var walletService: WalletService
    @Query private var wallets: [HDWallet]
    
    @State private var showCreateWallet = false
    @State private var showImportWallet = false
    @State private var selectedWallet: HDWallet?
    
    var body: some View {
        #if os(iOS)
        NavigationStack {
            WalletListView(
                wallets: wallets,
                onCreateWallet: { showCreateWallet = true },
                onImportWallet: { showImportWallet = true }
            )
            .onAppear {
                print("ContentView appeared with \(wallets.count) wallets")
            }
        }
        .sheet(isPresented: $showCreateWallet) {
            CreateWalletView { wallet in
                showCreateWallet = false
                selectedWallet = wallet
            }
        }
        .sheet(isPresented: $showImportWallet) {
            ImportWalletView { wallet in
                showImportWallet = false
                selectedWallet = wallet
            }
        }
        #else
        NavigationSplitView {
            // Wallet List
            List(selection: $selectedWallet) {
                Section("Wallets") {
                    ForEach(wallets) { wallet in
                        WalletRowView(wallet: wallet)
                            .tag(wallet)
                    }
                }
                
                Section {
                    Button(action: { showCreateWallet = true }) {
                        Label("Create New Wallet", systemImage: "plus.circle")
                    }
                    
                    Button(action: { showImportWallet = true }) {
                        Label("Import Wallet", systemImage: "square.and.arrow.down")
                    }
                }
            }
            .navigationTitle("Dash HD Wallets")
            .listStyle(SidebarListStyle())
        } detail: {
            // Wallet Detail
            if let wallet = selectedWallet {
                WalletDetailView(wallet: wallet)
            } else {
                EmptyWalletView()
            }
        }
        .sheet(isPresented: $showCreateWallet) {
            CreateWalletView { wallet in
                selectedWallet = wallet
            }
        }
        .sheet(isPresented: $showImportWallet) {
            ImportWalletView { wallet in
                selectedWallet = wallet
            }
        }
        #endif
    }
}

// MARK: - Wallet List View

struct WalletListView: View {
    let wallets: [HDWallet]
    let onCreateWallet: () -> Void
    let onImportWallet: () -> Void
    
    @State private var showingSettings = false
    
    var body: some View {
        #if os(iOS)
        List {
            if wallets.isEmpty {
                Section {
                    VStack(spacing: 20) {
                        Image(systemName: "wallet.pass")
                            .font(.system(size: 50))
                            .foregroundColor(.secondary)
                        
                        Text("No wallets yet")
                            .font(.headline)
                            .foregroundColor(.secondary)
                        
                        Text("Create or import a wallet to get started")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 20)
                }
                .listRowBackground(Color.clear)
            } else {
                Section("Wallets") {
                    ForEach(wallets) { wallet in
                        NavigationLink(destination: WalletDetailView(wallet: wallet)) {
                            WalletRowView(wallet: wallet)
                        }
                    }
                }
            }
            
            Section {
                Button(action: onCreateWallet) {
                    Label("Create New Wallet", systemImage: "plus.circle")
                }
                
                Button(action: onImportWallet) {
                    Label("Import Wallet", systemImage: "square.and.arrow.down")
                }
            }
        }
        .navigationTitle("Dash HD Wallets")
        .listStyle(.insetGrouped)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button {
                    showingSettings = true
                } label: {
                    Image(systemName: "gearshape")
                }
            }
        }
        .sheet(isPresented: $showingSettings) {
            SettingsView()
        }
        #else
        List(selection: $selectedWallet) {
            Section("Wallets") {
                ForEach(wallets) { wallet in
                    WalletRowView(wallet: wallet)
                        .tag(wallet)
                }
            }
            
            Section {
                Button(action: onCreateWallet) {
                    Label("Create New Wallet", systemImage: "plus.circle")
                }
                
                Button(action: onImportWallet) {
                    Label("Import Wallet", systemImage: "square.and.arrow.down")
                }
            }
        }
        .navigationTitle("Dash HD Wallets")
        .listStyle(SidebarListStyle())
        #endif
    }
}

// MARK: - Wallet Row View

struct WalletRowView: View {
    let wallet: HDWallet
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(wallet.name)
                    .font(.headline)
                
                Spacer()
                
                NetworkBadge(network: wallet.network)
            }
            
            HStack {
                Text("\(wallet.accounts.count) accounts")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                Spacer()
                
                Text(wallet.totalBalance.formattedTotal)
                    .font(.caption)
                    .monospacedDigit()
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Network Badge

struct NetworkBadge: View {
    let network: DashNetwork
    
    var body: some View {
        Text(network.rawValue.capitalized)
            .font(.caption2)
            .fontWeight(.medium)
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background(backgroundColor)
            .foregroundColor(.white)
            .cornerRadius(4)
    }
    
    private var backgroundColor: Color {
        switch network {
        case .mainnet:
            return .blue
        case .testnet:
            return .orange
        case .regtest:
            return .purple
        case .devnet:
            return .pink
        }
    }
}

// MARK: - Empty Wallet View

struct EmptyWalletView: View {
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "wallet.pass")
                .font(.system(size: 80))
                .foregroundColor(.secondary)
            
            Text("No Wallet Selected")
                .font(.title2)
                .foregroundColor(.secondary)
            
            Text("Create or import a wallet to get started")
                .font(.body)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}