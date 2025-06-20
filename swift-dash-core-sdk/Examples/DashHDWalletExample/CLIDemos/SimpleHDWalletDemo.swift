#!/usr/bin/swift

import Foundation
import SwiftUI

// MARK: - Simple Models

struct HDWallet {
    let id = UUID()
    var name: String
    var network: String
    var accounts: [HDAccount] = []
    var seedPhrase: [String]
}

struct HDAccount {
    let id = UUID()
    var index: UInt32
    var label: String
    var addresses: [String] = []
    var balance: Double = 0.0
    
    var derivationPath: String {
        "m/44'/5'/\(index)'"
    }
}

// MARK: - Mock Wallet Service

class MockWalletService: ObservableObject {
    @Published var wallets: [HDWallet] = []
    @Published var currentWallet: HDWallet?
    @Published var isConnected = false
    @Published var syncProgress: Double = 0.0
    @Published var currentBlock: Int = 0
    @Published var totalBlocks: Int = 1000000
    
    func createWallet(name: String, network: String) {
        let seedPhrase = [
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", 
            "abandon", "abandon", "abandon", "about"
        ]
        
        var wallet = HDWallet(name: name, network: network, seedPhrase: seedPhrase)
        
        // Create default account
        var account = HDAccount(index: 0, label: "Primary Account")
        account.addresses = [
            "XmockAddress1234567890",
            "XmockAddress0987654321"
        ]
        account.balance = 1.5
        wallet.accounts.append(account)
        
        wallets.append(wallet)
        currentWallet = wallet
    }
    
    func startSync() {
        guard !isConnected else { return }
        
        isConnected = true
        currentBlock = 900000
        
        // Simulate sync progress
        Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { timer in
            if self.currentBlock < self.totalBlocks {
                self.currentBlock += 1000
                self.syncProgress = Double(self.currentBlock) / Double(self.totalBlocks)
            } else {
                timer.invalidate()
                self.syncProgress = 1.0
            }
        }
    }
}

// MARK: - Views

struct ContentView: View {
    @StateObject private var walletService = MockWalletService()
    @State private var showCreateWallet = false
    
    var body: some View {
        NavigationView {
            VStack {
                if walletService.wallets.isEmpty {
                    EmptyStateView(onCreateWallet: { showCreateWallet = true })
                } else if let wallet = walletService.currentWallet {
                    WalletView(wallet: wallet, walletService: walletService)
                }
            }
            .navigationTitle("Dash HD Wallet Demo")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("Create Wallet") {
                        showCreateWallet = true
                    }
                }
            }
        }
        .sheet(isPresented: $showCreateWallet) {
            CreateWalletView(walletService: walletService, isPresented: $showCreateWallet)
        }
    }
}

struct EmptyStateView: View {
    let onCreateWallet: () -> Void
    
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "wallet.pass")
                .font(.system(size: 60))
                .foregroundColor(.gray)
            
            Text("No Wallets")
                .font(.title2)
            
            Text("Create a wallet to get started")
                .foregroundColor(.secondary)
            
            Button("Create Wallet", action: onCreateWallet)
                .buttonStyle(.borderedProminent)
        }
    }
}

struct CreateWalletView: View {
    @ObservedObject var walletService: MockWalletService
    @Binding var isPresented: Bool
    
    @State private var walletName = ""
    @State private var selectedNetwork = "testnet"
    
    var body: some View {
        NavigationView {
            Form {
                Section("Wallet Details") {
                    TextField("Wallet Name", text: $walletName)
                    
                    Picker("Network", selection: $selectedNetwork) {
                        Text("Mainnet").tag("mainnet")
                        Text("Testnet").tag("testnet")
                    }
                }
                
                Section("Recovery Phrase") {
                    Text("A new recovery phrase will be generated")
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle("Create Wallet")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        isPresented = false
                    }
                }
                
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") {
                        walletService.createWallet(name: walletName, network: selectedNetwork)
                        isPresented = false
                    }
                    .disabled(walletName.isEmpty)
                }
            }
        }
    }
}

struct WalletView: View {
    let wallet: HDWallet
    @ObservedObject var walletService: MockWalletService
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            // Wallet Info
            VStack(alignment: .leading, spacing: 10) {
                Text(wallet.name)
                    .font(.title)
                    .bold()
                
                HStack {
                    Label(wallet.network.capitalized, systemImage: "network")
                    Spacer()
                    Label(walletService.isConnected ? "Connected" : "Disconnected", 
                          systemImage: walletService.isConnected ? "circle.fill" : "circle")
                        .foregroundColor(walletService.isConnected ? .green : .red)
                }
                .font(.caption)
            }
            .padding()
            .background(Color.gray.opacity(0.1))
            .cornerRadius(10)
            
            // Sync Progress
            if walletService.isConnected && walletService.syncProgress < 1.0 {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Syncing...")
                        .font(.headline)
                    
                    ProgressView(value: walletService.syncProgress)
                    
                    HStack {
                        Text("Block \(walletService.currentBlock) of \(walletService.totalBlocks)")
                        Spacer()
                        Text("\(Int(walletService.syncProgress * 100))%")
                    }
                    .font(.caption)
                    .foregroundColor(.secondary)
                }
                .padding()
                .background(Color.blue.opacity(0.1))
                .cornerRadius(10)
            }
            
            // Accounts
            VStack(alignment: .leading, spacing: 10) {
                Text("Accounts")
                    .font(.headline)
                
                ForEach(wallet.accounts, id: \.id) { account in
                    AccountRow(account: account)
                }
            }
            
            Spacer()
            
            // Action Button
            if !walletService.isConnected {
                Button(action: {
                    walletService.startSync()
                }) {
                    Label("Start Sync", systemImage: "arrow.triangle.2.circlepath")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
    }
}

struct AccountRow: View {
    let account: HDAccount
    
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(account.label)
                    .font(.headline)
                Spacer()
                Text("\(account.balance, specifier: "%.8f") DASH")
                    .font(.system(.body, design: .monospaced))
            }
            
            Text(account.derivationPath)
                .font(.caption)
                .foregroundColor(.secondary)
            
            Text("\(account.addresses.count) addresses")
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color.gray.opacity(0.05))
        .cornerRadius(8)
    }
}

// MARK: - App

struct DashHDWalletDemoApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

// Run the app
DashHDWalletDemoApp.main()