import SwiftUI

struct CreateAccountView: View {
    @EnvironmentObject private var walletService: WalletService
    @Environment(\.dismiss) private var dismiss
    
    let wallet: HDWallet
    let onComplete: (HDAccount) -> Void
    
    @State private var accountLabel = ""
    @State private var accountIndex: UInt32 = 1
    @State private var password = ""
    @State private var isCreating = false
    @State private var errorMessage = ""
    
    var nextAvailableIndex: UInt32 {
        let usedIndices = wallet.accounts.map { $0.accountIndex }
        var index: UInt32 = 0
        while usedIndices.contains(index) {
            index += 1
        }
        return index
    }
    
    var isValid: Bool {
        !password.isEmpty && password.count >= 8
    }
    
    var body: some View {
        NavigationView {
            Form {
                Section("Account Details") {
                    TextField("Account Label (Optional)", text: $accountLabel)
                        .textFieldStyle(.roundedBorder)
                    
                    HStack {
                        Text("Account Index")
                        Spacer()
                        Text("\(accountIndex)")
                            .monospacedDigit()
                    }
                    
                    Text("Derivation Path: \(derivationPath)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fontDesign(.monospaced)
                }
                
                Section("Security") {
                    SecureField("Wallet Password", text: $password)
                        .textFieldStyle(.roundedBorder)
                    
                    if !password.isEmpty && password.count < 8 {
                        Text("Password must be at least 8 characters")
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                }
                
                if !errorMessage.isEmpty {
                    Section {
                        Text(errorMessage)
                            .foregroundColor(.red)
                    }
                }
            }
            .navigationTitle("Create Account")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") {
                        createAccount()
                    }
                    .disabled(!isValid || isCreating)
                }
            }
        }
        #if os(macOS)
        .frame(width: 450, height: 350)
        #endif
        .onAppear {
            accountIndex = nextAvailableIndex
        }
    }
    
    private var derivationPath: String {
        let coinType = BIP44.coinType(for: wallet.network)
        return "m/44'/\(coinType)'/\(accountIndex)'"
    }
    
    private func createAccount() {
        isCreating = true
        errorMessage = ""
        
        do {
            let label = accountLabel.isEmpty ? "Account #\(accountIndex)" : accountLabel
            
            let account = try walletService.createAccount(
                for: wallet,
                index: accountIndex,
                label: label,
                password: password
            )
            
            wallet.accounts.append(account)
            
            // Save to storage
            if let context = walletService.modelContext {
                try context.save()
            }
            
            onComplete(account)
            dismiss()
            
        } catch {
            errorMessage = error.localizedDescription
            isCreating = false
        }
    }
}