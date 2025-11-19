import SwiftUI
import SwiftDashCoreSDK

struct CreateWalletView: View {
    @EnvironmentObject private var walletService: WalletService
    @Environment(\.dismiss) private var dismiss

    @State private var walletName = "Dev Wallet \(Int.random(in: 1000...9999))"
    @State private var selectedNetwork: DashNetwork = .testnet
    @State private var password = "password123"
    @State private var confirmPassword = "password123"
    @State private var mnemonic: [String] = []
    @State private var showMnemonic = true
    @State private var mnemonicConfirmed = true
    @State private var isCreating = false
    @State private var errorMessage = ""

    let onComplete: (HDWallet) -> Void

    var isValid: Bool {
        !walletName.isEmpty &&
        !password.isEmpty &&
        password == confirmPassword &&
        password.count >= 8 &&
        mnemonicConfirmed
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Create New Wallet")
                    .font(.title2)
                    .fontWeight(.semibold)
                Spacer()
            }
            .padding()
            .background(PlatformColor.controlBackground)

            // Content
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Wallet Details
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Wallet Details")
                            .font(.headline)

                        TextField("Wallet Name", text: $walletName)
                            .textFieldStyle(.roundedBorder)

                        HStack {
                            Text("Network:")
                            Picker("", selection: $selectedNetwork) {
                                ForEach(DashNetwork.allCases, id: \.self) { network in
                                    Text(network.rawValue.capitalized).tag(network)
                                }
                            }
                            #if os(macOS)
                            .pickerStyle(.menu)
                            #else
                            .pickerStyle(.automatic)
                            #endif
                            .labelsHidden()
                            Spacer()
                        }
                    }

                    Divider()

                    // Security
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Security")
                            .font(.headline)

                        SecureField("Password (min 8 characters)", text: $password)
                            .textFieldStyle(.roundedBorder)

                        SecureField("Confirm Password", text: $confirmPassword)
                            .textFieldStyle(.roundedBorder)

                        // Password validation warnings
                        if !password.isEmpty && password.count < 8 {
                            Text("Password must be at least 8 characters")
                                .font(.caption)
                                .foregroundColor(.orange)
                        }

                        if !password.isEmpty && !confirmPassword.isEmpty && password != confirmPassword {
                            Text("Passwords don't match")
                                .font(.caption)
                                .foregroundColor(.red)
                        }

                        if password.isEmpty && confirmPassword.isEmpty && !walletName.isEmpty {
                            Text("Please set a password to protect your wallet")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }

                    Divider()

                    // Recovery Phrase
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Recovery Phrase")
                            .font(.headline)

                        if mnemonic.isEmpty {
                            Button("Generate Recovery Phrase") {
                                generateMnemonic()
                            }
                            .buttonStyle(.borderedProminent)
                        } else {
                            Text("Write down these words in order. You'll need them to recover your wallet.")
                                .font(.caption)
                                .foregroundColor(.orange)

                            MnemonicGridView(
                                words: mnemonic,
                                showWords: showMnemonic
                            )

                            HStack {
                                Toggle("Show words", isOn: $showMnemonic)

                                Spacer()

                                Button("Copy") {
                                    copyMnemonic()
                                }
                                #if os(iOS)
                                .buttonStyle(.borderless)
                                #else
                                .buttonStyle(.link)
                                #endif
                            }

                            Toggle("I have written down my recovery phrase", isOn: $mnemonicConfirmed)
                                #if os(macOS)
                                .toggleStyle(.checkbox)
                                #else
                                .toggleStyle(.automatic)
                                #endif
                        }
                    }

                    // Error Message
                    if !errorMessage.isEmpty {
                        Text(errorMessage)
                            .foregroundColor(.red)
                            .padding(.vertical, 8)
                    }
                }
                .padding()
            }

            Divider()

            // Footer buttons
            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.escape)

                Spacer()

                // Show what's missing if button is disabled
                if !isValid && !walletName.isEmpty {
                    VStack(alignment: .trailing, spacing: 4) {
                        if password.isEmpty {
                            Text("Password required")
                                .font(.caption)
                                .foregroundColor(.orange)
                        } else if password.count < 8 {
                            Text("Password too short")
                                .font(.caption)
                                .foregroundColor(.orange)
                        } else if password != confirmPassword {
                            Text("Passwords must match")
                                .font(.caption)
                                .foregroundColor(.orange)
                        } else if !mnemonicConfirmed {
                            Text("Confirm seed backup")
                                .font(.caption)
                                .foregroundColor(.orange)
                        }
                    }
                }

                Button("Create") {
                    createWallet()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!isValid || isCreating)
                .keyboardShortcut(.return)
            }
            .padding()
        }
        #if os(macOS)
        .frame(width: 600, height: 600)
        #endif
        .onAppear {
            // Auto-generate mnemonic for development
            if mnemonic.isEmpty {
                generateMnemonic()
            }
        }
    }

    private func generateMnemonic() {
        mnemonic = HDWalletService.generateMnemonic()
    }

    private func copyMnemonic() {
        let phrase = mnemonic.joined(separator: " ")
        Clipboard.copy(phrase)
    }

    private func createWallet() {
        isCreating = true
        errorMessage = ""

        do {
            let wallet = try walletService.createWallet(
                name: walletName,
                mnemonic: mnemonic,
                password: password,
                network: selectedNetwork
            )

            onComplete(wallet)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
            isCreating = false
        }
    }
}

// MARK: - Mnemonic Grid View

struct MnemonicGridView: View {
    let words: [String]
    let showWords: Bool

    private let columns = [
        GridItem(.flexible()),
        GridItem(.flexible()),
        GridItem(.flexible())
    ]

    var body: some View {
        LazyVGrid(columns: columns, spacing: 8) {
            ForEach(Array(words.enumerated()), id: \.offset) { index, word in
                HStack(spacing: 4) {
                    Text("\(index + 1).")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .frame(width: 20, alignment: .trailing)

                    Text(showWords ? word : "•••••")
                        .font(.system(.body, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(PlatformColor.controlBackground)
                .cornerRadius(6)
            }
        }
    }
}

// MARK: - Import Wallet View

struct ImportWalletView: View {
    @EnvironmentObject private var walletService: WalletService
    @Environment(\.dismiss) private var dismiss

    @State private var walletName = ""
    @State private var mnemonicText = ""
    @State private var selectedNetwork: DashNetwork = .testnet
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var isImporting = false
    @State private var errorMessage = ""

    let onComplete: (HDWallet) -> Void

    var isValid: Bool {
        !walletName.isEmpty &&
        !mnemonicText.isEmpty &&
        !password.isEmpty &&
        password == confirmPassword &&
        password.count >= 8
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Import Wallet")
                    .font(.title2)
                    .fontWeight(.semibold)
                Spacer()
            }
            .padding()
            .background(PlatformColor.controlBackground)

            // Content
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Wallet Details
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Wallet Details")
                            .font(.headline)

                        TextField("Wallet Name", text: $walletName)
                            .textFieldStyle(.roundedBorder)

                        HStack {
                            Text("Network:")
                            Picker("", selection: $selectedNetwork) {
                                ForEach(DashNetwork.allCases, id: \.self) { network in
                                    Text(network.rawValue.capitalized).tag(network)
                                }
                            }
                            #if os(macOS)
                            .pickerStyle(.menu)
                            #else
                            .pickerStyle(.automatic)
                            #endif
                            .labelsHidden()
                            Spacer()
                        }
                    }

                    Divider()

                    // Recovery Phrase
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Recovery Phrase")
                            .font(.headline)

                        Text("Enter your 12 or 24 word recovery phrase")
                            .font(.caption)
                            .foregroundColor(.secondary)

                        TextEditor(text: $mnemonicText)
                            .font(.system(.body, design: .monospaced))
                            .frame(height: 100)
                            .overlay(
                                RoundedRectangle(cornerRadius: 6)
                                    .stroke(Color.secondary.opacity(0.3), lineWidth: 1)
                            )
                    }

                    Divider()

                    // Security
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Security")
                            .font(.headline)

                        SecureField("Password (min 8 characters)", text: $password)
                            .textFieldStyle(.roundedBorder)

                        SecureField("Confirm Password", text: $confirmPassword)
                            .textFieldStyle(.roundedBorder)

                        // Password validation warnings
                        if !password.isEmpty && password.count < 8 {
                            Text("Password must be at least 8 characters")
                                .font(.caption)
                                .foregroundColor(.orange)
                        }

                        if !password.isEmpty && !confirmPassword.isEmpty && password != confirmPassword {
                            Text("Passwords don't match")
                                .font(.caption)
                                .foregroundColor(.red)
                        }

                        if password.isEmpty && confirmPassword.isEmpty && !walletName.isEmpty {
                            Text("Please set a password to protect your wallet")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }

                    // Error Message
                    if !errorMessage.isEmpty {
                        Text(errorMessage)
                            .foregroundColor(.red)
                            .padding(.vertical, 8)
                    }
                }
                .padding()
            }

            Divider()

            // Footer buttons
            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.escape)

                Spacer()

                Button("Import") {
                    importWallet()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!isValid || isImporting)
                .keyboardShortcut(.return)
            }
            .padding()
        }
        #if os(macOS)
        .frame(width: 600, height: 500)
        #endif
    }

    private func importWallet() {
        isImporting = true
        errorMessage = ""

        // Parse mnemonic
        let words = mnemonicText
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: " ")
            .map { String($0) }

        // Validate word count
        guard words.count == 12 || words.count == 24 else {
            errorMessage = "Recovery phrase must be 12 or 24 words"
            isImporting = false
            return
        }

        do {
            let wallet = try walletService.createWallet(
                name: walletName,
                mnemonic: words,
                password: password,
                network: selectedNetwork
            )

            onComplete(wallet)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
            isImporting = false
        }
    }
}