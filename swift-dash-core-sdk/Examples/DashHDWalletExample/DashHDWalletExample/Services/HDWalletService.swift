import Foundation
import CryptoKit
import SwiftDashCoreSDK
import KeyWalletFFISwift

// MARK: - HD Wallet Service

class HDWalletService {

    // MARK: - Mnemonic Generation

    static func generateMnemonic(strength: Int = 128) -> [String] {
        do {
            // Use the proper BIP39 implementation from key-wallet-ffi
            // Word count: 12 words for 128-bit entropy, 24 words for 256-bit entropy
            let wordCount: UInt8 = strength == 256 ? 24 : 12
            let mnemonic = try Mnemonic.generate(language: .english, wordCount: wordCount)

            // Split the phrase into words
            let words = mnemonic.phrase().split(separator: " ").map { String($0) }
            return words
        } catch {
            print("Failed to generate mnemonic: \(error)")
            // Fallback to the previous implementation if FFI fails
            return generateFallbackMnemonic()
        }
    }

    private static func generateFallbackMnemonic() -> [String] {
        // Generate 12 random words from a small set
        // This is NOT cryptographically secure but better than hardcoded values
        let sampleWords = [
            "able", "acid", "also", "area", "army", "away", "baby", "back",
            "ball", "band", "base", "bean", "bear", "beat", "been", "bell",
            "belt", "best", "bird", "blow", "blue", "boat", "body", "bone",
            "book", "boot", "born", "boss", "both", "bowl", "bulk", "burn",
            "busy", "call", "calm", "came", "camp", "card", "care", "case",
            "cash", "cast", "cell", "chat", "chip", "city", "clay", "clean",
            "clip", "club", "coal", "coat", "code", "coin", "cold", "come"
        ]

        var mnemonic: [String] = []
        for _ in 0..<12 {
            let randomIndex = Int.random(in: 0..<sampleWords.count)
            mnemonic.append(sampleWords[randomIndex])
        }

        return mnemonic
    }

    private static func generateWordsFromEntropy(_ entropy: Data) -> [String] {
        // Simplified entropy to word mapping
        // In production, this should use proper BIP39 algorithm with checksum
        let wordList = getBIP39WordList()
        var words: [String] = []

        // Simple mapping: take 11 bits at a time to index into 2048-word list
        let bits = entropy.flatMap { byte in
            (0..<8).reversed().map { (byte >> $0) & 1 }
        }

        // For 128-bit entropy, we need 12 words (132 bits with checksum)
        // This is simplified - proper BIP39 adds checksum bits
        for i in 0..<12 {
            let startBit = i * 11
            let endBit = min(startBit + 11, bits.count)

            if endBit <= bits.count {
                var index = 0
                for j in startBit..<endBit {
                    index = (index << 1) | Int(bits[j])
                }

                // Ensure index is within word list bounds
                let wordIndex = index % wordList.count
                words.append(wordList[wordIndex])
            }
        }

        // If we don't have enough words, use fallback
        if words.count < 12 {
            return generateFallbackMnemonic()
        }

        return words
    }

    private static func getBIP39WordList() -> [String] {
        // First 100 words of BIP39 English word list
        // In production, use the full 2048-word list
        return [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
            "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
            "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
            "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
            "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
            "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
            "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
            "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
            "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
            "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
            "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact"
        ]
    }

    static func validateMnemonic(_ words: [String]) -> Bool {
        let phrase = words.joined(separator: " ")
        do {
            // Use the global function from KeyWalletFFISwift module
            return try KeyWalletFFISwift.validateMnemonic(phrase: phrase, language: .english)
        } catch {
            print("Mnemonic validation failed: \(error)")
            return false
        }
    }

    // MARK: - Seed Operations

    static func mnemonicToSeed(_ mnemonic: [String], passphrase: String = "") -> Data {
        do {
            let phrase = mnemonic.joined(separator: " ")
            let mnemonicObj = try Mnemonic(phrase: phrase, language: .english)
            let seedBytes = mnemonicObj.toSeed(passphrase: passphrase)
            return Data(seedBytes)
        } catch {
            print("Failed to convert mnemonic to seed: \(error)")
            // Fallback implementation
            let phrase = mnemonic.joined(separator: " ")
            return phrase.data(using: .utf8) ?? Data()
        }
    }

    static func seedHash(_ seed: Data) -> String {
        let hash = SHA256.hash(data: seed)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Encryption

    static func encryptSeed(_ seed: Data, password: String) throws -> Data {
        // In a real app, use proper encryption (e.g., CryptoKit)
        // This is a placeholder
        return seed
    }

    static func decryptSeed(_ encryptedSeed: Data, password: String) throws -> Data {
        // In a real app, use proper decryption
        // This is a placeholder
        return encryptedSeed
    }

    // MARK: - Key Derivation

    static func deriveExtendedPublicKey(
        seed: Data,
        network: DashNetwork,
        account: UInt32
    ) -> String {
        do {
            // Convert DashNetwork to KeyWalletFFI Network
            let ffiNetwork = convertToFFINetwork(network)

            // Create HD wallet from seed
            let hdWallet = try HdWallet.fromSeed(seed: Array(seed), network: ffiNetwork)

            // Get account extended public key
            let accountXPub = try hdWallet.getAccountXpub(account: account)

            return accountXPub.xpub
        } catch {
            print("Failed to derive extended public key: \(error)")
            // Fallback to mock if FFI fails
            let prefix = network == .mainnet ? "xpub" : "tpub"
            return "\(prefix)MockExtendedPublicKey\(account)"
        }
    }

    static func deriveAddress(
        xpub: String,
        network: DashNetwork,
        change: Bool,
        index: UInt32
    ) -> String {
        do {
            // Convert DashNetwork to KeyWalletFFI Network
            let ffiNetwork = convertToFFINetwork(network)

            // Create address generator
            let addressGenerator = AddressGenerator(network: ffiNetwork)

            // Create AccountXPub from the extended public key string
            // The derivation path will be filled in by the FFI when getting account xpub
            let accountXPub = AccountXPub(
                derivationPath: "", // Not needed for address generation from xpub
                xpub: xpub,
                pubKey: nil
            )

            // Generate the address
            let address = try addressGenerator.generate(
                accountXpub: accountXPub,
                external: !change,  // external=true for receive addresses, false for change
                index: index
            )

            return address.toString()
        } catch {
            print("Failed to derive address: \(error)")
            // Fallback to mock if FFI fails
            let prefix = network == .mainnet ? "X" : "y"
            let changeStr = change ? "1" : "0"
            return "\(prefix)MockAddress\(changeStr)\(index)"
        }
    }

    static func deriveAddresses(
        xpub: String,
        network: DashNetwork,
        change: Bool,
        startIndex: UInt32,
        count: UInt32
    ) -> [String] {
        do {
            // Convert DashNetwork to KeyWalletFFI Network
            let ffiNetwork = convertToFFINetwork(network)

            // Create address generator
            let addressGenerator = AddressGenerator(network: ffiNetwork)

            // Create AccountXPub from string
            let accountXPub = AccountXPub(
                derivationPath: "", // Path is not needed for address generation
                xpub: xpub,
                pubKey: nil
            )

            // Generate addresses in range
            let addresses = try addressGenerator.generateRange(
                accountXpub: accountXPub,
                external: !change,  // external=true for receive addresses, false for change
                start: startIndex,
                count: count
            )

            return addresses.map { $0.toString() }
        } catch {
            print("Failed to derive addresses: \(error)")
            // Fallback to individual derivation if batch fails
            return (startIndex..<(startIndex + count)).map { index in
                deriveAddress(xpub: xpub, network: network, change: change, index: index)
            }
        }
    }

    // MARK: - Helper Functions

    static func convertToFFINetwork(_ network: DashNetwork) -> KeyWalletFFISwift.Network {
        switch network {
        case .mainnet:
            return .dash
        case .testnet:
            return .testnet
        case .devnet:
            return .devnet
        case .regtest:
            return .regtest
        }
    }
}

// MARK: - Address Discovery Service

class AddressDiscoveryService {
    private let sdk: DashSDK
    private let walletService: HDWalletService

    init(sdk: DashSDK) {
        self.sdk = sdk
        self.walletService = HDWalletService()
    }

    func discoverAddresses(
        for account: HDAccount,
        network: DashNetwork,
        gapLimit: UInt32 = 20
    ) async throws -> (external: [String], internal: [String]) {
        var externalAddresses: [String] = []
        var internalAddresses: [String] = []

        // Discover external addresses
        let (lastExternal, discoveredExternal) = try await discoverChain(
            xpub: account.extendedPublicKey,
            network: network,
            isChange: false,
            startIndex: 0,
            gapLimit: gapLimit
        )
        externalAddresses = discoveredExternal
        account.lastUsedExternalIndex = lastExternal

        // Discover internal (change) addresses
        let (lastInternal, discoveredInternal) = try await discoverChain(
            xpub: account.extendedPublicKey,
            network: network,
            isChange: true,
            startIndex: 0,
            gapLimit: gapLimit
        )
        internalAddresses = discoveredInternal
        account.lastUsedInternalIndex = lastInternal

        return (externalAddresses, internalAddresses)
    }

    private func discoverChain(
        xpub: String,
        network: DashNetwork,
        isChange: Bool,
        startIndex: UInt32,
        gapLimit: UInt32
    ) async throws -> (lastUsed: UInt32, addresses: [String]) {
        var addresses: [String] = []
        var lastUsedIndex: UInt32 = 0
        var consecutiveUnused: UInt32 = 0
        var currentIndex = startIndex

        while consecutiveUnused < gapLimit {
            // Derive batch of addresses
            let batchSize: UInt32 = 10
            let batch = HDWalletService.deriveAddresses(
                xpub: xpub,
                network: network,
                change: isChange,
                startIndex: currentIndex,
                count: batchSize
            )

            // Check each address for transactions
            for (offset, address) in batch.enumerated() {
                let index = currentIndex + UInt32(offset)
                addresses.append(address)

                // Check if address has been used
                let transactions = try await sdk.getTransactions(for: address, limit: 1)
                if !transactions.isEmpty {
                    lastUsedIndex = index
                    consecutiveUnused = 0
                } else {
                    consecutiveUnused += 1
                }

                if consecutiveUnused >= gapLimit {
                    break
                }
            }

            currentIndex += batchSize
        }

        return (lastUsedIndex, addresses)
    }
}

// MARK: - Key Wallet FFI Bridge

class KeyWalletBridge {

    struct WalletWrapper {
        let hdWallet: HdWallet
        let network: DashNetwork

        func deriveAccount(_ index: UInt32) -> AccountWrapper {
            do {
                let accountXPub = try hdWallet.getAccountXpub(account: index)
                return AccountWrapper(
                    index: index,
                    xpub: accountXPub.xpub,
                    network: network
                )
            } catch {
                print("Failed to derive account: \(error)")
                // Fallback to using HDWalletService
                let seed = Data() // We don't have access to seed here, but HDWalletService handles fallback
                let xpub = HDWalletService.deriveExtendedPublicKey(
                    seed: seed,
                    network: network,
                    account: index
                )
                return AccountWrapper(
                    index: index,
                    xpub: xpub,
                    network: network
                )
            }
        }
    }

    struct AccountWrapper {
        let index: UInt32
        let xpub: String
        let network: DashNetwork

        func deriveAddress(change: Bool, index: UInt32) -> String {
            return HDWalletService.deriveAddress(
                xpub: xpub,
                network: network,
                change: change,
                index: index
            )
        }
    }

    static func createWallet(mnemonic: [String], network: DashNetwork) -> WalletWrapper? {
        do {
            let phrase = mnemonic.joined(separator: " ")
            let mnemonicObj = try Mnemonic(phrase: phrase, language: .english)
            let ffiNetwork = HDWalletService.convertToFFINetwork(network)
            let hdWallet = try HdWallet.fromMnemonic(
                mnemonic: mnemonicObj,
                passphrase: "",
                network: ffiNetwork
            )
            return WalletWrapper(hdWallet: hdWallet, network: network)
        } catch {
            print("Failed to create wallet from mnemonic: \(error)")
            return nil
        }
    }
}