import XCTest
@testable import SwiftDashCoreSDK

final class DashSDKTests: XCTestCase {
    
    var sdk: DashSDK!
    
    override func setUp() async throws {
        // Create test configuration
        let config = SPVClientConfiguration()
        config.network = .testnet
        config.validationMode = .basic
        
        sdk = try DashSDK(configuration: config)
    }
    
    override func tearDown() async throws {
        if sdk.isConnected {
            try await sdk.disconnect()
        }
        sdk = nil
    }
    
    // MARK: - Configuration Tests
    
    func testDefaultConfiguration() throws {
        let config = SPVClientConfiguration.default
        XCTAssertEqual(config.network, .mainnet)
        XCTAssertEqual(config.validationMode, .basic)
        XCTAssertEqual(config.maxPeers, 8)
        XCTAssertTrue(config.enableFilterLoad)
    }
    
    func testNetworkSpecificConfigurations() throws {
        let mainnet = SPVClientConfiguration.mainnet()
        XCTAssertEqual(mainnet.network, .mainnet)
        
        let testnet = SPVClientConfiguration.testnet()
        XCTAssertEqual(testnet.network, .testnet)
        
        let regtest = SPVClientConfiguration.regtest()
        XCTAssertEqual(regtest.network, .regtest)
        XCTAssertEqual(regtest.validationMode, .none)
    }
    
    // MARK: - Model Tests
    
    func testNetworkProperties() {
        XCTAssertEqual(DashNetwork.mainnet.defaultPort, 9999)
        XCTAssertEqual(DashNetwork.testnet.defaultPort, 19999)
        XCTAssertEqual(DashNetwork.regtest.defaultPort, 19899)
        XCTAssertEqual(DashNetwork.devnet.defaultPort, 19799)
    }
    
    func testBalanceCalculations() {
        let balance = Balance(
            confirmed: 100_000_000,
            pending: 50_000_000,
            instantLocked: 25_000_000,
            total: 150_000_000
        )
        
        XCTAssertEqual(balance.available, 125_000_000)
        XCTAssertEqual(balance.unconfirmed, 50_000_000)
        XCTAssertEqual(balance.formattedConfirmed, "1.00000000 DASH")
        XCTAssertEqual(balance.formattedPending, "0.50000000 DASH")
    }
    
    func testTransactionStatus() {
        let pendingTx = Transaction(txid: "test1", confirmations: 0)
        XCTAssertEqual(pendingTx.status, .pending)
        XCTAssertTrue(pendingTx.isPending)
        XCTAssertFalse(pendingTx.isConfirmed)
        
        let confirmingTx = Transaction(txid: "test2", confirmations: 3)
        XCTAssertEqual(confirmingTx.status, .confirming(3))
        XCTAssertFalse(confirmingTx.isPending)
        XCTAssertTrue(confirmingTx.isConfirmed)
        
        let confirmedTx = Transaction(txid: "test3", confirmations: 6)
        XCTAssertEqual(confirmedTx.status, .confirmed)
        
        let instantTx = Transaction(txid: "test4", confirmations: 0, isInstantLocked: true)
        XCTAssertEqual(instantTx.status, .instantLocked)
        XCTAssertFalse(instantTx.isPending)
    }
    
    func testUTXOSpendability() {
        let unconfirmedUTXO = UTXO(
            outpoint: "txid:0",
            txid: "txid",
            vout: 0,
            address: "Xtest",
            script: Data(),
            value: 100_000_000,
            confirmations: 0
        )
        XCTAssertFalse(unconfirmedUTXO.isSpendable)
        
        let confirmedUTXO = UTXO(
            outpoint: "txid:1",
            txid: "txid",
            vout: 1,
            address: "Xtest",
            script: Data(),
            value: 100_000_000,
            confirmations: 1
        )
        XCTAssertTrue(confirmedUTXO.isSpendable)
        
        let instantUTXO = UTXO(
            outpoint: "txid:2",
            txid: "txid",
            vout: 2,
            address: "Xtest",
            script: Data(),
            value: 100_000_000,
            confirmations: 0,
            isInstantLocked: true
        )
        XCTAssertTrue(instantUTXO.isSpendable)
        
        let spentUTXO = UTXO(
            outpoint: "txid:3",
            txid: "txid",
            vout: 3,
            address: "Xtest",
            script: Data(),
            value: 100_000_000,
            isSpent: true,
            confirmations: 100
        )
        XCTAssertFalse(spentUTXO.isSpendable)
    }
    
    // MARK: - Address Validation Tests
    
    func testAddressValidation() {
        // Mainnet addresses start with 'X'
        XCTAssertTrue(sdk.validateAddress("Xtesttesttest"))
        
        // Testnet addresses start with 'y'
        XCTAssertTrue(sdk.validateAddress("ytesttesttest"))
        
        // Invalid addresses
        XCTAssertFalse(sdk.validateAddress("1testtesttest"))
        XCTAssertFalse(sdk.validateAddress("btesttesttest"))
    }
    
    // MARK: - Error Tests
    
    func testErrorDescriptions() {
        let networkError = DashSDKError.networkError("Connection failed")
        XCTAssertEqual(networkError.errorDescription, "Network error: Connection failed")
        XCTAssertNotNil(networkError.recoverySuggestion)
        
        let insufficientFunds = DashSDKError.insufficientFunds(
            required: 200_000_000,
            available: 100_000_000
        )
        XCTAssertTrue(insufficientFunds.errorDescription?.contains("2.0 DASH") ?? false)
        XCTAssertTrue(insufficientFunds.errorDescription?.contains("1.0 DASH") ?? false)
    }
    
    // MARK: - Async Tests
    
    func testConnectionLifecycle() async throws {
        XCTAssertFalse(sdk.isConnected)
        
        // Note: This would require a mock or test network
        // try await sdk.connect()
        // XCTAssertTrue(sdk.isConnected)
        
        // try await sdk.disconnect()
        // XCTAssertFalse(sdk.isConnected)
    }
    
    // MARK: - Storage Tests
    
    func testStorageStatistics() async throws {
        let stats = try sdk.getStorageStatistics()
        XCTAssertEqual(stats.watchedAddressCount, 0)
        XCTAssertEqual(stats.transactionCount, 0)
        XCTAssertEqual(stats.totalUTXOCount, 0)
    }
}

// MARK: - Mock Tests

final class MockFFIBridgeTests: XCTestCase {
    
    func testStringConversion() {
        let testString = "Hello, Dash!"
        let cString = FFIBridge.fromString(testString)
        XCTAssertEqual(String(cString: cString), testString)
    }
    
    func testErrorConversion() {
        let error = FFIError(code: 3)
        XCTAssertEqual(error, .networkError)
        
        let unknownError = FFIError(code: 999)
        XCTAssertEqual(unknownError, .unknown)
    }
}

// MARK: - Integration Tests

@available(iOS 17.0, *)
final class StorageIntegrationTests: XCTestCase {
    
    var storage: StorageManager!
    
    override func setUp() async throws {
        storage = try StorageManager()
    }
    
    override func tearDown() async throws {
        try storage.deleteAllData()
        storage = nil
    }
    
    func testWatchedAddressPersistence() async throws {
        let address = WatchedAddress(
            address: "XtestAddress123",
            label: "Test Wallet"
        )
        
        try storage.saveWatchedAddress(address)
        
        let fetched = try storage.fetchWatchedAddresses()
        XCTAssertEqual(fetched.count, 1)
        XCTAssertEqual(fetched.first?.address, "XtestAddress123")
        XCTAssertEqual(fetched.first?.label, "Test Wallet")
    }
    
    func testTransactionPersistence() async throws {
        let tx = Transaction(
            txid: "abc123",
            height: 1000,
            amount: 100_000_000,
            confirmations: 6
        )
        
        try storage.saveTransaction(tx)
        
        let fetched = try storage.fetchTransaction(by: "abc123")
        XCTAssertNotNil(fetched)
        XCTAssertEqual(fetched?.amount, 100_000_000)
        XCTAssertEqual(fetched?.confirmations, 6)
    }
    
    func testUTXOManagement() async throws {
        let utxo1 = UTXO(
            outpoint: "tx1:0",
            txid: "tx1",
            vout: 0,
            address: "Xaddr1",
            script: Data(),
            value: 50_000_000
        )
        
        let utxo2 = UTXO(
            outpoint: "tx2:0",
            txid: "tx2",
            vout: 0,
            address: "Xaddr1",
            script: Data(),
            value: 75_000_000,
            isSpent: true
        )
        
        try await storage.saveUTXOs([utxo1, utxo2])
        
        let unspent = try storage.fetchUTXOs(includeSpent: false)
        XCTAssertEqual(unspent.count, 1)
        XCTAssertEqual(unspent.first?.value, 50_000_000)
        
        let all = try storage.fetchUTXOs(includeSpent: true)
        XCTAssertEqual(all.count, 2)
    }
}