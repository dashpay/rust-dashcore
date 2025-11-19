import XCTest
@testable import SwiftDashCoreSDK
import DashSPVFFI

final class MempoolTests: XCTestCase {

    func testMempoolConfigCreation() {
        // Test disabled configuration
        let disabled = MempoolConfig.disabled
        XCTAssertFalse(disabled.enabled)

        // Test selective configuration
        let selective = MempoolConfig.selective(maxTransactions: 1000)
        XCTAssertTrue(selective.enabled)
        XCTAssertEqual(selective.strategy, .selective)
        XCTAssertEqual(selective.maxTransactions, 1000)
        XCTAssertEqual(selective.timeoutSeconds, 3600)

        // Test fetchAll configuration
        let fetchAll = MempoolConfig.fetchAll(maxTransactions: 5000)
        XCTAssertTrue(fetchAll.enabled)
        XCTAssertEqual(fetchAll.strategy, .fetchAll)
        XCTAssertEqual(fetchAll.maxTransactions, 5000)

        // Test custom configuration
        let custom = MempoolConfig(
            enabled: true,
            strategy: .bloomFilter,
            maxTransactions: 2000,
            timeoutSeconds: 7200,
            fetchTransactions: false,
            persistMempool: true
        )
        XCTAssertTrue(custom.enabled)
        XCTAssertEqual(custom.strategy, .bloomFilter)
        XCTAssertEqual(custom.maxTransactions, 2000)
        XCTAssertEqual(custom.timeoutSeconds, 7200)
        XCTAssertFalse(custom.fetchTransactions)
        XCTAssertTrue(custom.persistMempool)
    }

    func testMempoolBalanceCalculations() {
        let balance = MempoolBalance(pending: 1000000, pendingInstant: 500000)
        XCTAssertEqual(balance.pending, 1000000)
        XCTAssertEqual(balance.pendingInstant, 500000)
        XCTAssertEqual(balance.total, 1500000)
    }

    func testMempoolTransactionProperties() {
        let tx = MempoolTransaction(
            txid: "abc123",
            rawTransaction: Data(),
            firstSeen: Date(),
            fee: 1000,
            isInstantSend: false,
            isOutgoing: true,
            affectedAddresses: ["address1", "address2"],
            netAmount: -50000,
            size: 250
        )

        XCTAssertEqual(tx.txid, "abc123")
        XCTAssertEqual(tx.fee, 1000)
        XCTAssertEqual(tx.size, 250)
        XCTAssertEqual(tx.feeRate, 4.0) // 1000 / 250
        XCTAssertEqual(tx.affectedAddresses.count, 2)
        XCTAssertTrue(tx.isOutgoing)
        XCTAssertFalse(tx.isInstantSend)
    }

    func testMempoolRemovalReasons() {
        let reasons: [MempoolRemovalReason] = [.expired, .replaced, .doubleSpent, .confirmed, .manual, .unknown]

        XCTAssertEqual(reasons[0].rawValue, 0)
        XCTAssertEqual(reasons[1].rawValue, 1)
        XCTAssertEqual(reasons[2].rawValue, 2)
        XCTAssertEqual(reasons[3].rawValue, 3)
        XCTAssertEqual(reasons[4].rawValue, 4)
        XCTAssertEqual(reasons[5].rawValue, 255)
    }

    func testSPVClientConfigurationWithMempool() async throws {
        let config = SPVClientConfiguration()
        config.network = .testnet
        config.mempoolConfig = .fetchAll(maxTransactions: 1000)

        XCTAssertEqual(config.network, .testnet)
        XCTAssertTrue(config.mempoolConfig.enabled)
        XCTAssertEqual(config.mempoolConfig.strategy, .fetchAll)
        XCTAssertEqual(config.mempoolConfig.maxTransactions, 1000)

        // Test FFI config creation includes mempool settings
        let ffiConfig = try config.createFFIConfig()
        defer {
            dash_spv_ffi_config_destroy(OpaquePointer(ffiConfig))
        }

        XCTAssertTrue(dash_spv_ffi_config_get_mempool_tracking(OpaquePointer(ffiConfig)))
        XCTAssertEqual(
            dash_spv_ffi_config_get_mempool_strategy(OpaquePointer(ffiConfig)),
            FFIMempoolStrategy(rawValue: 0) // FetchAll
        )
    }

    func testMempoolEventTypes() {
        // Test transaction added event
        let addedTx = MempoolTransaction(
            txid: "tx1",
            rawTransaction: Data(),
            firstSeen: Date(),
            fee: 500,
            isInstantSend: true,
            isOutgoing: false,
            affectedAddresses: ["addr1"],
            netAmount: 10000,
            size: 200
        )
        let addedEvent = MempoolEvent.transactionAdded(addedTx)

        if case .transactionAdded(let tx) = addedEvent {
            XCTAssertEqual(tx.txid, "tx1")
            XCTAssertTrue(tx.isInstantSend)
        } else {
            XCTFail("Expected transactionAdded event")
        }

        // Test transaction confirmed event
        let confirmedEvent = MempoolEvent.transactionConfirmed(
            txid: "tx2",
            blockHeight: 12345,
            blockHash: "blockhash123"
        )

        if case .transactionConfirmed(let txid, let height, let hash) = confirmedEvent {
            XCTAssertEqual(txid, "tx2")
            XCTAssertEqual(height, 12345)
            XCTAssertEqual(hash, "blockhash123")
        } else {
            XCTFail("Expected transactionConfirmed event")
        }

        // Test transaction removed event
        let removedEvent = MempoolEvent.transactionRemoved(
            txid: "tx3",
            reason: .expired
        )

        if case .transactionRemoved(let txid, let reason) = removedEvent {
            XCTAssertEqual(txid, "tx3")
            XCTAssertEqual(reason, .expired)
        } else {
            XCTFail("Expected transactionRemoved event")
        }
    }
}