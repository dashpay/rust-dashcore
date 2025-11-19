import Foundation
import SwiftDashCoreSDK

// MARK: - BIP44 Helper

public enum BIP44 {
    public static let dashMainnetCoinType: UInt32 = 5
    public static let dashTestnetCoinType: UInt32 = 1
    public static let purpose: UInt32 = 44
    public static let defaultGapLimit: UInt32 = 20

    public static func coinType(for network: DashNetwork) -> UInt32 {
        switch network {
        case .mainnet:
            return dashMainnetCoinType
        case .testnet, .regtest, .devnet:
            return dashTestnetCoinType
        }
    }

    public static func derivationPath(
        network: DashNetwork,
        account: UInt32,
        change: Bool,
        index: UInt32
    ) -> String {
        let coinType = coinType(for: network)
        let changeValue: UInt32 = change ? 1 : 0
        return "m/44'/\(coinType)'/\(account)'/\(changeValue)/\(index)"
    }
}

// Note: This helper requires DashNetwork from SwiftDashCoreSDK
// Make sure to import SwiftDashCoreSDK where this is used