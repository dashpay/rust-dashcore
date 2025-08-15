// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwiftDashCoreSDK",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
        .tvOS(.v17),
        .watchOS(.v10)
    ],
    products: [
        .library(
            name: "SwiftDashCoreSDK",
            targets: ["SwiftDashCoreSDK"]
        ),
        // KeyWalletFFISwift is not exposed as a product - it requires external DashSPVFFI module
        // This package is designed to be used as part of the unified SDK in dashpay-ios
    ],
    dependencies: [
        // No external dependencies - using only Swift standard library and frameworks
    ],
    targets: [
        // IMPORTANT: This package is designed for unified SDK consumption only
        // DashSPVFFI and KeyWalletFFI targets removed - these are provided by the unified SDK in dashpay-ios
        // This package only provides SwiftDashCoreSDK which has no external dependencies
        .target(
            name: "SwiftDashCoreSDK",
            dependencies: [],
            path: "Sources/SwiftDashCoreSDK",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        .testTarget(
            name: "SwiftDashCoreSDKTests",
            dependencies: ["SwiftDashCoreSDK"],
            path: "Tests/SwiftDashCoreSDKTests"
        ),
    ]
)