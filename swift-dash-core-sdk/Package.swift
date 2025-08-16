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
        .library(
            name: "KeyWalletFFISwift",
            targets: ["KeyWalletFFISwift"]
        ),
    ],
    dependencies: [
        // No external dependencies - using only Swift standard library and frameworks
    ],
    targets: [
        // DashSPVFFI target removed - now provided by unified SDK in dashpay-ios
        // Note: This package cannot build standalone - it requires the unified SDK's DashSPVFFI module
        .target(
            name: "KeyWalletFFI",
            dependencies: [],
            path: "Sources/KeyWalletFFI",
            exclude: ["key_wallet_ffi.swift"],
            sources: ["dummy.c"],
            publicHeadersPath: ".",
            cSettings: [
                .headerSearchPath("."),
                .define("SWIFT_PACKAGE")
            ],
            linkerSettings: [
                .linkedLibrary("key_wallet_ffi"),
                .unsafeFlags([
                    "-L/Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Sources/DashSPVFFI",
                    "-L/Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample",
                    "-L/Users/quantum/src/rust-dashcore/swift-dash-core-sdk",
                    "-L/Users/quantum/src/rust-dashcore/target/aarch64-apple-ios-sim/release",
                    "-L/Users/quantum/src/rust-dashcore/target/x86_64-apple-ios/release",
                    "-L/Users/quantum/src/rust-dashcore/target/ios-simulator-universal/release",
                    "-L/Users/quantum/src/rust-dashcore/target/release",
                    "-L/Users/quantum/src/rust-dashcore/target/aarch64-apple-darwin/release"
                ])
            ]
        ),
        .target(
            name: "KeyWalletFFISwift",
            dependencies: ["KeyWalletFFI"],
            path: "Sources/KeyWalletFFI",
            sources: ["key_wallet_ffi.swift"]
        ),
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