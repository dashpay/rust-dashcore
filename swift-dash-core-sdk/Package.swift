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
        .target(
            name: "DashSPVFFI",
            dependencies: [],
            path: "Sources/DashSPVFFI",
            sources: ["DashSPVFFI.swift"],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
            ],
            linkerSettings: [
                .linkedLibrary("dash_spv_ffi"),
                .unsafeFlags([
                    "-L../target/aarch64-apple-ios-sim/release",
                    "-L../target/x86_64-apple-ios/release",
                    "-L../target/ios-simulator-universal/release",
                    "-L../target/release",
                    "-LExamples/DashHDWalletExample",
                    "-L."
                ])
            ]
        ),
        .target(
            name: "KeyWalletFFI",
            dependencies: [],
            path: "Sources/KeyWalletFFI",
            exclude: ["key_wallet_ffi.swift"],
            publicHeadersPath: ".",
            cSettings: [
                .headerSearchPath("."),
                .define("SWIFT_PACKAGE")
            ],
            linkerSettings: [
                .linkedLibrary("key_wallet_ffi"),
                .unsafeFlags([
                    "-L../target/aarch64-apple-ios-sim/release",
                    "-L../target/x86_64-apple-ios/release",
                    "-L../target/ios-simulator-universal/release",
                    "-L../target/release",
                    "-LExamples/DashHDWalletExample",
                    "-L."
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
            dependencies: ["DashSPVFFI"],
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