// swift-tools-version:6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "TunnelKit",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "TunnelKit",
            targets: ["TunnelKit"]
        ),
        .library(
            name: "TunnelKitOpenVPN",
            targets: ["TunnelKitOpenVPN"]
        ),
        .library(
            name: "TunnelKitOpenVPNAppExtension",
            targets: ["TunnelKitOpenVPNAppExtension"]
        ),
        .library(
            name: "TunnelKitWireGuard",
            targets: ["TunnelKitWireGuard"]
        ),
        .library(
            name: "TunnelKitWireGuardAppExtension",
            targets: ["TunnelKitWireGuardAppExtension"]
        ),
        .library(
            name: "TunnelKitCore",
            targets: ["TunnelKitCore"]
        ),
        .library(
            name: "TunnelKitWireGuardCore",
            targets: ["TunnelKitWireGuardCore"]
        ),
        .library(
            name: "TunnelKitWireGuardManager",
            targets: ["TunnelKitWireGuardManager"]
        ),
        .library(
            name: "__TunnelKitUtils",
            targets: ["__TunnelKitUtils"]
        ),
        .library(
            name: "TunnelKitLZO",
            targets: ["TunnelKitLZO"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/SwiftyBeaver/SwiftyBeaver", from: "2.1.1"),
        .package(
            url: "https://github.com/ridgelineinternational/wireguard-apple-xcframework",
            exact: "0.0.7"
        ),
        .package(
            url: "https://github.com/passepartoutvpn/openssl-apple",
            exact: "3.6.300"
        ),
    ],
    targets: [
        .target(
            name: "TunnelKit",
            dependencies: [
                "TunnelKitCore",
                "TunnelKitManager"
            ]
        ),
        .target(
            name: "TunnelKitCore",
            dependencies: [
                "__TunnelKitUtils",
                "CTunnelKitCore",
                "SwiftyBeaver"
            ]),
        .target(
            name: "TunnelKitManager",
            dependencies: [
                "SwiftyBeaver"
            ]),
        .target(
            name: "TunnelKitAppExtension",
            dependencies: [
                "TunnelKitCore"
            ]),
        .target(
            name: "TunnelKitOpenVPN",
            dependencies: [
                "TunnelKitOpenVPNCore",
                "TunnelKitOpenVPNManager"
            ]),
        //
        .target(
            name: "TunnelKitOpenVPNCore",
            dependencies: [
                "TunnelKitCore",
                "CTunnelKitOpenVPNCore",
                "CTunnelKitOpenVPNProtocol" // FIXME: remove dependency on TLSBox
            ]),
        .target(
            name: "TunnelKitOpenVPNManager",
            dependencies: [
                "TunnelKitManager",
                "TunnelKitOpenVPNCore"
            ]),
        .target(
            name: "TunnelKitOpenVPNProtocol",
            dependencies: [
                "TunnelKitOpenVPNCore",
                "CTunnelKitOpenVPNProtocol"
            ]),
        .target(
            name: "TunnelKitOpenVPNAppExtension",
            dependencies: [
                "TunnelKitAppExtension",
                "TunnelKitOpenVPNCore",
                "TunnelKitOpenVPNManager",
                "TunnelKitOpenVPNProtocol"
            ]),
        //
        .target(
            name: "TunnelKitWireGuard",
            dependencies: [
                "TunnelKitWireGuardCore",
                "TunnelKitWireGuardManager"
            ]),
        .target(
            name: "TunnelKitWireGuardCore",
            dependencies: [
                "__TunnelKitUtils",
                "TunnelKitCore",
                .product(name: "WireGuardKit", package: "wireguard-apple-xcframework"),
                "SwiftyBeaver"
            ]),
        .target(
            name: "TunnelKitWireGuardManager",
            dependencies: [
                "TunnelKitManager",
                "TunnelKitWireGuardCore"
            ]),
        .target(
            name: "TunnelKitWireGuardAppExtension",
            dependencies: [
                "TunnelKitWireGuardCore",
                "TunnelKitWireGuardManager"
            ]),
        .target(
            name: "TunnelKitLZO",
            dependencies: [],
            exclude: [
                "lib/COPYING",
                "lib/Makefile",
                "lib/README.LZO",
                "lib/testmini.c"
            ]),
        //
        .target(
            name: "CTunnelKitCore",
            dependencies: []),
        .target(
            name: "CTunnelKitOpenVPNCore",
            dependencies: []),
        .target(
            name: "CTunnelKitOpenVPNProtocol",
            dependencies: [
                "CTunnelKitCore",
                "CTunnelKitOpenVPNCore",
                .product(name: "openssl-apple", package: "openssl-apple")
            ]),
        .target(
            name: "__TunnelKitUtils",
            dependencies: []),
        //
        .testTarget(
            name: "TunnelKitCoreTests",
            dependencies: [
                "TunnelKitCore"
            ],
            exclude: [
                "RandomTests.swift",
                "RawPerformanceTests.swift",
                "RoutingTests.swift"
            ]),
        .testTarget(
            name: "TunnelKitOpenVPNTests",
            dependencies: [
                "TunnelKitOpenVPNCore",
                "TunnelKitOpenVPNAppExtension",
                "TunnelKitLZO"
            ],
            exclude: [
                "DataPathPerformanceTests.swift",
                "EncryptionPerformanceTests.swift"
            ],
            resources: [
                .process("Resources")
            ]),
        .testTarget(
            name: "TunnelKitLZOTests",
            dependencies: [
                "TunnelKitCore",
                "TunnelKitLZO"
            ]),
        .testTarget(
            name: "TunnelKitManagerTests",
            dependencies: [
                "TunnelKitManager"
            ]),
        .testTarget(
            name: "TunnelKitWireGuardTests",
            dependencies: [
                "TunnelKitWireGuardManager"
            ])
    ]
)

// The whole package is built in the Swift 6 language mode (see
// swift-tools-version above), so every first-party Swift target gets complete
// concurrency checking enforced as errors. No per-target StrictConcurrency
// opt-in is needed — the language mode subsumes it.
