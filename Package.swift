// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CrypsiSwift",
    products: [
        .library(name: "CrypsiSwift", targets: ["CrypsiSwift"]),
    ],
    targets: [
        .target(name: "CCrypsi"),
        .target(name: "CrypsiSwift", 
            dependencies: [
                .target(name: "CCrypsi")
            ],
            swiftSettings: [
                .unsafeFlags(["-Xfrontend", "-validate-tbd-against-ir=none"])
            ]),
        .testTarget(
            name: "CrypsiSwiftTests",
            dependencies: ["CrypsiSwift"]),
    ]
)
