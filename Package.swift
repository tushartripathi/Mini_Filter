// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "MiniFilter",
    platforms: [.macOS(.v13)],
    targets: [
        .target(
            name: "MiniFilterCore",
            path: "Sources/MiniFilter/Core",
            linkerSettings: [
                .linkedLibrary("bsm"),
                .linkedLibrary("EndpointSecurity"),
            ]
        ),
        .executableTarget(
            name: "MiniFilter",
            dependencies: ["MiniFilterCore"],
            path: "Sources/MiniFilter",
            exclude: ["Core"]
        ),
        .testTarget(
            name: "MiniFilterCoreTests",
            dependencies: ["MiniFilterCore"],
            path: "Tests/MiniFilterCoreTests"
        ),
    ]
)
