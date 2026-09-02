// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "MiniFilter",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "MiniFilter",
            path: "Sources/MiniFilter",
            linkerSettings: [
                .linkedLibrary("bsm"),
                .linkedLibrary("EndpointSecurity"),
            ]
        )
    ]
)
