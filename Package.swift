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
                .linkedFramework("AppKit"),
                .linkedFramework("ApplicationServices"),
                .linkedFramework("CoreGraphics"),
                .linkedFramework("SystemConfiguration"),
            ]
        ),
        .executableTarget(
            name: "MiniFilter",
            dependencies: ["MiniFilterCore"],
            path: "Sources/MiniFilter",
            exclude: ["Core"]
        ),
        .executableTarget(
            name: "MiniFilterTabHelper",
            dependencies: ["MiniFilterCore"],
            path: "Sources/MiniFilterTabHelper",
            exclude: ["Info.plist"],
            linkerSettings: [
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT",
                    "-Xlinker", "__info_plist",
                    "-Xlinker", "Sources/MiniFilterTabHelper/Info.plist",
                ])
            ]
        ),
        .testTarget(
            name: "MiniFilterCoreTests",
            dependencies: ["MiniFilterCore"],
            path: "Tests/MiniFilterCoreTests"
        ),
    ]
)
