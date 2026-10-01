// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "runner-manager-macos-vm",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "runner-manager-macos-vm", targets: ["RunnerManagerMacOSVM"]),
    ],
    targets: [
        .executableTarget(
            name: "RunnerManagerMacOSVM",
            linkerSettings: [
                .linkedFramework("Virtualization"),
                .linkedFramework("Security"),
            ]
        ),
        .testTarget(
            name: "RunnerManagerMacOSVMTests",
            dependencies: ["RunnerManagerMacOSVM"]
        ),
    ]
)
