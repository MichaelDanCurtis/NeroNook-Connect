// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "NeroConnect", platforms: [.macOS(.v14)], products: [
    .executable(name: "NeroConnect", targets: ["ConnectApp"]),
    .executable(name: "ConnectProbe", targets: ["ConnectProbe"]),
    .library(name: "ConnectCore", targets: ["ConnectCore"])
], dependencies: [.package(url: "https://github.com/supabase/supabase-swift.git", exact: "2.55.4")], targets: [
    .target(name: "ConnectCore", dependencies: [.product(name: "Auth", package: "supabase-swift")], swiftSettings: [.swiftLanguageMode(.v5)]),
    .executableTarget(name: "ConnectApp", dependencies: ["ConnectCore"], swiftSettings: [.swiftLanguageMode(.v5)]),
    .executableTarget(name: "ConnectProbe", dependencies: ["ConnectCore"], swiftSettings: [.swiftLanguageMode(.v5)]),
    .testTarget(name: "ConnectCoreTests", dependencies: ["ConnectCore"], swiftSettings: [.swiftLanguageMode(.v5)])
])
