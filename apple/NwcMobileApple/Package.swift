// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "NwcMobileApple",
  platforms: [
    .iOS(.v15),
    .macOS(.v13),
  ],
  products: [
    .library(name: "NwcMobileApple", targets: ["NwcMobileApple"])
  ],
  targets: [
    .target(name: "NwcMobileApple"),
    .testTarget(
      name: "NwcMobileAppleTests",
      dependencies: ["NwcMobileApple"]
    ),
  ]
)
