import XCTest
@testable import MiniFilterCore

final class EndpointSecurityMonitorTests: XCTestCase {
    func testSafariFilterIncludesWebKitHelpers() {
        XCTAssertTrue(
            EndpointSecurityMonitor.matchesProcess(
                name: "Safari",
                signingID: "com.apple.Safari",
                filters: ["safari"]
            )
        )
        XCTAssertTrue(
            EndpointSecurityMonitor.matchesProcess(
                name: "com.apple.WebKit.WebContent",
                signingID: "com.apple.WebKit.WebContent",
                filters: ["safari"]
            )
        )
        XCTAssertTrue(
            EndpointSecurityMonitor.matchesProcess(
                name: "com.apple.WebKit.Networking",
                signingID: "com.apple.WebKit.Networking",
                filters: ["safari"]
            )
        )
        XCTAssertFalse(
            EndpointSecurityMonitor.matchesProcess(
                name: "Google Chrome",
                signingID: "com.google.Chrome",
                filters: ["safari"]
            )
        )
    }

    func testSystemMuteDoesNotHideSafariExecutables() {
        XCTAssertTrue(EndpointSecurityMonitor.mutedTargetPrefixes.contains("/System/"))
        XCTAssertFalse(EndpointSecurityMonitor.mutedProcessPrefixes.contains("/System/"))
        XCTAssertFalse(
            EndpointSecurityMonitor.mutedProcessPrefixes.contains {
                "/System/Cryptexes/App/System/Applications/Safari.app".hasPrefix($0)
            }
        )
        XCTAssertFalse(
            EndpointSecurityMonitor.mutedProcessPrefixes.contains {
                "/System/Library/Frameworks/WebKit.framework".hasPrefix($0)
            }
        )
    }
}
