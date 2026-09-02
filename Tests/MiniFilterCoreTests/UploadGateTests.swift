import XCTest
@testable import MiniFilterCore

final class UploadGateTests: XCTestCase {
    func testGatesUserAppsNotFinderOrSpotlight() {
        XCTAssertTrue(UploadGate.shouldGate(process: "WhatsApp"))
        XCTAssertTrue(UploadGate.shouldGate(process: "Google Chrome"))
        XCTAssertTrue(UploadGate.shouldGate(process: "Mail"))
        XCTAssertTrue(UploadGate.shouldGate(process: "Slack"))
        XCTAssertFalse(UploadGate.shouldGate(process: "Finder"))
        XCTAssertFalse(UploadGate.shouldGate(process: "QuickLookUIService"))
        XCTAssertFalse(UploadGate.shouldGate(process: "mds"))
        XCTAssertFalse(UploadGate.shouldGate(process: "mdworker"))
        XCTAssertFalse(UploadGate.shouldGate(process: "MiniFilter"))
    }

    func testHoldsReadOfUserSource() {
        XCTAssertTrue(UploadGate.shouldHoldOpen(path: Fixtures.desktopPNG, access: "read"))
        XCTAssertTrue(UploadGate.shouldHoldOpen(path: Fixtures.desktopPNG, access: "read+write"))
        XCTAssertTrue(UploadGate.shouldHoldOpen(path: Fixtures.desktopPNG, access: nil))
        XCTAssertFalse(UploadGate.shouldHoldOpen(path: Fixtures.desktopPNG, access: "write"))
        XCTAssertFalse(UploadGate.shouldHoldOpen(path: Fixtures.whatsAppCopy, access: "read"))
        XCTAssertFalse(UploadGate.shouldHoldOpen(path: Fixtures.blob, access: "read"))
    }

    func testHoldsCopyIntoAppContainerOnly() {
        XCTAssertTrue(
            UploadGate.shouldHoldCopy(source: Fixtures.desktopPNG, destination: Fixtures.whatsAppCopy)
        )
        XCTAssertFalse(
            UploadGate.shouldHoldCopy(source: Fixtures.desktopPNG, destination: Fixtures.downloadsPNG)
        )
        XCTAssertFalse(
            UploadGate.shouldHoldCopy(source: Fixtures.desktopPNG, destination: nil)
        )
        XCTAssertFalse(
            UploadGate.shouldHoldCopy(source: Fixtures.whatsAppCopy, destination: Fixtures.whatsAppCopy)
        )
    }
}
