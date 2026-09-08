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

    func testPlanHoldFreezesWhenScanExceedsAuthDeadline() {
        let over = UploadGate.planHold(scanSeconds: 20, usableAuthSeconds: 13)
        XCTAssertEqual(over.scanSeconds, 20)
        XCTAssertEqual(over.authSeconds, 13)
        XCTAssertTrue(over.needsFreeze)

        let under = UploadGate.planHold(scanSeconds: 10, usableAuthSeconds: 13)
        XCTAssertEqual(under.scanSeconds, 10)
        XCTAssertEqual(under.authSeconds, 10)
        XCTAssertFalse(under.needsFreeze)
    }
}
