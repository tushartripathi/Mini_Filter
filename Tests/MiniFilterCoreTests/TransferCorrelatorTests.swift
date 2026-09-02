import XCTest
@testable import MiniFilterCore

final class TransferCorrelatorTests: XCTestCase {
    let pid: pid_t = 656
    let process = "WhatsApp"
    let t0 = Date(timeIntervalSince1970: 2_000_000)

    override func setUp() {
        super.setUp()
        TransferCorrelator.resetForTests()
    }

    override func tearDown() {
        TransferCorrelator.resetForTests()
        super.tearDown()
    }

    func testCloneUserFileIntoAppContainerIsUpload() {
        let transfer = TransferCorrelator.observe(
            event: "CLONE",
            path: Fixtures.desktopPNG,
            destination: Fixtures.whatsAppCopy,
            access: nil,
            pid: pid,
            process: process,
            at: t0
        )
        XCTAssertEqual(transfer?.direction, "upload")
        XCTAssertEqual(transfer?.path, Fixtures.desktopPNG)
    }

    func testOpenThenWriteIntoContainerIsUploadOfSource() {
        XCTAssertNil(
            TransferCorrelator.observe(
                event: "OPEN",
                path: Fixtures.desktopPNG,
                destination: nil,
                access: "read",
                pid: pid,
                process: process,
                at: t0
            )
        )
        let transfer = TransferCorrelator.observe(
            event: "WRITE",
            path: Fixtures.whatsAppContainer,
            destination: nil,
            access: nil,
            pid: pid,
            process: process,
            at: t0.addingTimeInterval(0.2)
        )
        XCTAssertEqual(transfer?.direction, "upload")
        XCTAssertEqual(transfer?.path, Fixtures.desktopPNG)
    }

    func testWriteToDownloadsIsDownload() {
        let transfer = TransferCorrelator.observe(
            event: "WRITE",
            path: Fixtures.downloadsPNG,
            destination: nil,
            access: nil,
            pid: pid,
            process: process,
            at: t0
        )
        XCTAssertEqual(transfer?.direction, "download")
        XCTAssertEqual(transfer?.path, Fixtures.downloadsPNG)
    }

    func testSameUploadIsDedupedWithinWindow() {
        XCTAssertNotNil(
            TransferCorrelator.recordUpload(
                path: Fixtures.desktopPNG,
                pid: pid,
                process: process,
                at: t0
            )
        )
        XCTAssertNil(
            TransferCorrelator.observe(
                event: "CLONE",
                path: Fixtures.desktopPNG,
                destination: Fixtures.whatsAppCopy,
                access: nil,
                pid: pid,
                process: process,
                at: t0.addingTimeInterval(1)
            ),
            "Later clone of the same send must not log a second UPLOAD"
        )
    }

    func testSameFileEmitsAgainAfterDedupeWindow() {
        XCTAssertNotNil(
            TransferCorrelator.recordUpload(
                path: Fixtures.desktopPNG,
                pid: pid,
                process: process,
                at: t0
            )
        )
        let again = TransferCorrelator.recordUpload(
            path: Fixtures.desktopPNG,
            pid: pid,
            process: process,
            at: t0.addingTimeInterval(15)
        )
        XCTAssertEqual(again?.direction, "upload")
        XCTAssertEqual(again?.path, Fixtures.desktopPNG)
    }

    func testRecentUploadDoesNotLookLikeDownload() {
        XCTAssertNotNil(
            TransferCorrelator.recordUpload(
                path: Fixtures.desktopPNG,
                pid: pid,
                process: process,
                at: t0
            )
        )
        XCTAssertNil(
            TransferCorrelator.observe(
                event: "WRITE",
                path: Fixtures.whatsAppCopy,
                destination: nil,
                access: nil,
                pid: pid,
                process: process,
                at: t0.addingTimeInterval(0.5)
            )
        )
    }
}
