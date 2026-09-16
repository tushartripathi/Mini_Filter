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

    func testGroupContainerMediaReceiveIsNotDownloadScan() {
        let media =
            "/Users/work/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/Message/Media/171652964950141@lid/f/c/fcff7305-8c05-40d5-9678-c42e9b36b0ce.jpg"
        XCTAssertNil(
            TransferCorrelator.observe(
                event: "WRITE",
                path: media,
                destination: nil,
                access: nil,
                pid: pid,
                process: process,
                at: t0
            ),
            "WhatsApp in-app media must not start a download scan"
        )
        XCTAssertNil(
            TransferCorrelator.observe(
                event: "WRITE",
                path: Fixtures.whatsAppCopy,
                destination: nil,
                access: nil,
                pid: pid,
                process: process,
                at: t0.addingTimeInterval(1)
            )
        )
        // Upload into Group Containers still works.
        let upload = TransferCorrelator.observe(
            event: "CLONE",
            path: Fixtures.desktopPNG,
            destination: Fixtures.whatsAppCopy,
            access: nil,
            pid: pid,
            process: process,
            at: t0.addingTimeInterval(2)
        )
        XCTAssertEqual(upload?.direction, "upload")
        XCTAssertEqual(upload?.path, Fixtures.desktopPNG)
    }

    func testChromeReopenOfDownloadIsNotUpload() {
        XCTAssertNotNil(
            TransferCorrelator.observe(
                event: "WRITE",
                path: Fixtures.downloadsPNG,
                destination: nil,
                access: nil,
                pid: pid,
                process: "Google Chrome",
                at: t0
            )
        )
        XCTAssertTrue(
            TransferCorrelator.recentlyDownloaded(
                path: Fixtures.downloadsPNG,
                pid: pid,
                process: "Google Chrome",
                at: t0.addingTimeInterval(1)
            )
        )
        XCTAssertNil(
            TransferCorrelator.recordUpload(
                path: Fixtures.downloadsPNG,
                pid: pid,
                process: "Google Chrome",
                at: t0.addingTimeInterval(1)
            ),
            "Re-opening a file this process just saved is not an upload"
        )
        XCTAssertNotNil(
            TransferCorrelator.recordUpload(
                path: Fixtures.desktopPNG,
                pid: pid,
                process: "Google Chrome",
                at: t0.addingTimeInterval(1)
            )
        )
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
