import XCTest
@testable import MiniFilterCore

final class DownloadGateTests: XCTestCase {
    let path = Fixtures.downloadsPNG

    override func setUp() {
        super.setUp()
        DownloadGate.resetForTests()
        TransferCorrelator.resetForTests()
        FileScanner.simulatedVerdict = .allow
        FileScanner.delaySeconds = 17
    }

    override func tearDown() {
        DownloadGate.resetForTests()
        TransferCorrelator.resetForTests()
        FileScanner.simulatedVerdict = .allow
        FileScanner.delaySeconds = 17
        super.tearDown()
    }

    func testHoldsAccessUntilScanAllows() {
        FileScanner.delaySeconds = 0.05
        let stopped = expectation(description: "scan stop")
        XCTAssertTrue(
            DownloadGate.startScan(
                path: path,
                onStart: {},
                onStop: { verdict, waited in
                    XCTAssertEqual(verdict, .allow)
                    XCTAssertEqual(waited, 0.05, accuracy: 0.001)
                    stopped.fulfill()
                }
            )
        )
        XCTAssertTrue(DownloadGate.isPending(path))
        XCTAssertTrue(DownloadGate.shouldHoldAccess(path))
        XCTAssertFalse(DownloadGate.shouldDenyAccess(path), "Pending must hold, not deny")
        XCTAssertFalse(DownloadGate.startScan(path: path, onStart: {}, onStop: { _, _ in }))
        wait(for: [stopped], timeout: 1.0)
        XCTAssertFalse(DownloadGate.shouldHoldAccess(path))
        XCTAssertFalse(DownloadGate.shouldDenyAccess(path))
        XCTAssertTrue(DownloadGate.isCleared(path))
        XCTAssertFalse(DownloadGate.isPending(path))
    }

    func testWriteOnlyOpenAllowedDuringPendingScan() {
        FileScanner.delaySeconds = 0.05
        XCTAssertTrue(DownloadGate.startScan(path: path, onStart: {}, onStop: { _, _ in }))
        XCTAssertTrue(DownloadGate.shouldAllowWriteOnlyOpen(access: "write"))
        XCTAssertFalse(DownloadGate.shouldAllowWriteOnlyOpen(access: "read"))
        XCTAssertFalse(DownloadGate.shouldAllowWriteOnlyOpen(access: "read+write"))
        XCTAssertFalse(DownloadGate.shouldAllowWriteOnlyOpen(access: nil))
    }

    func testSafariWebKitHelpersSkipDownloadScan() {
        XCTAssertFalse(DownloadGate.shouldScanProcess("com.apple.WebKit.Networking"))
        XCTAssertFalse(DownloadGate.shouldScanProcess("com.apple.Safari.SandboxBroker"))
        XCTAssertFalse(DownloadGate.shouldScanProcess("Cursor Helper (Plugin)"))
        XCTAssertFalse(DownloadGate.shouldScanProcess("Cursor Helper"))
        XCTAssertTrue(DownloadGate.shouldScanProcess("Safari"))
        XCTAssertTrue(DownloadGate.shouldScanProcess("Google Chrome"))
        XCTAssertTrue(DownloadGate.shouldScanProcess("WhatsApp"))

        XCTAssertNil(
            TransferCorrelator.observe(
                event: "WRITE",
                path: path,
                destination: nil,
                access: nil,
                pid: 77,
                process: "com.apple.WebKit.Networking",
                at: Date(timeIntervalSince1970: 5_000_000)
            )
        )
        XCTAssertNil(
            TransferCorrelator.observe(
                event: "WRITE",
                path: path,
                destination: nil,
                access: nil,
                pid: 78,
                process: "com.apple.Safari.SandboxBroker",
                at: Date(timeIntervalSince1970: 5_000_001)
            )
        )
        XCTAssertEqual(
            TransferCorrelator.observe(
                event: "WRITE",
                path: path,
                destination: nil,
                access: nil,
                pid: 79,
                process: "Safari",
                at: Date(timeIntervalSince1970: 5_000_002)
            )?.direction,
            "download"
        )
    }

    func testDenyVerdictKeepsFileBlocked() {
        FileScanner.delaySeconds = 0.05
        FileScanner.simulatedVerdict = .deny
        let stopped = expectation(description: "scan stop")
        XCTAssertTrue(
            DownloadGate.startScan(
                path: path,
                onStart: {},
                onStop: { verdict, _ in
                    XCTAssertEqual(verdict, .deny)
                    stopped.fulfill()
                }
            )
        )
        wait(for: [stopped], timeout: 1.0)
        XCTAssertTrue(DownloadGate.isBlocked(path))
        XCTAssertTrue(DownloadGate.shouldDenyAccess(path))
        XCTAssertFalse(DownloadGate.shouldHoldAccess(path))
        XCTAssertFalse(DownloadGate.isCleared(path))
        XCTAssertFalse(
            DownloadGate.startScan(path: path, onStart: {}, onStop: { _, _ in }),
            "A denied download must not be scanned again in this session"
        )
    }

    /// `--scan-reject`: simulated scanner finds sensitive data and never unblocks.
    func testSensitiveDataFoundKeepsDownloadUnreadable() {
        FileScanner.delaySeconds = 0.05
        FileScanner.simulatedVerdict = .deny
        let other = Fixtures.desktopPNG
        var loggedVerdict: String?
        let stopped = expectation(description: "sensitive scan stop")

        XCTAssertNotNil(
            TransferCorrelator.observe(
                event: "WRITE",
                path: path,
                destination: nil,
                access: nil,
                pid: 1122,
                process: "Google Chrome",
                at: Date(timeIntervalSince1970: 3_000_000)
            )
        )

        XCTAssertTrue(
            DownloadGate.startScan(
                path: path,
                onStart: {},
                onStop: { verdict, waited in
                    loggedVerdict = verdict == .deny ? "blocked" : "allowed"
                    XCTAssertEqual(waited, 0.05, accuracy: 0.001)
                    stopped.fulfill()
                }
            )
        )
        XCTAssertTrue(DownloadGate.isPending(path))
        XCTAssertTrue(DownloadGate.shouldHoldAccess(path), "During scan, opens are held")
        XCTAssertFalse(DownloadGate.shouldDenyAccess(path), "During scan, do not deny (avoids permission dialog)")
        XCTAssertFalse(DownloadGate.shouldHoldAccess(other))

        wait(for: [stopped], timeout: 1.0)

        XCTAssertEqual(loggedVerdict, "blocked")
        XCTAssertFalse(DownloadGate.isPending(path))
        XCTAssertTrue(DownloadGate.isBlocked(path))
        XCTAssertTrue(DownloadGate.shouldDenyAccess(path), "Sensitive verdict must stick after SCAN STOP")
        XCTAssertFalse(DownloadGate.isCleared(path))
        XCTAssertFalse(DownloadGate.shouldDenyAccess(other), "Other files stay usable")

        DownloadGate.releasePending()
        XCTAssertTrue(
            DownloadGate.shouldDenyAccess(path),
            "Quit must not clear a completed deny (only in-flight pending)"
        )
    }

    func testPlanHoldFreezesWhenRemainingScanExceedsAuth() {
        let over = UploadGate.planHold(scanSeconds: 17, usableAuthSeconds: 13)
        XCTAssertTrue(over.needsFreeze)
        let under = UploadGate.planHold(scanSeconds: 5, usableAuthSeconds: 13)
        XCTAssertFalse(under.needsFreeze)
    }

    func testDownloadingAppIsExemptFromHoldViaRecentDownload() {
        FileScanner.delaySeconds = 0.05
        let t0 = Date(timeIntervalSince1970: 4_000_000)
        XCTAssertNotNil(
            TransferCorrelator.observe(
                event: "WRITE",
                path: path,
                destination: nil,
                access: nil,
                pid: 9001,
                process: "WhatsApp",
                at: t0
            )
        )
        XCTAssertTrue(
            DownloadGate.startScan(
                path: path,
                pid: 9001,
                process: "WhatsApp",
                onStart: {},
                onStop: { _, _ in }
            )
        )
        XCTAssertTrue(DownloadGate.isDownloader(path: path, pid: 9001, process: "WhatsApp"))
        XCTAssertTrue(
            DownloadGate.isDownloader(path: path, pid: 9002, process: "WhatsApp"),
            "Same app name with another pid must also be exempt"
        )
        XCTAssertFalse(DownloadGate.isDownloader(path: path, pid: 42, process: "Preview"))
        XCTAssertTrue(
            TransferCorrelator.recentlyDownloaded(
                path: path,
                pid: 9001,
                process: "WhatsApp",
                at: t0.addingTimeInterval(0.5)
            )
        )
        XCTAssertFalse(
            TransferCorrelator.recentlyDownloaded(
                path: path,
                pid: 42,
                process: "Preview",
                at: t0.addingTimeInterval(0.5)
            )
        )
    }
}
