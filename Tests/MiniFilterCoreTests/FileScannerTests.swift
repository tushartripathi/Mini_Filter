import XCTest
@testable import MiniFilterCore

final class FileScannerTests: XCTestCase {
    override func tearDown() {
        FileScanner.simulatedVerdict = .allow
        super.tearDown()
    }

    func testDefaultDelayIsTenSeconds() {
        XCTAssertEqual(FileScanner.delaySeconds, 10)
    }

    func testScanCallsStartThenAllow() {
        let started = expectation(description: "scan start")
        let stopped = expectation(description: "scan stop")
        var verdict: FileScanner.Verdict?
        FileScanner.simulatedVerdict = .allow
        FileScanner.scan(delay: 0.05, onStart: {
            started.fulfill()
        }, onStop: { result in
            verdict = result
            stopped.fulfill()
        })
        wait(for: [started, stopped], timeout: 1.0, enforceOrder: true)
        XCTAssertEqual(verdict, .allow)
    }

    func testScanRejectReturnsDeny() {
        let stopped = expectation(description: "scan stop")
        var verdict: FileScanner.Verdict?
        FileScanner.simulatedVerdict = .deny
        FileScanner.scan(delay: 0.05, onStart: {}, onStop: { result in
            verdict = result
            stopped.fulfill()
        })
        wait(for: [stopped], timeout: 1.0)
        XCTAssertEqual(verdict, .deny)
    }
}
