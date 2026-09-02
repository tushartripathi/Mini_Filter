import XCTest
@testable import MiniFilterCore

final class VerdictCacheTests: XCTestCase {
    let path = Fixtures.desktopPNG
    let other = Fixtures.otherPNG
    let t0 = Date(timeIntervalSince1970: 1_000_000)

    func testAllowIsRememberedImmediately() {
        var cache = VerdictCache(allowReuseWindow: 2)
        cache.recordAllow(path: path, at: t0)
        XCTAssertTrue(cache.wasAllowed(path: path, now: t0))
        XCTAssertFalse(cache.isBlocked(path: path))
    }

    func testSameSendCloneWithinWindowIsStillAllowed() {
        var cache = VerdictCache(allowReuseWindow: 2)
        cache.recordAllow(path: path, at: t0)
        let cloneTime = t0.addingTimeInterval(0.4)
        XCTAssertTrue(
            cache.wasAllowed(path: path, now: cloneTime),
            "OPEN→CLONE of the same send must skip a second scan"
        )
    }

    func testReuploadAfterWindowExpiresIsNotAllowed() {
        var cache = VerdictCache(allowReuseWindow: 2)
        cache.recordAllow(path: path, at: t0)
        let reupload = t0.addingTimeInterval(2.0)
        XCTAssertFalse(
            cache.wasAllowed(path: path, now: reupload),
            "Attaching the same file again after the window must be scanned"
        )
        XCTAssertFalse(cache.wasAllowed(path: path, now: t0.addingTimeInterval(9)))
    }

    func testJustInsideWindowIsStillAllowed() {
        var cache = VerdictCache(allowReuseWindow: 2)
        cache.recordAllow(path: path, at: t0)
        XCTAssertTrue(cache.wasAllowed(path: path, now: t0.addingTimeInterval(1.999)))
    }

    func testDifferentFileIsIndependent() {
        var cache = VerdictCache(allowReuseWindow: 2)
        cache.recordAllow(path: path, at: t0)
        XCTAssertFalse(cache.wasAllowed(path: other, now: t0))
        XCTAssertFalse(cache.isBlocked(path: other))
    }

    func testDenySticksAndClearsAllow() {
        var cache = VerdictCache(allowReuseWindow: 2)
        cache.recordAllow(path: path, at: t0)
        cache.recordDeny(path: path)
        XCTAssertTrue(cache.isBlocked(path: path))
        XCTAssertFalse(cache.wasAllowed(path: path, now: t0))
        XCTAssertTrue(
            cache.isBlocked(path: path),
            "Deny must persist beyond the allow reuse window"
        )
        XCTAssertFalse(cache.wasAllowed(path: path, now: t0.addingTimeInterval(60)))
        XCTAssertTrue(cache.isBlocked(path: path))
    }

    func testUploadGateUsesTwoSecondWindow() {
        XCTAssertEqual(UploadGate.allowReuseWindow, 2.0)
    }
}
