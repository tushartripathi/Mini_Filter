import XCTest
@testable import MiniFilterCore

final class FileClassifierTests: XCTestCase {
    func testUserFacingAllowlist() {
        XCTAssertTrue(FileClassifier.isUserFacingFile(path: Fixtures.desktopPNG))
        XCTAssertTrue(FileClassifier.isUserFacingFile(path: Fixtures.desktopPDF))
        XCTAssertTrue(FileClassifier.isUserFacingFile(path: Fixtures.documentsDOCX))
        XCTAssertFalse(FileClassifier.isUserFacingFile(path: Fixtures.blob))
        XCTAssertFalse(FileClassifier.isUserFacingFile(path: "/Users/work/Desktop/noext"))
    }

    func testUserSourceIsDesktopDocumentsNotSandbox() {
        XCTAssertTrue(FileClassifier.isUserSource(path: Fixtures.desktopPNG))
        XCTAssertTrue(FileClassifier.isUserSource(path: Fixtures.documentsDOCX))
        XCTAssertTrue(FileClassifier.isUserSource(path: Fixtures.iCloudPDF))
        XCTAssertFalse(FileClassifier.isUserSource(path: Fixtures.whatsAppCopy))
        XCTAssertFalse(FileClassifier.isUserSource(path: Fixtures.appBundle))
        XCTAssertFalse(FileClassifier.isUserSource(path: Fixtures.blob))
        XCTAssertFalse(FileClassifier.isUserSource(path: "/usr/share/photo.png"))
    }

    func testAppContainerAndStaging() {
        XCTAssertTrue(FileClassifier.isAppContainer(path: Fixtures.whatsAppCopy))
        XCTAssertTrue(FileClassifier.isAppContainer(path: Fixtures.whatsAppStaging))
        XCTAssertTrue(FileClassifier.isAppMediaStore(path: Fixtures.whatsAppCopy))
        XCTAssertTrue(FileClassifier.isAppStaging(path: Fixtures.whatsAppStaging))
        XCTAssertFalse(FileClassifier.isAppContainer(path: Fixtures.desktopPNG))
        XCTAssertFalse(FileClassifier.isAppStaging(path: Fixtures.desktopPNG))
    }

    func testUserDestination() {
        XCTAssertTrue(FileClassifier.isUserDestination(path: Fixtures.downloadsPNG))
        XCTAssertTrue(FileClassifier.isUserDestination(path: Fixtures.desktopPNG))
        XCTAssertFalse(FileClassifier.isUserDestination(path: Fixtures.whatsAppCopy))
        XCTAssertFalse(FileClassifier.isUserDestination(path: Fixtures.blob))
    }
}
