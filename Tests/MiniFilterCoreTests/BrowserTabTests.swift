import Darwin
import XCTest
@testable import MiniFilterCore

final class BrowserTabTests: XCTestCase {
    func testMapsChromeAndHelpersToScriptableApp() {
        XCTAssertEqual(BrowserTab.catalog(for: "Google Chrome")?.app, "Google Chrome")
        XCTAssertEqual(BrowserTab.catalog(for: "Google Chrome Helper")?.app, "Google Chrome")
        XCTAssertEqual(BrowserTab.catalog(for: "Google Chrome Helper (Renderer)")?.app, "Google Chrome")
        XCTAssertEqual(BrowserTab.catalog(for: "Google Chrome Canary")?.app, "Google Chrome Canary")
        XCTAssertEqual(BrowserTab.catalog(for: "Safari")?.app, "Safari")
        XCTAssertEqual(BrowserTab.catalog(for: "com.apple.WebKit.WebContent")?.app, "Safari")
        XCTAssertEqual(BrowserTab.catalog(for: "com.apple.WebKit.Networking")?.app, "Safari")
        XCTAssertEqual(BrowserTab.catalog(for: "com.apple.WebKit.WebContent.EnhancedSecurity")?.app, "Safari")
        XCTAssertNil(BrowserTab.catalog(for: "filecoordinationd"))
        XCTAssertEqual(BrowserTab.catalog(for: "Microsoft Edge")?.app, "Microsoft Edge")
        XCTAssertEqual(BrowserTab.catalog(for: "Brave Browser")?.app, "Brave Browser")
        XCTAssertEqual(BrowserTab.catalog(for: "Arc")?.app, "Arc")
        XCTAssertNil(BrowserTab.catalog(for: "WhatsApp"))
        XCTAssertNil(BrowserTab.catalog(for: "Finder"))
        XCTAssertNil(BrowserTab.catalog(for: "Archive Utility"))
    }

    func testParsesAppleScriptTitleAndURL() {
        let page = BrowserTab.parseReply("Mini_Filter\u{1e}https://github.com/acme/Mini_Filter")
        XCTAssertEqual(page?.title, "Mini_Filter")
        XCTAssertEqual(page?.url, "https://github.com/acme/Mini_Filter")
    }

    func testParseIgnoresBlankReply() {
        XCTAssertNil(BrowserTab.parseReply(""))
        XCTAssertNil(BrowserTab.parseReply("\n"))
        XCTAssertNil(BrowserTab.parseReply("\u{1e}"))
    }

    func testLogSuffixIncludesTabAndURL() {
        let page = BrowserTab.Page(title: "Inbox", url: "https://mail.google.com/")
        XCTAssertEqual(
            BrowserTab.logSuffix(page),
            "  tab 'Inbox'  https://mail.google.com/"
        )
        XCTAssertEqual(BrowserTab.logSuffix(nil), "")
        XCTAssertEqual(BrowserTab.logSuffix(BrowserTab.Page(title: nil, url: nil)), "")
    }

    func testHistoryPathCandidatesIncludeCrdownload() {
        XCTAssertEqual(
            BrowserTab.historyPathCandidates("/Users/work/Downloads/a.png"),
            ["/Users/work/Downloads/a.png", "/Users/work/Downloads/a.png.crdownload"]
        )
        XCTAssertEqual(
            BrowserTab.historyPathCandidates("/Users/work/Downloads/a.png.crdownload"),
            ["/Users/work/Downloads/a.png.crdownload", "/Users/work/Downloads/a.png"]
        )
    }

    func testHistoryLookupFindsTabForDownloadPath() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = dir.appending(path: "History")
        let sql = """
        CREATE TABLE downloads (current_path TEXT, target_path TEXT, tab_url TEXT, start_time INTEGER);
        CREATE TABLE urls (url TEXT, title TEXT);
        INSERT INTO downloads VALUES (
          '/tmp/report.crdownload',
          '/tmp/report.pdf',
          'https://example.com/files',
          100
        );
        INSERT INTO urls VALUES ('https://example.com/files', 'Files');
        """
        let sqlite = Process()
        sqlite.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        sqlite.arguments = [db.path]
        let pipe = Pipe()
        sqlite.standardInput = pipe
        sqlite.standardOutput = FileHandle.nullDevice
        sqlite.standardError = FileHandle.nullDevice
        try sqlite.run()
        try pipe.fileHandleForWriting.write(contentsOf: Data(sql.utf8))
        try pipe.fileHandleForWriting.close()
        sqlite.waitUntilExit()
        XCTAssertEqual(sqlite.terminationStatus, 0)

        let page = BrowserTab.pageFromHistory(database: db, filePath: "/tmp/report.pdf")
        XCTAssertEqual(page?.url, "https://example.com/files")
        XCTAssertEqual(page?.title, "Files")
    }

    func testSessionFixtureYieldsActiveTab() {
        let data = ChromiumSession.makeFixture(
            tab: 42,
            index: 0,
            url: "https://mail.google.com/",
            title: "Inbox"
        )
        let page = ChromiumSession.activePage(data: data)
        XCTAssertEqual(page?.url, "https://mail.google.com/")
        XCTAssertEqual(page?.title, "Inbox")
    }

    func testSessionPicksMostRecentlyActiveTab() {
        var first = ChromiumSession.makeFixture(
            tab: 1,
            index: 0,
            url: "https://example.com/old",
            title: "Old",
            lastActive: 10
        )
        let second = ChromiumSession.makeFixture(
            tab: 2,
            index: 0,
            url: "https://github.com/acme/Mini_Filter",
            title: "Mini_Filter",
            lastActive: 99
        )
        // Drop the SNSS header from the second blob and append its commands.
        first.append(second.dropFirst(8))
        let page = ChromiumSession.activePage(data: first)
        XCTAssertEqual(page?.url, "https://github.com/acme/Mini_Filter")
        XCTAssertEqual(page?.title, "Mini_Filter")
    }

    func testSkipsFileDialogAndBareAppTitles() {
        XCTAssertNil(BrowserTab.cleanedWindowTitle("Open", app: "Google Chrome"))
        XCTAssertNil(BrowserTab.cleanedWindowTitle("Save", app: "Google Chrome"))
        XCTAssertNil(BrowserTab.cleanedWindowTitle("Save As…", app: "Safari"))
        XCTAssertNil(BrowserTab.cleanedWindowTitle("Open File", app: "Safari"))
        XCTAssertNil(BrowserTab.cleanedWindowTitle("", app: "Google Chrome"))
        XCTAssertNil(BrowserTab.cleanedWindowTitle("Google Chrome", app: "Google Chrome"))
        XCTAssertNil(BrowserTab.cleanedWindowTitle(" - Google Chrome", app: "Google Chrome"))
        XCTAssertEqual(
            BrowserTab.cleanedWindowTitle("Inbox - Google Chrome", app: "Google Chrome"),
            "Inbox"
        )
        XCTAssertEqual(
            BrowserTab.cleanedWindowTitle("Inbox - Safari", app: "Safari"),
            "Inbox"
        )
        XCTAssertEqual(
            BrowserTab.pickWindowTitle(
                windows: [
                    (pid: 30410, name: "Open"),
                    (pid: 30410, name: "Save"),
                    (pid: 30410, name: ""),
                    (pid: 30410, name: "Google Chrome"),
                    (pid: 1200, name: "Inbox - Google Chrome"),
                ],
                owners: [30410, 1200],
                app: "Google Chrome"
            ),
            "Inbox"
        )
    }

    func testPidChainWalksChromeHelperToBrowser() {
        let parents: [pid_t: pid_t] = [
            30410: 1200,
            1200: 1,
        ]
        XCTAssertEqual(
            BrowserTab.pidChain(starting: 30410, parentOf: { parents[$0] }),
            [30410, 1200, 1]
        )
        XCTAssertEqual(
            BrowserTab.pidChain(starting: 1200, parentOf: { parents[$0] }),
            [1200, 1]
        )
        XCTAssertEqual(
            BrowserTab.pidChain(starting: 42, parentOf: { _ in nil }),
            [42]
        )
        let owners = BrowserTab.axOwnerPIDs(eventPid: 4472, app: "Safari")
        XCTAssertTrue(owners.contains(4472))
    }

    func testQueryTimeoutReturnsNil() throws {
        let path = "/tmp/minifilter-tabhelper-test-\(getpid())-\(UUID().uuidString).sock"
        let server = try listenUnix(path)
        defer {
            close(server)
            unlink(path)
        }

        DispatchQueue.global().async {
            let client = accept(server, nil, nil)
            if client >= 0 {
                Thread.sleep(forTimeInterval: 0.5)
                close(client)
            }
        }

        let start = Date()
        switch TabHelper.query(pid: 30410, process: "Google Chrome", socketPath: path, timeout: 0.2) {
        case .answered(let page):
            XCTAssertNil(page)
        case .unreachable:
            XCTFail("connected helper should time out, not be unreachable")
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.45)
    }

    func testQueryUnreachableWithoutSocket() {
        let path = "/tmp/minifilter-tabhelper-missing-\(UUID().uuidString).sock"
        unlink(path)
        switch TabHelper.query(pid: 1, process: "Google Chrome", socketPath: path, timeout: 0.2) {
        case .answered:
            XCTFail("missing socket should be unreachable")
        case .unreachable:
            break
        }
    }

    func testQueryDecodesHelperReply() throws {
        let path = "/tmp/minifilter-tabhelper-ok-\(getpid())-\(UUID().uuidString).sock"
        let server = try listenUnix(path)
        defer {
            close(server)
            unlink(path)
        }

        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            let client = accept(server, nil, nil)
            guard client >= 0 else {
                group.leave()
                return
            }
            var buf = [UInt8](repeating: 0, count: 512)
            _ = Darwin.read(client, &buf, buf.count)
            let reply = Data("{\"title\":\"Inbox\",\"url\":\"https://mail.google.com/\"}\n".utf8)
            _ = reply.withUnsafeBytes { Darwin.write(client, $0.baseAddress, reply.count) }
            close(client)
            group.leave()
        }

        switch TabHelper.query(pid: 30410, process: "Google Chrome", socketPath: path, timeout: 0.3) {
        case .answered(let page):
            XCTAssertEqual(page?.title, "Inbox")
            XCTAssertEqual(page?.url, "https://mail.google.com/")
        case .unreachable:
            XCTFail("helper replied")
        }
        _ = group.wait(timeout: .now() + 2)
    }

    func testLogSuffixUnchangedWithHelperPage() {
        let page = BrowserTab.Page(title: "Inbox", url: "https://mail.google.com/")
        XCTAssertEqual(
            BrowserTab.logSuffix(page),
            "  tab 'Inbox'  https://mail.google.com/"
        )
        XCTAssertEqual(BrowserTab.logSuffix(nil), "")
        XCTAssertEqual(BrowserTab.logSuffix(BrowserTab.Page(title: nil, url: nil)), "")
    }

    private func listenUnix(_ path: String) throws -> Int32 {
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let maxPath = MemoryLayout.size(ofValue: addr.sun_path)
        path.withCString { src in
            withUnsafeMutablePointer(to: &addr.sun_path) { dst in
                dst.withMemoryRebound(to: CChar.self, capacity: maxPath) { dstChar in
                    _ = strncpy(dstChar, src, maxPath)
                }
            }
        }
        let bound = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sock in
                Darwin.bind(fd, sock, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        XCTAssertEqual(bound, 0)
        XCTAssertEqual(Darwin.listen(fd, 4), 0)
        return fd
    }
}
