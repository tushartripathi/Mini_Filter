import AppKit
import ApplicationServices
import CoreGraphics
import Darwin
import Foundation
import SystemConfiguration

/// Best-effort tab title + URL for browser file transfers.
///
/// Endpoint Security only sees the process. Chrome/Safari expose the front
/// tab over AppleScript; Chromium downloads also record `tab_url` in History.
/// Lookups are timed so AUTH replies are never blocked on a hung script.
enum BrowserTab {
    struct Page: Equatable {
        var title: String?
        var url: String?

        var isEmpty: Bool { title == nil && url == nil }
    }

    private static let lock = NSLock()
    private static var cache: [pid_t: (page: Page, at: Date)] = [:]
    private static let cacheTTL: TimeInterval = 2.5
    private static let separator = "\u{1e}"
    private static let separatorChar = Character("\u{1e}")

    /// Known browsers → AppleScript app name and Chromium user-data folder.
    /// Longer names first so Canary / helpers match before "Chrome".
    static let catalogs: [(process: String, app: String, userData: String?)] = [
        ("google chrome canary", "Google Chrome Canary", "Google/Chrome Canary"),
        ("google chrome", "Google Chrome", "Google/Chrome"),
        ("brave browser", "Brave Browser", "BraveSoftware/Brave-Browser"),
        ("microsoft edge", "Microsoft Edge", "Microsoft Edge"),
        ("safari technology preview", "Safari Technology Preview", nil),
        ("chromium", "Chromium", "Chromium"),
        ("vivaldi", "Vivaldi", "Vivaldi"),
        ("opera", "Opera", "com.operasoftware.Opera"),
        ("firefox", "Firefox", nil),
        ("safari", "Safari", nil),
        ("arc", "Arc", "Arc/User Data"),
    ]

    static func catalog(for process: String) -> (app: String, userData: String?)? {
        let name = process.lowercased()
        for entry in catalogs {
            if name == entry.process
                || name.hasPrefix(entry.process + " ")
                || name.hasPrefix(entry.process + "-") {
                return (entry.app, entry.userData)
            }
        }
        // WebKit XPCs (`com.apple.WebKit.WebContent`, Networking, …) do the
        // file open; the scriptable app is still Safari.
        if name.contains("webkit") {
            return ("Safari", nil)
        }
        return nil
    }

    static func parseReply(_ raw: String) -> Page? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        let parts = text.split(separator: separatorChar, omittingEmptySubsequences: false)
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
        let title: String?
        let url: String?
        if parts.count >= 2 {
            title = parts[0].isEmpty ? nil : parts[0]
            url = parts[1].isEmpty ? nil : parts[1]
        } else if looksLikeURL(text) {
            title = nil
            url = text
        } else {
            title = text
            url = nil
        }
        let page = Page(title: title, url: url)
        return page.isEmpty ? nil : page
    }

    /// `  tab 'Title'  https://example.com` — empty when we have no page.
    static func logSuffix(_ page: Page?) -> String {
        guard let page, !page.isEmpty else { return "" }
        var parts: [String] = []
        if let title = page.title, !title.isEmpty {
            parts.append("tab \(quote(title))")
        }
        if let url = page.url, !url.isEmpty {
            parts.append(url)
        }
        guard !parts.isEmpty else { return "" }
        return "  " + parts.joined(separator: "  ")
    }

    /// Front tab (and, for Chromium downloads, History `tab_url`) for this PID.
    static func current(
        process: String,
        pid: pid_t,
        path: String? = nil,
        direction: String? = nil
    ) -> Page? {
        lock.lock()
        if let hit = cache[pid], Date().timeIntervalSince(hit.at) < cacheTTL {
            lock.unlock()
            return hit.page
        }
        lock.unlock()

        guard let spec = catalog(for: process) else { return nil }

        var page: Page?
        if direction == "download", let path, let userData = spec.userData {
            page = pageFromChromiumHistory(userData: userData, filePath: path)
        }
        if (page?.url == nil || page?.title == nil), let userData = spec.userData {
            if let session = pageFromChromiumSession(userData: userData) {
                page = merge(history: page, live: session)
            }
        }
        if page?.url == nil || page?.title == nil {
            if let live = liveLookup(process: process, pid: pid) {
                page = merge(history: page, live: live)
            }
        }

        if let page, !page.isEmpty {
            lock.lock()
            cache[pid] = (page, Date())
            lock.unlock()
            return page
        }
        return page
    }

    static func pageFromHistory(database: URL, filePath: String) -> Page? {
        let candidates = historyPathCandidates(filePath)
        guard !candidates.isEmpty else { return nil }
        let quoted = candidates.map { "'\(sqlEscape($0))'" }.joined(separator: ", ")
        let sql = """
        SELECT IFNULL(u.title, ''), IFNULL(d.tab_url, '')
        FROM downloads d
        LEFT JOIN urls u ON u.url = d.tab_url
        WHERE d.target_path IN (\(quoted)) OR d.current_path IN (\(quoted))
        ORDER BY d.start_time DESC
        LIMIT 1;
        """
        let fileArg = "file:\(database.path)?mode=ro"
        guard let output = run(
            "/usr/bin/sqlite3",
            arguments: ["-readonly", "-batch", "-noheader", "-separator", separator, fileArg, sql],
            asUser: false,
            timeout: 0.4
        ) else { return nil }
        return parseReply(output)
    }

    /// Live title/url keyed by the ES event PID (not the frontmost app).
    /// When the user-level helper is listening, TCC runs there; otherwise
    /// the in-process CGWindow / AppleScript / AX path is used.
    static func liveLookup(process: String, pid: pid_t) -> Page? {
        if TabHelper.socketExists() {
            switch TabHelper.query(pid: pid, process: process) {
            case .answered(let page):
                return page
            case .unreachable:
                break
            }
        }
        return livePage(process: process, pid: pid)
    }

    /// AX window title for the ES event PID. No Screen Recording / Automation.
    static func livePage(process: String, pid: pid_t) -> Page? {
        guard let spec = catalog(for: process) else { return nil }
        let title = axWindowTitle(for: pid, app: spec.app)
        let page = Page(title: title, url: nil)
        return page.isEmpty ? nil : page
    }

    static func pidChain(
        starting pid: pid_t,
        maxDepth: Int = 4,
        parentOf: (pid_t) -> pid_t? = { parentPID(of: $0) }
    ) -> [pid_t] {
        var pids = [pid]
        var current = pid
        var seen: Set<pid_t> = [pid]
        for _ in 0..<maxDepth {
            guard let parent = parentOf(current), parent > 0, seen.insert(parent).inserted else {
                break
            }
            pids.append(parent)
            current = parent
        }
        return pids
    }

    /// Drop file-dialog chrome and ` - Google Chrome` / ` - Safari` suffixes.
    static func cleanedWindowTitle(_ raw: String, app: String) -> String? {
        var name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return nil }
        let suffix = " - \(app)"
        if name.hasSuffix(suffix) {
            name = String(name.dropLast(suffix.count))
                .trimmingCharacters(in: .whitespacesAndNewlines)
        } else if name.hasSuffix(app) {
            name = String(name.dropLast(app.count))
                .trimmingCharacters(in: .whitespacesAndNewlines.union(CharacterSet(charactersIn: "-")))
        }
        guard !name.isEmpty, name.caseInsensitiveCompare(app) != .orderedSame else {
            return nil
        }
        if isFileDialogTitle(name) { return nil }
        return name
    }

    static func isFileDialogTitle(_ raw: String) -> Bool {
        let folded = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "…", with: "...")
            .lowercased()
        switch folded {
        case "open", "save", "save as", "save as...",
             "open file", "save file", "open files":
            return true
        default:
            return false
        }
    }

    static func pickWindowTitle(
        windows: [(pid: pid_t, name: String)],
        owners: [pid_t],
        app: String
    ) -> String? {
        for owner in owners {
            for window in windows where window.pid == owner {
                if let title = cleanedWindowTitle(window.name, app: app) {
                    return title
                }
            }
        }
        return nil
    }

    // MARK: - Internals

    private static func merge(history: Page?, live: Page) -> Page {
        guard let history else { return live }
        let url = history.url ?? live.url
        let title: String?
        if let historyTitle = history.title, !historyTitle.isEmpty {
            title = historyTitle
        } else if history.url == nil || history.url == live.url {
            title = live.title
        } else {
            title = live.title
        }
        return Page(title: title, url: url)
    }

    private static func appleScriptPage(app: String, timeout: TimeInterval) -> Page? {
        // Firefox has no useful tab URL dictionary.
        guard app != "Firefox" else { return nil }
        guard isRunning(app: app) else { return nil }
        let script: String
        if app == "Safari" || app == "Safari Technology Preview" {
            script = """
            with timeout of 1 seconds
              tell application "\(app)"
                if (count of windows) is 0 then return ""
                set t to current tab of front window
                return (name of t) & "\(separator)" & (URL of t)
              end tell
            end timeout
            """
        } else {
            script = """
            with timeout of 1 seconds
              tell application "\(app)"
                if (count of windows) is 0 then return ""
                set t to active tab of front window
                return (title of t) & "\(separator)" & (URL of t)
              end tell
            end timeout
            """
        }
        guard let output = run(
            "/usr/bin/osascript",
            arguments: ["-e", script],
            asUser: true,
            timeout: timeout
        ) else {
            return nil
        }
        return parseReply(output)
    }

    private static func isRunning(app: String) -> Bool {
        NSWorkspace.shared.runningApplications.contains { $0.localizedName == app }
    }

    private static func pageFromChromiumHistory(userData: String, filePath: String) -> Page? {
        for dir in chromiumProfileDirectories(userData: userData) {
            let db = dir.appending(path: "History")
            guard FileManager.default.fileExists(atPath: db.path) else { continue }
            if let page = pageFromHistory(database: db, filePath: filePath) {
                return page
            }
        }
        return nil
    }

    private static func pageFromChromiumSession(userData: String) -> Page? {
        for dir in chromiumProfileDirectories(userData: userData) {
            let sessions = dir.appending(path: "Sessions")
            guard let file = ChromiumSession.latestSessionFile(in: sessions),
                  let page = ChromiumSession.activePage(file: file)
            else { continue }
            return page
        }
        return nil
    }

    static func historyPathCandidates(_ path: String) -> [String] {
        var paths = [path]
        if path.hasSuffix(".crdownload") {
            paths.append(String(path.dropLast(".crdownload".count)))
        } else {
            paths.append(path + ".crdownload")
        }
        return paths
    }

    private static func chromiumProfileDirectories(userData: String) -> [URL] {
        let root = userHome.appending(path: "Library/Application Support/\(userData)")
        var profiles: [String] = []
        if let last = lastUsedProfile(userDataRoot: root) {
            profiles.append(last)
        }
        profiles.append("Default")
        for i in 1...5 { profiles.append("Profile \(i)") }
        var seen = Set<String>()
        return profiles.compactMap { name in
            guard seen.insert(name).inserted else { return nil }
            let dir = root.appending(path: name)
            return FileManager.default.fileExists(atPath: dir.path) ? dir : nil
        }
    }

    private static func lastUsedProfile(userDataRoot: URL) -> String? {
        let localState = userDataRoot.appending(path: "Local State")
        guard let data = try? Data(contentsOf: localState),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let profile = json["profile"] as? [String: Any],
              let last = profile["last_used"] as? String,
              !last.isEmpty
        else { return nil }
        return last
    }

    private static func windowTitle(for pid: pid_t, app: String) -> String? {
        let owners = pidChain(starting: pid)
        guard let list = CGWindowListCopyWindowInfo(
            [.optionOnScreenOnly, .excludeDesktopElements],
            kCGNullWindowID
        ) as? [[String: Any]] else { return nil }

        var windows: [(pid: pid_t, name: String)] = []
        windows.reserveCapacity(list.count)
        for info in list {
            guard let windowPID = info[kCGWindowOwnerPID as String] as? pid_t,
                  let name = info[kCGWindowName as String] as? String
            else { continue }
            windows.append((windowPID, name))
        }
        return pickWindowTitle(windows: windows, owners: owners, app: app)
    }

    private static func axWindowTitle(for pid: pid_t, app: String) -> String? {
        // Safari file opens arrive as WebKit.WebContent. That XPC is often
        // parented by launchd, not Safari, so the window title lives on
        // Safari.app — look there first, then the event PID chain.
        for owner in axOwnerPIDs(eventPid: pid, app: app) {
            for raw in axTitles(pid: owner) {
                if let title = cleanedWindowTitle(raw, app: app) {
                    return title
                }
            }
        }
        return nil
    }

    /// Safari.app (or Chrome.app) first, then the ES pid and its parents.
    static func axOwnerPIDs(eventPid: pid_t, app: String) -> [pid_t] {
        var pids: [pid_t] = []
        var seen = Set<pid_t>()
        func append(_ pid: pid_t) {
            guard pid > 0, seen.insert(pid).inserted else { return }
            pids.append(pid)
        }
        for running in runningPIDs(named: app) {
            append(running)
        }
        for owner in pidChain(starting: eventPid) {
            append(owner)
        }
        return pids
    }

    private static func runningPIDs(named app: String) -> [pid_t] {
        NSWorkspace.shared.runningApplications.compactMap { ra in
            guard ra.localizedName == app else { return nil }
            return ra.processIdentifier
        }
    }

    private static func axTitles(pid: pid_t) -> [String] {
        let appEl = AXUIElementCreateApplication(pid)
        AXUIElementSetMessagingTimeout(appEl, 0.15)
        var titles: [String] = []

        var appTitle: CFTypeRef?
        if AXUIElementCopyAttributeValue(
            appEl,
            kAXTitleAttribute as CFString,
            &appTitle
        ) == .success, let appTitle = appTitle as? String {
            titles.append(appTitle)
        }

        var focused: CFTypeRef?
        if AXUIElementCopyAttributeValue(
            appEl,
            kAXFocusedWindowAttribute as CFString,
            &focused
        ) == .success, let focused {
            let window = unsafeBitCast(focused, to: AXUIElement.self)
            if let title = axTitle(window) {
                titles.append(title)
            }
        }

        var windowsRef: CFTypeRef?
        if AXUIElementCopyAttributeValue(
            appEl,
            kAXWindowsAttribute as CFString,
            &windowsRef
        ) == .success, let windows = windowsRef as? [AnyObject] {
            for item in windows {
                let window = unsafeBitCast(item, to: AXUIElement.self)
                if let title = axTitle(window) {
                    titles.append(title)
                }
            }
        }
        return titles
    }

    private static func axTitle(_ element: AXUIElement) -> String? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(
            element,
            kAXTitleAttribute as CFString,
            &value
        ) == .success else { return nil }
        return value as? String
    }

    static func parentPID(of pid: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.stride)
        let written = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        guard written == size else { return nil }
        let ppid = pid_t(info.pbi_ppid)
        return ppid > 0 ? ppid : nil
    }

    private static func run(
        _ launchPath: String,
        arguments: [String],
        asUser: Bool,
        timeout: TimeInterval
    ) -> String? {
        let proc = Process()
        proc.standardInput = FileHandle.nullDevice
        let out = Pipe()
        let err = Pipe()
        proc.standardOutput = out
        proc.standardError = err

        if asUser, geteuid() == 0, let user = consoleUserName(), let uid = uid(for: user) {
            // Root is outside the user's Aqua session; asuser + sudo -u is
            // what lets osascript talk to Chrome/Safari.
            proc.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            proc.arguments = ["asuser", String(uid), "/usr/bin/sudo", "-n", "-u", user, launchPath] + arguments
        } else {
            proc.executableURL = URL(fileURLWithPath: launchPath)
            proc.arguments = arguments
        }

        let done = DispatchSemaphore(value: 0)
        proc.terminationHandler = { _ in done.signal() }
        do {
            try proc.run()
        } catch {
            return nil
        }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            proc.terminate()
            return nil
        }
        guard proc.terminationStatus == 0 else { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)
    }

    private static func uid(for name: String) -> uid_t? {
        guard let pw = getpwnam(name) else { return nil }
        return pw.pointee.pw_uid
    }

    private static var userHome: URL {
        if let sudo = ProcessInfo.processInfo.environment["SUDO_USER"], !sudo.isEmpty {
            return URL(fileURLWithPath: "/Users/\(sudo)")
        }
        if let name = consoleUserName() {
            return URL(fileURLWithPath: "/Users/\(name)")
        }
        return FileManager.default.homeDirectoryForCurrentUser
    }

    private static func consoleUserName() -> String? {
        if let sudo = ProcessInfo.processInfo.environment["SUDO_USER"], !sudo.isEmpty {
            return sudo
        }
        var uid: uid_t = 0
        guard let name = SCDynamicStoreCopyConsoleUser(nil, &uid, nil) as String?,
              name != "loginwindow"
        else { return nil }
        return name
    }

    private static func looksLikeURL(_ text: String) -> Bool {
        let lower = text.lowercased()
        return lower.hasPrefix("http://")
            || lower.hasPrefix("https://")
            || lower.hasPrefix("file://")
            || lower.hasPrefix("chrome://")
            || lower.hasPrefix("edge://")
            || lower.hasPrefix("brave://")
            || lower.hasPrefix("about:")
    }

    private static func sqlEscape(_ value: String) -> String {
        value.replacingOccurrences(of: "'", with: "''")
    }

    private static func quote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
