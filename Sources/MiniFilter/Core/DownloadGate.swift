import Darwin
import EndpointSecurity
import Foundation

/// After a file is saved to Desktop/Downloads/…, hold every read/copy/exec
/// of that path until the (simulated) scan allows. Deny sticks for the
/// process lifetime; allow clears the file for later use.
///
/// Pending opens are **held** (thread frozen), not denied, so Finder/Preview
/// wait without a "you don't have permission" dialog. Write-only opens are
/// allowed immediately so the browser can finish saving.
enum DownloadGate {
    private static let deadlineMargin: TimeInterval = 2.0
    private static let minHold: TimeInterval = 0.05

    private static let lock = NSLock()
    private static var pending: Set<String> = []
    private static var cleared: Set<String> = []
    private static var blocked: Set<String> = []
    private static var scanEndsAt: [String: Date] = [:]
    private static var outstanding: [PendingAuth] = []
    private static var freezeByPath: [String: [(pid: pid_t, threadId: UInt64?, mode: ProcessHold.Mode)]] = [:]
    private static var downloader: [String: (pid: pid_t, process: String)] = [:]

    static func resetForTests() {
        lock.lock()
        defer { lock.unlock() }
        pending.removeAll()
        cleared.removeAll()
        blocked.removeAll()
        scanEndsAt.removeAll()
        outstanding.removeAll()
        freezeByPath.removeAll()
        downloader.removeAll()
    }

    static func isPending(_ path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return pending.contains(path)
    }

    static func isCleared(_ path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return cleared.contains(path)
    }

    static func isBlocked(_ path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return blocked.contains(path)
    }

    /// True while a read must wait on the in-flight download scan.
    static func shouldHoldAccess(_ path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return pending.contains(path)
    }

    /// True after a deny verdict — opens are refused for this session.
    static func shouldDenyAccess(_ path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return blocked.contains(path)
    }

    /// Helpers whose downloads we never hold/scan (Safari networking, Cursor, …).
    private static let skipDownloadScanExact: Set<String> = [
        "com.apple.webkit.networking",
        "com.apple.safari.sandboxbroker",
    ]

    private static let skipDownloadScanSubstrings: [String] = [
        "cursor helper",
    ]

    /// Write-only open while the download is still being written/saved.
    static func shouldAllowWriteOnlyOpen(access: String?) -> Bool {
        guard let access, !access.isEmpty else { return false }
        return access.contains("write") && !access.contains("read")
    }

    /// False for helpers whose downloads we never hold/scan.
    static func shouldScanProcess(_ process: String) -> Bool {
        let name = (process as NSString).lastPathComponent.lowercased()
        if skipDownloadScanExact.contains(name) { return false }
        return !skipDownloadScanSubstrings.contains { name.contains($0) }
    }

    /// The app that saved this file — holding it freezes chat UI (WhatsApp, Chrome, …).
    static func isDownloader(path: String, pid: pid_t, process: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let info = downloader[path] else { return false }
        return info.pid == pid || info.process.lowercased() == process.lowercased()
    }

    /// Start one simulated scan for this download. A second event for the
    /// same path while scanning is ignored. A new download of a previously
    /// allowed path is scanned again.
    @discardableResult
    static func startScan(
        path: String,
        pid: pid_t = 0,
        process: String = "",
        onStart: @escaping () -> Void,
        onStop: @escaping (FileScanner.Verdict, TimeInterval) -> Void
    ) -> Bool {
        lock.lock()
        if pending.contains(path) || blocked.contains(path) {
            lock.unlock()
            return false
        }
        cleared.remove(path)
        pending.insert(path)
        if !process.isEmpty {
            downloader[path] = (pid, process)
        }
        let waited = FileScanner.delaySeconds
        scanEndsAt[path] = Date().addingTimeInterval(waited)
        lock.unlock()

        FileScanner.scan(delay: waited, onStart: onStart) { verdict in
            finishScan(path: path, verdict: verdict, waited: waited, onStop: onStop)
        }
        return true
    }

    /// Hold this AUTH until the download scan finishes. Freezes the issuing
    /// thread when the remaining scan outlasts the AUTH deadline.
    @discardableResult
    static func holdAccess(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        path: String,
        pid: pid_t,
        onHold: @escaping (
            _ scanSeconds: TimeInterval,
            _ authSeconds: TimeInterval,
            _ freezeMode: ProcessHold.Mode?
        ) -> Void = { _, _, _ in },
        onResume: @escaping (_ mode: ProcessHold.Mode) -> Void = { _ in }
    ) -> Bool {
        lock.lock()
        guard pending.contains(path) else {
            lock.unlock()
            return false
        }
        let ends = scanEndsAt[path] ?? Date()
        let remainingScan = max(ends.timeIntervalSinceNow, minHold)
        lock.unlock()

        let remaining = MachDeadline.secondsRemaining(message.pointee.deadline)
        let usable = max(remaining - deadlineMargin, 0)
        let tid = UploadGate.threadId(from: message)
        let plan = UploadGate.planHold(scanSeconds: remainingScan, usableAuthSeconds: usable)

        let pendingAuth = PendingAuth(
            client: client,
            message: message,
            path: path,
            key: "download|\(path)",
            pid: pid,
            threadId: tid
        )
        lock.lock()
        outstanding.append(pendingAuth)
        lock.unlock()

        var freezeMode: ProcessHold.Mode?
        if plan.needsFreeze || usable < minHold {
            freezeMode = ProcessHold.freeze(
                pid: pid,
                threadId: tid,
                maxSeconds: max(remainingScan, FileScanner.delaySeconds)
            )
        }
        if let freezeMode {
            lock.lock()
            var list = freezeByPath[path] ?? []
            list.append((pid, tid, freezeMode))
            freezeByPath[path] = list
            lock.unlock()
        }
        onHold(plan.scanSeconds, plan.authSeconds, freezeMode)

        // Fail-open AUTH before the kernel kills us; frozen thread cannot proceed.
        let replyAfter = max(usable, 0)
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + replyAfter) {
            _ = pendingAuth.reply(deny: false)
        }

        // If the scan already finished between our check and now, release immediately.
        lock.lock()
        let stillPending = pending.contains(path)
        let isDenied = blocked.contains(path)
        lock.unlock()
        if !stillPending {
            completeHolds(
                path: path,
                deny: isDenied,
                onResume: onResume
            )
        }
        return true
    }

    /// On quit, allow held opens and drop in-flight pending so apps are not stuck.
    static func releasePending() {
        lock.lock()
        let paths = Array(pending)
        pending.removeAll()
        scanEndsAt.removeAll()
        downloader.removeAll()
        let items = outstanding
        outstanding.removeAll()
        let freezes = freezeByPath
        freezeByPath.removeAll()
        lock.unlock()

        for item in items {
            _ = item.reply(deny: false)
        }
        for (_, entries) in freezes {
            for entry in entries {
                _ = ProcessHold.thaw(pid: entry.pid, threadId: entry.threadId)
            }
        }
        _ = paths
    }

    // MARK: - Internals

    private static func finishScan(
        path: String,
        verdict: FileScanner.Verdict,
        waited: TimeInterval,
        onStop: @escaping (FileScanner.Verdict, TimeInterval) -> Void
    ) {
        lock.lock()
        pending.remove(path)
        scanEndsAt.removeValue(forKey: path)
        downloader.removeValue(forKey: path)
        if verdict == .deny {
            blocked.insert(path)
        } else {
            cleared.insert(path)
        }
        lock.unlock()

        // AUTH may already have fail-opened while the thread was frozen. Move the
        // file before thaw so that open cannot read sensitive content.
        if verdict == .deny {
            quarantine(path)
        }

        onStop(verdict, waited)
        completeHolds(path: path, deny: verdict == .deny, onResume: { _ in })
    }

    private static func quarantine(_ path: String) {
        let home: URL
        if let sudo = ProcessInfo.processInfo.environment["SUDO_USER"], !sudo.isEmpty {
            home = URL(fileURLWithPath: "/Users/\(sudo)")
        } else {
            home = FileManager.default.homeDirectoryForCurrentUser
        }
        let dir = home.appending(path: "Library/Logs/MiniFilter/Quarantine")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let name = UUID().uuidString + "-" + (path as NSString).lastPathComponent
        let dest = dir.appending(path: name)
        try? FileManager.default.moveItem(atPath: path, toPath: dest.path)
    }

    private static func completeHolds(
        path: String,
        deny: Bool,
        onResume: @escaping (ProcessHold.Mode) -> Void
    ) {
        lock.lock()
        let siblings = outstanding.filter { $0.path == path }
        outstanding.removeAll { $0.path == path }
        let freezes = freezeByPath.removeValue(forKey: path) ?? []
        lock.unlock()

        for sibling in siblings {
            _ = sibling.reply(deny: deny)
        }
        for entry in freezes {
            if ProcessHold.thaw(pid: entry.pid, threadId: entry.threadId) {
                onResume(entry.mode)
            }
        }
    }
}
