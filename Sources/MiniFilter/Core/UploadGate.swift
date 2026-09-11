import Darwin
import EndpointSecurity
import Foundation

/// One AUTH message we have retained so we can reply after the scan,
/// instead of blocking the Endpoint Security callback thread.
final class PendingAuth {
    let client: OpaquePointer
    let message: UnsafePointer<es_message_t>
    let path: String
    let key: String
    let pid: pid_t
    let threadId: UInt64?
    private let lock = NSLock()
    private var replied = false

    init(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        path: String,
        key: String,
        pid: pid_t,
        threadId: UInt64?
    ) {
        self.client = client
        self.message = message
        self.path = path
        self.key = key
        self.pid = pid
        self.threadId = threadId
        es_retain_message(message)
    }

    /// Returns true the first time a reply is sent. Later calls are no-ops.
    @discardableResult
    func reply(deny: Bool) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !replied else { return false }
        replied = true
        let msg = message.pointee
        switch msg.event_type {
        case ES_EVENT_TYPE_AUTH_OPEN:
            let flags: UInt32 = deny ? 0 : UInt32(bitPattern: Int32(truncatingIfNeeded: msg.event.open.fflag))
            _ = es_respond_flags_result(client, message, flags, false)
        case ES_EVENT_TYPE_AUTH_CLONE, ES_EVENT_TYPE_AUTH_COPYFILE:
            let result: es_auth_result_t = deny ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW
            _ = es_respond_auth_result(client, message, result, false)
        default:
            break
        }
        es_release_message(message)
        return true
    }
}

enum MachDeadline {
    private static let info: mach_timebase_info_data_t = {
        var value = mach_timebase_info_data_t()
        mach_timebase_info(&value)
        return value
    }()

    static func secondsRemaining(_ deadline: UInt64) -> TimeInterval {
        let now = mach_absolute_time()
        guard deadline > now else { return 0 }
        let ns = Double(deadline - now) * Double(info.numer) / Double(info.denom)
        return ns / 1_000_000_000
    }
}

/// Holds the AUTH syscall until the scan returns, then ALLOW or DENY.
/// The kernel AUTH deadline is ~15s; missing it kills this client. When the
/// scan is longer than that window we suspend the issuing thread (or SIGSTOP
/// the process as a fallback) so it cannot use the fail-open AUTH reply until
/// the full delay elapses.
enum UploadGate {
    /// Leave this much headroom so we reply before the kernel kills us.
    private static let deadlineMargin: TimeInterval = 2.0
    private static let minHold: TimeInterval = 0.3

    struct HoldPlan: Equatable {
        var scanSeconds: TimeInterval
        var authSeconds: TimeInterval
        /// True when the scan outlasts the usable AUTH window and we must
        /// freeze the issuing thread (or process) for the remainder.
        var needsFreeze: Bool
    }

    static func planHold(scanSeconds: TimeInterval, usableAuthSeconds: TimeInterval) -> HoldPlan {
        let auth = min(scanSeconds, max(usableAuthSeconds, 0))
        return HoldPlan(
            scanSeconds: scanSeconds,
            authSeconds: auth,
            needsFreeze: scanSeconds > usableAuthSeconds + 0.01
        )
    }

    static func threadId(from message: UnsafePointer<es_message_t>) -> UInt64? {
        let msg = message.pointee
        guard msg.version >= 4, let thread = msg.thread else { return nil }
        return thread.pointee.thread_id
    }

    /// macOS file-system agents — gating them stalls browsing, search, and iCloud.
    /// User apps (WhatsApp, Chrome, Mail, Slack, …) are gated.
    /// Short names (`rg`, `git`) are exact so they cannot match inside Chrome, etc.
    private static let skipHoldExact: Set<String> = [
        "mds",
        "rg",
        "git",
        "ripgrep",
    ]

    private static let skipHoldPrefixes: [String] = [
        "git-",
    ]

    private static let skipHoldSubstrings: [String] = [
        "minifilter",
        "finder",
        "quicklook",
        "thumbnailextension",
        "thumbnailing",
        "qlgenerator",
        "qlpreview",
        "mdworker",
        "mds_stores",
        "desktopserviceshelper",
        "fileprovider",
        "userfileindexing",
        "corespotlightd",
        "spotlight",
        "cloudd",
        "bird",
        "openandsavepanel",
        "filecoordinationd",
    ]

    /// After a scan allows a file, skip re-holding OPEN→CLONE of *that same
    /// send* (often a few hundred ms later). Expire quickly so attaching the
    /// same file again is scanned and delayed like the first time.
    static let allowReuseWindow: TimeInterval = 2.0

    private static let lock = NSLock()
    private static var inFlight: Set<String> = []
    private static var verdicts = VerdictCache(allowReuseWindow: allowReuseWindow)
    private static var outstanding: [PendingAuth] = []

    static func isBlocked(path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return verdicts.isBlocked(path: path)
    }

    static func wasAllowed(path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return verdicts.wasAllowed(path: path)
    }

    /// True for apps we will scan-and-hold. False for this monitor and for
    /// system file browsers/indexers that must not be delayed.
    static func shouldGate(process: String) -> Bool {
        let name = (process as NSString).lastPathComponent.lowercased()
        if skipHoldExact.contains(name) { return false }
        if skipHoldPrefixes.contains(where: { name.hasPrefix($0) }) { return false }
        return !skipHoldSubstrings.contains { name.contains($0) }
    }

    static func shouldHoldOpen(path: String, access: String?) -> Bool {
        FileClassifier.isUserSource(path: path)
            && (access == nil || access?.contains("read") == true)
    }

    static func shouldHoldCopy(source: String, destination: String?) -> Bool {
        FileClassifier.isUserSource(path: source)
            && (destination.map { FileClassifier.isAppContainer(path: $0) } ?? false)
    }

    /// Retain the AUTH message and reply after the scan (or just before deadline).
    /// Returns false if we cannot hold (no time, denied, or same-send reuse) —
    /// caller must reply in the ES callback.
    @discardableResult
    static func holdSyscall(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        path: String,
        destination: String?,
        pid: pid_t,
        process: String,
        onHold: @escaping (
            _ scanSeconds: TimeInterval,
            _ authSeconds: TimeInterval,
            _ freezeMode: ProcessHold.Mode?
        ) -> Void,
        onScanStart: @escaping () -> Void,
        onAuthReply: @escaping (_ deny: Bool, _ stillFrozen: Bool) -> Void,
        onScanStop: @escaping (FileScanner.Verdict, _ waited: TimeInterval) -> Void,
        onResume: @escaping (_ mode: ProcessHold.Mode) -> Void
    ) -> Bool {
        lock.lock()
        if verdicts.isBlocked(path: path) || verdicts.wasAllowed(path: path) {
            lock.unlock()
            return false
        }
        let key = "\(pid)|\(path)"
        let alreadyScanning = inFlight.contains(key)
        if !alreadyScanning {
            inFlight.insert(key)
        }
        lock.unlock()

        let remaining = MachDeadline.secondsRemaining(message.pointee.deadline)
        let usable = remaining - deadlineMargin
        guard usable >= minHold else {
            if !alreadyScanning {
                lock.lock()
                inFlight.remove(key)
                lock.unlock()
            }
            return false
        }

        let tid = threadId(from: message)
        let plan = planHold(scanSeconds: FileScanner.delaySeconds, usableAuthSeconds: usable)
        let pending = PendingAuth(
            client: client,
            message: message,
            path: path,
            key: key,
            pid: pid,
            threadId: tid
        )
        lock.lock()
        outstanding.append(pending)
        lock.unlock()

        if alreadyScanning {
            // Extra open/clone of the same file: do not start a second scan.
            // Reply this syscall when the first verdict lands, or at its own deadline.
            armAuthReply(pending, after: usable, deny: false, onAuthReply: onAuthReply)
            return true
        }

        var freezeMode: ProcessHold.Mode?
        if plan.needsFreeze {
            freezeMode = ProcessHold.freeze(pid: pid, threadId: tid, maxSeconds: plan.scanSeconds)
        }
        onHold(plan.scanSeconds, plan.authSeconds, freezeMode)

        FileScanner.scan(delay: plan.scanSeconds, onStart: onScanStart) { verdict in
            finish(
                pending: pending,
                destination: destination,
                verdict: verdict,
                waited: plan.scanSeconds,
                freezeMode: freezeMode,
                onAuthReply: onAuthReply,
                onScanStop: onScanStop,
                onResume: onResume
            )
        }
        // Always answer AUTH before the kernel deadline. If the scan is longer,
        // this fail-opens the syscall; the suspended thread cannot proceed yet.
        armAuthReply(pending, after: usable, deny: false, onAuthReply: onAuthReply)
        return true
    }

    /// Allow every held syscall so the target app is not left stuck on quit.
    static func replyAllAllow() {
        lock.lock()
        let items = outstanding
        outstanding.removeAll()
        inFlight.removeAll()
        lock.unlock()
        for item in items {
            item.reply(deny: false)
        }
        ProcessHold.thawAll()
    }

    /// Fail-open AUTH so this client is not killed. Does not end the scan.
    private static func armAuthReply(
        _ pending: PendingAuth,
        after: TimeInterval,
        deny: Bool,
        onAuthReply: @escaping (Bool, Bool) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + after) {
            guard pending.reply(deny: deny) else { return }
            onAuthReply(deny, ProcessHold.isFrozen(pid: pending.pid, threadId: pending.threadId))
        }
    }

    private static func finish(
        pending: PendingAuth,
        destination: String?,
        verdict: FileScanner.Verdict,
        waited: TimeInterval,
        freezeMode: ProcessHold.Mode?,
        onAuthReply: @escaping (Bool, Bool) -> Void,
        onScanStop: @escaping (FileScanner.Verdict, TimeInterval) -> Void,
        onResume: @escaping (ProcessHold.Mode) -> Void
    ) {
        let deny = verdict == .deny
        if pending.reply(deny: deny) {
            onAuthReply(deny, ProcessHold.isFrozen(pid: pending.pid, threadId: pending.threadId))
        }

        lock.lock()
        outstanding.removeAll { $0 === pending }
        let siblings = outstanding.filter { $0.key == pending.key }
        outstanding.removeAll { $0.key == pending.key }
        if deny {
            verdicts.recordDeny(path: pending.path)
        } else {
            verdicts.recordAllow(path: pending.path)
        }
        inFlight.remove(pending.key)
        lock.unlock()

        for sibling in siblings {
            if sibling.reply(deny: deny) {
                onAuthReply(deny, ProcessHold.isFrozen(pid: sibling.pid, threadId: sibling.threadId))
            }
        }

        if deny, let destination {
            quarantine(destination)
        }
        onScanStop(verdict, waited)
        if ProcessHold.thaw(pid: pending.pid, threadId: pending.threadId), let freezeMode {
            onResume(freezeMode)
        }
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
}
