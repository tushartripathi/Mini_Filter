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
    private let lock = NSLock()
    private var replied = false

    init(client: OpaquePointer, message: UnsafePointer<es_message_t>, path: String, key: String) {
        self.client = client
        self.message = message
        self.path = path
        self.key = key
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

/// Holds only the AUTH syscall (that one open/clone/copy) until the scan
/// returns. The rest of WhatsApp keeps running. Reply always happens before
/// the kernel AUTH deadline — missing it kills this client and hangs the syscall.
enum UploadGate {
    /// Leave this much headroom so we reply before the kernel kills us.
    private static let deadlineMargin: TimeInterval = 2.0
    private static let minHold: TimeInterval = 0.3

    private static let lock = NSLock()
    private static var inFlight: Set<String> = []
    private static var blocked: Set<String> = []
    private static var allowed: Set<String> = []
    private static var outstanding: [PendingAuth] = []

    static func isBlocked(path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return blocked.contains(path)
    }

    static func wasAllowed(path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return allowed.contains(path)
    }

    static func isWhatsApp(_ process: String) -> Bool {
        process.lowercased().contains("whatsapp")
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
    /// Returns false if we cannot hold (no time, or already decided) — caller
    /// must reply in the ES callback.
    @discardableResult
    static func holdSyscall(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        path: String,
        destination: String?,
        pid: pid_t,
        process: String,
        onHold: @escaping (_ seconds: TimeInterval) -> Void,
        onScanStart: @escaping () -> Void,
        onScanStop: @escaping (FileScanner.Verdict, _ waited: TimeInterval, _ deadlineForced: Bool) -> Void
    ) -> Bool {
        lock.lock()
        if blocked.contains(path) || allowed.contains(path) {
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

        let pending = PendingAuth(client: client, message: message, path: path, key: key)
        lock.lock()
        outstanding.append(pending)
        lock.unlock()

        if alreadyScanning {
            // Extra open/clone of the same file: do not start a second scan.
            // Reply this syscall when the first verdict lands, or at its own deadline.
            armDeadline(pending, usable: usable, destination: destination, onScanStop: onScanStop)
            return true
        }

        let wait = min(FileScanner.delaySeconds, usable)
        onHold(wait)
        FileScanner.scan(delay: wait, onStart: onScanStart) { verdict in
            finish(pending: pending, destination: destination, verdict: verdict, waited: wait, deadlineForced: false, onScanStop: onScanStop)
        }
        armDeadline(pending, usable: usable, destination: destination, onScanStop: onScanStop)
        return true
    }

    /// Allow every held syscall so WhatsApp is not left stuck on quit.
    static func replyAllAllow() {
        lock.lock()
        let items = outstanding
        outstanding.removeAll()
        inFlight.removeAll()
        lock.unlock()
        for item in items {
            item.reply(deny: false)
        }
    }

    private static func armDeadline(
        _ pending: PendingAuth,
        usable: TimeInterval,
        destination: String?,
        onScanStop: @escaping (FileScanner.Verdict, TimeInterval, Bool) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + usable) {
            finish(pending: pending, destination: destination, verdict: .allow, waited: usable, deadlineForced: true, onScanStop: onScanStop)
        }
    }

    private static func finish(
        pending: PendingAuth,
        destination: String?,
        verdict: FileScanner.Verdict,
        waited: TimeInterval,
        deadlineForced: Bool,
        onScanStop: @escaping (FileScanner.Verdict, TimeInterval, Bool) -> Void
    ) {
        guard pending.reply(deny: verdict == .deny) else { return }

        lock.lock()
        outstanding.removeAll { $0 === pending }
        let siblings = outstanding.filter { $0.key == pending.key }
        outstanding.removeAll { $0.key == pending.key }
        if verdict == .deny {
            blocked.insert(pending.path)
        } else {
            allowed.insert(pending.path)
        }
        inFlight.remove(pending.key)
        lock.unlock()

        for sibling in siblings {
            sibling.reply(deny: verdict == .deny)
        }

        if verdict == .deny, let destination {
            quarantine(destination)
        }
        onScanStop(verdict, waited, deadlineForced)
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
