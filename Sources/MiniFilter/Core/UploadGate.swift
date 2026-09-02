import Foundation

/// Freeze WhatsApp, run the scanner, then resume (allow) or deny later copies (block).
enum UploadGate {
    private static let lock = NSLock()
    private static var inFlight: Set<String> = []
    private static var blocked: Set<String> = []

    static func isBlocked(path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return blocked.contains(path)
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

    /// Returns false if this pid+path is already being scanned.
    @discardableResult
    static func begin(
        path: String,
        destination: String?,
        pid: pid_t,
        process: String,
        onHold: @escaping (_ froze: Bool) -> Void,
        onScanStart: @escaping () -> Void,
        onScanStop: @escaping (FileScanner.Verdict) -> Void,
        onResume: @escaping (FileScanner.Verdict) -> Void
    ) -> Bool {
        let key = "\(pid)|\(path)"
        lock.lock()
        if inFlight.contains(key) {
            lock.unlock()
            return false
        }
        inFlight.insert(key)
        lock.unlock()

        let watchdog = min(FileScanner.delaySeconds + 10, 120)
        let froze = ProcessHold.suspend(pid: pid, watchdogSeconds: watchdog)
        onHold(froze)

        FileScanner.scan(
            onStart: onScanStart,
            onStop: { verdict in
                if verdict == .deny {
                    lock.lock()
                    blocked.insert(path)
                    lock.unlock()
                    if let destination {
                        quarantine(destination)
                    }
                }
                ProcessHold.resume(pid: pid)
                onScanStop(verdict)
                onResume(verdict)
                lock.lock()
                inFlight.remove(key)
                lock.unlock()
            }
        )
        return true
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
