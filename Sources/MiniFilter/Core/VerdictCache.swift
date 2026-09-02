import Foundation

/// Allow/deny memory for one process lifetime.
///
/// Deny sticks. Allow expires after `allowReuseWindow` so a follow-up
/// OPEN→CLONE of the same send is not scanned twice, but attaching the
/// same file again later is held and scanned like the first time.
struct VerdictCache {
    var allowReuseWindow: TimeInterval
    private var blocked: Set<String> = []
    private var allowedAt: [String: Date] = [:]

    init(allowReuseWindow: TimeInterval = 2.0) {
        self.allowReuseWindow = allowReuseWindow
    }

    mutating func recordAllow(path: String, at time: Date = Date()) {
        allowedAt[path] = time
    }

    mutating func recordDeny(path: String) {
        blocked.insert(path)
        allowedAt.removeValue(forKey: path)
    }

    func isBlocked(path: String) -> Bool {
        blocked.contains(path)
    }

    mutating func wasAllowed(path: String, now: Date = Date()) -> Bool {
        pruneAllowed(now: now)
        guard let at = allowedAt[path] else { return false }
        return now.timeIntervalSince(at) < allowReuseWindow
    }

    mutating func pruneAllowed(now: Date = Date()) {
        allowedAt = allowedAt.filter { now.timeIntervalSince($0.value) < allowReuseWindow }
    }
}
