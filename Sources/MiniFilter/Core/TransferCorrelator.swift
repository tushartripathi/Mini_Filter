import Foundation

/// Turns a burst of Endpoint Security file events into one UPLOAD or DOWNLOAD
/// with the path the user actually cares about.
///
/// Upload: a user file (Desktop, Documents, …) is copied into an app container.
/// Download: an app writes a user-facing file to Desktop/Downloads/… or into
/// its media store, and that write is not part of an outgoing send.
enum TransferCorrelator {

    struct Transfer: Codable {
        let timestamp: Date
        let direction: String
        let pid: Int32
        let process: String
        let path: String
    }

    private static let lock = NSLock()
    private static let window: TimeInterval = 20
    private static let dedupeWindow: TimeInterval = 15

    private static var opens: [pid_t: [(path: String, time: Date)]] = [:]
    private static var uploadsAt: [pid_t: Date] = [:]
    private static var cloneDests: [(path: String, time: Date)] = []
    private static var emitted: [(key: String, time: Date)] = []

    static func observe(
        event: String,
        path: String,
        destination: String?,
        access: String?,
        pid: pid_t,
        process: String,
        at time: Date
    ) -> Transfer? {
        lock.lock()
        defer { lock.unlock() }
        prune(now: time)

        switch event {
        case "OPEN":
            if FileClassifier.isUserSource(path: path),
               access == nil || access?.contains("read") == true {
                rememberOpen(pid: pid, path: path, at: time)
            }
            return nil

        case "CLONE", "COPYFILE":
            if let destination {
                cloneDests.append((destination, time))
            }
            if FileClassifier.isUserSource(path: path),
               let destination, FileClassifier.isAppContainer(path: destination) {
                return emit(direction: "upload", path: path, pid: pid, process: process, at: time)
            }
            if let destination, FileClassifier.isUserDestination(path: destination) {
                return emit(direction: "download", path: destination, pid: pid, process: process, at: time)
            }
            if let destination,
               FileClassifier.isAppMediaStore(path: destination),
               !FileClassifier.isAppStaging(path: destination),
               !FileClassifier.isUserSource(path: path),
               !recentlyUploaded(pid: pid, at: time) {
                return emit(direction: "download", path: destination, pid: pid, process: process, at: time)
            }
            return nil

        case "CREATE", "WRITE":
            if isRecentCloneDest(path) { return nil }
            if FileClassifier.isAppStaging(path: path) { return nil }
            if FileClassifier.isUserDestination(path: path) {
                if recentOpen(pid: pid, at: time) == path { return nil }
                return emit(direction: "download", path: path, pid: pid, process: process, at: time)
            }
            if FileClassifier.isAppMediaStore(path: path),
               FileClassifier.isUserFacingFile(path: path),
               !recentlyUploaded(pid: pid, at: time) {
                return emit(direction: "download", path: path, pid: pid, process: process, at: time)
            }
            if FileClassifier.isAppContainer(path: path),
               let source = recentOpen(pid: pid, at: time) {
                return emit(direction: "upload", path: source, pid: pid, process: process, at: time)
            }
            return nil

        case "RENAME":
            guard let destination else { return nil }
            if FileClassifier.isUserSource(path: path),
               FileClassifier.isAppContainer(path: destination) {
                return emit(direction: "upload", path: path, pid: pid, process: process, at: time)
            }
            if FileClassifier.isUserDestination(path: destination) {
                return emit(direction: "download", path: destination, pid: pid, process: process, at: time)
            }
            return nil

        default:
            return nil
        }
    }

    // MARK: - Internals

    private static func emit(
        direction: String,
        path: String,
        pid: pid_t,
        process: String,
        at time: Date
    ) -> Transfer? {
        let key = "\(direction)|\(pid)|\(path)"
        if emitted.contains(where: { $0.key == key && time.timeIntervalSince($0.time) < dedupeWindow }) {
            return nil
        }
        emitted.append((key, time))
        if direction == "upload" {
            uploadsAt[pid] = time
        }
        return Transfer(
            timestamp: time,
            direction: direction,
            pid: pid,
            process: process,
            path: path
        )
    }

    private static func rememberOpen(pid: pid_t, path: String, at time: Date) {
        var list = opens[pid] ?? []
        list.append((path, time))
        if list.count > 8 { list.removeFirst(list.count - 8) }
        opens[pid] = list
    }

    private static func recentOpen(pid: pid_t, at time: Date) -> String? {
        opens[pid]?.last { time.timeIntervalSince($0.time) <= window }?.path
    }

    private static func recentlyUploaded(pid: pid_t, at time: Date) -> Bool {
        guard let start = uploadsAt[pid] else { return false }
        return time.timeIntervalSince(start) <= window
    }

    private static func isRecentCloneDest(_ path: String) -> Bool {
        cloneDests.contains { $0.path == path }
    }

    private static func prune(now: Date) {
        func fresh(_ time: Date) -> Bool { now.timeIntervalSince(time) <= window }
        for pid in opens.keys {
            opens[pid] = opens[pid]?.filter { fresh($0.time) }
        }
        uploadsAt = uploadsAt.filter { fresh($0.value) }
        cloneDests = cloneDests.filter { fresh($0.time) }
        emitted = emitted.filter { now.timeIntervalSince($0.time) <= dedupeWindow }
    }
}
