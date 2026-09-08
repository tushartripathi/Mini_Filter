import Darwin
import Foundation

/// Freezes only the thread that issued the AUTH syscall so a scan can outlast
/// the kernel AUTH deadline (~15s). Other threads in the app keep running.
/// Falls back to whole-process SIGSTOP if the Mach thread cannot be found.
public enum ProcessHold {
    public enum Mode: Equatable {
        /// One Mach thread suspended (`thread_suspend`).
        case thread(id: UInt64)
        /// Whole process stopped (`SIGSTOP`) — last resort.
        case process
    }

    private struct Entry {
        var count: Int
        var mode: Mode
        var pid: pid_t
        /// Retained Mach thread port when `mode == .thread`.
        var threadPort: mach_port_t
        var watchdog: Process?
    }

    private static let lock = NSLock()
    /// `"pid"` for process-wide holds, `"pid|threadId"` for thread holds.
    private static var entries: [String: Entry] = [:]

    static func isFrozen(pid: pid_t, threadId: UInt64? = nil) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if let threadId, entries[key(pid: pid, threadId: threadId)] != nil {
            return true
        }
        return entries[key(pid: pid, threadId: nil)] != nil
    }

    /// Suspend the issuing thread when possible; otherwise SIGSTOP the process.
    @discardableResult
    static func freeze(pid: pid_t, threadId: UInt64?, maxSeconds: TimeInterval) -> Mode {
        lock.lock()
        defer { lock.unlock() }

        if let threadId {
            let k = key(pid: pid, threadId: threadId)
            if var existing = entries[k] {
                existing.count += 1
                entries[k] = existing
                return existing.mode
            }
            if let port = retainThreadPort(pid: pid, threadId: threadId),
               thread_suspend(port) == KERN_SUCCESS {
                let dog = spawnWatchdog(pid: pid, threadId: threadId, capSeconds: cap(maxSeconds))
                entries[k] = Entry(
                    count: 1,
                    mode: .thread(id: threadId),
                    pid: pid,
                    threadPort: port,
                    watchdog: dog
                )
                return .thread(id: threadId)
            }
        }

        let k = key(pid: pid, threadId: nil)
        if var existing = entries[k] {
            existing.count += 1
            entries[k] = existing
            return .process
        }
        kill(pid, SIGSTOP)
        let dog = spawnWatchdog(pid: pid, threadId: nil, capSeconds: cap(maxSeconds))
        entries[k] = Entry(count: 1, mode: .process, pid: pid, threadPort: 0, watchdog: dog)
        return .process
    }

    /// Returns true if this call actually resumed (refcount hit zero).
    @discardableResult
    static func thaw(pid: pid_t, threadId: UInt64?) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        let preferred = threadId.map { key(pid: pid, threadId: $0) }
        let k: String
        if let preferred, entries[preferred] != nil {
            k = preferred
        } else {
            k = key(pid: pid, threadId: nil)
        }
        guard var entry = entries[k] else { return false }

        if entry.count <= 1 {
            entries.removeValue(forKey: k)
            cancelWatchdog(entry)
            applyResume(entry)
            return true
        }
        entry.count -= 1
        entries[k] = entry
        return false
    }

    static func thawAll() {
        lock.lock()
        let all = Array(entries.values)
        entries.removeAll()
        lock.unlock()
        for entry in all {
            cancelWatchdog(entry)
            applyResume(entry)
        }
    }

    /// Used by the detached watchdog / `--resume-hold` so a stuck hold can clear
    /// even if this process is gone.
    public static func forceResume(pid: pid_t, threadId: UInt64?) {
        if let threadId, let port = retainThreadPort(pid: pid, threadId: threadId) {
            // Clear any stacked suspend count.
            for _ in 0..<8 {
                if thread_resume(port) != KERN_SUCCESS { break }
            }
            mach_port_deallocate(mach_task_self_, port)
            return
        }
        kill(pid, SIGCONT)
    }

    // MARK: - Internals

    private static func key(pid: pid_t, threadId: UInt64?) -> String {
        if let threadId { return "\(pid)|\(threadId)" }
        return "\(pid)"
    }

    private static func cap(_ maxSeconds: TimeInterval) -> TimeInterval {
        min(max(maxSeconds + 10, 15), 120)
    }

    private static func applyResume(_ entry: Entry) {
        switch entry.mode {
        case .thread:
            if entry.threadPort != 0 {
                _ = thread_resume(entry.threadPort)
                mach_port_deallocate(mach_task_self_, entry.threadPort)
            }
        case .process:
            kill(entry.pid, SIGCONT)
        }
    }

    private static func retainThreadPort(pid: pid_t, threadId: UInt64) -> mach_port_t? {
        var task: mach_port_name_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else {
            return nil
        }
        defer { mach_port_deallocate(mach_task_self_, task) }

        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        guard task_threads(task, &threadList, &threadCount) == KERN_SUCCESS,
              let threads = threadList else {
            return nil
        }

        var found: mach_port_t = 0
        for i in 0..<Int(threadCount) {
            let thread = threads[i]
            var info = thread_identifier_info_data_t()
            var count = mach_msg_type_number_t(
                MemoryLayout<thread_identifier_info_data_t>.size / MemoryLayout<natural_t>.size
            )
            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                    thread_info(thread, thread_flavor_t(THREAD_IDENTIFIER_INFO), intPtr, &count)
                }
            }
            if kr == KERN_SUCCESS, info.thread_id == threadId {
                found = thread
                for j in 0..<Int(threadCount) where j != i {
                    mach_port_deallocate(mach_task_self_, threads[j])
                }
                break
            }
            mach_port_deallocate(mach_task_self_, thread)
        }

        let arraySize = vm_size_t(MemoryLayout<thread_t>.stride * Int(threadCount))
        vm_deallocate(mach_task_self_, vm_address_t(bitPattern: threads), arraySize)
        return found == 0 ? nil : found
    }

    private static func tokenURL(pid: pid_t, threadId: UInt64?) -> URL {
        let suffix = threadId.map { "\($0)" } ?? "proc"
        return URL(fileURLWithPath: "/tmp/minifilter-hold-\(pid)-\(suffix)")
    }

    private static func spawnWatchdog(pid: pid_t, threadId: UInt64?, capSeconds: TimeInterval) -> Process {
        let token = tokenURL(pid: pid, threadId: threadId)
        try? FileManager.default.removeItem(at: token)
        FileManager.default.createFile(atPath: token.path, contents: Data("1".utf8))
        let cap = Int(ceil(capSeconds))
        let exe = CommandLine.arguments[0]
        let resumeArgs: String
        if let threadId {
            resumeArgs = "'\(exe)' --resume-hold \(pid) \(threadId)"
        } else {
            resumeArgs = "kill -CONT \(pid) 2>/dev/null"
        }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sh")
        proc.arguments = [
            "-c",
            """
            i=0
            while [ -f '\(token.path)' ]; do
              sleep 1
              i=$((i+1))
              if [ "$i" -ge \(cap) ]; then
                rm -f '\(token.path)'
                \(resumeArgs)
                exit 0
              fi
            done
            """,
        ]
        proc.standardInput = FileHandle.nullDevice
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        return proc
    }

    private static func cancelWatchdog(_ entry: Entry) {
        let tid: UInt64?
        if case .thread(let id) = entry.mode { tid = id } else { tid = nil }
        try? FileManager.default.removeItem(at: tokenURL(pid: entry.pid, threadId: tid))
        guard let dog = entry.watchdog else { return }
        let id = dog.processIdentifier
        dog.terminate()
        if id > 0 {
            kill(id, SIGKILL)
        }
    }
}
