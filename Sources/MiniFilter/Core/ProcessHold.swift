import Darwin
import Foundation

private func minifilterResumeHeldProcesses() {
    ProcessHold.resumeAll()
}

/// Pauses another process with SIGSTOP so it cannot copy or send a file,
/// then resumes it with SIGCONT after the scan verdict.
///
/// AUTH events cannot wait for a 10s scan (the kernel kills this client if
/// the AUTH deadline is missed). Stopping the process is the hold that can.
enum ProcessHold {
    private static let lock = NSLock()
    private static var held: Set<pid_t> = []
    private static var exitHookInstalled = false

    static func installExitHandler() {
        lock.lock()
        defer { lock.unlock() }
        guard !exitHookInstalled else { return }
        exitHookInstalled = true
        atexit(minifilterResumeHeldProcesses)
    }

    @discardableResult
    static func suspend(pid: pid_t, watchdogSeconds: TimeInterval) -> Bool {
        if pid <= 1 || pid == getpid() { return false }
        lock.lock()
        if held.contains(pid) {
            lock.unlock()
            return true
        }
        lock.unlock()

        guard kill(pid, SIGSTOP) == 0 else { return false }

        lock.lock()
        held.insert(pid)
        lock.unlock()

        startWatchdog(pid: pid, seconds: watchdogSeconds)
        return true
    }

    static func resume(pid: pid_t) {
        lock.lock()
        held.remove(pid)
        lock.unlock()
        _ = kill(pid, SIGCONT)
    }

    static func resumeAll() {
        lock.lock()
        let pids = held
        held.removeAll()
        lock.unlock()
        for pid in pids {
            _ = kill(pid, SIGCONT)
        }
    }

    static func isHeld(_ pid: pid_t) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return held.contains(pid)
    }

    /// Detached `sleep; kill -CONT` so WhatsApp resumes even if this process
    /// is SIGKILL'd mid-scan.
    private static func startWatchdog(pid: pid_t, seconds: TimeInterval) {
        let secs = Int(min(max(seconds, 1), 120).rounded(.up))
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/sh")
        task.arguments = [
            "-c",
            "nohup sh -c 'sleep \(secs); kill -CONT \(pid) 2>/dev/null' >/dev/null 2>&1 &",
        ]
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        try? task.run()
    }
}
