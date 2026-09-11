import Darwin
import Foundation
import SystemConfiguration

/// User-level helper that can read browser window titles (and tab URLs)
/// under the logged-in Aqua session. The root Endpoint Security client
/// queries it over a Unix socket so AUTH replies never wait on TCC.
public enum TabHelper {
    public static let queryTimeout: TimeInterval = 0.3
    static let cacheTTL: TimeInterval = 2.0

    enum QueryResult: Equatable {
        /// Connected and got a reply, or the helper was too slow.
        case answered(BrowserTab.Page?)
        /// No socket, connect failed, or the helper is not listening.
        case unreachable
    }

    private struct Request: Codable {
        var pid: Int32
        var process: String
    }

    private struct Reply: Codable {
        var title: String?
        var url: String?
    }

    private static let lock = NSLock()
    private static var cache: [pid_t: (page: BrowserTab.Page, at: Date)] = [:]
    private static let maxMessage = 8192
    private static var boundSocketPath: String?

    public static func socketPath(uid: uid_t = consoleUID()) -> String {
        "/tmp/minifilter-tabhelper-\(uid).sock"
    }

    public static func socketExists(path: String = socketPath()) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    /// Ask the helper for a live title/url. Never prints. Times out in ≤ 400ms.
    static func query(
        pid: pid_t,
        process: String,
        socketPath path: String = socketPath(),
        timeout: TimeInterval = queryTimeout
    ) -> QueryResult {
        let deadline = Date().addingTimeInterval(max(0.05, min(timeout, 0.4)))
        guard let fd = connectUnix(path: path, deadline: deadline) else {
            return .unreachable
        }
        defer { close(fd) }

        let request = Request(pid: pid, process: process)
        guard let payload = try? JSONEncoder().encode(request) else {
            return .answered(nil)
        }
        var line = payload
        line.append(0x0a)
        guard writeAll(fd, line, deadline: deadline) else {
            return .answered(nil)
        }
        guard let raw = readLine(fd, deadline: deadline) else {
            return .answered(nil)
        }
        guard let reply = try? JSONDecoder().decode(Reply.self, from: Data(raw.utf8)) else {
            return .answered(nil)
        }
        let page = BrowserTab.Page(title: reply.title, url: reply.url)
        return .answered(page.isEmpty ? nil : page)
    }

    /// Foreground Unix-socket server. Call from the Aqua user, never from sudo.
    public static func runServer(socketPath path: String = socketPath()) -> Never {
        _ = signal(SIGPIPE, SIG_IGN)
        unlink(path)
        guard let fd = bindListen(path: path) else {
            fputs("MiniFilter tab helper: could not listen on \(path)\n", stderr)
            exit(1)
        }
        chmod(path, S_IRUSR | S_IWUSR)
        boundSocketPath = path
        signal(SIGINT, stopServer)
        signal(SIGTERM, stopServer)

        fputs("MiniFilter tab helper listening on \(path)\n", stderr)

        let queue = DispatchQueue(label: "minifilter.tabhelper", qos: .userInitiated, attributes: .concurrent)
        queue.async {
            while true {
                let client = accept(fd, nil, nil)
                if client < 0 {
                    if errno == EINTR { continue }
                    break
                }
                var nosig: Int32 = 1
                setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &nosig, socklen_t(MemoryLayout<Int32>.size))
                queue.async {
                    handle(client)
                    close(client)
                }
            }
        }
        dispatchMain()
    }

    private static let stopServer: @convention(c) (Int32) -> Void = { _ in
        if let path = TabHelper.boundSocketPath {
            unlink(path)
        }
        _exit(0)
    }

    static func resetCacheForTests() {
        lock.lock()
        cache.removeAll()
        lock.unlock()
    }

    // MARK: - Request handling

    private static func handle(_ fd: Int32) {
        let deadline = Date().addingTimeInterval(1.0)
        guard let raw = readLine(fd, deadline: deadline),
              let request = try? JSONDecoder().decode(Request.self, from: Data(raw.utf8))
        else {
            _ = writeAll(fd, Data("{}\n".utf8), deadline: deadline)
            return
        }

        let page = cachedPage(pid: request.pid, process: request.process)
        let reply = Reply(title: page?.title, url: page?.url)
        let payload = (try? JSONEncoder().encode(reply)) ?? Data("{}".utf8)
        var line = payload
        line.append(0x0a)
        _ = writeAll(fd, line, deadline: deadline)
    }

    private static func cachedPage(pid: pid_t, process: String) -> BrowserTab.Page? {
        lock.lock()
        if let hit = cache[pid], Date().timeIntervalSince(hit.at) < cacheTTL {
            let page = hit.page
            lock.unlock()
            return page
        }
        lock.unlock()

        let page = BrowserTab.livePage(process: process, pid: pid)
        if let page, !page.isEmpty {
            lock.lock()
            cache[pid] = (page, Date())
            lock.unlock()
        }
        return page
    }

    // MARK: - Console user

    public static func consoleUID() -> uid_t {
        if geteuid() != 0 {
            return geteuid()
        }
        var uid: uid_t = 0
        if let name = SCDynamicStoreCopyConsoleUser(nil, &uid, nil) as String?,
           name != "loginwindow",
           uid != 0 {
            return uid
        }
        if let sudo = ProcessInfo.processInfo.environment["SUDO_USER"], !sudo.isEmpty,
           let pw = getpwnam(sudo) {
            return pw.pointee.pw_uid
        }
        return getuid()
    }

    // MARK: - POSIX Unix socket

    private static func bindListen(path: String) -> Int32? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var nosig: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosig, socklen_t(MemoryLayout<Int32>.size))
        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        guard var addr = unixAddr(path) else {
            close(fd)
            return nil
        }
        let bound = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sock in
                bind(fd, sock, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, listen(fd, 16) == 0 else {
            close(fd)
            unlink(path)
            return nil
        }
        return fd
    }

    private static func connectUnix(path: String, deadline: Date) -> Int32? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var nosig: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosig, socklen_t(MemoryLayout<Int32>.size))
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        guard var addr = unixAddr(path) else {
            close(fd)
            return nil
        }
        let rc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sock in
                connect(fd, sock, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc != 0 && errno != EINPROGRESS {
            close(fd)
            return nil
        }
        if !wait(fd, events: Int16(POLLOUT), deadline: deadline) {
            close(fd)
            return nil
        }
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        if getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0 {
            close(fd)
            return nil
        }
        _ = fcntl(fd, F_SETFL, flags)
        return fd
    }

    private static func unixAddr(_ path: String) -> sockaddr_un? {
        var addr = sockaddr_un()
        let maxPath = MemoryLayout.size(ofValue: addr.sun_path)
        guard path.utf8.count < maxPath else { return nil }
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        path.withCString { src in
            withUnsafeMutablePointer(to: &addr.sun_path) { dst in
                dst.withMemoryRebound(to: CChar.self, capacity: maxPath) { dstChar in
                    _ = strncpy(dstChar, src, maxPath)
                }
            }
        }
        return addr
    }

    private static func writeAll(_ fd: Int32, _ data: Data, deadline: Date) -> Bool {
        var offset = 0
        return data.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return false }
            while offset < data.count {
                if !wait(fd, events: Int16(POLLOUT), deadline: deadline) { return false }
                let n = Darwin.write(fd, base.advanced(by: offset), data.count - offset)
                if n < 0 {
                    if errno == EINTR || errno == EAGAIN { continue }
                    return false
                }
                if n == 0 { return false }
                offset += n
            }
            return true
        }
    }

    private static func readLine(_ fd: Int32, deadline: Date) -> String? {
        var buffer = [UInt8]()
        buffer.reserveCapacity(256)
        var byte: UInt8 = 0
        while buffer.count < maxMessage {
            if !wait(fd, events: Int16(POLLIN), deadline: deadline) { return nil }
            let n = Darwin.read(fd, &byte, 1)
            if n < 0 {
                if errno == EINTR || errno == EAGAIN { continue }
                return nil
            }
            if n == 0 { break }
            if byte == 0x0a { break }
            buffer.append(byte)
        }
        guard !buffer.isEmpty else { return nil }
        return String(bytes: buffer, encoding: .utf8)
    }

    private static func wait(_ fd: Int32, events: Int16, deadline: Date) -> Bool {
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else { return false }
        var pfd = pollfd(fd: fd, events: events, revents: 0)
        let ms = Int32(min(remaining * 1000.0, Double(Int32.max - 1)))
        while true {
            let rc = poll(&pfd, 1, ms)
            if rc > 0 {
                let ready = (pfd.revents & events) != 0
                let failed = (pfd.revents & Int16(POLLHUP | POLLERR)) != 0
                return ready || failed
            }
            if rc == 0 { return false }
            if errno == EINTR { continue }
            return false
        }
    }
}
