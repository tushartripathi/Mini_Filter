import Foundation
import EndpointSecurity
import Darwin

/// Notify-only Endpoint Security client for file OPEN, CLONE and COPYFILE.
/// AUTH events (which can deny the open) are not subscribed: a missed reply
/// hangs the target process.
enum Monitor {

    struct Options {
        var seconds: TimeInterval?
        var processFilters: [String] = []
        var allFiles = false
        var json = false
    }

    struct AccessEvent: Codable {
        let timestamp: Date
        let event: String
        let pid: Int32
        let process: String
        let signingID: String
        let path: String
        let destination: String?
        let access: String?
    }

    static func run(_ options: Options) -> Never {
        setvbuf(stdout, nil, _IONBF, 0)

        guard geteuid() == 0 else {
            fputs("FAIL: must run as root (sudo).\n", stderr)
            exit(1)
        }

        jsonOutput = options.json
        processFilters = options.processFilters.map { $0.lowercased() }
        allFiles = options.allFiles

        print("ESMonitor")
        print(String(repeating: "-", count: 72))
        print("events:    OPEN, CLONE, COPYFILE")
        print("files:     \(allFiles ? "all paths" : "documents / media only")")
        print("processes: \(processFilters.isEmpty ? "all" : processFilters.joined(separator: ", "))")
        if let seconds = options.seconds {
            print("duration:  \(Int(seconds))s")
        }
        print("log:       \(logFile.path)")
        print(String(repeating: "-", count: 72))
        print("Open or attach a document in any app.\n")

        var client: OpaquePointer?
        let result = es_new_client(&client) { _, message in
            handle(message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
            fputs(explain(result) + "\n", stderr)
            exit(1)
        }
        esClient = client

        muteNoisyPaths(client)

        let types: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_CLONE,
            ES_EVENT_TYPE_NOTIFY_COPYFILE,
        ]
        guard es_subscribe(client, types, UInt32(types.count)) == ES_RETURN_SUCCESS else {
            fputs("FAIL: es_subscribe failed.\n", stderr)
            es_delete_client(client)
            exit(1)
        }

        if let seconds = options.seconds {
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds) {
                es_delete_client(client)
                print("\nStopped.")
                exit(0)
            }
        }

        signal(SIGINT) { _ in
            if let client = Monitor.esClient {
                es_delete_client(client)
            }
            print("\nStopped.")
            exit(0)
        }

        RunLoop.main.run()
        exit(0)
    }

    // MARK: - State

    private static var esClient: OpaquePointer?
    private static var jsonOutput = false
    private static var processFilters: [String] = []
    private static var allFiles = false
    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.sortedKeys]
        return e
    }()
    private static let logQueue = DispatchQueue(label: "esmonitor.log")

    private static var logFile: URL {
        let home: URL
        if let sudo = ProcessInfo.processInfo.environment["SUDO_USER"], !sudo.isEmpty {
            home = URL(fileURLWithPath: "/Users/\(sudo)")
        } else {
            home = FileManager.default.homeDirectoryForCurrentUser
        }
        let dir = home.appending(path: "Library/Logs/ESMonitor")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let day = ISO8601DateFormatter().string(from: Date()).prefix(10)
        return dir.appending(path: "access-\(day).jsonl")
    }

    // MARK: - Events

    private static func handle(_ message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        let process = msg.process.pointee
        let pid = audit_token_to_pid(process.audit_token)
        if pid == getpid() { return }

        let signingID = esString(process.signing_id)
        let exe = esString(process.executable.pointee.path)
        let processName = (exe as NSString).lastPathComponent
        if !matchesProcess(name: processName, signingID: signingID) { return }

        var eventName = ""
        var path = ""
        var destination: String?
        var access: String?

        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            path = esString(msg.event.open.file.pointee.path)
            let read = (msg.event.open.fflag & FREAD) != 0
            let write = (msg.event.open.fflag & FWRITE) != 0
            eventName = "OPEN"
            access = [read ? "read" : nil, write ? "write" : nil]
                .compactMap { $0 }.joined(separator: "+")

        case ES_EVENT_TYPE_NOTIFY_CLONE:
            path = esString(msg.event.clone.source.pointee.path)
            destination = join(
                dir: esString(msg.event.clone.target_dir.pointee.path),
                name: esString(msg.event.clone.target_name)
            )
            eventName = "CLONE"

        case ES_EVENT_TYPE_NOTIFY_COPYFILE:
            path = esString(msg.event.copyfile.source.pointee.path)
            if let target = msg.event.copyfile.target_file {
                destination = esString(target.pointee.path)
            } else {
                destination = join(
                    dir: esString(msg.event.copyfile.target_dir.pointee.path),
                    name: esString(msg.event.copyfile.target_name)
                )
            }
            eventName = "COPYFILE"

        default:
            return
        }

        guard !path.isEmpty else { return }
        if !allFiles && !FileFilter.isDocument(path: path) {
            if let destination, FileFilter.isDocument(path: destination) {
                // Keep copies whose destination is a real document.
            } else {
                return
            }
        }

        emit(AccessEvent(
            timestamp: Date(),
            event: eventName,
            pid: pid,
            process: processName,
            signingID: signingID,
            path: path,
            destination: destination,
            access: access.flatMap { $0.isEmpty ? nil : $0 }
        ))
    }

    private static func emit(_ event: AccessEvent) {
        if jsonOutput, let data = try? encoder.encode(event),
           let line = String(data: data, encoding: .utf8) {
            print(line)
        } else {
            let clock = DateFormatter.localizedString(from: event.timestamp, dateStyle: .none, timeStyle: .medium)
            var line = "[\(clock)] \(event.event.padding(toLength: 8, withPad: " ", startingAt: 0))  \(event.process)[\(event.pid)]  \(event.path)"
            if let access = event.access { line += "  (\(access))" }
            if let destination = event.destination { line += "  → \(destination)" }
            print(line)
        }
        persist(event)
    }

    private static func persist(_ event: AccessEvent) {
        logQueue.async {
            guard let data = try? encoder.encode(event) else { return }
            var blob = data
            blob.append(0x0A)
            let file = logFile
            if FileManager.default.fileExists(atPath: file.path),
               let handle = try? FileHandle(forWritingTo: file) {
                defer { try? handle.close() }
                _ = try? handle.seekToEnd()
                try? handle.write(contentsOf: blob)
            } else {
                try? blob.write(to: file, options: .atomic)
            }
        }
    }

    // MARK: - Helpers

    private static func matchesProcess(name: String, signingID: String) -> Bool {
        guard !processFilters.isEmpty else { return true }
        let nameL = name.lowercased()
        let sid = signingID.lowercased()
        return processFilters.contains { nameL.contains($0) || sid.contains($0) }
    }

    private static func muteNoisyPaths(_ client: OpaquePointer) {
        for prefix in ["/System/", "/usr/", "/bin/", "/sbin/", "/private/var/db/", "/Library/Apple/", "/dev/"] {
            _ = prefix.withCString { es_mute_path(client, $0, ES_MUTE_PATH_TYPE_PREFIX) }
        }
    }

    private static func esString(_ token: es_string_token_t) -> String {
        guard let data = token.data, token.length > 0 else { return "" }
        return String(cString: data)
    }

    private static func join(dir: String, name: String) -> String {
        dir.hasSuffix("/") ? dir + name : dir + "/" + name
    }

    private static func explain(_ result: es_new_client_result_t) -> String {
        switch result {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return """
            FAIL: not entitled as an Endpoint Security client.
            Local PoC: disable SIP (see README), then ./run.sh again.
            Production: Apple-granted com.apple.developer.endpoint-security.client
            on a Developer ID, shipped as a system extension.
            Do not ad-hoc-sign that entitlement while SIP is on — AMFI SIGKILLs the process.
            """
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return """
            FAIL: Full Disk Access is not granted to this binary.
            System Settings → Privacy & Security → Full Disk Access
            → add build/esmonitor, then sudo it again.
            """
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "FAIL: must run as root (sudo)."
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "FAIL: too many Endpoint Security clients already running."
        default:
            return "FAIL: es_new_client returned \(result.rawValue)."
        }
    }
}

@_silgen_name("audit_token_to_pid")
private func audit_token_to_pid(_ token: audit_token_t) -> pid_t
