import Foundation
import EndpointSecurity
import Darwin

/// Subscribes to Endpoint Security file events so we see the moment any process
/// opens, copies or creates a user-facing file — the trigger a normal app cannot
/// get by watching WhatsApp's container after the fact.
///
/// This is notify-only. AUTH events (which can deny the open) are the production
/// block path; they are not subscribed here because a missed reply hangs the
/// target process. A Network Extension still has to cover the actual bytes on
/// the wire — ES sees files, not HTTPS bodies.
enum EndpointSecurityMonitor {

    struct Options {
        var seconds: TimeInterval?
        var processFilters: [String] = []
        var userFacingOnly = true
        var json = false
        var verbose = false
    }

    struct AccessEvent: Codable {
        let timestamp: Date
        let event: String
        let pid: Int32
        let process: String
        let signingID: String
        let teamID: String
        let path: String
        let destination: String?
        let access: String?
        /// Best-effort guess from the file event alone. Confirmed transfer
        /// direction still needs the network side (Network Extension).
        let inferred: String?
    }

    static func run(arguments: [String]) -> Never {
        setvbuf(stdout, nil, _IONBF, 0)
        let options = parse(arguments)

        guard geteuid() == 0 else {
            fputs("FAIL: Endpoint Security requires root. Re-run with sudo.\n", stderr)
            exit(1)
        }

        print("MiniFilter Endpoint Security monitor")
        print(String(repeating: "-", count: 72))
        print("events:    UPLOAD / DOWNLOAD (original file path)")
        print("files:     \(options.userFacingOnly ? "user-facing extensions only" : "all paths")")
        print("processes: \(options.processFilters.isEmpty ? "all" : options.processFilters.joined(separator: ", "))")
        if options.verbose { print("verbose:   raw Endpoint Security events") }
        if let seconds = options.seconds {
            print("duration:  \(Int(seconds))s")
        }
        print("log:       \(logFile.path)")
        print(String(repeating: "-", count: 72))
        print("Send or receive a file. Only the transfer path is printed.")
        print("Pass --verbose to see every kernel file event.\n")

        jsonOutput = options.json
        verbose = options.verbose
        processFilters = options.processFilters.map { $0.lowercased() }
        userFacingOnly = options.userFacingOnly

        var client: OpaquePointer?
        let result = es_new_client(&client) { _, message in
            handle(message: message)
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
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
        ]
        guard es_subscribe(client, types, UInt32(types.count)) == ES_RETURN_SUCCESS else {
            fputs("FAIL: es_subscribe failed.\n", stderr)
            es_delete_client(client)
            exit(1)
        }

        print("Listening. Send or save a file, or press Ctrl+C to stop.\n")

        if let seconds = options.seconds {
            DispatchQueue.main.asyncAfter(deadline: .now() + seconds) {
                stop(message: "Monitor finished.")
            }
        }

        signal(SIGINT, SIG_IGN)
        let sigint = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigint.setEventHandler {
            stop(message: "Monitor stopped.")
        }
        sigint.resume()
        signalSource = sigint

        RunLoop.main.run()
        exit(0)
    }

    // MARK: - Callback state (ES delivers on its own queue)

    private static var esClient: OpaquePointer?
    private static var signalSource: DispatchSourceSignal?
    private static var jsonOutput = false
    private static var verbose = false
    private static var processFilters: [String] = []
    private static var userFacingOnly = true
    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.sortedKeys]
        return e
    }()
    private static let logQueue = DispatchQueue(label: "com.minifilter.eslog")

    private static var logFile: URL {
        let home: URL
        if let sudo = ProcessInfo.processInfo.environment["SUDO_USER"], !sudo.isEmpty {
            home = URL(fileURLWithPath: "/Users/\(sudo)")
        } else {
            home = FileManager.default.homeDirectoryForCurrentUser
        }
        let dir = home.appending(path: "Library/Logs/MiniFilter")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let day = DateFormatter.logDay.string(from: Date())
        return dir.appending(path: "es-access-\(day).jsonl")
    }

    // MARK: - Event handling

    private static func handle(message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        let process = msg.process.pointee
        let pid = pid_t(bitPattern: process.audit_token.val.5)
        if pid == getpid() { return }

        let signingID = esString(process.signing_id)
        let exe = esString(process.executable.pointee.path)
        let processName = (exe as NSString).lastPathComponent
        if !matchesProcess(name: processName, signingID: signingID) { return }

        var eventName = ""
        var path = ""
        var destination: String?
        var access: String?
        var inferred: String?

        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            path = esString(msg.event.open.file.pointee.path)
            let read = (msg.event.open.fflag & FREAD) != 0
            let write = (msg.event.open.fflag & FWRITE) != 0
            eventName = "OPEN"
            access = [read ? "read" : nil, write ? "write" : nil]
                .compactMap { $0 }.joined(separator: "+")
            if read { inferred = "possible-upload-source" }

        case ES_EVENT_TYPE_NOTIFY_CLONE:
            path = esString(msg.event.clone.source.pointee.path)
            destination = join(
                dir: esString(msg.event.clone.target_dir.pointee.path),
                name: esString(msg.event.clone.target_name)
            )
            eventName = "CLONE"
            inferred = "possible-upload-copy"

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
            inferred = "possible-upload-copy"

        case ES_EVENT_TYPE_NOTIFY_CREATE:
            path = createdPath(msg.event.create)
            eventName = "CREATE"
            inferred = "possible-download-dest"

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            path = esString(msg.event.rename.source.pointee.path)
            destination = renamedDestination(msg.event.rename)
            eventName = "RENAME"

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            guard msg.event.close.modified else { return }
            path = esString(msg.event.close.target.pointee.path)
            eventName = "WRITE"
            inferred = "possible-download-dest"

        default:
            return
        }

        guard !path.isEmpty else { return }
        if shouldIgnore(path: path) { return }
        if let destination, shouldIgnore(path: destination) && shouldIgnore(path: path) { return }
        if userFacingOnly && !FileClassifier.isUserFacingFile(path: path) {
            if let destination, FileClassifier.isUserFacingFile(path: destination) {
                // Keep copies whose destination is a real document (WhatsApp staging).
            } else {
                return
            }
        }

        let now = Date()
        let accessLabel = access.flatMap { $0.isEmpty ? nil : $0 }

        if verbose {
            emitRaw(AccessEvent(
                timestamp: now,
                event: eventName,
                pid: pid,
                process: processName,
                signingID: signingID,
                teamID: esString(process.team_id),
                path: path,
                destination: destination,
                access: accessLabel,
                inferred: inferred
            ))
        }

        if let transfer = TransferCorrelator.observe(
            event: eventName,
            path: path,
            destination: destination,
            access: accessLabel,
            pid: pid,
            process: processName,
            at: now
        ) {
            emitTransfer(transfer)
        }
    }

    private static func emitTransfer(_ event: TransferCorrelator.Transfer) {
        if jsonOutput, let data = try? encoder.encode(event),
           let line = String(data: data, encoding: .utf8) {
            print(line)
        } else {
            let time = DateFormatter.clock.string(from: event.timestamp)
            let label = event.direction.uppercased().padding(toLength: 8, withPad: " ", startingAt: 0)
            print("[\(time)] \(label)  \(event.process)[\(event.pid)]  \(shellQuoted(event.path))")
        }
        persist(event)
    }

    private static func emitRaw(_ event: AccessEvent) {
        let time = DateFormatter.clock.string(from: event.timestamp)
        var line = "[\(time)] \(event.event.padding(toLength: 8, withPad: " ", startingAt: 0))  \(event.process)[\(event.pid)]  \(shellQuoted(event.path))"
        if let access = event.access { line += "  (\(access))" }
        if let destination = event.destination { line += "  → \(shellQuoted(destination))" }
        if let inferred = event.inferred { line += "  [\(inferred)]" }
        print(line)
    }

    /// Quote a path so it pastes into `open`, `ls`, etc. without the shell
    /// splitting on spaces (WhatsApp lives under `Group Containers`).
    private static func shellQuoted(_ path: String) -> String {
        let safe = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "/._-+@~"))
        if !path.isEmpty, path.unicodeScalars.allSatisfy({ safe.contains($0) }) {
            return path
        }
        return "'" + path.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func persist<T: Encodable>(_ event: T) {
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

    // MARK: - Filters

    private static func matchesProcess(name: String, signingID: String) -> Bool {
        guard !processFilters.isEmpty else { return true }
        let nameL = name.lowercased()
        let sid = signingID.lowercased()
        return processFilters.contains { nameL.contains($0) || sid.contains($0) }
    }

    private static func shouldIgnore(path: String) -> Bool {
        if path.hasPrefix("/dev/") { return true }
        if path.contains(".app/Contents/") { return true }
        if path.contains("/Library/Caches/") { return true }
        if path.contains("/Library/Logs/") { return true }
        if path.contains("/.git/") { return true }
        return false
    }

    private static func muteNoisyPaths(_ client: OpaquePointer) {
        let prefixes = [
            "/System/",
            "/usr/",
            "/bin/",
            "/sbin/",
            "/private/var/db/",
            "/Library/Apple/",
            "/dev/",
        ]
        for prefix in prefixes {
            _ = prefix.withCString { es_mute_path(client, $0, ES_MUTE_PATH_TYPE_PREFIX) }
        }
    }

    // MARK: - ES helpers

    private static func stop(message: String) {
        if let client = esClient {
            es_delete_client(client)
            esClient = nil
        }
        print("\n\(message)")
        exit(0)
    }

    /// ES strings are length-prefixed and are not required to be NUL-terminated.
    private static func esString(_ token: es_string_token_t) -> String {
        guard token.length > 0, let data = token.data else { return "" }
        let bytes = UnsafeRawBufferPointer(start: data, count: Int(token.length))
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func join(dir: String, name: String) -> String {
        if dir.hasSuffix("/") { return dir + name }
        return dir + "/" + name
    }

    private static func createdPath(_ create: es_event_create_t) -> String {
        switch create.destination_type {
        case ES_DESTINATION_TYPE_NEW_PATH:
            return join(
                dir: esString(create.destination.new_path.dir.pointee.path),
                name: esString(create.destination.new_path.filename)
            )
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            return esString(create.destination.existing_file.pointee.path)
        default:
            return ""
        }
    }

    private static func renamedDestination(_ rename: es_event_rename_t) -> String {
        switch rename.destination_type {
        case ES_DESTINATION_TYPE_NEW_PATH:
            return join(
                dir: esString(rename.destination.new_path.dir.pointee.path),
                name: esString(rename.destination.new_path.filename)
            )
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            return esString(rename.destination.existing_file.pointee.path)
        default:
            return ""
        }
    }

    private static func explain(_ result: es_new_client_result_t) -> String {
        switch result {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return """
            FAIL: this binary is not entitled as an Endpoint Security client.
            Local PoC: disable SIP, then sign with packaging/EndpointSecurity.entitlements
            (see ./run_esmonitor.sh). Production: request
            com.apple.developer.endpoint-security.client from Apple and ship a
            system extension.
            """
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return """
            FAIL: Full Disk Access is not granted to this binary.
            System Settings → Privacy & Security → Full Disk Access → add the signed MiniFilter binary,
            then sudo it again.
            """
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "FAIL: Endpoint Security requires root (sudo)."
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "FAIL: too many Endpoint Security clients are already running."
        default:
            return "FAIL: es_new_client returned \(result.rawValue)."
        }
    }

    private static func parse(_ arguments: [String]) -> Options {
        var options = Options()
        var i = 0
        while i < arguments.count {
            let arg = arguments[i]
            if arg == "--seconds", i + 1 < arguments.count {
                options.seconds = Double(arguments[i + 1])
                i += 2
                continue
            }
            if arg == "--process", i + 1 < arguments.count {
                options.processFilters.append(arguments[i + 1])
                i += 2
                continue
            }
            if arg == "--all-files" {
                options.userFacingOnly = false
                i += 1
                continue
            }
            if arg == "--json" {
                options.json = true
                i += 1
                continue
            }
            if arg == "--verbose" {
                options.verbose = true
                i += 1
                continue
            }
            i += 1
        }
        return options
    }
}
