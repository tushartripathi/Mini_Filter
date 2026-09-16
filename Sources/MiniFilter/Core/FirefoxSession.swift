import Compression
import Foundation

/// Reads Firefox `recovery.jsonlz4` (and related sessionstore files) for the
/// selected tab's title and URL. Same idea as Chromium `Session_*` files:
/// on-disk, no AppleScript, works from a root Endpoint Security client.
enum FirefoxSession {
    private static let magic = Data([0x6d, 0x6f, 0x7a, 0x4c, 0x7a, 0x34, 0x30, 0x00]) // mozLz40\0

    static func latestSessionFile(in profile: URL) -> URL? {
        let candidates = [
            profile.appending(path: "sessionstore-backups/recovery.jsonlz4"),
            profile.appending(path: "sessionstore-backups/recovery.baklz4"),
            profile.appending(path: "sessionstore.jsonlz4"),
        ]
        return candidates
            .filter { FileManager.default.fileExists(atPath: $0.path) }
            .max { a, b in
                let da = (try? a.resourceValues(forKeys: [.contentModificationDateKey])
                    .contentModificationDate) ?? .distantPast
                let db = (try? b.resourceValues(forKeys: [.contentModificationDateKey])
                    .contentModificationDate) ?? .distantPast
                return da < db
            }
    }

    static func profileDirectories(root: URL, ini: String) -> [URL] {
        var installDefault: String?
        var defaultProfile: String?
        var profiles: [String] = []
        var section = ""
        for raw in ini.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("["), line.hasSuffix("]") {
                section = String(line.dropFirst().dropLast())
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq])
            let value = String(line[line.index(after: eq)...])
            if section.hasPrefix("Install"), key == "Default", !value.isEmpty {
                installDefault = value
            } else if section.hasPrefix("Profile") {
                if key == "Path", !value.isEmpty {
                    profiles.append(value)
                } else if key == "Default", value == "1" {
                    defaultProfile = profiles.last
                }
            }
        }

        var ordered: [String] = []
        var seen = Set<String>()
        func append(_ path: String?) {
            guard let path, !path.isEmpty, seen.insert(path).inserted else { return }
            ordered.append(path)
        }
        append(installDefault)
        append(defaultProfile)
        profiles.forEach { append($0) }

        return ordered.map { path in
            if path.hasPrefix("/") {
                return URL(fileURLWithPath: path)
            }
            return root.appending(path: path)
        }
    }

    static func activePage(file: URL) -> BrowserTab.Page? {
        guard let data = try? Data(contentsOf: file) else { return nil }
        return activePage(data: data)
    }

    static func activePage(data: Data) -> BrowserTab.Page? {
        let json: Data
        if data.starts(with: magic) {
            guard let decoded = decompressMozillaLZ4(data) else { return nil }
            json = decoded
        } else {
            json = data
        }
        return activePage(json: json)
    }

    static func activePage(json: Data) -> BrowserTab.Page? {
        guard let root = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
              let windows = root["windows"] as? [[String: Any]],
              !windows.isEmpty
        else { return nil }

        let selectedWindow = oneBasedIndex(root["selectedWindow"], count: windows.count)
        let window = windows[selectedWindow]
        guard let tabs = window["tabs"] as? [[String: Any]], !tabs.isEmpty else { return nil }
        let selectedTab = oneBasedIndex(window["selected"], count: tabs.count)
        return page(from: tabs[selectedTab])
    }

    static func decompressMozillaLZ4(_ data: Data) -> Data? {
        guard data.count > 12, data.starts(with: magic) else { return nil }
        let expected = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt32.self) }
        guard expected > 0, expected < 32 * 1024 * 1024 else { return nil }
        var out = Data(count: Int(expected))
        let written = out.withUnsafeMutableBytes { dest in
            data.withUnsafeBytes { src in
                guard let destBase = dest.bindMemory(to: UInt8.self).baseAddress,
                      let srcBase = src.bindMemory(to: UInt8.self).baseAddress
                else { return 0 }
                return compression_decode_buffer(
                    destBase,
                    dest.count,
                    srcBase.advanced(by: 12),
                    data.count - 12,
                    nil,
                    COMPRESSION_LZ4_RAW
                )
            }
        }
        guard written > 0 else { return nil }
        if written != out.count {
            out.count = written
        }
        return out
    }

    static func makeMozLz4(_ json: Data) -> Data? {
        var compressed = Data(count: json.count + 64)
        let written = compressed.withUnsafeMutableBytes { dest in
            json.withUnsafeBytes { src in
                guard let destBase = dest.bindMemory(to: UInt8.self).baseAddress,
                      let srcBase = src.bindMemory(to: UInt8.self).baseAddress
                else { return 0 }
                return compression_encode_buffer(
                    destBase,
                    dest.count,
                    srcBase,
                    json.count,
                    nil,
                    COMPRESSION_LZ4_RAW
                )
            }
        }
        guard written > 0 else { return nil }
        compressed.count = written
        var blob = magic
        var size = UInt32(json.count).littleEndian
        blob.append(Data(bytes: &size, count: 4))
        blob.append(compressed)
        return blob
    }

    // MARK: - Internals

    private static func page(from tab: [String: Any]) -> BrowserTab.Page? {
        guard let entries = tab["entries"] as? [[String: Any]], !entries.isEmpty else {
            return nil
        }
        let index = oneBasedIndex(tab["index"], count: entries.count)
        let entry = entries[index]
        let title = string(entry["title"])
        let url = string(entry["url"]) ?? string(entry["originalURI"])
        let page = BrowserTab.Page(title: title, url: url)
        return page.isEmpty ? nil : page
    }

    private static func oneBasedIndex(_ raw: Any?, count: Int) -> Int {
        let value: Int
        if let n = raw as? Int {
            value = n
        } else if let n = raw as? NSNumber {
            value = n.intValue
        } else {
            value = count
        }
        if value <= 0 { return 0 }
        return min(count, value) - 1
    }

    private static func string(_ raw: Any?) -> String? {
        guard let text = raw as? String else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
