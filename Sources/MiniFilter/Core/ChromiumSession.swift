import Foundation

/// Reads Chromium `Session_*` SNSS files (Chrome, Edge, Brave, …) to recover
/// the front tab's title and URL. This uses the profile on disk, so it works
/// from a root Endpoint Security client without AppleScript / Automation.
enum ChromiumSession {
    private static let magic = Data("SNSS".utf8)
    private static let cmdSetTabWindow: UInt8 = 0
    private static let cmdTabIndexInWindow: UInt8 = 2
    private static let cmdUpdateTabNavigation: UInt8 = 6
    private static let cmdSetSelectedNavigationIndex: UInt8 = 7
    private static let cmdSetSelectedTabInIndex: UInt8 = 8
    private static let cmdSetActiveWindow: UInt8 = 20
    private static let cmdLastActiveTime: UInt8 = 21

    static func latestSessionFile(in directory: URL) -> URL? {
        let files = (try? FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        )) ?? []
        return files
            .filter { $0.lastPathComponent.hasPrefix("Session_") }
            .max { a, b in
                let da = (try? a.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                let db = (try? b.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                return da < db
            }
    }

    static func activePage(file: URL) -> BrowserTab.Page? {
        guard let data = try? Data(contentsOf: file) else { return nil }
        return activePage(data: data)
    }

    static func activePage(data: Data) -> BrowserTab.Page? {
        guard data.count >= 8, data.prefix(4) == magic else { return nil }

        var histories: [Int32: [Int32: (title: String, url: String)]] = [:]
        var selectedNav: [Int32: Int32] = [:]
        var lastActive: [Int32: UInt64] = [:]
        var tabWindow: [Int32: Int32] = [:]
        var tabIndex: [Int32: Int32] = [:]
        var selectedTabInWindow: [Int32: Int32] = [:]
        var activeWindow: Int32?

        var offset = 8
        while offset + 2 <= data.count {
            let size = Int(readUInt16(data, offset) ?? 0)
            let body = offset + 2
            if size == 0 || body + size > data.count { break }
            let id = data[body]
            let payload = data.subdata(in: (body + 1)..<(body + size))
            switch id {
            case cmdUpdateTabNavigation:
                if let nav = decodeNavigation(payload) {
                    histories[nav.tab, default: [:]][nav.index] = (nav.title, nav.url)
                }
            case cmdSetSelectedNavigationIndex:
                if let (tab, index) = intPair(payload), tab >= 0 {
                    selectedNav[tab] = index
                }
            case cmdLastActiveTime:
                if let (tab, time) = lastActiveTime(payload), tab >= 0 {
                    lastActive[tab] = time
                }
            case cmdSetTabWindow:
                if let (window, tab) = intPair(payload), tab >= 0 {
                    tabWindow[tab] = window
                }
            case cmdTabIndexInWindow:
                if let (tab, index) = intPair(payload), tab >= 0 {
                    tabIndex[tab] = index
                }
            case cmdSetSelectedTabInIndex:
                if let (window, index) = intPair(payload) {
                    selectedTabInWindow[window] = index
                }
            case cmdSetActiveWindow:
                if let window = intValue(payload) {
                    activeWindow = window
                }
            default:
                break
            }
            offset = body + size
        }

        func page(for tab: Int32) -> BrowserTab.Page? {
            guard let entries = histories[tab], !entries.isEmpty else { return nil }
            let index = selectedNav[tab] ?? entries.keys.max()
            let pair: (String, String)
            if let index, let hit = entries[index] {
                pair = hit
            } else if let last = entries[entries.keys.max() ?? 0] {
                pair = last
            } else {
                return nil
            }
            let title = pair.0.isEmpty ? nil : pair.0
            let url = pair.1.isEmpty ? nil : pair.1
            if title == nil && url == nil { return nil }
            return BrowserTab.Page(title: title, url: url)
        }

        if let tab = lastActive.max(by: { $0.value < $1.value })?.key,
           let page = page(for: tab) {
            return page
        }

        if let window = activeWindow {
            let tabs = tabWindow.filter { $0.value == window }
            if let wantedIndex = selectedTabInWindow[window],
               let tab = tabs.first(where: { tabIndex[$0.key] == wantedIndex })?.key,
               let page = page(for: tab) {
                return page
            }
            if let tab = tabs.keys.sorted().first, let page = page(for: tab) {
                return page
            }
        }

        if let tab = histories.keys.sorted().last, let page = page(for: tab) {
            return page
        }
        return nil
    }

    // MARK: - SNSS / Pickle

    private struct Nav {
        var tab: Int32
        var index: Int32
        var url: String
        var title: String
    }

    private static func decodeNavigation(_ payload: Data) -> Nav? {
        var pickle = Pickle(payload)
        guard let tab = pickle.readInt32(),
              let index = pickle.readInt32(),
              let url = pickle.readString(),
              let title = pickle.readString16()
        else { return nil }
        return Nav(tab: tab, index: index, url: url, title: title)
    }

    private struct Pickle {
        let data: Data
        var cursor: Int

        init(_ payload: Data) {
            data = payload
            cursor = 4
        }

        mutating func readInt32() -> Int32? {
            guard cursor + 4 <= data.count else { return nil }
            let value = ChromiumSession.readInt32(data, cursor)
            cursor += 4
            return value
        }

        mutating func readString() -> String? {
            guard let count = readLength(), cursor + count <= data.count else { return nil }
            let slice = data.subdata(in: cursor..<(cursor + count))
            cursor += count
            align()
            return String(data: slice, encoding: .utf8) ?? String(decoding: slice, as: UTF8.self)
        }

        mutating func readString16() -> String? {
            guard let units = readLength() else { return nil }
            let nbytes = units * 2
            guard cursor + nbytes <= data.count else { return nil }
            let slice = data.subdata(in: cursor..<(cursor + nbytes))
            cursor += nbytes
            align()
            return String(data: slice, encoding: .utf16LittleEndian)
        }

        mutating func readLength() -> Int? {
            guard let n = readInt32(), n >= 0 else { return nil }
            return Int(n)
        }

        mutating func align() {
            let rem = cursor % 4
            if rem != 0 { cursor += 4 - rem }
        }
    }

    private static func intPair(_ payload: Data) -> (Int32, Int32)? {
        guard payload.count >= 8,
              let a = readInt32(payload, 0),
              let b = readInt32(payload, 4)
        else { return nil }
        return (a, b)
    }

    private static func intValue(_ payload: Data) -> Int32? {
        guard payload.count >= 4 else { return nil }
        return readInt32(payload, 0)
    }

    private static func lastActiveTime(_ payload: Data) -> (Int32, UInt64)? {
        guard payload.count >= 16, let tab = readInt32(payload, 0) else { return nil }
        return (tab, readUInt64(payload, 8) ?? 0)
    }

    private static func readUInt16(_ data: Data, _ offset: Int) -> UInt16? {
        guard offset + 2 <= data.count else { return nil }
        return UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
    }

    private static func readInt32(_ data: Data, _ offset: Int) -> Int32? {
        guard offset + 4 <= data.count else { return nil }
        let u = UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
        return Int32(bitPattern: u)
    }

    private static func readUInt64(_ data: Data, _ offset: Int) -> UInt64? {
        guard offset + 8 <= data.count else { return nil }
        var value: UInt64 = 0
        for i in 0..<8 {
            value |= UInt64(data[offset + i]) << (8 * i)
        }
        return value
    }

    /// Builds a tiny SNSS blob for tests.
    static func makeFixture(
        tab: Int32,
        index: Int32,
        url: String,
        title: String,
        lastActive: UInt64 = 1
    ) -> Data {
        var pickleBody = Data()
        pickleBody.append(contentsOf: int32Bytes(tab))
        pickleBody.append(contentsOf: int32Bytes(index))
        pickleBody.append(pickleString(url))
        pickleBody.append(pickleString16(title))
        var pickle = Data()
        pickle.append(contentsOf: uint32Bytes(UInt32(pickleBody.count)))
        pickle.append(pickleBody)

        var file = Data(magic)
        file.append(contentsOf: int32Bytes(3))
        appendCommand(&file, id: cmdUpdateTabNavigation, payload: pickle)
        var selected = Data()
        selected.append(contentsOf: int32Bytes(tab))
        selected.append(contentsOf: int32Bytes(index))
        appendCommand(&file, id: cmdSetSelectedNavigationIndex, payload: selected)
        var active = Data()
        active.append(contentsOf: int32Bytes(tab))
        active.append(contentsOf: int32Bytes(0))
        active.append(contentsOf: uint64Bytes(lastActive))
        appendCommand(&file, id: cmdLastActiveTime, payload: active)
        return file
    }

    private static func appendCommand(_ file: inout Data, id: UInt8, payload: Data) {
        let size = UInt16(1 + payload.count)
        file.append(contentsOf: [UInt8(size & 0xFF), UInt8(size >> 8)])
        file.append(id)
        file.append(payload)
    }

    private static func pickleString(_ value: String) -> Data {
        let bytes = Array(value.utf8)
        var data = Data(int32Bytes(Int32(bytes.count)))
        data.append(contentsOf: bytes)
        while data.count % 4 != 0 { data.append(0) }
        return data
    }

    private static func pickleString16(_ value: String) -> Data {
        let units = Array(value.utf16)
        var data = Data(int32Bytes(Int32(units.count)))
        for u in units {
            data.append(UInt8(u & 0xFF))
            data.append(UInt8(u >> 8))
        }
        while data.count % 4 != 0 { data.append(0) }
        return data
    }

    private static func int32Bytes(_ value: Int32) -> [UInt8] {
        uint32Bytes(UInt32(bitPattern: value))
    }

    private static func uint32Bytes(_ value: UInt32) -> [UInt8] {
        [
            UInt8(value & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 24) & 0xFF),
        ]
    }

    private static func uint64Bytes(_ value: UInt64) -> [UInt8] {
        (0..<8).map { UInt8((value >> (8 * $0)) & 0xFF) }
    }
}
