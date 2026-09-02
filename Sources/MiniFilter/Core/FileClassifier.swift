import Foundation

/// Allowlist of extensions a person would recognise as their own file.
/// WhatsApp (and other apps) write many internal artefacts; those are ignored.
enum FileClassifier {
    static let userFacingExtensions: Set<String> = [
        // Images
        "jpg", "jpeg", "png", "gif", "heic", "heif", "webp", "bmp", "tiff", "tif", "svg", "avif",
        // Video
        "mp4", "mov", "m4v", "avi", "mkv", "webm", "3gp", "mpg", "mpeg", "wmv", "flv",
        // Audio
        "mp3", "m4a", "aac", "wav", "opus", "ogg", "flac", "aiff", "aif", "amr",
        // Documents
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "txt", "md", "csv", "rtf", "odt", "ods", "odp",
        "pages", "numbers", "key", "epub", "json", "xml", "html", "htm", "vcf", "ics",
        // Archives
        "zip", "rar", "7z", "tar", "gz", "tgz", "dmg", "iso",
    ]

    static func isUserFacingFile(path: String) -> Bool {
        let ext = (path as NSString).pathExtension.lowercased()
        return !ext.isEmpty && userFacingExtensions.contains(ext)
    }

    /// A file the user owns, outside an app sandbox (Desktop, Documents, …).
    static func isUserSource(path: String) -> Bool {
        guard path.hasPrefix("/Users/") else { return false }
        if isAppContainer(path: path) { return false }
        if path.contains(".app/Contents/") { return false }
        if path.contains("/Library/") {
            if path.contains("/Library/CloudStorage/") { return isUserFacingFile(path: path) }
            if path.contains("/Library/Mobile Documents/") { return isUserFacingFile(path: path) }
            return false
        }
        return isUserFacingFile(path: path)
    }

    static func isAppContainer(path: String) -> Bool {
        path.contains("/Library/Containers/")
            || path.contains("/Library/Group Containers/")
            || path.contains("/Library/Application Support/")
            || path.contains("/Library/Daemon Containers/")
    }

    /// Where a person would save or drop a received file.
    static func isUserDestination(path: String) -> Bool {
        guard !isAppContainer(path: path) else { return false }
        let folders = ["/Desktop/", "/Downloads/", "/Documents/", "/Pictures/", "/Movies/", "/Music/"]
        return folders.contains { path.contains($0) } && isUserFacingFile(path: path)
    }

    /// Incoming media stores (WhatsApp Message/Media, and similar).
    static func isAppMediaStore(path: String) -> Bool {
        path.contains("/Message/Media/") || path.contains("/Media/Media/")
    }

    /// App-internal copies: staging, transcode, NSTemporaryDirectory.
    static func isAppStaging(path: String) -> Bool {
        let lower = path.lowercased()
        return lower.contains("whatsapp-inbox")
            || lower.contains("mediaediting")
            || lower.contains("/temporaryitems/")
            || lower.contains("/tmp/documents/")
            || (isAppContainer(path: path) && lower.contains("/tmp/"))
    }
}
